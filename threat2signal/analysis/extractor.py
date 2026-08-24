"""Deterministic HTML parsing and extraction engine (parse phase)."""

from dataclasses import dataclass, field
import html
import ipaddress
import logging
import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup, Tag
import yara

from threat2signal.analysis.ioc_validator import validate_ioc

logger = logging.getLogger(__name__)


# --- Dataclasses (B.1) ---


@dataclass(frozen=True)
class RuleRecord:
    rule_name: str | None
    rule_text: str
    raw_extracted: str | None
    source: str | None
    rule_format: str
    validation_status: str
    validation_error: str | None


@dataclass(frozen=True)
class TechniqueRecord:
    technique_id: str
    tactic: str | None
    name: str | None
    use_description: str | None
    confidence: str
    framework: str
    version: str | None


@dataclass(frozen=True)
class CveRecord:
    cve_id: str
    link_url: str | None
    link_source: str | None


@dataclass(frozen=True)
class IocRecord:
    type: str
    value: str
    context: str | None
    validation_status: str
    source_verified: bool
    needs_review: bool


@dataclass(frozen=True)
class AssetRecord:
    asset_type: str
    original_url: str
    caption: str | None
    alt_text: str | None


@dataclass(frozen=True)
class ActorAlias:
    tracking_name: str
    organization: str | None


@dataclass(frozen=True)
class ExtractionLogEntry:
    extractor: str
    severity: str
    message: str
    context: str | None


@dataclass
class ParseResult:
    detection_rules: list[RuleRecord] = field(default_factory=list)
    techniques: list[TechniqueRecord] = field(default_factory=list)
    d3fend: list[TechniqueRecord] = field(default_factory=list)
    cves: list[CveRecord] = field(default_factory=list)
    iocs: list[IocRecord] = field(default_factory=list)
    figures: list[AssetRecord] = field(default_factory=list)
    assets: list[AssetRecord] = field(default_factory=list)
    sectors: list[str] = field(default_factory=list)
    actor_aliases: list[ActorAlias] = field(default_factory=list)
    logs: list[ExtractionLogEntry] = field(default_factory=list)


# --- Shared Helpers ---


def _warn(
    logs: list[ExtractionLogEntry], extractor: str, message: str,
    context: str | None = None,
) -> None:
    """Append a warning-severity extraction log entry (C1 keystone)."""
    logs.append(ExtractionLogEntry(
        extractor=extractor, severity='warning',
        message=message, context=context,
    ))


def _strip_to_plain_text(element: Tag | str) -> str:
    """Strip all HTML wrapper tags to plain text."""
    if isinstance(element, str):
        return element.strip()
    return element.get_text(strip=True)


def _tag_text_with_breaks(tag: Tag) -> str:
    """Get text from a tag, converting <br>/<p> to newlines without mutating the tree."""
    markup = re.sub(r'<br\s*/?>', '\n', tag.decode_contents())
    markup = re.sub(r'</p\s*>', '\n', markup, flags=re.IGNORECASE)
    text = re.sub(r'<[^>]+>', '', markup)
    return html.unescape(text)


def _dedup_by_id(records: list[TechniqueRecord]) -> list[TechniqueRecord]:
    seen: set[str] = set()
    result: list[TechniqueRecord] = []
    for rec in records:
        if rec.technique_id not in seen:
            seen.add(rec.technique_id)
            result.append(rec)
    return result


# --- Detection Rule Extraction (B.2) ---

_DETECTION_HEADING_RE = re.compile(
    r'\b(yara|sigma|snort|detection(?:s)?)\b', re.IGNORECASE
)
_YARA_NAME_RE = re.compile(r'^rule\s+(\w+)', re.MULTILINE)


def _clean_rule_text(raw_text: str) -> str:
    # Text reaching here is already entity-decoded (get_text / _tag_text_with_breaks);
    # a second html.unescape would corrupt double-escaped markup (M-5).
    lines = raw_text.splitlines()
    cleaned = [line.rstrip() for line in lines]
    while cleaned and not cleaned[0].strip():
        cleaned.pop(0)
    while cleaned and not cleaned[-1].strip():
        cleaned.pop()
    return '\n'.join(cleaned)


def _detect_rule_format(rule_text: str) -> str | None:
    stripped = rule_text.strip()
    if re.search(r'^rule\s+\w+', stripped, re.MULTILINE) and '{' in stripped:
        return 'yara'
    if 'title:' in stripped and 'logsource:' in stripped:
        return 'sigma'
    # Scan past leading comment lines for the Snort/Suricata action keyword (L-2).
    for line in stripped.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if re.match(r'^(alert|drop|reject|pass|log|sdrop|rewrite)\s', line):
            return 'snort'
        break
    return None


def _extract_rule_name(
    rule_text: str, heading_text: str | None, th_text: str | None,
) -> str | None:
    match = _YARA_NAME_RE.search(rule_text)
    if match:
        return match.group(1)
    if th_text and th_text.strip():
        return th_text.strip()
    if heading_text and heading_text.strip():
        return heading_text.strip()
    return None


def _validate_yara_rule(rule_text: str) -> tuple[str, str | None]:
    try:
        yara.compile(source=rule_text)
        return ('valid', None)
    except yara.SyntaxError as e:
        return ('invalid', str(e))
    except yara.Error as e:
        return ('invalid', str(e))


def _build_rule_record(
    rule_text: str,
    raw_text: str | None,
    heading_text: str | None,
    th_text: str | None,
    logs: list[ExtractionLogEntry],
) -> RuleRecord | None:
    cleaned = _clean_rule_text(rule_text)
    if not cleaned.strip():
        return None
    fmt = _detect_rule_format(cleaned)
    if fmt is None:
        # Substantive block inside a detection section that matched no known
        # rule format — recognized-but-unparseable, so flag for review (C1).
        if len(cleaned) > 40:
            _warn(
                logs, 'detection_rules',
                'detection section content did not match a known rule format',
                context=(heading_text or th_text),
            )
        return None
    name = _extract_rule_name(cleaned, heading_text, th_text)
    if fmt == 'yara':
        status, error = _validate_yara_rule(cleaned)
    else:
        status, error = 'unvalidated', None
    return RuleRecord(
        rule_name=name, rule_text=cleaned, raw_extracted=raw_text,
        source='html_parsed', rule_format=fmt,
        validation_status=status, validation_error=error,
    )


def _p_to_text(p: Tag) -> str:
    code = p.find('code')
    return _tag_text_with_breaks(code) if code else p.get_text()


def _extract_cell_text(cell: Tag) -> str:
    """Extract rule text from a table cell, handling nested <p> and <br/> (L-12)."""
    p_tags = cell.find_all('p')
    if p_tags:
        return '\n'.join(_p_to_text(p) for p in p_tags)
    return _tag_text_with_breaks(cell)


def _is_rule_name_row(row: Tag) -> str | None:
    cells = row.find_all('td')
    if len(cells) != 1:
        return None
    cell = cells[0]
    strong = cell.find('strong')
    if not strong:
        return None
    if strong.get_text(strip=True) == cell.get_text(strip=True):
        return strong.get_text(strip=True)
    return None


def _find_largest_cell_text(table: Tag) -> str | None:
    best = ''
    for td in table.find_all('td'):
        text = _extract_cell_text(td)
        if len(text) > len(best):
            best = text
    return best if best.strip() else None


def _extract_pattern_c_rules(
    rows: list[Tag],
    name_rows: list[tuple[int, str]],
    heading_text: str,
    logs: list[ExtractionLogEntry],
) -> list[RuleRecord]:
    rules: list[RuleRecord] = []
    for j, (start_idx, name) in enumerate(name_rows):
        end_idx = name_rows[j + 1][0] if j + 1 < len(name_rows) else len(rows)
        content_rows = rows[start_idx + 1:end_idx]
        lines = [
            _extract_cell_text(td)
            for tr in content_rows for td in tr.find_all('td')
            if td.get_text(strip=True)
        ]
        if lines:
            combined = '\n'.join(lines)
            record = _build_rule_record(
                combined, combined, heading_text, name, logs,
            )
            if record:
                rules.append(record)
    return rules


def _extract_rules_from_table(
    table: Tag, heading_text: str, logs: list[ExtractionLogEntry],
) -> list[RuleRecord]:
    rows = table.find_all('tr')
    name_rows = [(i, _is_rule_name_row(row)) for i, row in enumerate(rows)]
    labeled = [(i, name) for i, name in name_rows if name is not None]
    if labeled:
        return _extract_pattern_c_rules(rows, labeled, heading_text, logs)
    # Patterns A/B: single rule per table
    th = table.find('th')
    th_text = th.get_text(strip=True) if th else None
    rule_text = _find_largest_cell_text(table)
    if rule_text:
        record = _build_rule_record(
            rule_text, rule_text, heading_text, th_text, logs,
        )
        if record:
            return [record]
    return []


def _collect_code_lines(el: Tag, lines: list[str], code_started: bool) -> bool:
    """Append rule lines from ``el``; returns whether code has begun.

    Prose-only elements preceding the first <code> are dropped so leading
    narration does not contaminate the rule text (M-2).
    """
    code_tags = el.find_all('code')
    if code_tags:
        for code in code_tags:
            lines.append(_tag_text_with_breaks(code))
        return True
    if code_started:
        text = el.get_text(strip=True)
        if text:
            lines.append(text)
    return code_started


def _flush_div_rule(
    rules: list[RuleRecord],
    lines: list[str],
    heading_text: str,
    name: str | None,
    logs: list[ExtractionLogEntry],
) -> None:
    combined = '\n'.join(lines)
    record = _build_rule_record(combined, combined, heading_text, name, logs)
    if record:
        rules.append(record)


def _extract_rules_from_divs(
    elements: list[Tag], heading_text: str, logs: list[ExtractionLogEntry],
) -> list[RuleRecord]:
    rules: list[RuleRecord] = []
    current_name: str | None = heading_text
    current_lines: list[str] = []
    code_started = False
    for el in elements:
        if el.name and re.match(r'^h[2-6]$', el.name):
            if current_lines:
                _flush_div_rule(
                    rules, current_lines, heading_text, current_name, logs,
                )
                current_lines = []
            current_name = el.get_text(strip=True)
            code_started = False
            continue
        code_started = _collect_code_lines(el, current_lines, code_started)
    if current_lines:
        _flush_div_rule(rules, current_lines, heading_text, current_name, logs)
    return rules


def _find_detection_sections(
    soup: BeautifulSoup,
) -> list[tuple[str, list[Tag]]]:
    sections: list[tuple[str, list[Tag]]] = []
    for heading in soup.find_all(re.compile(r'^h[234]$')):
        text = heading.get_text(strip=True)
        if not _DETECTION_HEADING_RE.search(text):
            continue
        siblings: list[Tag] = []
        for sib in heading.next_siblings:
            if not isinstance(sib, Tag):
                continue
            if sib.name and re.match(r'^h[234]$', sib.name):
                if int(sib.name[1]) <= int(heading.name[1]):
                    break
                siblings.append(sib)
                continue
            siblings.append(sib)
        sections.append((text, siblings))
    return sections


def _extract_detection_rules(
    soup: BeautifulSoup, source: str, logs: list[ExtractionLogEntry],
) -> list[RuleRecord]:
    """Extract YARA, Sigma, and Snort detection rules from advisory HTML."""
    if source != 'cisa':
        return []
    rules: list[RuleRecord] = []
    for heading_text, elements in _find_detection_sections(soup):
        tables = [el for el in elements if el.name == 'table']
        non_tables = [el for el in elements if el.name != 'table']
        for table in tables:
            rules.extend(_extract_rules_from_table(table, heading_text, logs))
        if non_tables:
            rules.extend(
                _extract_rules_from_divs(non_tables, heading_text, logs)
            )
    rules = _dedup_rules(rules)
    if not rules:
        logger.debug("No detection rules found in %s advisory", source)
    return rules


def _dedup_rules(rules: list[RuleRecord]) -> list[RuleRecord]:
    """Dedupe rules by (name, text) — nested detection headings double-collect (M-1)."""
    seen: set[tuple[str | None, str]] = set()
    result: list[RuleRecord] = []
    for rule in rules:
        key = (rule.rule_name, rule.rule_text)
        if key not in seen:
            seen.add(key)
            result.append(rule)
    return result


# --- ATT&CK Technique Extraction (B.3) ---

_TECHNIQUE_ID_RE = re.compile(r'T\d{4}(?:\.\d{3})?')
# ATT&CK URLs use /T1078/003/ path format for sub-techniques
_TECHNIQUE_URL_RE = re.compile(r'/techniques/(T\d{4})(?:/(\d{3}))?')
_ATTACK_URL_RE = re.compile(r'attack\.mitre\.org')
_ATTACK_VERSION_RE = re.compile(r'/versions/v(\d+)/')


def _is_attack_table(table: Tag) -> bool:
    for th in table.find_all('th'):
        if 'technique' in _strip_to_plain_text(th).lower():
            return True
    return False


def _extract_tactic_from_caption(table: Tag) -> str | None:
    caption = table.find('caption')
    if caption:
        text = _strip_to_plain_text(caption)
        return text if text else None
    return None


def _technique_id_from_url(href: str) -> str | None:
    """Parse technique ID from ATT&CK URL path (/techniques/T1078/003/ format)."""
    match = _TECHNIQUE_URL_RE.search(href)
    if match:
        base = match.group(1)
        sub = match.group(2)
        return f"{base}.{sub}" if sub else base
    return None


def _parse_technique_from_cell(cell: Tag) -> tuple[str | None, str | None]:
    link = cell.find('a', href=True)
    if link:
        href = link['href']
        version_match = _ATTACK_VERSION_RE.search(href)
        version = f"v{version_match.group(1)}" if version_match else None
        if _ATTACK_URL_RE.search(href):
            tech_id = _technique_id_from_url(href)
            if tech_id:
                return (tech_id, version)
        # H-2: broken links point at cisa.gov news pages, not attack.mitre.org;
        # the technique ID still lives in the title attribute, so search it
        # regardless of host.
        id_match = _TECHNIQUE_ID_RE.search(link.get('title', ''))
        if id_match:
            return (id_match.group(), version)
    text = _strip_to_plain_text(cell)
    id_match = _TECHNIQUE_ID_RE.search(text)
    if id_match:
        return (id_match.group(), None)
    return (None, None)


def _map_attack_columns(headers: list[str]) -> dict[str, int]:
    """Map ATT&CK column roles to indices from header text (M-6)."""
    roles: dict[str, int] = {}
    for idx, header in enumerate(headers):
        tokens = set(re.findall(r'[a-z0-9]+', header.lower()))
        if 'tactic' in tokens:
            role = 'tactic'
        elif 'id' in tokens:
            role = 'id'
        elif tokens & {'use', 'description', 'procedure'}:
            role = 'use'
        elif tokens & {'technique', 'title', 'name'}:
            role = 'name'
        else:
            continue
        roles.setdefault(role, idx)
    return roles


def _cell_text_at(cells: list[Tag], idx: int | None) -> str | None:
    if idx is None or idx >= len(cells):
        return None
    text = _strip_to_plain_text(cells[idx])
    return text if text else None


def _parse_attack_row(
    cells: list[Tag], roles: dict[str, int], caption_tactic: str | None,
) -> TechniqueRecord | None:
    id_idx = roles.get('id', roles.get('name'))
    if id_idx is None or id_idx >= len(cells):
        return None
    tech_id, version = _parse_technique_from_cell(cells[id_idx])
    if not tech_id:
        return None
    return TechniqueRecord(
        technique_id=tech_id,
        tactic=_cell_text_at(cells, roles.get('tactic')) or caption_tactic,
        name=_cell_text_at(cells, roles.get('name')),
        use_description=_cell_text_at(cells, roles.get('use')),
        confidence='advisory_stated', framework='attack', version=version,
    )


def _parse_attack_table_rows(
    table: Tag, roles: dict[str, int], caption_tactic: str | None,
    logs: list[ExtractionLogEntry],
) -> list[TechniqueRecord]:
    records: list[TechniqueRecord] = []
    for row in table.find_all('tr'):
        cells = row.find_all('td')
        if not cells:
            continue
        record = _parse_attack_row(cells, roles, caption_tactic)
        if record:
            records.append(record)
        elif any(_strip_to_plain_text(c) for c in cells):
            # C1: recognized ATT&CK data row we could not pull a technique ID from.
            _warn(
                logs, 'techniques',
                'ATT&CK table row had no extractable technique ID',
                context=_strip_to_plain_text(row)[:120] or None,
            )
    return records


def _extract_inline_attack_refs(soup: BeautifulSoup) -> list[TechniqueRecord]:
    records: list[TechniqueRecord] = []
    for link in soup.find_all('a', href=True):
        if 'attack.mitre.org' not in link['href']:
            continue
        if link.find_parent('table'):
            continue
        href = link['href']
        tech_id = _technique_id_from_url(href)
        if not tech_id:
            id_match = _TECHNIQUE_ID_RE.search(link.get('title', ''))
            tech_id = id_match.group() if id_match else None
        if not tech_id:
            continue
        version_match = _ATTACK_VERSION_RE.search(href)
        version = f"v{version_match.group(1)}" if version_match else None
        records.append(TechniqueRecord(
            technique_id=tech_id, tactic=None,
            name=link.get_text(strip=True) or None,
            use_description=None, confidence='advisory_stated',
            framework='attack', version=version,
        ))
    return records


def _extract_attack_techniques(
    soup: BeautifulSoup, source: str, logs: list[ExtractionLogEntry],
) -> list[TechniqueRecord]:
    """Extract ATT&CK technique references from advisory HTML."""
    records: list[TechniqueRecord] = []
    for table in soup.find_all('table'):
        if not _is_attack_table(table):
            continue
        headers = [_strip_to_plain_text(th) for th in table.find_all('th')]
        roles = _map_attack_columns(headers)
        if 'id' not in roles and 'name' not in roles:
            _warn(
                logs, 'techniques',
                'ATT&CK table headers did not map to a technique/ID column',
                context='; '.join(headers) or None,
            )
            continue
        caption_tactic = (
            _extract_tactic_from_caption(table) if 'tactic' not in roles else None
        )
        records.extend(
            _parse_attack_table_rows(table, roles, caption_tactic, logs)
        )
    records.extend(_extract_inline_attack_refs(soup))
    return _dedup_by_id(records)


def _scan_text_for_techniques(text: str) -> list[TechniqueRecord]:
    """Scan plain text for ATT&CK technique IDs via regex."""
    seen: set[str] = set()
    records: list[TechniqueRecord] = []
    for match in _TECHNIQUE_ID_RE.finditer(text):
        tech_id = match.group()
        if tech_id not in seen:
            seen.add(tech_id)
            records.append(TechniqueRecord(
                technique_id=tech_id, tactic=None, name=None,
                use_description=None, confidence='regex_match',
                framework='attack', version=None,
            ))
    return records


# --- D3FEND Extraction (B.3b) ---

_D3FEND_ID_RE = re.compile(r'D3-[A-Z]+')


def _is_d3fend_table(table: Tag) -> bool:
    for th in table.find_all('th'):
        text = _strip_to_plain_text(th).lower()
        if 'countermeasure' in text or 'd3fend' in text:
            return True
    return False


def _parse_d3fend_id(cell: Tag) -> str | None:
    id_match = _D3FEND_ID_RE.search(_strip_to_plain_text(cell))
    if id_match:
        return id_match.group()
    link = cell.find('a', href=True)
    if link:
        id_match = _D3FEND_ID_RE.search(link['href'])
        if id_match:
            return id_match.group()
    return None


def _parse_d3fend_table_rows(table: Tag) -> list[TechniqueRecord]:
    records: list[TechniqueRecord] = []
    for row in table.find_all('tr'):
        cells = row.find_all('td')
        if len(cells) < 2:
            continue
        name = _strip_to_plain_text(cells[0])
        tech_id = _parse_d3fend_id(cells[1])
        if not tech_id:
            continue
        description = (
            _strip_to_plain_text(cells[2]) if len(cells) >= 3 else None
        )
        records.append(TechniqueRecord(
            technique_id=tech_id, tactic=None, name=name,
            use_description=description, confidence='advisory_stated',
            framework='d3fend', version=None,
        ))
    return records


def _extract_inline_d3fend_refs(soup: BeautifulSoup) -> list[TechniqueRecord]:
    records: list[TechniqueRecord] = []
    for link in soup.find_all('a', href=True):
        if 'd3fend.mitre.org' not in link['href']:
            continue
        if link.find_parent('table'):
            continue
        id_match = _D3FEND_ID_RE.search(link['href'])
        if not id_match:
            id_match = _D3FEND_ID_RE.search(link.get_text())
        if not id_match:
            continue
        records.append(TechniqueRecord(
            technique_id=id_match.group(), tactic=None,
            name=link.get_text(strip=True) or None,
            use_description=None, confidence='advisory_stated',
            framework='d3fend', version=None,
        ))
    return records


def _extract_d3fend(
    soup: BeautifulSoup, source: str, logs: list[ExtractionLogEntry],
) -> list[TechniqueRecord]:
    """Extract D3FEND countermeasure references from advisory HTML."""
    records: list[TechniqueRecord] = []
    for table in soup.find_all('table'):
        if not _is_d3fend_table(table):
            continue
        records.extend(_parse_d3fend_table_rows(table))
    records.extend(_extract_inline_d3fend_refs(soup))
    return _dedup_by_id(records)


def _scan_text_for_d3fend(text: str) -> list[TechniqueRecord]:
    """Scan plain text for D3FEND technique IDs via regex."""
    seen: set[str] = set()
    records: list[TechniqueRecord] = []
    for match in _D3FEND_ID_RE.finditer(text):
        tech_id = match.group()
        if tech_id not in seen:
            seen.add(tech_id)
            records.append(TechniqueRecord(
                technique_id=tech_id, tactic=None, name=None,
                use_description=None, confidence='regex_match',
                framework='d3fend', version=None,
            ))
    return records


# --- CVE Extraction (B.4) ---

_CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}')


def _classify_cve_link(href: str) -> str | None:
    if 'cve.org' in href or 'cve.mitre.org' in href:
        return 'cve_org'
    if 'nvd.nist.gov' in href:
        return 'nvd'
    if 'msrc.microsoft.com' in href:
        return 'msrc'
    return None


def _build_cve_link_map(soup: BeautifulSoup) -> dict[str, tuple[str, str]]:
    cve_links: dict[str, tuple[str, str]] = {}
    for link in soup.find_all('a', href=True):
        href = link['href']
        link_source = _classify_cve_link(href)
        if link_source is None:
            continue
        combined = link.get_text() + ' ' + href
        for match in _CVE_RE.finditer(combined):
            cve_id = match.group()
            if cve_id not in cve_links:
                cve_links[cve_id] = (href, link_source)
    return cve_links


def _extract_cve_ids(
    text_or_soup: BeautifulSoup | str, logs: list[ExtractionLogEntry],
) -> list[CveRecord]:
    """Extract CVE identifiers from advisory HTML or plain text."""
    if isinstance(text_or_soup, str):
        full_text = text_or_soup
        cve_links: dict[str, tuple[str, str]] = {}
    else:
        cve_links = _build_cve_link_map(text_or_soup)
        # Separator prevents adjacent cells merging into a fabricated CVE ID (M-3).
        full_text = text_or_soup.get_text(' ')
    seen: set[str] = set()
    records: list[CveRecord] = []
    for match in _CVE_RE.finditer(full_text):
        cve_id = match.group()
        if cve_id in seen:
            continue
        seen.add(cve_id)
        # link_source is always one of cve_org|nvd|msrc|none, never None (L-6).
        link_url, link_source = cve_links.get(cve_id, (None, 'none'))
        records.append(CveRecord(
            cve_id=cve_id, link_url=link_url, link_source=link_source,
        ))
    return records


# --- IOC Extraction (B.5) ---

_SKIP_TABLE_KEYWORDS = frozenset({
    'technique', 'countermeasure', 'tactic', 'command', 'plugin',
})

_IOC_VALUE_KEYWORDS = frozenset({
    'hash', 'md5', 'sha', 'sha256', 'sha1', 'sha512', 'ssdeep',
    'ip', 'address', 'domain', 'url', 'email', 'ioc',
})

_CONTEXT_KEYWORDS = frozenset({
    'description', 'details', 'use', 'context', 'notes',
    'file', 'filename', 'content',
})

# Types precise enough to trust from an unstructured per-cell scan; domains are
# excluded because arbitrary config/metadata text produces too many false positives
# (WS-8 A.2).
_HIGH_CONFIDENCE_IOC_TYPES = frozenset({
    'ip', 'md5', 'sha1', 'sha256', 'sha512', 'ssdeep',
})

# Last labels that mark a filename, not a domain (M-7).
_FILE_EXTENSIONS = frozenset({
    'exe', 'dll', 'bat', 'ps1', 'lnk', 'vbs', 'scr', 'doc', 'docx',
    'xls', 'xlsx', 'zip', 'rar', '7z', 'jsp', 'aspx', 'php',
})


def _defang_normalize(value: str) -> str:
    """Reverse defanging in IOC values."""
    from threat2signal.analysis.ioc_validator import refang_value
    return refang_value(value)


# Unix path: at least two '/' separators and a non-empty filename component
# (rejects bare '/' and directory-only paths like '/tmp/').
_UNIX_FILEPATH_RE = re.compile(r'^/([^/\0]+/)+[^/\0]+$')

# Windows drive-letter path, e.g. C:\Windows\System32\cmd.exe.
_WINDOWS_FILEPATH_RE = re.compile(r'^[A-Za-z]:\\')


def _looks_like_filepath(value: str) -> bool:
    """Detect Unix paths, Windows drive paths, and %env%-style Windows paths."""
    if _UNIX_FILEPATH_RE.match(value):
        return True
    if value.startswith('%'):
        return True
    return bool(_WINDOWS_FILEPATH_RE.match(value))


def _infer_ioc_type(value: str, context_hint: str | None = None) -> str | None:
    """Infer IOC type from value format."""
    if re.fullmatch(r'[a-f0-9]{32}', value, re.I):
        return 'md5'
    if re.fullmatch(r'[a-f0-9]{40}', value, re.I):
        return 'sha1'
    if re.fullmatch(r'[a-f0-9]{64}', value, re.I):
        return 'sha256'
    if re.fullmatch(r'[a-f0-9]{128}', value, re.I):
        return 'sha512'
    if re.fullmatch(r'\d+:[A-Za-z0-9/+]+:[A-Za-z0-9/+]+', value):
        return 'ssdeep'
    if value.startswith(('http://', 'https://')):
        return 'url'
    if '@' in value and '.' in value.split('@')[-1]:
        return 'email'
    try:
        ipaddress.ip_address(value)
        return 'ip'
    except ValueError:
        pass
    if '.' in value and ' ' not in value and re.fullmatch(
        r'[\w.*-]+(?:\.[\w-]+)+', value,
    ):
        # A trailing executable/document extension is a filename, not a domain (M-7).
        if value.rsplit('.', 1)[-1].lower() in _FILE_EXTENSIONS:
            return None
        return 'domain'
    if _looks_like_filepath(value):
        return 'filepath'
    # Mutexes are arbitrary strings with no distinguishing format -- only trust
    # the surrounding table caption / heading text when it names them explicitly
    # (WS-8 B.2), so this never fires on hash-like or free-text values by accident.
    if context_hint and re.search(r'\b(?:mutex|mutant)\b', context_hint, re.I):
        return 'mutex'
    return None


def _split_cell_values(text: str) -> list[str]:
    """Split combined IOC cell values (e.g. 'IP aka domain')."""
    if ' aka ' in text:
        return [v.strip() for v in text.split(' aka ') if v.strip()]
    if ' / ' in text:
        return [v.strip() for v in text.split(' / ') if v.strip()]
    return [text.strip()] if text.strip() else []


# Only high-confidence formats are trusted when pulled out of a compound bullet
# string (WS-8 A.1) -- domains are excluded because tokens like "Storm-0501" or
# an actor alias can accidentally match the domain-label regex.
_COMPOUND_TOKEN_TYPES = frozenset({
    'md5', 'sha1', 'sha256', 'sha512', 'ip', 'url', 'filepath',
})


def _extract_compound_token(
    normalized: str, context_hint: str | None,
) -> tuple[str, str, str] | None:
    """Pull a high-confidence IOC token out of a compound bullet string.

    JPCERT bullet lists commonly read "MALWARE_NAME hash_value" (or, less
    often, "hash_value MALWARE_NAME"). Returns (ioc_type, ioc_value,
    remaining_text) for the first matching token, checking the last token
    first since that ordering is the common case.
    """
    tokens = normalized.split()
    if len(tokens) < 2:
        return None
    ordered = [tokens[-1], *tokens[:-1]]
    for token in ordered:
        token_type = _infer_ioc_type(token, context_hint=context_hint)
        if token_type in _COMPOUND_TOKEN_TYPES:
            remaining = ' '.join(t for t in tokens if t != token)
            return (token_type, token, remaining)
    return None


def _build_ioc_from_value(
    raw_value: str, context: str | None, logs: list[ExtractionLogEntry],
    context_hint: str | None = None,
) -> IocRecord | None:
    """Build an IocRecord from a raw value with defanging, inference, and validation."""
    normalized = _defang_normalize(raw_value)
    if not normalized:
        return None
    ioc_type = _infer_ioc_type(normalized, context_hint=context_hint)
    if ioc_type is None:
        compound = _extract_compound_token(normalized, context_hint)
        if compound is None:
            return None
        ioc_type, normalized, remaining = compound
        context = f"{remaining}; {context}" if context else remaining
    if ioc_type in ('md5', 'sha1', 'sha256', 'sha512'):
        normalized = normalized.lower()
    status, needs_review = validate_ioc(ioc_type, normalized)
    return IocRecord(
        type=ioc_type, value=normalized, context=context,
        validation_status=status, source_verified=True,
        needs_review=needs_review,
    )


def _is_ioc_skip_table(table: Tag) -> bool:
    """Check if table should be skipped for IOC extraction (ATT&CK/D3FEND/command)."""
    for th in table.find_all('th'):
        header_lower = _strip_to_plain_text(th).lower()
        if any(kw in header_lower for kw in _SKIP_TABLE_KEYWORDS):
            return True
    return False


def _is_vertical_table(table: Tag) -> bool:
    """Check if table uses th/td pair layout (vertical metadata table)."""
    rows = table.find_all('tr')
    if len(rows) < 2:
        return False
    # Vertical tables have <th> and <td> in each row as field label + value
    th_td_rows = sum(1 for row in rows if row.find('th') and row.find('td'))
    return th_td_rows >= len(rows) * 0.8


def _cells_mostly_iocs(table: Tag) -> bool:
    """True if >50% of non-empty body cells parse as IOCs (shared >50% gate)."""
    values = [
        text for td in table.find_all('td')
        if (text := _strip_to_plain_text(td))
    ]
    if not values:
        return False
    ioc_count = sum(
        1 for v in values
        if _infer_ioc_type(_defang_normalize(v)) is not None
    )
    return ioc_count > len(values) * 0.5


def _is_grid_table(table: Tag) -> bool:
    """Check if table is a headerless IOC grid (each cell is an independent IOC).

    A headerless table is only a grid when most of its cells actually parse as
    IOCs; layout/hex-config tables must not be treated as grids (M-8).
    """
    if table.find('thead') is not None or table.find('th') is not None:
        return False
    return _cells_mostly_iocs(table)


def _extract_iocs_from_vertical_table(
    table: Tag, logs: list[ExtractionLogEntry],
) -> list[IocRecord]:
    """Extract IOCs from vertical th/td pair tables (per-sample metadata)."""
    iocs: list[IocRecord] = []
    for row in table.find_all('tr'):
        th = row.find('th')
        td = row.find('td')
        if not th or not td:
            continue
        field_name = _strip_to_plain_text(th).lower()
        if not any(kw in field_name for kw in ('md5', 'sha', 'hash', 'ssdeep')):
            continue
        raw_value = _strip_to_plain_text(td)
        for part in _split_cell_values(raw_value):
            record = _build_ioc_from_value(part, field_name, logs)
            if record:
                iocs.append(record)
    return iocs


def _extract_iocs_from_grid_table(
    table: Tag, logs: list[ExtractionLogEntry],
) -> list[IocRecord]:
    """Extract IOCs from headerless grid tables (each cell is an IOC)."""
    iocs: list[IocRecord] = []
    for td in table.find_all('td'):
        raw_value = _strip_to_plain_text(td)
        for part in _split_cell_values(raw_value):
            record = _build_ioc_from_value(part, None, logs)
            if record:
                iocs.append(record)
    return iocs


def _map_table_columns(headers: list[str]) -> dict[int, str]:
    """Map column indices to IOC field classifications from header text.

    Match keywords on whole tokens, not substrings, so 'Description' no longer
    reads as an IP column via 'ip' in 'description'; context keywords win over
    generic value keywords (H-1).
    """
    mapping: dict[int, str] = {}
    for idx, header in enumerate(headers):
        tokens = set(re.findall(r'[a-z0-9]+', header.lower()))
        if tokens & _CONTEXT_KEYWORDS:
            mapping[idx] = 'context'
        elif tokens & _IOC_VALUE_KEYWORDS or 'indicator' in tokens:
            mapping[idx] = 'ioc_value'
    return mapping


def _extract_row_context(
    cells: list[Tag], ctx_cols: list[int],
) -> str | None:
    """Collect context text from designated context columns in a row."""
    parts: list[str] = []
    for i in ctx_cols:
        if i >= len(cells):
            continue
        text = _strip_to_plain_text(cells[i])
        if text:
            parts.append(text)
    return '; '.join(parts) if parts else None


def _extract_iocs_from_horizontal_table(
    table: Tag, col_map: dict[int, str], logs: list[ExtractionLogEntry],
) -> list[IocRecord]:
    """Extract IOCs from standard horizontal tables with mapped IOC columns."""
    ioc_cols = [i for i, c in col_map.items() if c == 'ioc_value']
    ctx_cols = [i for i, c in col_map.items() if c == 'context']
    caption_tag = table.find('caption')
    context_hint = _strip_to_plain_text(caption_tag) if caption_tag else None
    iocs: list[IocRecord] = []
    for row in table.find_all('tr'):
        cells = row.find_all('td')
        if not cells:
            continue
        context = _extract_row_context(cells, ctx_cols)
        for col_idx in ioc_cols:
            if col_idx >= len(cells):
                continue
            raw_value = _strip_to_plain_text(cells[col_idx])
            for part in _split_cell_values(raw_value):
                record = _build_ioc_from_value(
                    part, context, logs, context_hint=context_hint,
                )
                if record:
                    iocs.append(record)
    return iocs


def _extract_iocs_percell(
    table: Tag, logs: list[ExtractionLogEntry],
) -> list[IocRecord]:
    """Per-cell fallback for tables whose headers do not align (colspan/time-period).

    Uses any row <th> as context so C2 IPs under month columns are not lost (H-4).
    """
    iocs: list[IocRecord] = []
    for row in table.find_all('tr'):
        row_header = row.find('th')
        context = _strip_to_plain_text(row_header) if row_header else None
        for td in row.find_all('td'):
            for part in _split_cell_values(_strip_to_plain_text(td)):
                record = _build_ioc_from_value(part, context, logs)
                if record:
                    iocs.append(record)
    return iocs


def _extract_iocs_from_headerless_table(
    table: Tag, logs: list[ExtractionLogEntry],
) -> list[IocRecord]:
    """Handle a table with no <th>: grid if mostly IOCs, else warn (M-8/C1)."""
    if _is_grid_table(table):
        return _extract_iocs_from_grid_table(table, logs)
    _warn(
        logs, 'iocs',
        'headerless table did not parse as an IOC grid (>50% gate failed)',
    )
    return []


def _extract_iocs_from_headed_table(
    table: Tag, headers: list[str], logs: list[ExtractionLogEntry],
) -> list[IocRecord]:
    """Map headers to IOC columns; fall back per-cell / warn when unmapped (H-4/C1)."""
    col_map = _map_table_columns(headers)
    if any(role == 'ioc_value' for role in col_map.values()):
        return _extract_iocs_from_horizontal_table(table, col_map, logs)
    # Recognized IOC-ish table whose headers map to no IOC column.
    if _cells_mostly_iocs(table):
        _warn(
            logs, 'iocs',
            'table headers mapped to no IOC column; used per-cell fallback',
            context='; '.join(headers) or None,
        )
        return _extract_iocs_percell(table, logs)
    # Low-confidence per-cell scan: recover IPs and hashes from config/metadata
    # tables where most cells are non-IOC but a minority hold high-value
    # indicators, e.g. a malware config table with one C2 IP among a dozen
    # hex bytes / sleep timers / file paths (WS-8 A.2).
    recovered: list[IocRecord] = []
    for td in table.find_all('td'):
        cell_text = _strip_to_plain_text(td)
        if not cell_text:
            continue
        normalized = _defang_normalize(cell_text)
        if not normalized:
            continue
        ioc_type = _infer_ioc_type(normalized)
        if ioc_type not in _HIGH_CONFIDENCE_IOC_TYPES:
            continue
        if ioc_type in ('md5', 'sha1', 'sha256', 'sha512'):
            normalized = normalized.lower()
        status, _ = validate_ioc(ioc_type, normalized)
        recovered.append(IocRecord(
            type=ioc_type, value=normalized, context='; '.join(headers) or None,
            validation_status=status, source_verified=False, needs_review=True,
        ))
    if recovered:
        _warn(
            logs, 'iocs',
            f'recovered {len(recovered)} high-confidence IOC(s) from '
            'config/metadata table via per-cell scan',
            context='; '.join(headers) or None,
        )
    _warn(
        logs, 'iocs',
        'table headers mapped to no IOC column and cells did not parse as IOCs',
        context='; '.join(headers) or None,
    )
    return recovered


def _extract_iocs_from_one_table(
    table: Tag, logs: list[ExtractionLogEntry],
) -> list[IocRecord]:
    if _is_ioc_skip_table(table):
        return []
    if _is_vertical_table(table):
        return _extract_iocs_from_vertical_table(table, logs)
    headers = [_strip_to_plain_text(th) for th in table.find_all('th')]
    if not headers:
        return _extract_iocs_from_headerless_table(table, logs)
    return _extract_iocs_from_headed_table(table, headers, logs)


def _extract_iocs_from_tables(
    soup: BeautifulSoup, source: str, logs: list[ExtractionLogEntry],
) -> list[IocRecord]:
    """Extract IOCs from all eligible tables in the HTML."""
    iocs: list[IocRecord] = []
    for table in soup.find_all('table'):
        iocs.extend(_extract_iocs_from_one_table(table, logs))
    return iocs


def _is_ioc_pre_block(text: str) -> bool:
    """Check if >50% of non-empty lines in a pre block match IOC patterns."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return False
    ioc_count = sum(
        1 for line in lines
        if _infer_ioc_type(_defang_normalize(line)) is not None
    )
    return ioc_count > len(lines) * 0.5


def _get_pre_block_context(pre: Tag) -> str | None:
    """Find preceding heading text for a pre block as context signal."""
    for sibling in pre.previous_siblings:
        if not isinstance(sibling, Tag):
            continue
        if sibling.name and re.match(r'^h[1-6]$', sibling.name):
            text = sibling.get_text(strip=True).lower()
            if any(kw in text for kw in ('appendix', 'ioc', 'indicator')):
                return sibling.get_text(strip=True)
            break
    return None


def _extract_iocs_from_pre_blocks(
    soup: BeautifulSoup, logs: list[ExtractionLogEntry],
) -> list[IocRecord]:
    """Extract IOCs from JPCERT pre blocks with line-separated values."""
    iocs: list[IocRecord] = []
    for pre in soup.find_all('pre'):
        text = pre.get_text()
        if not _is_ioc_pre_block(text):
            continue
        context = _get_pre_block_context(pre)
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            record = _build_ioc_from_value(line, context, logs)
            if record:
                iocs.append(record)
    return iocs


def _find_appendix_headings(soup: BeautifulSoup) -> list[Tag]:
    """Find headings that introduce appendix or IOC sections."""
    headings: list[Tag] = []
    for heading in soup.find_all(re.compile(r'^h[1-6]$')):
        text = heading.get_text(strip=True).lower()
        if 'appendix' in text or 'ioc' in text or 'indicator' in text:
            headings.append(heading)
    return headings


def _extract_iocs_from_bullet_lists(
    soup: BeautifulSoup, logs: list[ExtractionLogEntry],
) -> list[IocRecord]:
    """Extract IOCs from ul/li bullet lists in appendix sections."""
    iocs: list[IocRecord] = []
    for heading in _find_appendix_headings(soup):
        context = heading.get_text(strip=True)
        for sibling in heading.next_siblings:
            if not isinstance(sibling, Tag):
                continue
            if sibling.name and re.match(r'^h[1-6]$', sibling.name):
                break
            if sibling.name != 'ul':
                continue
            for li in sibling.find_all('li'):
                raw_value = li.get_text(strip=True)
                record = _build_ioc_from_value(
                    raw_value, context, logs, context_hint=context,
                )
                if record:
                    iocs.append(record)
    return iocs


# Headings whose content signals a dedicated IOC listing section in plain text.
_IOC_SECTION_KEYWORDS = re.compile(
    r'\b(?:IOCs?|Indicators?|MD5|Hash(?:es)?|SHA(?:-?\d+)?|URLs?|IPs?'
    r'|C2|C&C|Infrastructure)\b',
    re.I,
)

# "Page 3 of 8" pagination artifacts in PDF-extracted text.
_PAGE_HEADER_RE = re.compile(r'^Page\s+\d+\s+of\s+\d+$', re.I)


def _is_plaintext_heading(line: str) -> bool:
    """True if the line looks like a section heading in plain-text reports."""
    if len(line) > 80:
        return False
    # All-caps short lines (e.g. "MD5", "URL", "INDICATORS OF COMPROMISE")
    if line.isupper() and len(line) < 60:
        return True
    # Numbered section headers ("1. Past Attack Cases", "2.3 Additional Behaviors")
    if re.match(r'^\d+(?:\.\d+)*\.?\s+\S', line):
        return True
    # Short phrase without sentence-end punctuation and no IOC tokens in any word
    words = line.split()
    if 1 <= len(words) <= 5 and len(line) < 50:
        if not line.rstrip().endswith(('.', ',', ';', ')')):
            has_ioc = any(
                _infer_ioc_type(_defang_normalize(w.strip('(),;:\'"')))
                for w in words
            )
            if not has_ioc:
                return True
    return False


def _is_noise_line(line: str) -> bool:
    """True if the line is pagination noise or too short to contain IOCs."""
    if _PAGE_HEADER_RE.match(line):
        return True
    # Very short lines unlikely to contain IOCs (e.g. "by", "and", "--")
    # but let short hex strings through (could be truncated hashes)
    if len(line) < 6 and re.fullmatch(r'[a-f0-9]{5,}', line, re.I):
        return False
    return len(line) < 6


def _downgrade_to_prose_zone(record: IocRecord) -> IocRecord:
    """Return a copy of the record with prose-zone confidence markings."""
    return IocRecord(
        type=record.type, value=record.value, context=record.context,
        validation_status=record.validation_status,
        source_verified=False, needs_review=True,
    )


# Types trusted from unstructured prose -- excludes domains (actor-name false
# positives like "Storm-0501") and filepaths/mutexes (need structural context).
_PROSE_TRUSTED_TYPES = frozenset({
    'md5', 'sha1', 'sha256', 'sha512', 'ip', 'url', 'email',
})


def _collect_line_iocs(
    line: str, context: str | None, logs: list[ExtractionLogEntry],
) -> list[IocRecord]:
    """Try the full line as one IOC, then fall back to per-token extraction."""
    record = _build_ioc_from_value(line, context, logs)
    if record:
        return [record]
    # Per-token fallback for inline IOCs in prose ("downloaded from hxxp://evil[.]com")
    results: list[IocRecord] = []
    for token in line.split():
        token = token.strip('(),;:.\'"')
        if len(token) < 5:
            continue
        record = _build_ioc_from_value(token, context, logs)
        if record:
            results.append(record)
    return results


def _extract_iocs_from_plaintext(
    text: str, logs: list[ExtractionLogEntry],
    exclude_urls: frozenset[str] | None = None,
) -> list[IocRecord]:
    """Extract IOCs from plain-text reports via line-by-line scanning."""
    iocs: list[IocRecord] = []
    in_ioc_section = False
    current_heading: str | None = None
    _excl = exclude_urls or frozenset()

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if _is_noise_line(line):
            continue
        if _is_plaintext_heading(line):
            current_heading = line
            in_ioc_section = bool(_IOC_SECTION_KEYWORDS.search(line))
            continue

        context = current_heading
        hits = _collect_line_iocs(line, context, logs)

        for record in hits:
            if record.type == 'url' and record.value in _excl:
                continue
            if in_ioc_section:
                iocs.append(record)
            elif record.type in _PROSE_TRUSTED_TYPES:
                iocs.append(_downgrade_to_prose_zone(record))
            # else: skip low-confidence types (domains, filepaths, mutexes) in prose

    return _dedup_iocs(iocs)


def _dedup_iocs(iocs: list[IocRecord]) -> list[IocRecord]:
    """Deduplicate IOCs by (type, value) tuple."""
    seen: set[tuple[str, str]] = set()
    result: list[IocRecord] = []
    for ioc in iocs:
        key = (ioc.type, ioc.value)
        if key not in seen:
            seen.add(key)
            result.append(ioc)
    return result


def _extract_iocs(
    soup: BeautifulSoup, source: str, logs: list[ExtractionLogEntry],
) -> list[IocRecord]:
    """Extract IOC values from tables, pre blocks, and bullet lists."""
    iocs: list[IocRecord] = []
    iocs.extend(_extract_iocs_from_tables(soup, source, logs))
    if source == 'jpcert':
        iocs.extend(_extract_iocs_from_pre_blocks(soup, logs))
        iocs.extend(_extract_iocs_from_bullet_lists(soup, logs))
    return _dedup_iocs(iocs)


# --- Figure Extraction (B.7) ---

_SOURCE_BASE_URLS: dict[str, str] = {
    'cisa': 'https://www.cisa.gov',
    'acsc': 'https://www.cyber.gov.au',
    'jpcert': 'https://blogs.jpcert.or.jp',
    'orkl': 'https://orkl.eu',
}


def _resolve_url(src: str, source: str) -> str:
    """Resolve relative/protocol-relative URLs and strip Drupal itok tokens (L-7)."""
    if src.startswith(('http://', 'https://')):
        return src.split('?itok=')[0]
    base = _SOURCE_BASE_URLS.get(source, '')
    if base:
        resolved = urljoin(base + '/', src)
    elif src.startswith('//'):
        resolved = 'https:' + src
    else:
        resolved = src
    return resolved.split('?itok=')[0]


def _extract_cisa_figures(soup: BeautifulSoup) -> list[AssetRecord]:
    """Extract figures from CISA c-figure containers."""
    figures: list[AssetRecord] = []
    for fig in soup.find_all('figure', class_='c-figure'):
        img = fig.find('img')
        if not img or not img.get('src'):
            continue
        src = _resolve_url(img['src'], 'cisa')
        caption_tag = fig.find('figcaption')
        caption = _strip_to_plain_text(caption_tag) if caption_tag else None
        figures.append(AssetRecord(
            asset_type='figure', original_url=src,
            caption=caption, alt_text=img.get('alt'),
        ))
    return figures


def _extract_acsc_figures(soup: BeautifulSoup) -> list[AssetRecord]:
    """Extract figures from ACSC advisory HTML."""
    figures: list[AssetRecord] = []
    for fig in soup.find_all('figure'):
        img = fig.find('img')
        if not img or not img.get('src'):
            continue
        src = _resolve_url(img['src'], 'acsc')
        caption_tag = fig.find('figcaption')
        caption = _strip_to_plain_text(caption_tag) if caption_tag else None
        figures.append(AssetRecord(
            asset_type='figure', original_url=src,
            caption=caption, alt_text=img.get('alt'),
        ))
    return figures


def _find_jpcert_img_caption(img: Tag) -> str | None:
    """Find centered caption div following a bare JPCERT image."""
    for sibling in img.next_siblings:
        if not isinstance(sibling, Tag):
            continue
        if sibling.name == 'br':
            continue
        if sibling.name == 'div':
            style = sibling.get('style', '')
            if 'text-align' in style and 'center' in style:
                return _strip_to_plain_text(sibling)
        break
    return None


def _extract_jpcert_figures(soup: BeautifulSoup) -> list[AssetRecord]:
    """Extract figures from JPCERT articles (mt-figure and bare img patterns)."""
    figures: list[AssetRecord] = []
    for fig in soup.find_all('figure', class_='mt-figure'):
        img = fig.find('img')
        if not img or not img.get('src'):
            continue
        src = _resolve_url(img['src'], 'jpcert')
        caption_tag = fig.find('figcaption')
        caption = _strip_to_plain_text(caption_tag) if caption_tag else None
        figures.append(AssetRecord(
            asset_type='figure', original_url=src,
            caption=caption, alt_text=img.get('alt'),
        ))
    # Older pattern: bare img + centered div caption
    seen_srcs = {f.original_url for f in figures}
    for img in soup.find_all('img'):
        src = _resolve_url(img.get('src', ''), 'jpcert')
        if not src or src in seen_srcs:
            continue
        if img.find_parent('figure'):
            continue
        caption = _find_jpcert_img_caption(img)
        figures.append(AssetRecord(
            asset_type='figure', original_url=src,
            caption=caption, alt_text=img.get('alt'),
        ))
    return figures


def _extract_figures(
    soup: BeautifulSoup, source: str, logs: list[ExtractionLogEntry],
) -> list[AssetRecord]:
    """Extract figure images from advisory HTML."""
    if source == 'cisa':
        return _extract_cisa_figures(soup)
    if source == 'acsc':
        return _extract_acsc_figures(soup)
    if source == 'jpcert':
        return _extract_jpcert_figures(soup)
    return []


# --- Download Link Extraction (B.8) ---

# Longer extensions first to avoid partial matches
_ASSET_TYPE_MAP: dict[str, str] = {
    '.stix_.json': 'stix_json',
    '.stix.json': 'stix_json',
    '.stix_.xml': 'stix_xml',
    '.stix.xml': 'stix_xml',
    '.yaml': 'sigma_yaml',
    '.yml': 'sigma_yaml',
    '.pdf': 'pdf',
    '.csv': 'csv',
}


def _classify_asset_type(url: str) -> str | None:
    """Classify download link file type from URL path suffix (L-8)."""
    path = urlparse(url).path.lower()
    for ext, asset_type in _ASSET_TYPE_MAP.items():
        if path.endswith(ext):
            return asset_type
    # CISA STIX bundle filenames don't follow one consistent suffix convention
    # (e.g. AA25-071A-stix.json, MAR-251126.r1.v1.CLEAR_stix2.json,
    # stix-FIRESTARTER.json) -- fall back to a loose 'stix' substring match.
    filename = path.rsplit('/', 1)[-1]
    if 'stix' in filename:
        if path.endswith('.json'):
            return 'stix_json'
        if path.endswith('.xml'):
            return 'stix_xml'
    return None


def _normalize_asset_url(url: str) -> str:
    """Normalize STIX URLs for deduplication (Drupal-sanitized underscores)."""
    return url.replace('.stix_.', '.stix.')


def _extract_cfile_links(
    soup: BeautifulSoup, source: str, logs: list[ExtractionLogEntry],
) -> list[AssetRecord]:
    """Extract download links from CISA c-file blocks."""
    assets: list[AssetRecord] = []
    for div in soup.find_all('div', class_='c-file'):
        link = div.find('a', class_='c-file__link')
        if not link or not link.get('href'):
            continue
        href = _resolve_url(link['href'], source)
        asset_type = _classify_asset_type(href)
        if not asset_type:
            # Recognized download block whose file type we could not classify (C1).
            _warn(
                logs, 'assets',
                'c-file download link had an unrecognized file type',
                context=href,
            )
            continue
        assets.append(AssetRecord(
            asset_type=asset_type, original_url=href,
            caption=link.get_text(strip=True), alt_text=None,
        ))
    return assets


def _extract_plain_download_links(
    soup: BeautifulSoup, source: str,
) -> list[AssetRecord]:
    """Extract download links from plain anchor tags and button elements."""
    assets: list[AssetRecord] = []
    for link in soup.find_all('a', href=True):
        href = link['href']
        asset_type = _classify_asset_type(href)
        if not asset_type:
            continue
        # Skip if inside a c-file block (already captured by _extract_cfile_links)
        if link.find_parent('div', class_='c-file'):
            continue
        resolved = _resolve_url(href, source)
        assets.append(AssetRecord(
            asset_type=asset_type, original_url=resolved,
            caption=link.get_text(strip=True), alt_text=None,
        ))
    return assets


def _dedup_assets(assets: list[AssetRecord]) -> list[AssetRecord]:
    """Deduplicate assets by normalized URL."""
    seen: set[str] = set()
    result: list[AssetRecord] = []
    for asset in assets:
        key = _normalize_asset_url(asset.original_url)
        if key not in seen:
            seen.add(key)
            result.append(asset)
    return result


def _extract_download_links(
    soup: BeautifulSoup, source: str, logs: list[ExtractionLogEntry],
) -> list[AssetRecord]:
    """Extract downloadable asset links from advisory HTML."""
    assets: list[AssetRecord] = []
    assets.extend(_extract_cfile_links(soup, source, logs))
    assets.extend(_extract_plain_download_links(soup, source))
    return _dedup_assets(assets)


# --- Sector Extraction (B.9) ---

_SECTOR_LINK_RE = re.compile(
    r'/topics/.*/critical-infrastructure-sectors/.*-sector'
)


def _extract_sectors(
    soup: BeautifulSoup, source: str, logs: list[ExtractionLogEntry],
) -> list[str]:
    """Extract critical infrastructure sector tags from CISA advisories."""
    if source != 'cisa':
        return []
    sectors: list[str] = []
    seen: set[str] = set()
    for link in soup.find_all('a', href=True):
        if not _SECTOR_LINK_RE.search(link['href']):
            continue
        name = link.get_text(strip=True)
        if name.endswith(' Sector'):
            name = name[:-7]
        if name and name not in seen:
            seen.add(name)
            sectors.append(name)
    return sectors


# --- Actor Alias Extraction (B.10) ---

_TRACKING_HEADING_RE = re.compile(
    r'cybersecurity\s+industry\s+tracking', re.IGNORECASE
)
_ALIAS_ORG_RE = re.compile(r'^(.+?)\s*\(([^)]+)\)\s*$')
_ACTOR_NAME_RE = re.compile(r'\b(APT-?[\w-]+|UNC\d+|DEV-\d+|TEMP\.\w+)\b')


def _parse_alias_item(text: str, aliases: list[ActorAlias]) -> None:
    """Parse a single alias list item into ActorAlias."""
    match = _ALIAS_ORG_RE.match(text)
    if match:
        aliases.append(ActorAlias(
            tracking_name=match.group(1).strip(),
            organization=match.group(2).strip(),
        ))
    elif text:
        aliases.append(ActorAlias(tracking_name=text, organization=None))


def _extract_cisa_actor_aliases(
    soup: BeautifulSoup, logs: list[ExtractionLogEntry],
) -> list[ActorAlias]:
    """Extract actor aliases from CISA 'Cybersecurity industry tracking' sections."""
    aliases: list[ActorAlias] = []
    for heading in soup.find_all(re.compile(r'^h[1-6]$')):
        if not _TRACKING_HEADING_RE.search(heading.get_text()):
            continue
        for sibling in heading.next_siblings:
            if not isinstance(sibling, Tag):
                continue
            if sibling.name and re.match(r'^h[1-6]$', sibling.name):
                break
            if sibling.name != 'ul':
                continue
            for li in sibling.find_all('li'):
                text = li.get_text(strip=True)
                _parse_alias_item(text, aliases)
    return aliases


def _extract_jpcert_actor_names(soup: BeautifulSoup) -> list[ActorAlias]:
    """Extract actor names from JPCERT article title."""
    h1 = soup.find('h1')
    if not h1:
        return []
    title = h1.get_text(strip=True)
    matches = _ACTOR_NAME_RE.findall(title)
    return [ActorAlias(tracking_name=m, organization=None) for m in matches]


def _extract_actor_aliases(
    soup: BeautifulSoup, source: str, logs: list[ExtractionLogEntry],
) -> list[ActorAlias]:
    """Extract threat actor aliases from advisory HTML."""
    if source == 'cisa':
        return _extract_cisa_actor_aliases(soup, logs)
    if source == 'jpcert':
        return _extract_jpcert_actor_names(soup)
    return []


# --- Orchestrator (B.11) ---


def _log_extractor_error(
    result: ParseResult, name: str, advisory_id: str, exc: Exception,
) -> None:
    """Log an extractor failure to both result logs and Python logger."""
    result.logs.append(ExtractionLogEntry(
        extractor=name, severity='error',
        message=str(exc), context=None,
    ))
    logger.error(
        "Extractor %s failed for %s: %s",
        name, advisory_id, exc, exc_info=True,
    )


def _log_extraction_summary(result: ParseResult, advisory_id: str) -> None:
    """Log counts of all extracted items for monitoring."""
    logger.info(
        "Parse phase extracted %d rules, %d techniques, %d d3fend, %d CVEs, %d IOCs, "
        "%d figures, %d assets, %d sectors, %d actors for %s",
        len(result.detection_rules), len(result.techniques),
        len(result.d3fend), len(result.cves), len(result.iocs),
        len(result.figures), len(result.assets), len(result.sectors),
        len(result.actor_aliases), advisory_id,
    )


def _run_all_extractors(
    soup: BeautifulSoup, source: str, advisory_id: str,
    result: ParseResult,
) -> None:
    """Run each sub-extractor with per-extractor error handling."""
    extractors = [
        ('detection_rules',
         lambda: _extract_detection_rules(soup, source, result.logs)),
        ('techniques',
         lambda: _extract_attack_techniques(soup, source, result.logs)),
        ('d3fend',
         lambda: _extract_d3fend(soup, source, result.logs)),
        ('cves',
         lambda: _extract_cve_ids(soup, result.logs)),
        ('iocs',
         lambda: _extract_iocs(soup, source, result.logs)),
        ('figures',
         lambda: _extract_figures(soup, source, result.logs)),
        ('assets',
         lambda: _extract_download_links(soup, source, result.logs)),
        ('sectors',
         lambda: _extract_sectors(soup, source, result.logs)),
        ('actor_aliases',
         lambda: _extract_actor_aliases(soup, source, result.logs)),
    ]
    for field_name, fn in extractors:
        try:
            setattr(result, field_name, fn())
        except Exception as exc:
            _log_extractor_error(result, field_name, advisory_id, exc)


def _run_plaintext_extractors(
    text: str, source: str, advisory_id: str,
    result: ParseResult,
) -> None:
    """Run plain-text extractors for non-HTML sources like ORKL."""
    # The first line of ORKL plain_text is the article's own source URL;
    # exclude it from IOC extraction to avoid false-positive highlighting.
    first_line = text.split('\n', 1)[0].strip()
    exclude_urls: frozenset[str] = frozenset()
    if first_line.startswith(('http://', 'https://')) and ' ' not in first_line:
        exclude_urls = frozenset({first_line})
    extractors = [
        ('iocs', lambda: _extract_iocs_from_plaintext(
            text, result.logs, exclude_urls=exclude_urls)),
        ('techniques', lambda: _scan_text_for_techniques(text)),
        ('d3fend', lambda: _scan_text_for_d3fend(text)),
        ('cves', lambda: _extract_cve_ids(text, result.logs)),
    ]
    for field_name, fn in extractors:
        try:
            setattr(result, field_name, fn())
        except Exception as exc:
            _log_extractor_error(result, field_name, advisory_id, exc)


def parse_advisory(
    advisory_id: str, article_body: str, source: str,
) -> ParseResult:
    """Run all parse-phase extractors and return unified result."""
    result = ParseResult()
    if source == 'orkl':
        _run_plaintext_extractors(article_body, source, advisory_id, result)
    else:
        soup = BeautifulSoup(article_body, 'html.parser')
        _run_all_extractors(soup, source, advisory_id, result)
    _log_extraction_summary(result, advisory_id)
    return result
