"""Article body enrichment: images, IOC highlights, ATT&CK links, detection rule formatting."""

from collections.abc import Callable
import html as html_mod
import logging
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlsplit, urlunsplit

from bs4 import BeautifulSoup, NavigableString, Tag

from threat2signal.analysis.extractor import (
    IocRecord, ParseResult, RuleRecord, TechniqueRecord,
    _ASSET_TYPE_MAP, _CVE_RE, _DETECTION_HEADING_RE, _SOURCE_BASE_URLS,
    _find_detection_sections,
)

logger = logging.getLogger(__name__)


# --- Shared Annotation Helpers ---


def _is_inside_skip_tag(element: NavigableString, skip_tags: set[str]) -> bool:
    """Check if a text node is inside a tag that should not be annotated."""
    for parent in element.parents:
        if parent.name in skip_tags:
            return True
    return False


def _split_and_wrap(
    text_node: NavigableString,
    pattern: re.Pattern[str],
    wrapper_factory: Callable[[re.Match[str], BeautifulSoup], Tag],
    soup: BeautifulSoup,
) -> None:
    """Split a text node on pattern matches and insert wrapper elements."""
    text = str(text_node)
    matches = list(pattern.finditer(text))
    if not matches:
        return
    parts: list[NavigableString | Tag] = []
    last_end = 0
    for match in matches:
        if match.start() > last_end:
            parts.append(NavigableString(text[last_end:match.start()]))
        parts.append(wrapper_factory(match, soup))
        last_end = match.end()
    if last_end < len(text):
        parts.append(NavigableString(text[last_end:]))
    # Reverse so each insert_after places element right after text_node
    for part in reversed(parts):
        text_node.insert_after(part)
    text_node.extract()


def _annotate_text_nodes(
    soup: BeautifulSoup,
    pattern: re.Pattern[str],
    wrapper_factory: Callable[[re.Match[str], BeautifulSoup], Tag],
    skip_tags: set[str],
) -> None:
    """Replace regex matches in text nodes with wrapper elements."""
    # Snapshot nodes before mutation to avoid infinite loops
    nodes = list(soup.strings)
    for text_node in nodes:
        if type(text_node) is not NavigableString:
            continue
        if _is_inside_skip_tag(text_node, skip_tags):
            continue
        _split_and_wrap(text_node, pattern, wrapper_factory, soup)


# --- C8/F3: Strip incoming (attacker-supplied) annotations ---

# Scraped article_body is semi-trusted; strip any pre-existing t2s markup so
# only enricher-added annotations carry trust styling and data attributes.
_INCOMING_DATA_PREFIXES = (
    'data-ioc-', 'data-technique-', 'data-cve-', 'data-rule-', 'data-asset-',
    'data-tactic',
)


def _strip_incoming_annotations(soup: BeautifulSoup) -> None:
    """Remove pre-existing t2s classes/data attributes and IOC marks from scraped HTML."""
    for mark in list(soup.find_all('mark', class_='t2s-ioc')):
        mark.unwrap()
    for el in soup.find_all(True):
        classes = el.get('class')
        if classes:
            kept = [c for c in classes if not c.startswith('t2s-')]
            if kept:
                el['class'] = kept
            else:
                del el['class']
        for attr in list(el.attrs):
            if attr.startswith(_INCOMING_DATA_PREFIXES):
                del el[attr]


# --- F16: Neutralize dangerous href schemes ---

_DANGEROUS_SCHEMES = ('javascript:', 'data:', 'vbscript:', 'blob:')


def _neuter_dangerous_hrefs(soup: BeautifulSoup) -> None:
    """Defuse javascript:/data:/vbscript:/blob: hrefs in the stored artifact."""
    # enriched_body is stored and may be consumed by clients without DOMPurify,
    # so we cannot rely solely on frontend sanitization.
    for link in soup.find_all('a', href=True):
        cleaned = re.sub(r'[\s\x00-\x1f]', '', link['href']).lower()
        if cleaned.startswith(_DANGEROUS_SCHEMES):
            link['href'] = '#'


# --- B+.8: Non-Content Cleanup (runs first to avoid interference) ---


def _unwrap_word_artifacts(soup: BeautifulSoup) -> None:
    """Unwrap Microsoft Word export wrapper divs, keeping text content."""
    # 4 of 14 CISA advisories contain Drupal/Word paste artifacts adding 10-20% bloat
    for div in list(soup.find_all('div', class_=re.compile(r'^(SCXW|OutlineElement|BCX)'))):
        div.unwrap()


def _looks_like_attribution(text: str) -> bool:
    """Heuristic: is this short right-aligned text an author byline, not prose?"""
    # Bylines are short and are not full sentences; body paragraphs are long.
    if not text or len(text) > 80 or len(text.split()) > 8:
        return False
    if 'JPCERT' in text:
        return True
    # Trailing prose sentences end with a period + space earlier; bylines do not.
    return '. ' not in text


def _strip_jpcert_attribution(soup: BeautifulSoup) -> None:
    """Remove trailing right-aligned author attribution bylines."""
    children = [c for c in soup.children if isinstance(c, Tag)]
    for tag in reversed(children[-3:]):
        if tag.name != 'p':
            break
        style = tag.get('style', '')
        if 'text-align' not in style or 'right' not in style:
            break
        if not _looks_like_attribution(tag.get_text(strip=True)):
            break
        tag.decompose()


def _remove_hidden_elements(soup: BeautifulSoup) -> None:
    """Remove elements explicitly hidden via attribute or inline style."""
    for el in list(soup.find_all(True)):
        if el.attrs is None:
            continue
        if el.has_attr('hidden'):
            el.decompose()
            continue
        style = el.get('style', '')
        if re.search(r'display\s*:\s*none|visibility\s*:\s*hidden', style, re.I):
            el.decompose()


def _remove_empty_wrappers(soup: BeautifulSoup) -> None:
    """Remove div elements with no text or meaningful children."""
    meaningful = {'img', 'table', 'pre', 'figure', 'video', 'audio'}
    for div in list(soup.find_all('div')):
        if div.get_text(strip=True):
            continue
        if div.find(meaningful):
            continue
        # Keep wrappers around id-bearing anchors (cross-reference targets).
        if div.find(attrs={'id': True}):
            continue
        div.decompose()


def _strip_empty_anchors(soup: BeautifulSoup) -> None:
    """Remove ck-anchor elements with no id attribute."""
    for anchor in list(soup.find_all('a', class_='ck-anchor')):
        if not anchor.get('id'):
            anchor.decompose()


def _cleanup_non_content(soup: BeautifulSoup, source: str) -> None:
    """Remove non-content artifacts based on source type."""
    if source == 'cisa':
        _unwrap_word_artifacts(soup)
    elif source == 'jpcert':
        _strip_jpcert_attribution(soup)
    _remove_hidden_elements(soup)
    _remove_empty_wrappers(soup)
    _strip_empty_anchors(soup)


# --- B+.1: Image URL Rewriting ---


def _strip_itok(url: str) -> str:
    """Remove Drupal's transient itok= parameter, preserving other query params."""
    parts = urlsplit(url)
    if not parts.query:
        return url
    kept = [
        (k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if k != 'itok'
    ]
    return urlunsplit(parts._replace(query=urlencode(kept)))


def _resolve_to_absolute(src: str, source: str) -> str:
    """Resolve relative URL to absolute using source base URL."""
    if src.startswith(('http://', 'https://')):
        return src
    base = _SOURCE_BASE_URLS.get(source, '')
    return base + src


def _extract_filename(url: str) -> str:
    """Extract the last path segment from a URL."""
    path = url.split('?')[0].split('#')[0]
    return path.rsplit('/', 1)[-1] if '/' in path else path


def _rewrite_image_urls(
    soup: BeautifulSoup, source: str, numeric_id: int,
) -> None:
    """Rewrite img src attributes to local asset endpoints."""
    for img in soup.find_all('img'):
        src = img.get('src', '')
        if not src:
            continue
        src = _strip_itok(src)
        src = _resolve_to_absolute(src, source)
        filename = _extract_filename(src)
        img['src'] = f'/api/assets/{numeric_id}/figures/{filename}'


# --- B+.2: IOC Highlighting ---

# Defang-tolerant fragments: extractor stores normalized IOC values, but the
# article text may render them defanged (evil[.]com, hxxp://, 1.1.1[.]1, a[:]b).
_DEFANG_DOT = r'(?:\[\.\]|\[dot\]|\(dot\)|\.)'
_DEFANG_COLON = r'(?:\[:\]|:)'


def _defang_tolerant_fragment(value: str) -> str:
    """Build a regex fragment matching any defanging variant of an IOC value."""
    frag = re.escape(value)
    # Replace colons before inserting the dot-group: that group contains "(?:",
    # whose colon must not be rewritten.
    frag = frag.replace(':', _DEFANG_COLON)
    frag = frag.replace(r'\.', _DEFANG_DOT)
    lower = value.lower()
    if lower.startswith('https://'):
        frag = '(?:hxxps|https)' + frag[len('https'):]
    elif lower.startswith('http://'):
        frag = '(?:hxxp|http)' + frag[len('http'):]
    return frag


def _refang(text: str) -> str:
    """Reverse defanging in matched IOC text to recover the normalized value."""
    t = text.replace('[.]', '.').replace('[:]', ':')
    t = re.sub(r'\[dot\]|\(dot\)', '.', t, flags=re.IGNORECASE)
    t = re.sub(r'^hxxp', 'http', t, flags=re.IGNORECASE)
    return t


def _build_ioc_pattern_and_map(
    iocs: list[IocRecord],
) -> tuple[re.Pattern[str] | None, dict[str, IocRecord]]:
    """Build a boundary-guarded IOC matching pattern and normalized-value lookup map."""
    if not iocs:
        return None, {}
    # Longest normalized value first so alternation prefers longer matches
    sorted_iocs = sorted(iocs, key=lambda i: len(i.value), reverse=True)
    parts: list[str] = []
    value_map: dict[str, IocRecord] = {}
    for ioc in sorted_iocs:
        key = ioc.value.lower()
        if key in value_map:
            continue
        value_map[key] = ioc
        parts.append(_defang_tolerant_fragment(ioc.value))
    if not parts:
        return None, {}
    # Guards stop 10.1.1.1 matching inside 210.1.1.10, but allow a sentence-final dot.
    body = r'(?<![\w.])(?:' + '|'.join(parts) + r')(?![\w-])(?!\.\w)'
    return re.compile(body, re.IGNORECASE), value_map


def _ioc_wrapper_factory(
    value_map: dict[str, IocRecord],
) -> Callable[[re.Match[str], BeautifulSoup], Tag]:
    """Create a wrapper factory for IOC mark elements."""
    def make_mark(match: re.Match[str], soup: BeautifulSoup) -> Tag:
        normalized = _refang(match.group(0)).lower()
        ioc = value_map[normalized]
        tag = soup.new_tag('mark', tabindex='0')
        tag['class'] = ['t2s-ioc']
        tag['data-ioc-type'] = ioc.type
        tag['data-ioc-value'] = ioc.value
        tag.string = match.group(0)
        return tag
    return make_mark


def _highlight_iocs(soup: BeautifulSoup, result: ParseResult) -> None:
    """Wrap IOC values in highlight mark elements."""
    pattern, value_map = _build_ioc_pattern_and_map(result.iocs)
    if pattern is None:
        return
    skip = {'a', 'code', 'pre', 'mark', 'script', 'style'}
    _annotate_text_nodes(soup, pattern, _ioc_wrapper_factory(value_map), skip)


# --- B+.3: ATT&CK Technique Linking ---


def _technique_id_to_url(technique_id: str) -> str:
    """Convert ATT&CK technique ID to MITRE URL path."""
    # T1234.567 -> techniques/T1234/567/
    parts = technique_id.split('.')
    path = '/'.join(parts)
    return f'https://attack.mitre.org/techniques/{path}/'


def _upgrade_existing_mitre_links(
    soup: BeautifulSoup, tech_map: dict[str, TechniqueRecord],
) -> None:
    """Add t2s-mitre class and data attributes to genuine ATT&CK links."""
    for link in soup.find_all('a', href=True):
        # Require an exact host match: substring matching would trust
        # evil.attack.mitre.org.example.com and attack.mitre.org.evil.com.
        host = (urlparse(link['href']).hostname or '').lower()
        if host != 'attack.mitre.org':
            continue
        match = re.search(r'T\d{4}(?:\.\d{3})?', link['href'])
        if not match or match.group(0) not in tech_map:
            continue
        tech = tech_map[match.group(0)]
        # Rewrite to the canonical URL so a tampered path cannot survive.
        link['href'] = _technique_id_to_url(tech.technique_id)
        classes = link.get('class', [])
        if 't2s-mitre' not in classes:
            link['class'] = classes + ['t2s-mitre']
        link['data-technique-id'] = tech.technique_id
        link['data-tactic'] = tech.tactic or ''
        link['title'] = tech.name or tech.technique_id
        link['tabindex'] = '0'


def _technique_wrapper_factory(
    tech_map: dict[str, TechniqueRecord],
) -> Callable[[re.Match[str], BeautifulSoup], Tag]:
    """Create a wrapper factory for ATT&CK technique links."""
    def make_link(match: re.Match[str], soup: BeautifulSoup) -> Tag:
        tid = match.group(0)
        tech = tech_map[tid]
        tag = soup.new_tag('a', href=_technique_id_to_url(tid), tabindex='0')
        tag['class'] = ['t2s-mitre']
        tag['data-technique-id'] = tid
        tag['data-tactic'] = tech.tactic or ''
        tag['title'] = tech.name or tid
        tag.string = tid
        return tag
    return make_link


def _link_attack_techniques(
    soup: BeautifulSoup, result: ParseResult,
) -> None:
    """Link ATT&CK technique IDs to MITRE pages."""
    if not result.techniques:
        return
    tech_map = {t.technique_id: t for t in result.techniques}
    _upgrade_existing_mitre_links(soup, tech_map)
    ids = sorted(tech_map.keys(), key=len, reverse=True)
    pattern = re.compile(r'\b(' + '|'.join(re.escape(t) for t in ids) + r')\b')
    skip = {'a', 'script', 'style'}
    _annotate_text_nodes(soup, pattern, _technique_wrapper_factory(tech_map), skip)


# --- B+.4: CVE ID Linking ---


def _cve_href(cve_id: str, known_msrc_cves: set[str]) -> str:
    """Route a CVE to our internal MSRC page when known, else NVD."""
    if cve_id.upper() in known_msrc_cves:
        return f'/msrc/{cve_id}'
    return f'https://nvd.nist.gov/vuln/detail/{cve_id}'


def _cve_wrapper_factory(
    known_msrc_cves: set[str],
) -> Callable[[re.Match[str], BeautifulSoup], Tag]:
    """Create a wrapper factory for CVE ID links."""
    def make_link(match: re.Match[str], soup: BeautifulSoup) -> Tag:
        cve_id = match.group(0)
        tag = soup.new_tag('a', href=_cve_href(cve_id, known_msrc_cves))
        tag['class'] = ['t2s-cve']
        tag['data-cve-id'] = cve_id
        tag.string = cve_id
        return tag
    return make_link


def _retarget_existing_cve_links(
    soup: BeautifulSoup, known_msrc_cves: set[str],
) -> None:
    """Re-target existing NVD/MSRC anchors to our canonical route."""
    for link in soup.find_all('a', href=True):
        href = link['href']
        host = (urlparse(href).hostname or '').lower()
        is_cve_link = (
            host in ('nvd.nist.gov', 'msrc.microsoft.com')
            or href.startswith('/msrc/')
        )
        if not is_cve_link:
            continue
        match = _CVE_RE.search(href) or _CVE_RE.search(link.get_text())
        if not match:
            continue
        cve_id = match.group(0)
        link['href'] = _cve_href(cve_id, known_msrc_cves)
        link['data-cve-id'] = cve_id
        classes = link.get('class', [])
        if 't2s-cve' not in classes:
            link['class'] = classes + ['t2s-cve']


def _link_cve_ids(soup: BeautifulSoup, known_msrc_cves: set[str]) -> None:
    """Wrap CVE IDs in text nodes and re-target existing CVE anchors."""
    _retarget_existing_cve_links(soup, known_msrc_cves)
    skip = {'a', 'script', 'style'}
    _annotate_text_nodes(soup, _CVE_RE, _cve_wrapper_factory(known_msrc_cves), skip)


# --- B+.5: Detection Rule Formatting ---


def _rule_first_line(rule: RuleRecord) -> str:
    """Return the first non-empty line of a rule, or '' when empty."""
    lines = rule.rule_text.strip().splitlines()
    return lines[0].strip() if lines else ''


def _match_rules_in_container(
    container_text: str,
    rules: list[RuleRecord],
    used: set[int],
) -> list[RuleRecord]:
    """Find every unused RuleRecord whose first line appears in the container."""
    normalized = re.sub(r'\s+', '', container_text.lower())
    if not normalized:
        return []
    matched: list[RuleRecord] = []
    for i, rule in enumerate(rules):
        if i in used:
            continue
        first = _rule_first_line(rule)
        if not first:
            continue
        first_norm = re.sub(r'\s+', '', first.lower())
        if first_norm and first_norm in normalized:
            used.add(i)
            matched.append(rule)
    return matched


def _make_rule_pre(rule: RuleRecord, soup: BeautifulSoup) -> Tag:
    """Build a formatted pre/code block for one detection rule."""
    pre = soup.new_tag('pre')
    pre['class'] = [f't2s-{rule.rule_format}']
    pre['data-rule-name'] = rule.rule_name or ''
    pre['data-rule-format'] = rule.rule_format
    code = soup.new_tag('code')
    code.string = rule.rule_text
    pre.append(code)
    return pre


def _replace_container_with_rules(
    container: Tag, rules: list[RuleRecord], soup: BeautifulSoup,
) -> None:
    """Replace a container with one pre/code block per matched rule."""
    # A single container may hold several rules (Pattern C: 5 YARA + 1 Sigma in
    # one table; Pattern D: multiple rules per div) -- emit all of them.
    pres = [_make_rule_pre(rule, soup) for rule in rules]
    container.replace_with(pres[0])
    anchor = pres[0]
    for pre in pres[1:]:
        anchor.insert_after(pre)
        anchor = pre


def _format_detection_rules(
    soup: BeautifulSoup, result: ParseResult,
) -> None:
    """Replace detection rule containers with formatted pre/code blocks."""
    if not result.detection_rules:
        return
    used: set[int] = set()
    for _, elements in _find_detection_sections(soup):
        for el in elements:
            if el.name not in ('table', 'div'):
                continue
            if el.parent is None:
                continue
            rules = _match_rules_in_container(
                el.get_text(), result.detection_rules, used,
            )
            if rules:
                _replace_container_with_rules(el, rules, soup)


# --- B+.6: Download Link Enrichment ---


def _classify_asset_type(filename: str) -> str:
    """Classify download file type from extension."""
    lower = filename.lower()
    for ext, asset_type in _ASSET_TYPE_MAP.items():
        if lower.endswith(ext):
            return asset_type
    return 'unknown'


def _enrich_download_links(
    soup: BeautifulSoup, numeric_id: int,
) -> None:
    """Rewrite download links to local asset endpoints."""
    for file_div in soup.find_all('div', class_='c-file'):
        for link in file_div.find_all('a', href=True):
            href = link['href']
            filename = _extract_filename(href)
            link['href'] = f'/api/assets/{numeric_id}/files/{filename}'
            link['data-asset-type'] = _classify_asset_type(filename)
            classes = link.get('class', [])
            if 't2s-asset-download' not in classes:
                link['class'] = classes + ['t2s-asset-download']


# --- B+.7: External Link Safety ---


def _resolve_relative_links(soup: BeautifulSoup, source: str) -> None:
    """Resolve relative href attributes to absolute URLs using source base URL."""
    base = _SOURCE_BASE_URLS.get(source, '')
    if not base:
        return
    for link in soup.find_all('a', href=True):
        href = link['href']
        # Never re-prefix our own internal app routes (asset endpoints, MSRC
        # pages) that earlier passes already produced.
        if href.startswith(('/api/', '/msrc/')):
            continue
        if href.startswith(('http://', 'https://', 'mailto:', '#', 'javascript:')):
            continue
        if href.startswith('/'):
            link['href'] = base + href
        elif not href.startswith(('data:', 'blob:')):
            link['href'] = base + '/' + href


def _add_external_link_attrs(soup: BeautifulSoup) -> None:
    """Add target and rel to external http(s) links; never to internal/asset links."""
    for link in soup.find_all('a', href=re.compile(r'^https?://', re.IGNORECASE)):
        link['target'] = '_blank'
        link['rel'] = 'noopener noreferrer'
        classes = link.get('class', [])
        # t2s-mitre / t2s-cve carry their own styling; only plain externals get the icon.
        if not any(c.startswith('t2s-') for c in classes):
            link['class'] = classes + ['t2s-external']


# --- Main Enrichment Function ---


_PLAINTEXT_SOURCES = frozenset({'orkl'})


_PAGE_FOOTER_RE = re.compile(r'^Page \d+ of \d+$')


def _plaintext_to_html(text: str) -> str:
    """Convert PDF-extracted plain text to paragraph-structured HTML.

    ORKL plain_text uses \\n\\n for every line break (PDF column wraps
    AND paragraph breaks).  We join continuation lines with a space
    and flush a paragraph when a fragment ends with sentence-ending
    punctuation or looks like a heading.
    """
    fragments = re.split(r'\n{2,}', text)
    paragraphs: list[str] = []
    buf: list[str] = []

    def _flush() -> None:
        if buf:
            paragraphs.append(' '.join(buf))
            buf.clear()

    for frag in fragments:
        frag = frag.replace('\n', ' ').strip()
        if not frag:
            continue
        if _PAGE_FOOTER_RE.match(frag):
            _flush()
            continue
        if frag.startswith(('http://', 'https://')) and ' ' not in frag:
            _flush()
            continue

        buf.append(frag)

        last_char = frag.rstrip()[-1:] if frag.rstrip() else ''
        is_short = len(frag) < 60
        ends_sentence = last_char in '.!?'
        if ends_sentence or (is_short and last_char not in ',-;'):
            _flush()

    _flush()
    return '\n'.join(
        f'<p>{html_mod.escape(p)}</p>' for p in paragraphs if p.strip()
    )


def enrich_article_body(
    article_body: str,
    source: str,
    advisory_id: str,
    result: ParseResult,
    numeric_id: int,
    known_msrc_cves: set[str] | None = None,
) -> str:
    """Transform article_body into enriched HTML with annotations and working images."""
    if source in _PLAINTEXT_SOURCES:
        article_body = _plaintext_to_html(article_body)
    soup = BeautifulSoup(article_body, 'html.parser')
    logger.debug(
        "Enriching %s advisory %s (%d chars)", source, advisory_id, len(article_body),
    )
    known = {c.upper() for c in (known_msrc_cves or set())}
    # Strip attacker-controlled t2s markup before adding trusted annotations (C8/F3).
    _strip_incoming_annotations(soup)
    _cleanup_non_content(soup, source)
    _neuter_dangerous_hrefs(soup)
    _rewrite_image_urls(soup, source, numeric_id)
    _highlight_iocs(soup, result)
    _link_attack_techniques(soup, result)
    _link_cve_ids(soup, known)
    _format_detection_rules(soup, result)
    # Resolve relative links BEFORE rewriting downloads so /api/ hrefs are never
    # re-prefixed with the source base URL (F0).
    _resolve_relative_links(soup, source)
    _enrich_download_links(soup, numeric_id)
    _add_external_link_attrs(soup)
    enriched = str(soup)
    logger.debug(
        "Enrichment complete for %s: %d -> %d chars",
        advisory_id, len(article_body), len(enriched),
    )
    return enriched
