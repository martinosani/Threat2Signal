"""Tests for threat2signal.analysis.extractor -- parse-phase HTML extraction pipeline."""

from pathlib import Path
from unittest.mock import patch

import pytest
from bs4 import BeautifulSoup

from threat2signal.analysis.extractor import (
    ExtractionLogEntry,
    IocRecord,
    ParseResult,
    RuleRecord,
    TechniqueRecord,
    _build_ioc_from_value,
    _classify_asset_type,
    _clean_rule_text,
    _defang_normalize,
    _detect_rule_format,
    _dedup_iocs,
    _extract_actor_aliases,
    _extract_attack_techniques,
    _extract_d3fend,
    _extract_detection_rules,
    _extract_download_links,
    _extract_figures,
    _extract_iocs,
    _extract_iocs_from_headed_table,
    _infer_ioc_type,
    _log_extractor_error,
    _run_all_extractors,
    _split_cell_values,
    _validate_yara_rule,
    parse_advisory,
)
from threat2signal.analysis.enricher import enrich_article_body
from threat2signal.analysis.ioc_validator import validate_ioc
from threat2signal.storage.db import (
    _compute_extraction_status,
    count_advisory_cves,
    count_advisory_techniques,
    count_detection_rules,
    count_iocs,
    delete_extraction_logs,
    get_advisory_assets,
    get_advisory_cves,
    get_advisory_techniques,
    get_detection_rules,
    get_extraction_logs,
    get_iocs,
    insert_extraction_log,
    mark_asset_downloaded,
    save_parse_results,
    upsert_advisory,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures"


# -- Helpers -------------------------------------------------------------------


def _load_fixture(name: str) -> str:
    return (FIXTURE_DIR / name).read_text(encoding="utf-8")


def _soup(html: str) -> BeautifulSoup:
    return BeautifulSoup(html, "html.parser")


def _make_advisory(db_conn, advisory_id: str = "test-001") -> str:
    """Insert a minimal advisory row for FK-dependent tests."""
    upsert_advisory(db_conn, {
        "advisory_id": advisory_id,
        "type": "cybersecurity_advisory",
        "source": "cisa",
        "scrape_status": "scraped",
    })
    return advisory_id


# -- Pytest fixtures -----------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_allowlist_cache():
    """Clear the IOC allowlist lru_cache between tests.

    The validator caches the allowlist via functools.lru_cache (no mutable
    module state, per CODING.md), so the cache must be cleared around any test
    that monkeypatches the allowlist to keep it from leaking between tests.
    """
    from threat2signal.analysis.ioc_validator import _load_allowlist
    _load_allowlist.cache_clear()
    yield
    _load_allowlist.cache_clear()


@pytest.fixture
def patched_allowlist(monkeypatch):
    """Monkeypatch the IOC allowlist so tests never depend on prod config (M-6)."""
    allowlist = {
        "domains": ["microsoft.com", "google.com", "cisa.gov"],
        "ips": ["8.8.8.8", "1.1.1.1"],
        "hashes": [],
    }
    monkeypatch.setattr(
        "threat2signal.analysis.ioc_validator._load_allowlist",
        lambda: allowlist,
    )
    return allowlist


# =============================================================================
# G.2 -- Detection Rule Extraction
# =============================================================================


@pytest.mark.unit
class TestYaraPatternA:
    """YARA in <td> with <br/> line breaks."""

    def test_extracts_rule(self):
        html = _load_fixture("cisa_yara_pattern_a.html")
        soup = _soup(html)
        logs: list[ExtractionLogEntry] = []
        rules = _extract_detection_rules(soup, "cisa", logs)

        assert len(rules) == 1
        rule = rules[0]
        assert rule.rule_format == "yara"
        assert rule.rule_name == "test_malware_a"
        assert "malware_payload_a" in rule.rule_text
        assert rule.validation_status == "valid"
        assert rule.validation_error is None


@pytest.mark.unit
class TestYaraPatternB:
    """YARA in <td> with <p> tags, one rule per table."""

    def test_extracts_rule(self):
        html = _load_fixture("cisa_yara_pattern_b.html")
        soup = _soup(html)
        logs: list[ExtractionLogEntry] = []
        rules = _extract_detection_rules(soup, "cisa", logs)

        assert len(rules) == 1
        rule = rules[0]
        assert rule.rule_format == "yara"
        assert rule.rule_name == "test_malware_b"
        assert "evil_string_b" in rule.rule_text
        assert rule.validation_status == "valid"


@pytest.mark.unit
class TestYaraPatternC:
    """YARA in <td> with <p> tags, single table with name-separator rows."""

    def test_extracts_two_rules(self):
        html = _load_fixture("cisa_yara_pattern_c.html")
        soup = _soup(html)
        logs: list[ExtractionLogEntry] = []
        rules = _extract_detection_rules(soup, "cisa", logs)

        assert len(rules) == 2
        names = {r.rule_name for r in rules}
        assert "rule_alpha" in names
        assert "rule_beta" in names

    def test_each_rule_validates(self):
        html = _load_fixture("cisa_yara_pattern_c.html")
        rules = _extract_detection_rules(_soup(html), "cisa", [])
        for rule in rules:
            assert rule.validation_status == "valid"
            assert rule.rule_format == "yara"


@pytest.mark.unit
class TestYaraPatternD:
    """YARA in <div> with <p><code>, no table."""

    def test_extracts_rule(self):
        html = _load_fixture("cisa_yara_pattern_d.html")
        soup = _soup(html)
        logs: list[ExtractionLogEntry] = []
        rules = _extract_detection_rules(soup, "cisa", logs)

        assert len(rules) == 1
        rule = rules[0]
        assert rule.rule_format == "yara"
        assert rule.rule_name == "test_malware_d"
        assert "div_code_pattern" in rule.rule_text
        assert rule.validation_status == "valid"


@pytest.mark.unit
class TestYaraValidation:
    """Validation of YARA rule syntax via yara-python."""

    def test_valid_yara_returns_valid(self):
        rule = 'rule test { strings: $a = "test" condition: $a }'
        status, error = _validate_yara_rule(rule)
        assert status == "valid"
        assert error is None

    def test_invalid_yara_returns_invalid_with_error(self):
        rule = "rule broken { condition: }"
        status, error = _validate_yara_rule(rule)
        assert status == "invalid"
        assert error is not None
        assert len(error) > 0


@pytest.mark.unit
class TestSigmaExtraction:
    """Sigma rule in <td> with <p> tags."""

    def test_extracts_sigma(self):
        html = _load_fixture("cisa_sigma.html")
        soup = _soup(html)
        logs: list[ExtractionLogEntry] = []
        rules = _extract_detection_rules(soup, "cisa", logs)

        assert len(rules) == 1
        rule = rules[0]
        assert rule.rule_format == "sigma"
        assert "title:" in rule.rule_text
        assert "logsource:" in rule.rule_text
        assert rule.validation_status == "unvalidated"


@pytest.mark.unit
def test_detection_rules_non_cisa_returns_empty():
    """Detection rule extraction returns empty for non-CISA sources."""
    html = _load_fixture("cisa_yara_pattern_a.html")
    rules = _extract_detection_rules(_soup(html), "jpcert", [])
    assert rules == []


@pytest.mark.unit
def test_detect_rule_format():
    assert _detect_rule_format("rule foo { condition: true }") == "yara"
    assert _detect_rule_format("title: x\nlogsource:\n  product: y") == "sigma"
    assert _detect_rule_format("alert tcp any any -> any any (msg:\"x\";)") == "snort"
    assert _detect_rule_format("this is just text") is None


@pytest.mark.unit
def test_clean_rule_text_normalizes_whitespace_only():
    """_clean_rule_text handles whitespace/blank lines only.

    M-5: HTML entity decoding now happens once upstream (via get_text /
    _tag_text_with_breaks). A second html.unescape here would corrupt
    double-escaped markup, so _clean_rule_text must NOT unescape entities.
    """
    raw = "\n  rule foo bar {  \n  }\n\n"
    cleaned = _clean_rule_text(raw)
    # Leading line indentation is preserved
    assert "  rule foo bar {" in cleaned
    # Trailing whitespace on each line is stripped
    assert "{  " not in cleaned
    # Leading/trailing blank lines are stripped
    assert not cleaned.startswith("\n")
    assert not cleaned.endswith("\n")
    # Entities are left untouched -- no double-decode
    assert _clean_rule_text("rule foo &amp; bar {") == "rule foo &amp; bar {"


@pytest.mark.unit
def test_detection_rule_entities_decoded_via_pipeline():
    """Entity decoding for rule bodies happens through the real extraction
    path (get_text collapses entities once), not in _clean_rule_text (M-5)."""
    html = (
        '<h3>YARA Rules</h3>'
        '<table><thead><tr><th>Rule</th></tr></thead><tbody>'
        '<tr><td>rule entity_rule {<br/>'
        '    strings:<br/>'
        '        $a = "a &amp; b"<br/>'
        '        $b = "x &lt; y &gt; z"<br/>'
        '    condition:<br/>        all of them<br/>}</td></tr>'
        '</tbody></table>'
    )
    rules = _extract_detection_rules(_soup(html), "cisa", [])
    assert len(rules) == 1
    text = rules[0].rule_text
    assert "a & b" in text
    assert "x < y > z" in text
    assert "&amp;" not in text
    assert "&lt;" not in text
    assert "&gt;" not in text


# =============================================================================
# G.2 -- ATT&CK Technique Extraction
# =============================================================================


@pytest.mark.unit
class TestAttack3Col:
    """ATT&CK 3-column table (Technique, ID, Use) with caption tactic."""

    def test_extracts_techniques(self):
        html = _load_fixture("cisa_attack_3col.html")
        soup = _soup(html)
        techs = _extract_attack_techniques(soup, "cisa", [])

        # Should find T1566, T1059.001, and T1078 (from title fallback)
        ids = {t.technique_id for t in techs}
        assert "T1566" in ids
        assert "T1059.001" in ids

    def test_subtechnique_from_url(self):
        html = _load_fixture("cisa_attack_3col.html")
        techs = _extract_attack_techniques(_soup(html), "cisa", [])
        sub = [t for t in techs if t.technique_id == "T1059.001"]
        assert len(sub) == 1
        assert sub[0].name == "Command and Scripting Interpreter: PowerShell"

    def test_caption_tactic_applied(self):
        html = _load_fixture("cisa_attack_3col.html")
        techs = _extract_attack_techniques(_soup(html), "cisa", [])
        t1566 = [t for t in techs if t.technique_id == "T1566"][0]
        assert t1566.tactic == "Initial Access"

    def test_broken_link_title_fallback(self):
        """Link URL has no technique path; ID comes from the title attribute."""
        html = _load_fixture("cisa_attack_3col.html")
        techs = _extract_attack_techniques(_soup(html), "cisa", [])
        t1078 = [t for t in techs if t.technique_id == "T1078"]
        assert len(t1078) == 1
        assert t1078[0].use_description == "Uses stolen credentials"


@pytest.mark.unit
class TestAttack4Col:
    """ATT&CK 4-column table (Tactic, Name, ID, Use)."""

    def test_extracts_techniques(self):
        html = _load_fixture("cisa_attack_4col.html")
        techs = _extract_attack_techniques(_soup(html), "cisa", [])

        ids = {t.technique_id for t in techs}
        assert "T1190" in ids
        assert "T1505.003" in ids

    def test_tactic_from_cell(self):
        html = _load_fixture("cisa_attack_4col.html")
        techs = _extract_attack_techniques(_soup(html), "cisa", [])
        t1190 = [t for t in techs if t.technique_id == "T1190"][0]
        assert t1190.tactic == "Initial Access"

    def test_version_from_url(self):
        html = _load_fixture("cisa_attack_4col.html")
        techs = _extract_attack_techniques(_soup(html), "cisa", [])
        t1190 = [t for t in techs if t.technique_id == "T1190"][0]
        assert t1190.version == "v15"


@pytest.mark.unit
def test_extract_inline_attack_refs():
    """Inline ATT&CK links outside tables are extracted."""
    html = (
        '<p>See <a href="https://attack.mitre.org/techniques/T1027/">Obfuscated '
        'Files</a> for more details.</p>'
    )
    techs = _extract_attack_techniques(_soup(html), "cisa", [])
    assert len(techs) == 1
    assert techs[0].technique_id == "T1027"
    assert techs[0].framework == "attack"


@pytest.mark.unit
def test_attack_deduplication():
    """Same technique ID in table and inline link is deduplicated."""
    html = """
    <table>
    <thead><tr><th>Technique</th><th>ID</th><th>Use</th></tr></thead>
    <tbody><tr>
      <td>Phishing</td>
      <td><a href="https://attack.mitre.org/techniques/T1566/">T1566</a></td>
      <td>Sends phishing</td>
    </tr></tbody>
    </table>
    <p>Also see <a href="https://attack.mitre.org/techniques/T1566/">T1566</a>.</p>
    """
    techs = _extract_attack_techniques(_soup(html), "cisa", [])
    t1566 = [t for t in techs if t.technique_id == "T1566"]
    assert len(t1566) == 1


# =============================================================================
# G.2 -- D3FEND Extraction
# =============================================================================


@pytest.mark.unit
def test_extract_d3fend_from_table():
    html = """
    <table>
    <thead><tr><th>Countermeasure</th><th>D3FEND ID</th><th>Description</th></tr></thead>
    <tbody><tr>
      <td>Network Traffic Filtering</td>
      <td><a href="https://d3fend.mitre.org/technique/d3f:D3-NTF/">D3-NTF</a></td>
      <td>Filter network traffic to block malicious connections</td>
    </tr></tbody>
    </table>
    """
    techs = _extract_d3fend(_soup(html), "cisa", [])
    assert len(techs) == 1
    assert techs[0].technique_id == "D3-NTF"
    assert techs[0].framework == "d3fend"
    assert techs[0].name == "Network Traffic Filtering"


@pytest.mark.unit
def test_extract_d3fend_inline_link():
    html = (
        '<p>Apply <a href="https://d3fend.mitre.org/technique/d3f:D3-SPP/">'
        'D3-SPP Strong Password Policy</a> as a countermeasure.</p>'
    )
    techs = _extract_d3fend(_soup(html), "cisa", [])
    assert len(techs) == 1
    assert techs[0].technique_id == "D3-SPP"


@pytest.mark.unit
def test_d3fend_separate_from_attack():
    """D3FEND and ATT&CK techniques are extracted into separate lists."""
    html = """
    <table>
    <thead><tr><th>Technique</th><th>ID</th><th>Use</th></tr></thead>
    <tbody><tr>
      <td>Phishing</td>
      <td><a href="https://attack.mitre.org/techniques/T1566/">T1566</a></td>
      <td>Phishing emails</td>
    </tr></tbody>
    </table>
    <table>
    <thead><tr><th>Countermeasure</th><th>D3FEND ID</th></tr></thead>
    <tbody><tr>
      <td>Network Filtering</td>
      <td>D3-NTF</td>
    </tr></tbody>
    </table>
    """
    soup = _soup(html)
    attack = _extract_attack_techniques(soup, "cisa", [])
    d3fend = _extract_d3fend(soup, "cisa", [])
    assert all(t.framework == "attack" for t in attack)
    assert all(t.framework == "d3fend" for t in d3fend)
    attack_ids = {t.technique_id for t in attack}
    d3fend_ids = {t.technique_id for t in d3fend}
    assert attack_ids.isdisjoint(d3fend_ids)


# =============================================================================
# G.2 -- IOC Extraction
# =============================================================================


@pytest.mark.unit
class TestIocHorizontal:
    """IOC table with horizontal layout, multiple schemas."""

    def test_extracts_hashes(self):
        html = _load_fixture("cisa_ioc_horizontal.html")
        iocs = _extract_iocs(_soup(html), "cisa", [])
        sha256s = [i for i in iocs if i.type == "sha256"]
        assert len(sha256s) == 2

    def test_extracts_ip_and_domain(self):
        html = _load_fixture("cisa_ioc_horizontal.html")
        iocs = _extract_iocs(_soup(html), "cisa", [])
        ips = [i for i in iocs if i.type == "ip"]
        domains = [i for i in iocs if i.type == "domain"]
        assert len(ips) >= 1
        assert len(domains) >= 1

    def test_context_from_details_column(self):
        html = _load_fixture("cisa_ioc_horizontal.html")
        iocs = _extract_iocs(_soup(html), "cisa", [])
        sha = [i for i in iocs if i.value.startswith("e3b0c4")]
        assert len(sha) == 1
        assert sha[0].context is not None
        assert "dropper" in sha[0].context.lower()

    def test_context_from_notes_column(self):
        html = _load_fixture("cisa_ioc_horizontal.html")
        iocs = _extract_iocs(_soup(html), "cisa", [])
        ip = [i for i in iocs if i.type == "ip"]
        assert len(ip) >= 1
        assert ip[0].context is not None
        assert "c2" in ip[0].context.lower()


@pytest.mark.unit
class TestIocVertical:
    """IOC table with per-sample vertical metadata."""

    def test_extracts_hashes(self):
        html = _load_fixture("cisa_ioc_vertical.html")
        iocs = _extract_iocs(_soup(html), "cisa", [])
        types = {i.type for i in iocs}
        assert "md5" in types
        assert "sha256" in types

    def test_extracts_sha1(self):
        html = _load_fixture("cisa_ioc_vertical.html")
        iocs = _extract_iocs(_soup(html), "cisa", [])
        sha1s = [i for i in iocs if i.type == "sha1"]
        assert len(sha1s) >= 1


@pytest.mark.unit
class TestIocDefanged:
    """IOCs with various defanging patterns."""

    def test_domain_defanged(self):
        html = _load_fixture("cisa_ioc_defanged.html")
        iocs = _extract_iocs(_soup(html), "cisa", [])
        domains = [i for i in iocs if i.type == "domain"]
        assert any(i.value == "evil.example.com" for i in domains)

    def test_ip_defanged(self):
        html = _load_fixture("cisa_ioc_defanged.html")
        iocs = _extract_iocs(_soup(html), "cisa", [])
        ips = [i for i in iocs if i.type == "ip"]
        assert any(i.value == "185.220.101.1" for i in ips)

    def test_url_defanged_https(self):
        html = _load_fixture("cisa_ioc_defanged.html")
        iocs = _extract_iocs(_soup(html), "cisa", [])
        urls = [i for i in iocs if i.type == "url"]
        assert any(
            i.value == "https://malware.example.com/payload" for i in urls
        )

    def test_url_defanged_http(self):
        html = _load_fixture("cisa_ioc_defanged.html")
        iocs = _extract_iocs(_soup(html), "cisa", [])
        urls = [i for i in iocs if i.type == "url"]
        assert any(
            i.value == "http://dropper.example.net/stage2" for i in urls
        )


@pytest.mark.unit
def test_defang_normalize():
    assert _defang_normalize("evil[.]com") == "evil.com"
    assert _defang_normalize("192[.]168[.]1[.]1") == "192.168.1.1"
    assert _defang_normalize("a[:]b") == "a:b"
    assert _defang_normalize("hxxps://evil[.]com") == "https://evil.com"
    assert _defang_normalize("hxxp://evil[.]com") == "http://evil.com"
    assert _defang_normalize("test[dot]com") == "test.com"
    assert _defang_normalize("  padded  ") == "padded"


@pytest.mark.unit
def test_ioc_deduplication():
    """Same IOC appearing multiple times is deduplicated."""
    html = """
    <table>
    <thead><tr><th>Hash</th></tr></thead>
    <tbody>
    <tr><td>d41d8cd98f00b204e9800998ecf8427e</td></tr>
    <tr><td>d41d8cd98f00b204e9800998ecf8427e</td></tr>
    </tbody>
    </table>
    """
    iocs = _extract_iocs(_soup(html), "cisa", [])
    assert len(iocs) == 1


@pytest.mark.unit
def test_ioc_html_entity_decoding():
    """HTML entities in IOC values are properly decoded."""
    html = """
    <table>
    <thead><tr><th>URL</th></tr></thead>
    <tbody>
    <tr><td>http://evil.com/path?a=1&amp;b=2</td></tr>
    </tbody>
    </table>
    """
    iocs = _extract_iocs(_soup(html), "cisa", [])
    urls = [i for i in iocs if i.type == "url"]
    assert len(urls) == 1
    assert urls[0].value == "http://evil.com/path?a=1&b=2"


@pytest.mark.unit
def test_ioc_cell_splitting():
    """Combined cell values ('IP aka domain') are split into separate IOCs."""
    html = """
    <table>
    <thead><tr><th>Indicator</th></tr></thead>
    <tbody>
    <tr><td>185.220.101.1 aka evil.example.com</td></tr>
    </tbody>
    </table>
    """
    iocs = _extract_iocs(_soup(html), "cisa", [])
    types = {i.type for i in iocs}
    assert "ip" in types
    assert "domain" in types


@pytest.mark.unit
def test_split_cell_values():
    assert _split_cell_values("a aka b") == ["a", "b"]
    assert _split_cell_values("x / y") == ["x", "y"]
    assert _split_cell_values("single") == ["single"]
    assert _split_cell_values("") == []


# -- Added-fixture coverage: colspan / missing-colon / JPCERT table schema -----


@pytest.mark.unit
def test_ioc_colspan_time_period_table():
    """Colspan/time-period IOC table: IPs recovered per-cell, warning logged."""
    html = _load_fixture("cisa_ioc_colspan.html")
    logs: list[ExtractionLogEntry] = []
    iocs = _extract_iocs(_soup(html), "cisa", logs)
    ips = {i.value for i in iocs if i.type == "ip"}
    assert ips == {
        "185.220.101.5", "185.220.101.6",
        "91.219.236.10", "91.219.236.11",
    }
    assert any(entry.severity == "warning" and entry.extractor == "iocs"
               for entry in logs)


@pytest.mark.unit
def test_ioc_missing_protocol_colon_defang():
    """http//host defang (missing protocol colon) normalizes to a real URL."""
    html = _load_fixture("cisa_ioc_missing_colon.html")
    iocs = _extract_iocs(_soup(html), "cisa", [])
    urls = {i.value for i in iocs if i.type == "url"}
    assert "http://45.61.150.94:8000/storm.exe" in urls
    # Partial defang (only www dot) also normalizes
    assert "https://www.live.com/redirect" in urls


@pytest.mark.unit
def test_jpcert_content_filename_sha256_schema():
    """JPCERT `Content | Filename | SHA256` table schema extracts hashes + context."""
    html = _load_fixture("jpcert_ioc_table.html")
    iocs = _extract_iocs(_soup(html), "jpcert", [])
    sha256s = [i for i in iocs if i.type == "sha256"]
    assert len(sha256s) == 2
    values = {i.value for i in sha256s}
    assert (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        in values
    )
    # Content + Filename columns become context
    loader = [
        i for i in sha256s
        if i.value.startswith("e3b0c4")
    ][0]
    assert loader.context is not None
    assert "loader.dll" in loader.context


@pytest.mark.unit
def test_broken_attack_link_falls_back_to_cisa_news_page():
    """H-2: technique href points at a cisa.gov /news-events/ page; ID from title."""
    html = _load_fixture("cisa_attack_3col.html")
    soup = _soup(html)
    # Fixture faithfully models ar25-261a: the broken link is NOT attack.mitre.org
    assert "cisa.gov/news-events" in html
    techs = _extract_attack_techniques(soup, "cisa", [])
    t1078 = [t for t in techs if t.technique_id == "T1078"]
    assert len(t1078) == 1
    assert t1078[0].use_description == "Uses stolen credentials"


@pytest.mark.unit
def test_media_defense_external_pdf_download():
    """media.defense.gov PDFs keep their external URL and dedup c-button+c-file."""
    html = _load_fixture("cisa_download_media_defense.html")
    assets = _extract_download_links(_soup(html), "cisa", [])
    pdfs = [a for a in assets if a.asset_type == "pdf"]
    # c-button and c-file point at the same URL -> deduplicated to one asset
    assert len(pdfs) == 1
    assert pdfs[0].original_url == (
        "https://media.defense.gov/2025/Jan/01/2003/CSA-Report.pdf"
    )
    # External domain must NOT be re-prefixed with the CISA base URL
    assert "cisa.gov/2025" not in pdfs[0].original_url
    stix = [a for a in assets if a.asset_type == "stix_json"]
    assert len(stix) == 1


# -- JPCERT IOC extraction paths -----------------------------------------------


@pytest.mark.unit
def test_jpcert_pre_block_iocs():
    html = _load_fixture("jpcert_ioc_pre.html")
    iocs = _extract_iocs(_soup(html), "jpcert", [])
    md5s = [i for i in iocs if i.type == "md5"]
    assert len(md5s) == 4
    values = {i.value for i in md5s}
    assert "d41d8cd98f00b204e9800998ecf8427e" in values


@pytest.mark.unit
def test_jpcert_bullet_list_iocs():
    html = _load_fixture("jpcert_ioc_bullets.html")
    iocs = _extract_iocs(_soup(html), "jpcert", [])
    types = {i.type for i in iocs}
    assert "md5" in types
    assert "domain" in types
    assert "ip" in types
    assert len(iocs) == 4


@pytest.mark.unit
def test_jpcert_advisory_7():
    """APT-C-60: pre IOC blocks + table IOCs + actor extraction."""
    html = _load_fixture("jpcert_advisory_7.html")
    result = parse_advisory("jpcert-7", html, "jpcert")
    md5s = [i for i in result.iocs if i.type == "md5"]
    sha256s = [i for i in result.iocs if i.type == "sha256"]
    assert len(md5s) >= 3
    assert len(sha256s) >= 1
    # Actor from title
    actor_names = {a.tracking_name for a in result.actor_aliases}
    assert "APT-C-60" in actor_names


@pytest.mark.unit
def test_jpcert_advisory_317():
    """Ivanti: ATT&CK table + CVEs, Cobalt Strike config not misidentified."""
    html = _load_fixture("jpcert_advisory_317.html")
    result = parse_advisory("jpcert-317", html, "jpcert")

    tech_ids = {t.technique_id for t in result.techniques}
    assert "T1190" in tech_ids
    assert "T1105" in tech_ids

    cve_ids = {c.cve_id for c in result.cves}
    assert "CVE-2025-0282" in cve_ids
    assert "CVE-2025-0283" in cve_ids

    # Cobalt Strike config lines should NOT be extracted as IOCs
    ioc_values = {i.value for i in result.iocs}
    assert "BeaconType" not in str(ioc_values)


@pytest.mark.unit
def test_jpcert_advisory_319_empty():
    """Empty advisory: zero IOCs, zero CVEs, zero techniques."""
    html = _load_fixture("jpcert_advisory_319.html")
    result = parse_advisory("jpcert-319", html, "jpcert")
    assert len(result.iocs) == 0
    assert len(result.cves) == 0
    assert len(result.techniques) == 0


@pytest.mark.unit
def test_jpcert_advisory_323_empty():
    """Event log advisory: event IDs should not be extracted as IOCs."""
    html = _load_fixture("jpcert_advisory_323.html")
    result = parse_advisory("jpcert-323", html, "jpcert")
    assert len(result.iocs) == 0
    assert len(result.cves) == 0


# =============================================================================
# G.2 -- Download Link Extraction
# =============================================================================


@pytest.mark.unit
class TestDownloadLinks:

    def test_cfile_links_extracted(self):
        html = _load_fixture("cisa_download_links.html")
        assets = _extract_download_links(_soup(html), "cisa", [])
        types = {a.asset_type for a in assets}
        assert "stix_json" in types
        assert "csv" in types

    def test_plain_links_extracted(self):
        html = _load_fixture("cisa_download_links.html")
        assets = _extract_download_links(_soup(html), "cisa", [])
        types = {a.asset_type for a in assets}
        assert "pdf" in types
        assert "sigma_yaml" in types

    def test_stix_url_dedup(self):
        """STIX URLs with Drupal underscore sanitization are deduplicated."""
        html = _load_fixture("cisa_download_links.html")
        assets = _extract_download_links(_soup(html), "cisa", [])
        stix = [a for a in assets if a.asset_type == "stix_json"]
        # report.stix.json and report.stix_.json should deduplicate to 1
        assert len(stix) == 1

    def test_urls_resolved(self):
        html = _load_fixture("cisa_download_links.html")
        assets = _extract_download_links(_soup(html), "cisa", [])
        for asset in assets:
            assert asset.original_url.startswith("https://www.cisa.gov/")


# =============================================================================
# WS-8 A.3 -- STIX Bundle URL Recognition
# =============================================================================


@pytest.mark.unit
class TestClassifyAssetType:

    @pytest.mark.parametrize(
        "url,expected",
        [
            (
                "https://www.cisa.gov/sites/default/files/AA25-071A-stix.json",
                "stix_json",
            ),
            (
                "https://www.cisa.gov/sites/default/files/AA25-071A-stix.xml",
                "stix_xml",
            ),
            (
                "https://www.cisa.gov/sites/default/files/MAR-251126.r1.v1.CLEAR_stix2.json",
                "stix_json",
            ),
            (
                "https://www.cisa.gov/sites/default/files/stix-FIRESTARTER.json",
                "stix_json",
            ),
            (
                "https://www.cisa.gov/sites/default/files/file.stix.json",
                "stix_json",
            ),
            (
                "https://www.cisa.gov/sites/default/files/file.stix_.json",
                "stix_json",
            ),
            (
                "https://www.cisa.gov/sites/default/files/report.pdf",
                "pdf",
            ),
            (
                "https://www.cisa.gov/sites/default/files/rule.yaml",
                "sigma_yaml",
            ),
            (
                "https://www.cisa.gov/sites/default/files/data.json",
                None,
            ),
        ],
    )
    def test_classify_asset_type(self, url, expected):
        assert _classify_asset_type(url) == expected


# =============================================================================
# G.2 -- Figure Extraction
# =============================================================================


@pytest.mark.unit
class TestCisaFigures:

    def test_extracts_figures(self):
        html = _load_fixture("cisa_figure.html")
        figures = _extract_figures(_soup(html), "cisa", [])
        assert len(figures) == 2

    def test_itok_stripped(self):
        html = _load_fixture("cisa_figure.html")
        figures = _extract_figures(_soup(html), "cisa", [])
        for fig in figures:
            assert "?itok=" not in fig.original_url

    def test_caption_extracted(self):
        html = _load_fixture("cisa_figure.html")
        figures = _extract_figures(_soup(html), "cisa", [])
        captions = [f.caption for f in figures if f.caption]
        assert any("C2 communication" in c for c in captions)

    def test_alt_text_extracted(self):
        html = _load_fixture("cisa_figure.html")
        figures = _extract_figures(_soup(html), "cisa", [])
        assert any(f.alt_text == "Network diagram" for f in figures)


@pytest.mark.unit
class TestJpcertFigures:

    def test_mt_figure_pattern(self):
        html = _load_fixture("jpcert_figures.html")
        figures = _extract_figures(_soup(html), "jpcert", [])
        mt_figs = [
            f for f in figures
            if f.original_url == "https://blogs.jpcert.or.jp/image1.png"
        ]
        assert len(mt_figs) == 1
        assert mt_figs[0].caption == "Figure 1: Infection chain overview"

    def test_bare_img_with_centered_caption(self):
        html = _load_fixture("jpcert_figures.html")
        figures = _extract_figures(_soup(html), "jpcert", [])
        img2 = [
            f for f in figures
            if f.original_url == "https://blogs.jpcert.or.jp/image2.png"
        ]
        assert len(img2) == 1
        assert img2[0].caption == "Figure 2: C2 communication"

    def test_bare_img_no_caption(self):
        html = _load_fixture("jpcert_figures.html")
        figures = _extract_figures(_soup(html), "jpcert", [])
        img3 = [
            f for f in figures
            if f.original_url == "https://blogs.jpcert.or.jp/image3.png"
        ]
        assert len(img3) == 1
        assert img3[0].caption is None


# =============================================================================
# G.2 -- Actor Alias Extraction
# =============================================================================


@pytest.mark.unit
class TestCisaActors:

    def test_extracts_aliases(self):
        html = _load_fixture("cisa_actors.html")
        aliases = _extract_actor_aliases(_soup(html), "cisa", [])
        assert len(aliases) == 3

    def test_organization_parsed(self):
        html = _load_fixture("cisa_actors.html")
        aliases = _extract_actor_aliases(_soup(html), "cisa", [])
        vt = [a for a in aliases if a.tracking_name == "Volt Typhoon"]
        assert len(vt) == 1
        assert vt[0].organization == "Microsoft"

    def test_no_organization(self):
        html = _load_fixture("cisa_actors.html")
        aliases = _extract_actor_aliases(_soup(html), "cisa", [])
        vp = [a for a in aliases if a.tracking_name == "Vanguard Panda"]
        assert len(vp) == 1
        assert vp[0].organization is None


@pytest.mark.unit
def test_jpcert_actor_from_title():
    html = _load_fixture("jpcert_advisory_7.html")
    aliases = _extract_actor_aliases(_soup(html), "jpcert", [])
    names = {a.tracking_name for a in aliases}
    assert "APT-C-60" in names


# =============================================================================
# G.2 -- End-to-End parse phase
# =============================================================================


@pytest.mark.unit
def test_parse_advisory_end_to_end():
    """Full parse_advisory with a complete CISA advisory fixture."""
    html = (
        '<h1>Threat Advisory: APT-X Campaign</h1>'
        '<h3>YARA Rules</h3>'
        '<table><thead><tr><th>Rule</th></tr></thead><tbody>'
        '<tr><td>rule apt_x {<br/>    strings:<br/>'
        '        $s = "apt_x_payload"<br/>'
        '    condition:<br/>        $s<br/>}</td></tr>'
        '</tbody></table>'
        '<table><thead><tr><th>Technique</th><th>ID</th><th>Use</th></tr></thead>'
        '<tbody><tr><td>Phishing</td>'
        '<td><a href="https://attack.mitre.org/techniques/T1566/">T1566</a></td>'
        '<td>Spearphishing emails</td></tr></tbody></table>'
        '<p>Tracked as <a href="https://cve.org/CVERecord?id=CVE-2025-1234">'
        'CVE-2025-1234</a>.</p>'
        '<table><thead><tr><th>SHA256 Hash</th><th>Description</th></tr></thead>'
        '<tbody><tr>'
        '<td>e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</td>'
        '<td>Dropper</td></tr></tbody></table>'
        '<figure class="c-figure">'
        '<img src="/sites/default/files/images/c2.png?itok=x" alt="C2">'
        '<figcaption>C2 diagram</figcaption></figure>'
        '<a href="/topics/cyber/critical-infrastructure-sectors/energy-sector">'
        'Energy Sector</a>'
        '<h2>Cybersecurity Industry Tracking</h2>'
        '<ul><li>APT-X (Mandiant)</li></ul>'
    )
    result = parse_advisory("test-e2e", html, "cisa")

    assert len(result.detection_rules) == 1
    assert result.detection_rules[0].rule_name == "apt_x"
    assert len(result.techniques) >= 1
    assert any(t.technique_id == "T1566" for t in result.techniques)
    assert any(c.cve_id == "CVE-2025-1234" for c in result.cves)
    assert len(result.iocs) >= 1
    assert len(result.figures) >= 1
    assert "?itok=" not in result.figures[0].original_url
    assert "Energy" in result.sectors
    assert any(a.tracking_name == "APT-X" for a in result.actor_aliases)


# =============================================================================
# G.3 -- IOC Validator Tests
# =============================================================================


@pytest.mark.unit
class TestValidateHashes:

    @pytest.mark.parametrize("value", [
        "d41d8cd98f00b204e9800998ecf8427e",
        "5d41402abc4b2a76b9719d911017c592",
    ])
    def test_valid_md5(self, value):
        status, _ = validate_ioc("md5", value)
        assert status == "verified"

    def test_invalid_md5_wrong_length(self):
        status, _ = validate_ioc("md5", "d41d8cd98f00b204e9800998ecf842")
        assert status == "invalid"

    def test_invalid_md5_non_hex(self):
        status, _ = validate_ioc("md5", "z41d8cd98f00b204e9800998ecf8427e")
        assert status == "invalid"

    @pytest.mark.parametrize("value", [
        "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
    ])
    def test_valid_sha1(self, value):
        status, _ = validate_ioc("sha1", value)
        assert status == "verified"

    def test_invalid_sha1(self):
        status, _ = validate_ioc("sha1", "aaf4c61ddcc5e8a2dabede0f3b482cd")
        assert status == "invalid"

    @pytest.mark.parametrize("value", [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ])
    def test_valid_sha256(self, value):
        status, needs_review = validate_ioc("sha256", value)
        assert status == "verified"
        # SHA-256 ambiguity flag
        assert needs_review is True

    def test_invalid_sha256(self):
        status, _ = validate_ioc("sha256", "e3b0c44298fc1c149afbf4c8")
        assert status == "invalid"

    def test_valid_sha512(self):
        h = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        status, _ = validate_ioc("sha512", h)
        assert status == "verified"

    def test_invalid_sha512(self):
        status, _ = validate_ioc("sha512", "cf83e1357eefb8bdf1542850d66d80")
        assert status == "invalid"


@pytest.mark.unit
class TestValidateIPs:

    @pytest.mark.parametrize("value", [
        "185.220.101.1",
        "45.33.32.156",
    ])
    def test_valid_ipv4(self, value):
        status, _ = validate_ioc("ip", value)
        assert status == "verified"

    def test_ipv6_documentation_range_rejected(self):
        status, _ = validate_ioc("ip", "2001:db8::1")
        assert status == "invalid", "2001:db8::/32 documentation range should be rejected"

    def test_valid_public_ipv6(self):
        status, _ = validate_ioc("ip", "2606:4700:4700::1111")
        assert status == "verified"

    @pytest.mark.parametrize("value", [
        "not.an.ip.address",
        "256.1.2.3",
        "999.999.999.999",
    ])
    def test_invalid_ipv4(self, value):
        status, _ = validate_ioc("ip", value)
        assert status == "invalid"

    @pytest.mark.parametrize("value,label", [
        ("192.168.1.1", "RFC1918 class C"),
        ("192.168.0.1", "RFC1918 class C"),
        ("10.0.0.1", "RFC1918 class A"),
        ("10.255.255.255", "RFC1918 class A"),
        ("172.16.0.1", "RFC1918 class B lower"),
        ("172.31.255.255", "RFC1918 class B upper"),
    ])
    def test_rfc1918_rejected(self, value, label):
        status, _ = validate_ioc("ip", value)
        assert status == "invalid", f"{label} ({value}) should be rejected"

    def test_loopback_rejected(self):
        status, _ = validate_ioc("ip", "127.0.0.1")
        assert status == "invalid"

    def test_link_local_rejected(self):
        status, _ = validate_ioc("ip", "169.254.1.1")
        assert status == "invalid", "Link-local (169.254.x.x) should be rejected"


@pytest.mark.unit
class TestValidateDomains:

    @pytest.mark.parametrize("value", [
        "evil.example.com",
        "sub.domain.example.org",
        "x.io",
    ])
    def test_valid_domain(self, value):
        status, _ = validate_ioc("domain", value)
        assert status in ("verified", "allowlisted")

    def test_wildcard_domain(self):
        status, _ = validate_ioc("domain", "*.example.com")
        assert status in ("verified", "allowlisted")

    def test_invalid_single_label(self):
        status, _ = validate_ioc("domain", "localhost")
        assert status == "invalid"

    def test_invalid_numeric_tld(self):
        status, _ = validate_ioc("domain", "test.123")
        assert status == "invalid"


@pytest.mark.unit
class TestValidateURLs:

    def test_valid_http(self):
        status, _ = validate_ioc("url", "http://evil.com/path")
        assert status in ("verified", "allowlisted")

    def test_valid_https(self):
        status, _ = validate_ioc("url", "https://evil.com/path")
        assert status in ("verified", "allowlisted")

    def test_invalid_no_scheme(self):
        status, _ = validate_ioc("url", "evil.com/path")
        assert status == "invalid"


@pytest.mark.unit
class TestValidateSsdeep:

    def test_valid_ssdeep(self):
        status, _ = validate_ioc("ssdeep", "3:AXGBicFlgVNhBGK:AXGBiWn")
        assert status == "verified"

    def test_invalid_ssdeep(self):
        status, _ = validate_ioc("ssdeep", "not-an-ssdeep-hash")
        assert status == "invalid"


@pytest.mark.unit
class TestValidateEmail:

    def test_valid_email(self):
        status, _ = validate_ioc("email", "attacker@evil.com")
        assert status == "verified"

    def test_invalid_email_no_at(self):
        status, _ = validate_ioc("email", "not-an-email")
        assert status == "invalid"

    def test_invalid_email_no_domain(self):
        status, _ = validate_ioc("email", "user@")
        assert status == "invalid"


@pytest.mark.unit
class TestInferFilepathType:

    @pytest.mark.parametrize("value", [
        "/lib/libdsupgrade.so",
        "/opt/vmware/sbin/vmware-sphere",
        "%userprofile%\\AppData\\Local\\malware.exe",
        "C:\\Windows\\System32\\cmd.exe",
    ])
    def test_recognized_filepaths(self, value):
        assert _infer_ioc_type(value) == "filepath"

    def test_bare_root_is_not_filepath(self):
        assert _infer_ioc_type("/") is None

    def test_trailing_slash_no_filename_is_not_filepath(self):
        assert _infer_ioc_type("/tmp/") is None

    def test_url_wins_over_filepath(self):
        assert _infer_ioc_type("http://evil.com/path") == "url"

    def test_ip_wins_over_filepath(self):
        # IP check runs before filepath detection; private IPs are rejected
        # later by the validator, not by _infer_ioc_type.
        assert _infer_ioc_type("192.168.1.1") == "ip"

    def test_domain_wins_over_filepath(self):
        assert _infer_ioc_type("example.com") == "domain"

    def test_filename_with_extension_is_not_filepath(self):
        # Caught (and rejected) by the _FILE_EXTENSIONS check in the domain
        # branch since it has no path separator.
        assert _infer_ioc_type("malware.exe") is None


@pytest.mark.unit
class TestValidateFilepath:

    def test_valid_unix_filepath(self):
        status, needs_review = validate_ioc("filepath", "/lib/libdsupgrade.so")
        assert status == "verified"
        assert needs_review is True

    def test_empty_value_invalid(self):
        status, needs_review = validate_ioc("filepath", "")
        assert status == "invalid"
        assert needs_review is True

    def test_no_separators_invalid(self):
        status, needs_review = validate_ioc("filepath", "no-separators")
        assert status == "invalid"
        assert needs_review is True


@pytest.mark.unit
class TestBuildIocFromValueCompound:
    """WS-8 A.1: split compound 'MALWARE_NAME hash_value' bullet strings."""

    def test_malware_name_then_hash_extracts_sha256(self):
        sha256 = "94b1087af3" + "a" * 54
        record = _build_ioc_from_value(
            f"SPAWNCHIMERA {sha256}", None, [],
        )
        assert record is not None
        assert record.type == "sha256"
        assert record.value == sha256
        assert "SPAWNCHIMERA" in record.context

    def test_malware_name_then_filepath_extracts_filepath(self):
        record = _build_ioc_from_value(
            "MALWARE /lib/libdsupgrade.so", None, [],
        )
        assert record is not None
        assert record.type == "filepath"
        assert record.value == "/lib/libdsupgrade.so"
        assert "MALWARE" in record.context

    def test_ip_then_malware_name_extracts_first_token_ip(self):
        record = _build_ioc_from_value(
            "3.112.192.119 DslogdRAT", None, [],
        )
        assert record is not None
        assert record.type == "ip"
        assert record.value == "3.112.192.119"

    def test_plain_text_with_no_ioc_returns_none(self):
        assert _build_ioc_from_value("plain text no IOC here", None, []) is None

    def test_actor_name_does_not_false_positive_as_domain(self):
        record = _build_ioc_from_value(
            "Storm-0501 192.168.1.1", None, [],
        )
        assert record is not None
        assert record.type == "ip"
        assert record.value == "192.168.1.1"
        # Private IP fails format validation, but the compound split must
        # still fire -- "Storm-0501" must never be misread as a domain.
        assert record.validation_status == "invalid"


@pytest.mark.unit
class TestInferIocTypeMutex:
    """WS-8 B.2: mutex is only inferred when context_hint names it explicitly."""

    def test_no_context_hint_returns_none(self):
        assert _infer_ioc_type("K31610KIO9834PG79A90B") is None

    def test_mutex_keyword_in_context_hint(self):
        assert (
            _infer_ioc_type("K31610KIO9834PG79A90B", context_hint="Mutex")
            == "mutex"
        )

    def test_mutant_keyword_in_context_hint(self):
        assert (
            _infer_ioc_type(
                "K31610KIO9834PG79A90B", context_hint="Other IoC: mutant name",
            )
            == "mutex"
        )

    def test_unrelated_context_hint_returns_none(self):
        assert (
            _infer_ioc_type("K31610KIO9834PG79A90B", context_hint="Hash values")
            is None
        )


@pytest.mark.unit
class TestValidateMutex:

    def test_valid_mutex(self):
        status, needs_review = validate_ioc("mutex", "K31610KIO9834PG79A90B")
        assert status == "verified"
        assert needs_review is True

    def test_empty_mutex_invalid(self):
        status, needs_review = validate_ioc("mutex", "")
        assert status == "invalid"
        assert needs_review is True


@pytest.mark.unit
@pytest.mark.usefixtures("patched_allowlist")
class TestAllowlist:
    """Allowlist matching against a monkeypatched allowlist (not prod config)."""

    def test_allowlisted_domain(self):
        status, needs_review = validate_ioc("domain", "microsoft.com")
        assert status == "allowlisted"
        assert needs_review is True

    def test_allowlisted_subdomain(self):
        status, _ = validate_ioc("domain", "login.microsoft.com")
        assert status == "allowlisted"

    def test_allowlisted_ip(self):
        status, _ = validate_ioc("ip", "8.8.8.8")
        assert status == "allowlisted"

    def test_allowlisted_url_domain(self):
        status, _ = validate_ioc("url", "https://update.microsoft.com/path")
        assert status == "allowlisted"

    def test_non_allowlisted_domain(self):
        status, _ = validate_ioc("domain", "evil.example.com")
        assert status == "verified"

    def test_non_allowlisted_ip_is_verified(self):
        status, _ = validate_ioc("ip", "185.220.101.1")
        assert status == "verified"


# =============================================================================
# G.5 -- Extraction Logging Tests
# =============================================================================


@pytest.mark.unit
class TestComputeExtractionStatus:

    def test_no_logs_returns_done(self):
        assert _compute_extraction_status([]) == "parse_done"

    def test_warnings_only_returns_partial(self):
        logs = [
            ExtractionLogEntry("iocs", "warning", "unknown schema", None),
        ]
        assert _compute_extraction_status(logs) == "parse_partial"

    def test_errors_returns_failed(self):
        logs = [
            ExtractionLogEntry("iocs", "error", "parser crashed", None),
        ]
        assert _compute_extraction_status(logs) == "parse_failed"

    def test_errors_override_warnings(self):
        logs = [
            ExtractionLogEntry("iocs", "warning", "unknown schema", None),
            ExtractionLogEntry("rules", "error", "parser crashed", None),
        ]
        assert _compute_extraction_status(logs) == "parse_failed"


@pytest.mark.unit
class TestSubExtractorExceptionHandling:

    def test_exception_caught_and_logged(self):
        """A sub-extractor exception is caught and recorded in result.logs."""
        result = ParseResult()
        _log_extractor_error(result, "test_ext", "adv-001", ValueError("boom"))
        assert len(result.logs) == 1
        assert result.logs[0].severity == "error"
        assert result.logs[0].extractor == "test_ext"
        assert "boom" in result.logs[0].message

    def test_remaining_extractors_still_run(self):
        """If one sub-extractor throws, the others still run."""
        html = (
            '<table><thead><tr><th>SHA256 Hash</th></tr></thead>'
            '<tbody><tr>'
            '<td>e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</td>'
            '</tr></tbody></table>'
            '<p><a href="https://cve.org/CVERecord?id=CVE-2025-9999">'
            'CVE-2025-9999</a></p>'
        )
        with patch(
            "threat2signal.analysis.extractor._extract_detection_rules",
            side_effect=RuntimeError("boom"),
        ):
            result = parse_advisory("adv-exc", html, "cisa")
        assert len(result.iocs) >= 1
        assert any(c.cve_id == "CVE-2025-9999" for c in result.cves)
        assert any(
            log.severity == "error" and "boom" in log.message
            for log in result.logs
        )


@pytest.mark.unit
class TestExtractionLogCRUD:

    def test_insert_and_query(self, db_conn):
        _make_advisory(db_conn, "log-test-001")
        insert_extraction_log(
            db_conn, "log-test-001", "parse",
            "iocs", "warning", "Unknown table schema", "table_3",
        )
        logs = get_extraction_logs(db_conn, "log-test-001")
        assert len(logs) == 1
        assert logs[0]["extractor"] == "iocs"
        assert logs[0]["severity"] == "warning"
        assert logs[0]["message"] == "Unknown table schema"
        assert logs[0]["context"] == "table_3"

    def test_query_by_severity(self, db_conn):
        _make_advisory(db_conn, "sev-test-001")
        insert_extraction_log(
            db_conn, "sev-test-001", "parse",
            "iocs", "warning", "warn msg",
        )
        insert_extraction_log(
            db_conn, "sev-test-001", "parse",
            "rules", "error", "error msg",
        )
        warnings = get_extraction_logs(db_conn, "sev-test-001", severity="warning")
        errors = get_extraction_logs(db_conn, "sev-test-001", severity="error")
        assert len(warnings) == 1
        assert len(errors) == 1
        assert warnings[0]["severity"] == "warning"
        assert errors[0]["severity"] == "error"

    def test_delete_by_phase(self, db_conn):
        _make_advisory(db_conn, "del-test-001")
        insert_extraction_log(
            db_conn, "del-test-001", "parse",
            "iocs", "warning", "parse warn",
        )
        insert_extraction_log(
            db_conn, "del-test-001", "intel",
            "iocs", "warning", "intel warn",
        )
        deleted = delete_extraction_logs(db_conn, "del-test-001", phase="parse")
        assert deleted == 1
        remaining = get_extraction_logs(db_conn, "del-test-001")
        assert len(remaining) == 1
        assert remaining[0]["phase"] == "intel"


@pytest.mark.unit
class TestSaveParseResults:

    def test_sets_parse_done(self, db_conn):
        aid = _make_advisory(db_conn, "save-done-001")
        result = ParseResult()
        status = save_parse_results(db_conn, aid, result, "<p>enriched</p>")
        assert status == "parse_done"
        row = db_conn.execute(
            "SELECT extraction_status, enriched_body FROM advisory "
            "WHERE advisory_id = ?", (aid,),
        ).fetchone()
        assert row[0] == "parse_done"
        assert row[1] == "<p>enriched</p>"

    def test_sets_parse_partial_on_warnings(self, db_conn):
        aid = _make_advisory(db_conn, "save-partial-001")
        result = ParseResult(
            logs=[ExtractionLogEntry("iocs", "warning", "unknown schema", None)],
        )
        status = save_parse_results(db_conn, aid, result, "<p>enriched</p>")
        assert status == "parse_partial"
        row = db_conn.execute(
            "SELECT extraction_status FROM advisory WHERE advisory_id = ?",
            (aid,),
        ).fetchone()
        assert row[0] == "parse_partial"

    def test_sets_parse_failed_on_errors(self, db_conn):
        aid = _make_advisory(db_conn, "save-failed-001")
        result = ParseResult(
            logs=[ExtractionLogEntry("rules", "error", "crash", None)],
        )
        status = save_parse_results(db_conn, aid, result, "<p>enriched</p>")
        assert status == "parse_failed"
        row = db_conn.execute(
            "SELECT extraction_status FROM advisory WHERE advisory_id = ?",
            (aid,),
        ).fetchone()
        assert row[0] == "parse_failed"

    def test_re_extraction_clears_prior_logs(self, db_conn):
        aid = _make_advisory(db_conn, "re-extract-001")

        # First extraction with a warning
        result1 = ParseResult(
            logs=[ExtractionLogEntry("iocs", "warning", "first run", None)],
        )
        save_parse_results(db_conn, aid, result1, "<p>v1</p>")
        logs1 = get_extraction_logs(db_conn, aid)
        assert len(logs1) == 1
        assert logs1[0]["message"] == "first run"

        # Re-extraction replaces logs
        result2 = ParseResult(
            logs=[ExtractionLogEntry("rules", "warning", "second run", None)],
        )
        save_parse_results(db_conn, aid, result2, "<p>v2</p>")
        logs2 = get_extraction_logs(db_conn, aid)
        assert len(logs2) == 1
        assert logs2[0]["message"] == "second run"

    def test_saves_iocs(self, db_conn):
        aid = _make_advisory(db_conn, "save-ioc-001")
        result = ParseResult(
            iocs=[
                IocRecord(
                    type="md5",
                    value="d41d8cd98f00b204e9800998ecf8427e",
                    context="test",
                    validation_status="verified",
                    source_verified=True,
                    needs_review=False,
                ),
            ],
        )
        save_parse_results(db_conn, aid, result, "<p>body</p>")
        ioc_rows = db_conn.execute(
            "SELECT type, value FROM ioc WHERE advisory_id = ?", (aid,),
        ).fetchall()
        assert len(ioc_rows) == 1
        assert ioc_rows[0][0] == "md5"

    def test_saves_detection_rules(self, db_conn):
        aid = _make_advisory(db_conn, "save-rule-001")
        result = ParseResult(
            detection_rules=[
                RuleRecord(
                    rule_name="test_rule",
                    rule_text="rule test_rule { condition: true }",
                    raw_extracted=None,
                    source="html_parsed",
                    rule_format="yara",
                    validation_status="valid",
                    validation_error=None,
                ),
            ],
        )
        save_parse_results(db_conn, aid, result, "<p>body</p>")
        rule_rows = db_conn.execute(
            "SELECT rule_name, rule_format FROM detection_rule "
            "WHERE advisory_id = ?", (aid,),
        ).fetchall()
        assert len(rule_rows) == 1
        assert rule_rows[0][0] == "test_rule"
        assert rule_rows[0][1] == "yara"

    def test_records_extraction_history(self, db_conn):
        aid = _make_advisory(db_conn, "save-hist-001")
        result = ParseResult()
        save_parse_results(db_conn, aid, result, "<p>body</p>")
        hist = db_conn.execute(
            "SELECT phase, extracted_json FROM extraction_history "
            "WHERE advisory_id = ?", (aid,),
        ).fetchall()
        assert len(hist) == 1
        assert hist[0][0] == "parse"


# =============================================================================
# G.4 -- Integration round-trip: HTML -> extract -> save -> query back
# =============================================================================


# A clean multi-section advisory: Pattern-D rule (no rule table, so the IOC
# scanner has no rule table to choke on) and an <h2> heading terminating the
# detection section, so extraction produces zero warnings (parse_done).
_ROUNDTRIP_HTML = (
    '<h1>Threat Advisory: APT-X Campaign</h1>'
    '<h3>YARA Rules</h3>'
    '<div><p><code>rule apt_x {</code></p>'
    '<p><code>    strings:</code></p>'
    '<p><code>        $s = "apt_x_payload"</code></p>'
    '<p><code>    condition:</code></p>'
    '<p><code>        $s</code></p>'
    '<p><code>}</code></p></div>'
    '<h2>Indicators of Compromise</h2>'
    '<table><thead><tr><th>Technique</th><th>ID</th><th>Use</th></tr></thead>'
    '<tbody><tr><td>Phishing</td>'
    '<td><a href="https://attack.mitre.org/techniques/T1566/">T1566</a></td>'
    '<td>Spearphishing emails</td></tr></tbody></table>'
    '<p>Tracked as <a href="https://cve.org/CVERecord?id=CVE-2025-1234">'
    'CVE-2025-1234</a> and plain CVE-2024-9999.</p>'
    '<table><thead><tr><th>SHA256 Hash</th><th>Description</th></tr></thead>'
    '<tbody><tr>'
    '<td>e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</td>'
    '<td>Dropper</td></tr></tbody></table>'
    '<figure class="c-figure">'
    '<img src="/sites/default/files/images/c2.png?itok=x" alt="C2">'
    '<figcaption>C2 diagram</figcaption></figure>'
    '<a href="/topics/cyber/critical-infrastructure-sectors/energy-sector">'
    'Energy Sector</a>'
)


@pytest.mark.integration
def test_roundtrip_extract_save_query(db_conn):
    """Full pipeline: extract -> save_parse_results -> query back matches."""
    aid = _make_advisory(db_conn, "rt-001")
    result = parse_advisory(aid, _ROUNDTRIP_HTML, "cisa")
    enriched = enrich_article_body(_ROUNDTRIP_HTML, "cisa", aid, result, 1)
    status = save_parse_results(db_conn, aid, result, enriched)
    assert status == "parse_done"

    # IOCs round-trip
    ioc_rows = get_iocs(db_conn, aid)
    assert {r["value"] for r in ioc_rows} == {
        i.value for i in result.iocs
    }
    assert any(r["type"] == "sha256" for r in ioc_rows)

    # Detection rules round-trip
    rule_rows = get_detection_rules(db_conn, aid)
    assert {r["rule_name"] for r in rule_rows} == {
        r.rule_name for r in result.detection_rules
    }
    assert rule_rows[0]["rule_format"] == "yara"

    # Techniques round-trip
    tech_rows = get_advisory_techniques(db_conn, aid)
    assert {r["technique_id"] for r in tech_rows} == {
        t.technique_id for t in result.techniques + result.d3fend
    }

    # CVEs round-trip: LEFT JOIN returns ALL linked CVEs (not just MSRC)
    cve_rows = get_advisory_cves(db_conn, aid)
    assert {r["cve_id"] for r in cve_rows} == {"CVE-2025-1234", "CVE-2024-9999"}
    # No msrc_cve rows seeded, so none are msrc-known
    assert all(r["is_msrc"] is False for r in cve_rows)
    # link_source persisted (cve.org for the linked one, 'none' for plain text)
    link_sources = {r["cve_id"]: r["link_source"] for r in cve_rows}
    assert link_sources["CVE-2024-9999"] == "none"
    assert link_sources["CVE-2025-1234"] is not None

    # Enriched body stored
    row = db_conn.execute(
        "SELECT enriched_body FROM advisory WHERE advisory_id = ?", (aid,),
    ).fetchone()
    assert row[0] == enriched


@pytest.mark.integration
def test_roundtrip_idempotent_counts(db_conn):
    """Re-extracting the same advisory leaves record counts unchanged."""
    aid = _make_advisory(db_conn, "rt-idem-001")
    result = parse_advisory(aid, _ROUNDTRIP_HTML, "cisa")
    save_parse_results(db_conn, aid, result, "<p>v1</p>")

    counts_first = (
        count_iocs(db_conn, aid),
        count_detection_rules(db_conn, aid),
        count_advisory_techniques(db_conn, aid),
        count_advisory_cves(db_conn, aid),
    )

    # Re-extract + re-save (DELETE-then-INSERT idempotency)
    result2 = parse_advisory(aid, _ROUNDTRIP_HTML, "cisa")
    save_parse_results(db_conn, aid, result2, "<p>v2</p>")

    counts_second = (
        count_iocs(db_conn, aid),
        count_detection_rules(db_conn, aid),
        count_advisory_techniques(db_conn, aid),
        count_advisory_cves(db_conn, aid),
    )
    assert counts_first == counts_second


@pytest.mark.integration
def test_roundtrip_preserves_downloaded_assets(db_conn):
    """Re-extraction preserves advisory_asset download_status/local_path (C9).

    advisory_asset is NOT deleted on re-extraction; an already-downloaded figure
    keeps its 'completed' status and local path.
    """
    aid = _make_advisory(db_conn, "rt-asset-001")
    result = parse_advisory(aid, _ROUNDTRIP_HTML, "cisa")
    save_parse_results(db_conn, aid, result, "<p>v1</p>")

    assets = get_advisory_assets(db_conn, aid)
    assert len(assets) >= 1
    figure_url = assets[0]["original_url"]

    # Simulate a completed download (C9: status is 'completed', not 'downloaded')
    mark_asset_downloaded(
        db_conn, aid, figure_url,
        local_path="data/assets/cisa/rt-asset-001/figures/c2.png",
        file_size=2048, downloaded_at="2026-08-21T00:00:00+00:00",
    )

    # Re-extract: asset rows must survive with their download state intact
    result2 = parse_advisory(aid, _ROUNDTRIP_HTML, "cisa")
    save_parse_results(db_conn, aid, result2, "<p>v2</p>")

    after = get_advisory_assets(db_conn, aid)
    preserved = [a for a in after if a["original_url"] == figure_url]
    assert len(preserved) == 1
    assert preserved[0]["download_status"] == "completed"
    assert preserved[0]["local_path"] == (
        "data/assets/cisa/rt-asset-001/figures/c2.png"
    )


@pytest.mark.integration
@pytest.mark.parametrize("fixture,expected_names", [
    ("cisa_yara_pattern_a.html", {"test_malware_a"}),
    ("cisa_yara_pattern_b.html", {"test_malware_b"}),
    ("cisa_yara_pattern_c.html", {"rule_alpha", "rule_beta"}),
    ("cisa_yara_pattern_d.html", {"test_malware_d"}),
])
def test_roundtrip_per_yara_pattern(db_conn, fixture, expected_names):
    """One advisory per YARA HTML pattern (A/B/C/D) round-trips through the DB."""
    aid = _make_advisory(db_conn, f"rt-{fixture}")
    html = _load_fixture(fixture)
    result = parse_advisory(aid, html, "cisa")
    save_parse_results(db_conn, aid, result, "<p>body</p>")

    rule_rows = get_detection_rules(db_conn, aid)
    assert {r["rule_name"] for r in rule_rows} == expected_names

    # Idempotency: re-extract yields the same rule count
    before = count_detection_rules(db_conn, aid)
    result2 = parse_advisory(aid, html, "cisa")
    save_parse_results(db_conn, aid, result2, "<p>body</p>")
    assert count_detection_rules(db_conn, aid) == before


# =============================================================================
# G.5 -- Warning emission from real extraction (C1 keystone)
# =============================================================================


@pytest.mark.unit
def test_headerless_non_ioc_table_emits_warning():
    """A headerless non-IOC table failing the >50% grid gate warns, not raises."""
    html = (
        "<table><tbody>"
        "<tr><td>Some prose here</td><td>More prose text</td></tr>"
        "<tr><td>Narrative content</td><td>Even more words</td></tr>"
        "</tbody></table>"
    )
    logs: list[ExtractionLogEntry] = []
    iocs = _extract_iocs(_soup(html), "cisa", logs)
    assert iocs == []
    warnings = [entry for entry in logs if entry.severity == "warning"]
    assert len(warnings) == 1
    assert warnings[0].extractor == "iocs"


@pytest.mark.unit
def test_colspan_time_period_table_emits_warning_and_recovers_iocs():
    """A colspan/time-period IOC table warns but still recovers IPs per-cell (H-4)."""
    html = (
        "<table><thead><tr><th colspan='2'>January 2025</th></tr></thead>"
        "<tbody><tr><td>185.220.101.5</td><td>185.220.101.6</td></tr></tbody>"
        "</table>"
    )
    logs: list[ExtractionLogEntry] = []
    iocs = _extract_iocs(_soup(html), "cisa", logs)
    ips = {i.value for i in iocs if i.type == "ip"}
    assert ips == {"185.220.101.5", "185.220.101.6"}
    warnings = [entry for entry in logs if entry.severity == "warning"]
    assert len(warnings) == 1
    assert warnings[0].extractor == "iocs"


@pytest.mark.unit
def test_parse_advisory_surfaces_warning_in_result_logs():
    """parse_advisory threads sub-extractor warnings into ParseResult.logs."""
    html = (
        "<table><tbody>"
        "<tr><td>Prose one</td><td>Prose two</td></tr>"
        "<tr><td>Prose three</td><td>Prose four</td></tr>"
        "</tbody></table>"
    )
    result = parse_advisory("warn-adv", html, "cisa")
    assert any(
        entry.severity == "warning" and entry.extractor == "iocs"
        for entry in result.logs
    )


@pytest.mark.unit
def test_save_maps_real_warning_to_parse_partial(db_conn):
    """A real extraction warning drives extraction_status to parse_partial."""
    aid = _make_advisory(db_conn, "warn-save-001")
    html = (
        "<table><tbody>"
        "<tr><td>Prose one</td><td>Prose two</td></tr>"
        "<tr><td>Prose three</td><td>Prose four</td></tr>"
        "</tbody></table>"
    )
    result = parse_advisory(aid, html, "cisa")
    status = save_parse_results(db_conn, aid, result, "<p>body</p>")
    assert status == "parse_partial"
    stored_logs = get_extraction_logs(db_conn, aid, severity="warning")
    assert len(stored_logs) >= 1


# -- Config table IOC recovery (WS-8 A.2) ---------------------------------------


@pytest.mark.unit
def test_config_table_recovers_high_confidence_ioc_via_percell_scan():
    """jpcert-202504-dslogdrat: Description/Content headers map to no IOC column
    and the >50% gate fails (1 IP among non-IOC config values), but the C2 IP
    must still be recovered via the low-confidence per-cell scan."""
    html = """
    <table>
    <tr><th>Description</th><th>Content</th></tr>
    <tr><td>Sleep timer</td><td>0x1234</td></tr>
    <tr><td>C2 Server</td><td>3.112.192[.]119</td></tr>
    <tr><td>Port</td><td>443</td></tr>
    <tr><td>Mutex name</td><td>Global\\DSLOG</td></tr>
    </table>
    """
    table = _soup(html).find("table")
    logs: list[ExtractionLogEntry] = []
    iocs = _extract_iocs_from_headed_table(table, ["Description", "Content"], logs)

    ips = [i for i in iocs if i.type == "ip"]
    assert len(ips) == 1
    assert ips[0].value == "3.112.192.119"
    assert ips[0].needs_review is True
    assert ips[0].source_verified is False

    # Non-IOC config cells (hex byte, port number, mutex name) must not leak through.
    values = {i.value for i in iocs}
    assert "0x1234" not in values
    assert "443" not in values
    assert "Global\\DSLOG" not in values

    assert any(
        "recovered" in entry.message and entry.severity == "warning"
        for entry in logs
    )


@pytest.mark.unit
def test_config_table_with_no_high_confidence_iocs_returns_empty():
    """A metadata table with no IPs/hashes recovers nothing (no false positives)."""
    html = """
    <table>
    <tr><th>Date</th><th>Event</th></tr>
    <tr><td>2024-01-01</td><td>Incident reported</td></tr>
    <tr><td>2024-01-05</td><td>Remediation completed</td></tr>
    </table>
    """
    table = _soup(html).find("table")
    logs: list[ExtractionLogEntry] = []
    iocs = _extract_iocs_from_headed_table(table, ["Date", "Event"], logs)
    assert iocs == []
