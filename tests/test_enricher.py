"""Tests for threat2signal.analysis.enricher -- article body enrichment.

Covers image URL rewriting, IOC highlighting (boundary guards + defang
tolerance + skip contexts), anti-spoofing of scraped annotations (C8),
MITRE host validation (F2), external link safety (C7), dangerous-href
neutering (F16), download-link rewriting (F0), multi-rule containers (F1),
and CVE routing (F8).
"""

import inspect

import pytest
from bs4 import BeautifulSoup

from threat2signal.analysis.enricher import (
    _strip_itok,
    enrich_article_body,
)
from threat2signal.analysis.extractor import (
    IocRecord,
    ParseResult,
    RuleRecord,
    TechniqueRecord,
)


# -- Record builders -----------------------------------------------------------


def _ioc(
    ioc_type: str,
    value: str,
    context: str | None = None,
    validation_status: str = "verified",
    source_verified: bool = True,
    needs_review: bool = False,
) -> IocRecord:
    return IocRecord(
        type=ioc_type,
        value=value,
        context=context,
        validation_status=validation_status,
        source_verified=source_verified,
        needs_review=needs_review,
    )


def _tech(
    technique_id: str,
    tactic: str | None = None,
    name: str | None = None,
    use_description: str | None = None,
    confidence: str = "advisory_stated",
    framework: str = "attack",
    version: str | None = None,
) -> TechniqueRecord:
    return TechniqueRecord(
        technique_id=technique_id,
        tactic=tactic,
        name=name,
        use_description=use_description,
        confidence=confidence,
        framework=framework,
        version=version,
    )


def _rule(
    rule_name: str,
    rule_text: str,
    rule_format: str = "yara",
    validation_status: str = "valid",
    validation_error: str | None = None,
) -> RuleRecord:
    return RuleRecord(
        rule_name=rule_name,
        rule_text=rule_text,
        raw_extracted=None,
        source="html_parsed",
        rule_format=rule_format,
        validation_status=validation_status,
        validation_error=validation_error,
    )


def _soup(html: str) -> BeautifulSoup:
    return BeautifulSoup(html, "html.parser")


# -- Signature contract (C0) ---------------------------------------------------


@pytest.mark.unit
def test_numeric_id_is_required():
    """numeric_id must have no default so a forgotten arg can't emit /api/assets/0/."""
    sig = inspect.signature(enrich_article_body)
    assert sig.parameters["numeric_id"].default is inspect.Parameter.empty
    assert sig.parameters["known_msrc_cves"].default is None


# -- B+.1: Image URL rewriting -------------------------------------------------


@pytest.mark.unit
def test_strip_itok_first_param_only():
    assert _strip_itok("https://x.gov/f.png?itok=AbC") == "https://x.gov/f.png"


@pytest.mark.unit
def test_strip_itok_non_first_param_preserves_others():
    result = _strip_itok("https://x.gov/f.png?width=100&itok=AbC&height=50")
    assert result == "https://x.gov/f.png?width=100&height=50"


@pytest.mark.unit
def test_strip_itok_no_query_unchanged():
    assert _strip_itok("https://x.gov/f.png") == "https://x.gov/f.png"


@pytest.mark.unit
def test_image_relative_rewritten_to_asset_endpoint():
    result = ParseResult()
    body = (
        '<figure><img alt="d" '
        'src="/sites/default/files/styles/large/public/2025-09/diagram.png?itok=AbC123">'
        "</figure>"
    )
    out = enrich_article_body(body, "cisa", "adv", result, 42)
    img = _soup(out).find("img")
    assert img["src"] == "/api/assets/42/figures/diagram.png"


@pytest.mark.unit
def test_image_absolute_jpcert_rewritten_to_asset_endpoint():
    result = ParseResult()
    body = '<img src="https://blogs.jpcert.or.jp/en/img/chart.png">'
    out = enrich_article_body(body, "jpcert", "adv", result, 9)
    img = _soup(out).find("img")
    assert img["src"] == "/api/assets/9/figures/chart.png"


# -- B+.2: IOC highlighting boundary guards ------------------------------------


@pytest.mark.unit
def test_ioc_not_matched_as_substring():
    """10.1.1.1 must NOT be highlighted inside 210.1.1.10."""
    result = ParseResult(iocs=[_ioc("ip", "10.1.1.1")])
    body = "<p>The benign subnet 210.1.1.10 is unrelated to the campaign.</p>"
    out = enrich_article_body(body, "cisa", "adv", result, 1)
    assert "t2s-ioc" not in out


@pytest.mark.unit
def test_ioc_trailing_sentence_dot_still_matches():
    """A sentence-final period after an IOC must not block the match."""
    result = ParseResult(iocs=[_ioc("ip", "10.1.1.1")])
    body = "<p>The C2 server is 10.1.1.1.</p>"
    out = enrich_article_body(body, "cisa", "adv", result, 1)
    marks = _soup(out).find_all("mark", class_="t2s-ioc")
    assert len(marks) == 1
    assert marks[0].get_text() == "10.1.1.1"
    assert marks[0]["data-ioc-value"] == "10.1.1.1"
    assert marks[0]["data-ioc-type"] == "ip"
    assert marks[0].get("tabindex") == "0"


# -- B+.2: Defang-tolerant highlighting ----------------------------------------


@pytest.mark.unit
def test_defang_tolerant_domain_bracket_dot():
    result = ParseResult(iocs=[_ioc("domain", "evil.com")])
    out = enrich_article_body("<p>Beacon to evil[.]com now.</p>", "cisa", "a", result, 1)
    mark = _soup(out).find("mark", class_="t2s-ioc")
    assert mark is not None
    # visible text keeps the defanged form; data attribute holds normalized value
    assert mark.get_text() == "evil[.]com"
    assert mark["data-ioc-value"] == "evil.com"


@pytest.mark.unit
def test_defang_tolerant_url_hxxp():
    result = ParseResult(iocs=[_ioc("url", "http://bad.com/x")])
    out = enrich_article_body("<p>GET hxxp://bad[.]com/x here.</p>", "cisa", "a", result, 1)
    mark = _soup(out).find("mark", class_="t2s-ioc")
    assert mark is not None
    assert mark["data-ioc-value"] == "http://bad.com/x"


@pytest.mark.unit
def test_defang_tolerant_ipv6_bracket_colon():
    value = "2001:41d0:700:65dc::f656:929f"
    result = ParseResult(iocs=[_ioc("ip", value)])
    body = "<p>Traffic to 2001:41d0:700:65dc::f656[:]929f was observed.</p>"
    out = enrich_article_body(body, "cisa", "a", result, 1)
    mark = _soup(out).find("mark", class_="t2s-ioc")
    assert mark is not None
    assert mark["data-ioc-value"] == value


# -- B+.2: Skip contexts -------------------------------------------------------


@pytest.mark.unit
def test_ioc_skipped_inside_code_pre_and_anchor():
    result = ParseResult(iocs=[_ioc("domain", "evil.com")])
    body = (
        "<p><code>evil.com</code></p>"
        '<p><a href="https://ref.example">evil.com</a></p>'
        "<pre>evil.com</pre>"
    )
    out = enrich_article_body(body, "cisa", "a", result, 1)
    assert "t2s-ioc" not in out


@pytest.mark.unit
def test_ioc_skipped_inside_existing_mark():
    """A plain <mark> is a skip context -- no double-wrapping."""
    result = ParseResult(iocs=[_ioc("domain", "evil.com")])
    out = enrich_article_body("<p><mark>evil.com</mark></p>", "cisa", "a", result, 1)
    assert "t2s-ioc" not in out
    assert "evil.com" in out


# -- C8: Anti-spoofing of scraped annotations ----------------------------------


@pytest.mark.unit
def test_c8_incoming_t2s_mark_unwrapped_text_preserved():
    result = ParseResult()  # nothing to re-annotate
    body = (
        '<p><mark class="t2s-ioc" data-ioc-type="ip" data-ioc-value="9.9.9.9">'
        "9.9.9.9</mark> is spoofed.</p>"
    )
    out = enrich_article_body(body, "cisa", "a", result, 1)
    # mark unwrapped, visible text preserved
    assert "9.9.9.9 is spoofed." in _soup(out).get_text()
    assert "t2s-ioc" not in out
    assert "data-ioc-value" not in out


@pytest.mark.unit
def test_c8_incoming_data_and_t2s_class_stripped():
    result = ParseResult()
    body = (
        '<p><span class="t2s-mitre other" data-technique-id="T1059" '
        'data-tactic="Execution">T1059</span></p>'
    )
    out = enrich_article_body(body, "cisa", "a", result, 1)
    assert "t2s-mitre" not in out
    assert "data-technique-id" not in out
    assert "data-tactic" not in out
    # non-t2s class survives; text preserved
    span = _soup(out).find("span")
    assert span is not None
    assert span.get("class") == ["other"]
    assert span.get_text() == "T1059"


# -- F2: MITRE host validation -------------------------------------------------


@pytest.mark.unit
def test_f2_spoofed_mitre_host_not_trusted():
    result = ParseResult(techniques=[_tech("T1059", tactic="Execution", name="Cmd")])
    body = '<p><a href="https://attack.mitre.org.evil.com/techniques/T1059/">T1059</a></p>'
    out = enrich_article_body(body, "cisa", "a", result, 1)
    link = _soup(out).find("a")
    assert "t2s-mitre" not in (link.get("class") or [])
    # spoofed host href is left as-is (only external-link attrs added)
    assert link["href"] == "https://attack.mitre.org.evil.com/techniques/T1059/"


@pytest.mark.unit
def test_f2_genuine_mitre_link_canonicalized():
    result = ParseResult(
        techniques=[_tech("T1190", tactic="Initial Access", name="Exploit Public-Facing App")],
    )
    body = '<p><a href="https://attack.mitre.org/versions/v15/techniques/T1190/">T1190</a></p>'
    out = enrich_article_body(body, "cisa", "a", result, 1)
    link = _soup(out).find("a", class_="t2s-mitre")
    assert link is not None
    assert link["href"] == "https://attack.mitre.org/techniques/T1190/"
    assert link["data-technique-id"] == "T1190"
    assert link["data-tactic"] == "Initial Access"


@pytest.mark.unit
def test_mitre_inline_text_linked():
    result = ParseResult(techniques=[_tech("T1027", tactic="Defense Evasion", name="Obfuscation")])
    out = enrich_article_body("<p>Uses T1027 to hide.</p>", "cisa", "a", result, 1)
    link = _soup(out).find("a", class_="t2s-mitre")
    assert link is not None
    assert link["data-technique-id"] == "T1027"
    assert link["href"] == "https://attack.mitre.org/techniques/T1027/"


# -- C7: External link safety --------------------------------------------------


@pytest.mark.unit
def test_c7_external_link_gets_target_and_rel():
    result = ParseResult()
    body = '<p><a href="https://example.com/report">Report</a></p>'
    out = enrich_article_body(body, "cisa", "a", result, 1)
    assert 'target="_blank"' in out
    assert 'rel="noopener noreferrer"' in out
    link = _soup(out).find("a")
    assert "t2s-external" in link.get("class", [])


@pytest.mark.unit
def test_c7_internal_link_not_marked_external():
    result = ParseResult()
    # A known-MSRC CVE keeps its /msrc/ internal route and must not become
    # target=_blank/external.
    body = '<p><a href="/msrc/CVE-2025-0001">CVE-2025-0001</a></p>'
    out = enrich_article_body(
        body, "cisa", "a", result, 1, known_msrc_cves={"CVE-2025-0001"},
    )
    link = _soup(out).find("a")
    assert link["href"] == "/msrc/CVE-2025-0001"
    assert link.get("target") is None
    assert "t2s-external" not in (link.get("class") or [])


# -- F16: Dangerous href neutering ---------------------------------------------


@pytest.mark.unit
def test_f16_dangerous_hrefs_neutered():
    result = ParseResult()
    body = (
        '<p><a href="javascript:alert(1)">x</a>'
        '<a href="data:text/html,evil">y</a>'
        '<a href="  JAVA\tSCRIPT:alert(2)">z</a></p>'
    )
    out = enrich_article_body(body, "cisa", "a", result, 1)
    for link in _soup(out).find_all("a"):
        assert link["href"] == "#"
    assert "javascript:" not in out.lower()
    assert "data:text/html" not in out


# -- F0: Download link rewriting -----------------------------------------------


@pytest.mark.unit
def test_f0_download_link_rewritten_not_reprefixed():
    result = ParseResult()
    body = (
        '<div class="c-file"><a class="c-file__link" '
        'href="/sites/default/files/2025-09/report.pdf">PDF</a></div>'
    )
    out = enrich_article_body(body, "cisa", "a", result, 7)
    link = _soup(out).find("a")
    assert link["href"] == "/api/assets/7/files/report.pdf"
    assert link["data-asset-type"] == "pdf"
    assert "t2s-asset-download" in link.get("class", [])
    # never re-prefixed with source base URL, never marked external
    assert "cisa.gov/api/assets" not in out
    assert "t2s-external" not in out


# -- F1: Multi-rule container (Pattern C) --------------------------------------


@pytest.mark.unit
def test_f1_multiple_rules_one_pre_each():
    rules = [
        _rule("rule_alpha", "rule rule_alpha {\n    condition:\n        true\n}"),
        _rule("rule_beta", "rule rule_beta {\n    condition:\n        false\n}"),
    ]
    result = ParseResult(detection_rules=rules)
    body = (
        "<h3>Yara Rules</h3>"
        "<table><tbody><tr><td>"
        "<p>rule rule_alpha {</p><p>    condition:</p><p>        true</p><p>}</p>"
        "<p>rule rule_beta {</p><p>    condition:</p><p>        false</p><p>}</p>"
        "</td></tr></tbody></table>"
    )
    out = enrich_article_body(body, "cisa", "a", result, 1)
    pres = _soup(out).find_all("pre", class_="t2s-yara")
    assert len(pres) == 2
    names = {p["data-rule-name"] for p in pres}
    assert names == {"rule_alpha", "rule_beta"}
    for pre in pres:
        assert pre["data-rule-format"] == "yara"
        assert pre.find("code") is not None


# -- F8: CVE routing (MSRC vs NVD) ---------------------------------------------


@pytest.mark.unit
def test_f8_known_msrc_cve_routes_internal_others_nvd():
    result = ParseResult()
    body = "<p>See CVE-2025-0001 and CVE-2025-9999 for details.</p>"
    out = enrich_article_body(
        body, "cisa", "a", result, 1, known_msrc_cves={"CVE-2025-0001"},
    )
    links = {
        a["data-cve-id"]: a["href"]
        for a in _soup(out).find_all("a", class_="t2s-cve")
    }
    assert links["CVE-2025-0001"] == "/msrc/CVE-2025-0001"
    assert links["CVE-2025-9999"] == "https://nvd.nist.gov/vuln/detail/CVE-2025-9999"


@pytest.mark.unit
def test_f8_existing_nvd_anchor_retargeted_to_msrc():
    result = ParseResult()
    body = '<p><a href="https://nvd.nist.gov/vuln/detail/CVE-2025-0001">CVE-2025-0001</a></p>'
    out = enrich_article_body(
        body, "cisa", "a", result, 1, known_msrc_cves={"CVE-2025-0001"},
    )
    link = _soup(out).find("a", class_="t2s-cve")
    assert link is not None
    assert link["href"] == "/msrc/CVE-2025-0001"
    assert link["data-cve-id"] == "CVE-2025-0001"
