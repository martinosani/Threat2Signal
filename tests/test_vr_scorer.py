"""Tests for the VR scoring engine (threat2signal.analysis.msrc_scorer VR functions)."""

from __future__ import annotations

from pathlib import Path

import pytest

from threat2signal.analysis.msrc_scorer import (
    _apply_vr_bonuses,
    _determine_vr_priority,
    _match_vr_component,
    compute_vr_score,
    generate_vr_tags,
    load_scoring_config,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_cve(**overrides) -> dict:
    """Build a minimal CVE dict with sensible defaults, allowing test-specific overrides."""
    base = {
        "cve_id": "CVE-2025-99999",
        "title": "Test Vulnerability",
        "component": None,
        "component_category": None,
        "impact": None,
        "severity": None,
        "av": None,
        "ac": None,
        "pr": None,
        "ui": None,
        "scope": None,
        "cwe_id": None,
        "cwe_description": None,
        "exploit_status": None,
        "exploited_wild": 0,
        "publicly_disclosed": 0,
        "customer_action": None,
        "has_kb_entries": False,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def scoring_config():
    """Load the real scoring config from config/scoring.yaml."""
    config_path = Path(__file__).resolve().parent.parent / "config" / "scoring.yaml"
    return load_scoring_config(config_path)


# ---------------------------------------------------------------------------
# _determine_vr_priority
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_vr_priority_prime(scoring_config):
    thresholds = scoring_config["vr_scoring"]["thresholds"]
    assert _determine_vr_priority(150, thresholds) == "PRIME"


@pytest.mark.unit
def test_vr_priority_prime_at_boundary(scoring_config):
    """Exactly 100 hits the PRIME threshold."""
    thresholds = scoring_config["vr_scoring"]["thresholds"]
    assert _determine_vr_priority(100, thresholds) == "PRIME"


@pytest.mark.unit
def test_vr_priority_high_just_below_prime(scoring_config):
    """Score 99 falls one point below PRIME into HIGH."""
    thresholds = scoring_config["vr_scoring"]["thresholds"]
    assert _determine_vr_priority(99, thresholds) == "HIGH"


@pytest.mark.unit
def test_vr_priority_high(scoring_config):
    thresholds = scoring_config["vr_scoring"]["thresholds"]
    assert _determine_vr_priority(85, thresholds) == "HIGH"


@pytest.mark.unit
def test_vr_priority_medium(scoring_config):
    thresholds = scoring_config["vr_scoring"]["thresholds"]
    assert _determine_vr_priority(55, thresholds) == "MEDIUM"


@pytest.mark.unit
def test_vr_priority_low(scoring_config):
    thresholds = scoring_config["vr_scoring"]["thresholds"]
    assert _determine_vr_priority(30, thresholds) == "LOW"


@pytest.mark.unit
def test_vr_priority_noise(scoring_config):
    thresholds = scoring_config["vr_scoring"]["thresholds"]
    assert _determine_vr_priority(10, thresholds) == "NOISE"


@pytest.mark.unit
def test_vr_priority_noise_zero(scoring_config):
    thresholds = scoring_config["vr_scoring"]["thresholds"]
    assert _determine_vr_priority(0, thresholds) == "NOISE"


# ---------------------------------------------------------------------------
# _match_vr_component
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_vr_component_win32k(scoring_config):
    vr = scoring_config["vr_scoring"]
    score, name = _match_vr_component("win32k", None, vr)
    assert score == 38
    assert name == "win32k"


@pytest.mark.unit
def test_vr_component_matched_via_title(scoring_config):
    """Component pattern found in title when component field is None."""
    vr = scoring_config["vr_scoring"]
    score, name = _match_vr_component(None, "Windows TCP/IP Remote Code Execution", vr)
    assert score == 35
    assert name == "Windows TCP/IP"


@pytest.mark.unit
def test_vr_component_highest_score_wins(scoring_config):
    """When multiple patterns match, the one with the highest score is returned."""
    vr = scoring_config["vr_scoring"]
    # "Windows Kernel win32k" matches "win32k" (38) and "Windows Kernel" (15)
    score, name = _match_vr_component("Windows Kernel win32k", None, vr)
    assert score == 38
    assert name == "win32k"


@pytest.mark.unit
def test_vr_component_catchall_fallback(scoring_config):
    """Unrecognized component falls back to a catchall category."""
    vr = scoring_config["vr_scoring"]
    score, name = _match_vr_component("Azure Foo Service", None, vr)
    assert score == 3
    assert name == "Azure"


@pytest.mark.unit
def test_vr_component_no_match_returns_default(scoring_config):
    """Completely unknown component gets default_component_score (5)."""
    vr = scoring_config["vr_scoring"]
    score, name = _match_vr_component("Something Unknown", "Unknown Title", vr)
    assert score == 5
    assert name == ""


# ---------------------------------------------------------------------------
# _apply_vr_bonuses
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_vr_bonus_exploit_active_penalty(scoring_config):
    """exploited_wild=True applies exploit_active penalty (-20)."""
    bonuses_cfg = scoring_config["vr_scoring"]["bonuses"]
    cve = _make_cve(exploited_wild=1)
    total, bonuses, penalties = _apply_vr_bonuses(cve, bonuses_cfg)
    assert total == -20
    assert len(penalties) == 1
    assert penalties[0] == {"name": "exploit_active", "score": -20}
    assert all(b["name"] != "exploit_active" for b in bonuses)


@pytest.mark.unit
def test_vr_bonus_publicly_disclosed_penalty(scoring_config):
    """publicly_disclosed=True (not exploited) applies -5 penalty."""
    bonuses_cfg = scoring_config["vr_scoring"]["bonuses"]
    cve = _make_cve(publicly_disclosed=1, exploited_wild=0)
    total, bonuses, penalties = _apply_vr_bonuses(cve, bonuses_cfg)
    assert total == -5
    assert len(penalties) == 1
    assert penalties[0] == {"name": "publicly_disclosed", "score": -5}


@pytest.mark.unit
def test_vr_bonus_exploit_unproven(scoring_config):
    """Neither exploited nor disclosed gives exploit_unproven bonus (+5)."""
    bonuses_cfg = scoring_config["vr_scoring"]["bonuses"]
    cve = _make_cve(exploited_wild=0, publicly_disclosed=0)
    total, bonuses, penalties = _apply_vr_bonuses(cve, bonuses_cfg)
    assert total == 5
    assert len(bonuses) == 1
    assert bonuses[0] == {"name": "exploit_unproven", "score": 5}
    assert len(penalties) == 0


@pytest.mark.unit
def test_vr_bonus_critical_severity(scoring_config):
    """severity='Critical' adds critical_severity bonus (+8)."""
    bonuses_cfg = scoring_config["vr_scoring"]["bonuses"]
    cve = _make_cve(severity="Critical", exploited_wild=0, publicly_disclosed=0)
    total, bonuses, penalties = _apply_vr_bonuses(cve, bonuses_cfg)
    # exploit_unproven (+5) + critical_severity (+8) = 13
    assert total == 13
    bonus_names = [b["name"] for b in bonuses]
    assert "critical_severity" in bonus_names
    assert "exploit_unproven" in bonus_names


@pytest.mark.unit
def test_vr_bonus_scope_changed(scoring_config):
    """scope='Changed' adds scope_changed bonus (+12)."""
    bonuses_cfg = scoring_config["vr_scoring"]["bonuses"]
    cve = _make_cve(scope="Changed", exploited_wild=0, publicly_disclosed=0)
    total, bonuses, penalties = _apply_vr_bonuses(cve, bonuses_cfg)
    # exploit_unproven (+5) + scope_changed (+12) = 17
    assert total == 17
    bonus_names = [b["name"] for b in bonuses]
    assert "scope_changed" in bonus_names


@pytest.mark.unit
def test_vr_bonus_customer_action_required(scoring_config):
    """customer_action set adds customer_action_required bonus (+15)."""
    bonuses_cfg = scoring_config["vr_scoring"]["bonuses"]
    cve = _make_cve(
        customer_action="Apply the latest security update",
        exploited_wild=0,
        publicly_disclosed=0,
    )
    total, bonuses, penalties = _apply_vr_bonuses(cve, bonuses_cfg)
    # customer_action_required (+15) + exploit_unproven (+5) = 20
    assert total == 20
    bonus_names = [b["name"] for b in bonuses]
    assert "customer_action_required" in bonus_names


@pytest.mark.unit
def test_vr_bonuses_and_penalties_in_separate_lists(scoring_config):
    """Positive modifiers go in bonuses list, negative ones in penalties list."""
    bonuses_cfg = scoring_config["vr_scoring"]["bonuses"]
    cve = _make_cve(
        customer_action="Apply patch",
        exploited_wild=1,
        severity="Critical",
        scope="Changed",
    )
    total, bonuses, penalties = _apply_vr_bonuses(cve, bonuses_cfg)
    # customer_action(+15) + exploit_active(-20) + critical(+8) + scope(+12) = 15
    assert total == 15
    bonus_names = {b["name"] for b in bonuses}
    penalty_names = {p["name"] for p in penalties}
    assert bonus_names == {"customer_action_required", "critical_severity", "scope_changed"}
    assert penalty_names == {"exploit_active"}


# ---------------------------------------------------------------------------
# compute_vr_score — PRIME case
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_vr_score_prime_win32k_uaf(scoring_config):
    """Win32k UAF, local, novel, Important — should score 104 and reach PRIME."""
    cve = _make_cve(
        component="win32k",
        title="Use After Free in win32k",
        cwe_id="CWE-416",
        impact="Elevation of Privilege",
        av="L",
        pr="L",
        ui="N",
        severity="Important",
        exploited_wild=0,
        publicly_disclosed=0,
    )
    total, priority, breakdown = compute_vr_score(cve, set(), scoring_config)
    # component(38) + cwe(20) + impact(16) + av(8) + pr(6) + ui(8)
    # + exploit_unproven(5) + important_severity(3) = 104
    assert total == 104
    assert priority == "PRIME"
    assert breakdown["component"]["score"] == 38
    assert breakdown["cwe"]["score"] == 20
    assert breakdown["impact"]["score"] == 16
    assert breakdown["attack_vector"]["score"] == 8
    assert breakdown["privileges"]["score"] == 6
    assert breakdown["user_interaction"]["score"] == 8


# ---------------------------------------------------------------------------
# compute_vr_score — penalized case
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_vr_score_penalized_tcpip_rce_exploited(scoring_config):
    """TCP/IP RCE exploited in the wild — penalty lowers score below what it would be novel."""
    cve_exploited = _make_cve(
        component="Windows TCP/IP",
        title="Windows TCP/IP Remote Code Execution Vulnerability",
        impact="Remote Code Execution",
        av="N",
        pr="N",
        ui="N",
        exploited_wild=1,
    )
    total, priority, breakdown = compute_vr_score(cve_exploited, set(), scoring_config)
    # component(35) + impact(18) + av(15) + pr(12) + ui(8) + exploit_active(-20) = 68
    assert total == 68
    assert priority == "MEDIUM"
    assert breakdown["component"]["score"] == 35
    penalty_names = [p["name"] for p in breakdown["penalties"]]
    assert "exploit_active" in penalty_names

    # Same CVE without exploitation would score higher
    cve_novel = _make_cve(
        component="Windows TCP/IP",
        title="Windows TCP/IP Remote Code Execution Vulnerability",
        impact="Remote Code Execution",
        av="N",
        pr="N",
        ui="N",
        exploited_wild=0,
        publicly_disclosed=0,
    )
    novel_total, novel_priority, _ = compute_vr_score(cve_novel, set(), scoring_config)
    # base(88) + exploit_unproven(5) = 93 → HIGH
    assert novel_total > total
    assert novel_priority == "HIGH"


# ---------------------------------------------------------------------------
# generate_vr_tags
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_vr_tags_mem_corrupt(scoring_config):
    """CWE-416 triggers the mem_corrupt tag."""
    cve = _make_cve(cwe_id="CWE-416", exploited_wild=1)
    tags = generate_vr_tags(cve, set(), scoring_config)
    assert "mem_corrupt" in tags


@pytest.mark.unit
def test_vr_tags_kernel(scoring_config):
    """win32k component triggers the kernel tag."""
    cve = _make_cve(component="win32k", exploited_wild=1)
    tags = generate_vr_tags(cve, set(), scoring_config)
    assert "kernel" in tags


@pytest.mark.unit
def test_vr_tags_remote_preauth(scoring_config):
    """av=N and pr=N together trigger remote_preauth."""
    cve = _make_cve(av="N", pr="N", exploited_wild=1)
    tags = generate_vr_tags(cve, set(), scoring_config)
    assert "remote_preauth" in tags


@pytest.mark.unit
def test_vr_tags_scope_change(scoring_config):
    """scope=Changed triggers scope_change."""
    cve = _make_cve(scope="Changed", exploited_wild=1)
    tags = generate_vr_tags(cve, set(), scoring_config)
    assert "scope_change" in tags


@pytest.mark.unit
def test_vr_tags_novel(scoring_config):
    """Not exploited, not disclosed, not in KEV triggers novel."""
    cve = _make_cve(exploited_wild=0, publicly_disclosed=0)
    tags = generate_vr_tags(cve, set(), scoring_config)
    assert "novel" in tags


@pytest.mark.unit
def test_vr_tags_patchable(scoring_config):
    """has_kb_entries=True triggers patchable."""
    cve = _make_cve(has_kb_entries=True, exploited_wild=1)
    tags = generate_vr_tags(cve, set(), scoring_config)
    assert "patchable" in tags


@pytest.mark.unit
def test_vr_tags_high_impact(scoring_config):
    """Remote Code Execution triggers high_impact."""
    cve = _make_cve(impact="Remote Code Execution", exploited_wild=1)
    tags = generate_vr_tags(cve, set(), scoring_config)
    assert "high_impact" in tags


@pytest.mark.unit
def test_vr_tags_info_leak(scoring_config):
    """Information Disclosure triggers info_leak."""
    cve = _make_cve(impact="Information Disclosure", exploited_wild=1)
    tags = generate_vr_tags(cve, set(), scoring_config)
    assert "info_leak" in tags


@pytest.mark.unit
def test_vr_tags_sorted_order(scoring_config):
    """Tags are returned in sorted alphabetical order."""
    cve = _make_cve(
        cwe_id="CWE-416",
        component="win32k",
        av="N",
        pr="N",
        scope="Changed",
        has_kb_entries=True,
        impact="Remote Code Execution",
        exploited_wild=0,
        publicly_disclosed=0,
    )
    tags = generate_vr_tags(cve, set(), scoring_config)
    assert tags == sorted(tags)
    expected = [
        "high_impact",
        "kernel",
        "mem_corrupt",
        "novel",
        "patchable",
        "remote_preauth",
        "scope_change",
    ]
    assert tags == expected


@pytest.mark.unit
def test_vr_tags_empty_when_no_conditions_met(scoring_config):
    """CVE matching no tag conditions produces an empty list."""
    cve = _make_cve(
        component="Azure Foo",
        impact="Spoofing",
        av="L",
        pr="H",
        exploited_wild=1,
        has_kb_entries=False,
    )
    tags = generate_vr_tags(cve, set(), scoring_config)
    assert tags == []


# ---------------------------------------------------------------------------
# Tag absence — verify tags NOT generated when conditions are unmet
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_vr_tags_no_novel_when_exploited(scoring_config):
    """exploited_wild=True prevents the novel tag."""
    cve = _make_cve(exploited_wild=1, publicly_disclosed=0)
    tags = generate_vr_tags(cve, set(), scoring_config)
    assert "novel" not in tags


@pytest.mark.unit
def test_vr_tags_no_remote_preauth_with_local_av(scoring_config):
    """av=L prevents remote_preauth even when pr=N."""
    cve = _make_cve(av="L", pr="N", exploited_wild=1)
    tags = generate_vr_tags(cve, set(), scoring_config)
    assert "remote_preauth" not in tags


# ---------------------------------------------------------------------------
# Score breakdown shape
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_vr_score_breakdown_has_expected_keys(scoring_config):
    """Breakdown dict from compute_vr_score contains all expected keys."""
    cve = _make_cve()
    _, _, breakdown = compute_vr_score(cve, set(), scoring_config)
    expected_keys = {
        "component",
        "cwe",
        "impact",
        "attack_vector",
        "privileges",
        "user_interaction",
        "bonuses",
        "penalties",
        "total",
        "priority",
    }
    assert set(breakdown.keys()) == expected_keys
