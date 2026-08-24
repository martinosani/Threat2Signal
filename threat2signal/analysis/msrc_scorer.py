"""CVE defense scoring engine."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from threat2signal.storage import db

if TYPE_CHECKING:
    import sqlite3

logger = logging.getLogger(__name__)

# CVSS single-letter abbreviations to full-word forms
_AV_ALIASES: dict[str, str] = {
    "n": "network",
    "a": "adjacent",
    "l": "local",
    "p": "physical",
}

_PR_ALIASES: dict[str, str] = {
    "n": "none",
    "l": "low",
    "h": "high",
}

_UI_ALIASES: dict[str, str] = {
    "n": "none",
    "r": "required",
}

# MSRC impact strings to normalized short keys
_IMPACT_ALIASES: dict[str, str] = {
    "remote code execution": "rce",
    "elevation of privilege": "eop",
    "information disclosure": "info_disclosure",
    "denial of service": "dos",
    "security feature bypass": "security_feature_bypass",
    "spoofing": "spoofing",
}


def load_scoring_config(config_path: str | Path) -> dict:
    """Load the scoring model from a YAML config file."""
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def _ci_lookup(key: str, mapping: dict) -> tuple[int, str] | None:
    """Case-insensitive dict lookup returning (value, original_key) or None."""
    lower = key.lower()
    for k, v in mapping.items():
        if k.lower() == lower:
            return (v, k)
    return None


def _match_component_score(
    component: str | None, component_scores: dict
) -> tuple[int, str]:
    """Return (score, matched_name) via case-insensitive substring match."""
    if not component:
        return (0, "")
    comp_lower = component.strip().lower()
    for name, score in component_scores.items():
        if name.lower() in comp_lower:
            return (score, name)
    return (0, "")


def _match_cwe_weight(
    cwe_id: str | None, cwe_weights: dict
) -> tuple[int, str]:
    """Return (score, cwe_description) by exact match on CWE ID."""
    if not cwe_id:
        return (0, "")
    if cwe_id in cwe_weights:
        return (cwe_weights[cwe_id], cwe_id)
    return (0, "")


def _match_impact_weight(
    impact: str | None, impact_weights: dict
) -> tuple[int, str]:
    """Return (score, matched_key) mapping MSRC impact strings to config keys."""
    if not impact:
        return (0, "")
    stripped = impact.strip()
    # Direct case-insensitive match against config keys
    result = _ci_lookup(stripped, impact_weights)
    if result:
        return result
    # Fall back to abbreviated alias lookup
    alias = _IMPACT_ALIASES.get(stripped.lower())
    if alias:
        result = _ci_lookup(alias, impact_weights)
        if result:
            return result
    return (0, "")


def _match_attack_vector(av: str | None, config: dict) -> tuple[int, str]:
    """Return (score, label) mapping CVSS attack-vector to config score."""
    if not av:
        return (0, "")
    av_scores = config["attack_vector"]
    key = _AV_ALIASES.get(av.strip().lower(), av.strip().lower())
    result = _ci_lookup(key, av_scores)
    if result:
        return result
    return (0, "")


def _match_privileges(pr: str | None, config: dict) -> tuple[int, str]:
    """Return (score, label) mapping CVSS privileges-required to config score."""
    if not pr:
        return (0, "")
    pr_scores = config["privileges_required"]
    key = _PR_ALIASES.get(pr.strip().lower(), pr.strip().lower())
    result = _ci_lookup(key, pr_scores)
    if result:
        return result
    return (0, "")


def _match_user_interaction(ui: str | None, config: dict) -> tuple[int, str]:
    """Return (score, label) mapping CVSS user-interaction to config score."""
    if not ui:
        return (0, "")
    ui_scores = config["user_interaction"]
    key = _UI_ALIASES.get(ui.strip().lower(), ui.strip().lower())
    result = _ci_lookup(key, ui_scores)
    if result:
        return result
    return (0, "")


def _determine_priority(score: float, thresholds: dict) -> str:
    """Map a numeric score to a priority label using threshold config."""
    if score >= thresholds["HIGH"]:
        return "HIGH"
    if score >= thresholds["MEDIUM"]:
        return "MEDIUM"
    if score >= thresholds["LOW"]:
        return "LOW"
    return "NOISE"


def _apply_bonuses(
    cve: dict, kev_ids: set[str], bonuses_cfg: dict
) -> tuple[int, list[dict[str, int | str]]]:
    """Return (bonus_total, applied_bonuses_list) for situational bonuses."""
    total = 0
    applied: list[dict[str, int | str]] = []

    if cve.get("customer_action"):
        val = bonuses_cfg["customer_action_required"]
        total += val
        applied.append({"name": "customer_action_required", "score": val})

    if cve.get("exploited_wild"):
        val = bonuses_cfg["exploit_active"]
        total += val
        applied.append({"name": "exploit_active", "score": val})

    if cve.get("cve_id", "") in kev_ids:
        val = bonuses_cfg["kev_listed"]
        total += val
        applied.append({"name": "kev_listed", "score": val})

    return (total, applied)


def compute_defense_score(
    cve: dict, kev_ids: set[str], config: dict
) -> tuple[float, str, dict]:
    """Compute additive defense score with priority label and full breakdown."""
    comp_score, comp_name = _match_component_score(
        cve.get("component"), config["component_scores"]
    )
    cwe_score, cwe_desc = _match_cwe_weight(
        cve.get("cwe_id"), config["cwe_weights"]
    )
    impact_score, impact_key = _match_impact_weight(
        cve.get("impact"), config["impact_weights"]
    )
    av_score, av_label = _match_attack_vector(cve.get("av"), config)
    pr_score, pr_label = _match_privileges(cve.get("pr"), config)
    ui_score, ui_label = _match_user_interaction(cve.get("ui"), config)

    base = comp_score + cwe_score + impact_score + av_score + pr_score + ui_score
    bonus_total, applied_bonuses = _apply_bonuses(cve, kev_ids, config["bonuses"])
    total = float(base + bonus_total)
    priority = _determine_priority(total, config["priority_thresholds"])

    breakdown = {
        "component": {"name": comp_name, "score": comp_score},
        "cwe": {"id": cve.get("cwe_id", ""), "description": cwe_desc, "score": cwe_score},
        "impact": {"type": impact_key, "score": impact_score},
        "attack_vector": {"value": av_label, "score": av_score},
        "privileges": {"value": pr_label, "score": pr_score},
        "user_interaction": {"value": ui_label, "score": ui_score},
        "bonuses": applied_bonuses,
        "total": total,
        "priority": priority,
    }

    return (total, priority, breakdown)


def is_ignored(component: str | None, ignore_list: list[str]) -> bool:
    """Return True if component matches any entry in the ignore list."""
    if component is None:
        return False
    comp_lower = component.lower()
    return any(entry.lower() in comp_lower for entry in ignore_list)


def _match_vr_component(
    component: str | None,
    title: str | None,
    vr_config: dict,
) -> tuple[int, str]:
    """Match component against VR scoring config, checking both component and title fields."""
    combined = f"{component or ''} {title or ''}".lower()
    best_score = 0
    best_name = ""
    for name, score in vr_config["components"].items():
        if name.lower() in combined and score > best_score:
            best_score = score
            best_name = name
    if best_score > 0:
        return (best_score, best_name)
    for cat, score in vr_config["catchall_categories"].items():
        if cat.lower() in combined and score > best_score:
            best_score = score
            best_name = cat
    if best_score > 0:
        return (best_score, best_name)
    return (vr_config["default_component_score"], "")


def _match_vr_vector(
    value: str | None, weights: dict,
) -> tuple[int, str]:
    """Match a single-letter CVSS metric against VR weight dict."""
    if not value:
        return (0, "")
    key = value.strip().upper()[:1]
    if key in weights:
        return (weights[key], key)
    return (0, "")


def _apply_vr_bonuses(
    cve: dict, bonuses_cfg: dict,
) -> tuple[int, list[dict[str, int | str]], list[dict[str, int | str]]]:
    """Return (total, bonuses_list, penalties_list) for VR situational modifiers."""
    total = 0
    bonuses: list[dict[str, int | str]] = []
    penalties: list[dict[str, int | str]] = []
    if cve.get("customer_action"):
        val = bonuses_cfg["customer_action_required"]
        total += val
        bonuses.append({"name": "customer_action_required", "score": val})
    if cve.get("exploited_wild"):
        val = bonuses_cfg["exploit_active"]
        total += val
        penalties.append({"name": "exploit_active", "score": val})
    elif cve.get("publicly_disclosed"):
        val = bonuses_cfg["publicly_disclosed"]
        total += val
        penalties.append({"name": "publicly_disclosed", "score": val})
    else:
        val = bonuses_cfg["exploit_unproven"]
        total += val
        bonuses.append({"name": "exploit_unproven", "score": val})
    severity = (cve.get("severity") or "").strip()
    if severity == "Critical":
        val = bonuses_cfg["critical_severity"]
        total += val
        bonuses.append({"name": "critical_severity", "score": val})
    elif severity == "Important":
        val = bonuses_cfg["important_severity"]
        total += val
        bonuses.append({"name": "important_severity", "score": val})
    if (cve.get("scope") or "").lower() == "changed":
        val = bonuses_cfg["scope_changed"]
        total += val
        bonuses.append({"name": "scope_changed", "score": val})
    return (total, bonuses, penalties)


def _determine_vr_priority(score: float, thresholds: dict) -> str:
    """Map VR score to 5-tier priority: PRIME/HIGH/MEDIUM/LOW/NOISE."""
    if score >= thresholds["PRIME"]:
        return "PRIME"
    if score >= thresholds["HIGH"]:
        return "HIGH"
    if score >= thresholds["MEDIUM"]:
        return "MEDIUM"
    if score >= thresholds["LOW"]:
        return "LOW"
    return "NOISE"


def compute_vr_score(
    cve: dict, kev_ids: set[str], config: dict,
) -> tuple[float, str, dict]:
    """Compute VR research interest score with priority and breakdown."""
    vr = config["vr_scoring"]
    comp_score, comp_name = _match_vr_component(
        cve.get("component"), cve.get("title"), vr,
    )
    cwe_score, cwe_desc = _match_cwe_weight(
        cve.get("cwe_id"), vr["cwe_weights"],
    )
    impact_score, impact_key = _match_impact_weight(
        cve.get("impact"), vr["impact_weights"],
    )
    av_score, av_label = _match_vr_vector(cve.get("av"), vr["attack_vector_weights"])
    pr_score, pr_label = _match_vr_vector(cve.get("pr"), vr["privileges_required_weights"])
    ui_score, ui_label = _match_vr_vector(cve.get("ui"), vr["user_interaction_weights"])

    base = comp_score + cwe_score + impact_score + av_score + pr_score + ui_score
    bonus_total, applied_bonuses, applied_penalties = _apply_vr_bonuses(
        cve, vr["bonuses"],
    )
    total = float(base + bonus_total)
    priority = _determine_vr_priority(total, vr["thresholds"])

    breakdown = {
        "component": {"name": comp_name, "score": comp_score},
        "cwe": {"id": cve.get("cwe_id", ""), "description": cwe_desc, "score": cwe_score},
        "impact": {"type": impact_key, "score": impact_score},
        "attack_vector": {"value": av_label, "score": av_score},
        "privileges": {"value": pr_label, "score": pr_score},
        "user_interaction": {"value": ui_label, "score": ui_score},
        "bonuses": applied_bonuses,
        "penalties": applied_penalties,
        "total": total,
        "priority": priority,
    }

    return (total, priority, breakdown)


def generate_vr_tags(
    cve: dict, kev_ids: set[str], config: dict,
) -> list[str]:
    """Generate sorted list of VR research tags from CVE attributes."""
    rules = config["vr_scoring"]["tag_rules"]
    tags: list[str] = []
    combined = f"{cve.get('component') or ''} {cve.get('title') or ''}".lower()

    if cve.get("cwe_id") in rules["mem_corrupt"]["cwe_ids"]:
        tags.append("mem_corrupt")
    if any(p.lower() in combined for p in rules["kernel"]["component_patterns"]):
        tags.append("kernel")
    if (cve.get("av") or "").upper() == "N" and (cve.get("pr") or "").upper() == "N":
        tags.append("remote_preauth")
    if (cve.get("scope") or "").lower() == "changed":
        tags.append("scope_change")
    if (
        not cve.get("exploited_wild")
        and not cve.get("publicly_disclosed")
        and cve.get("cve_id", "") not in kev_ids
    ):
        tags.append("novel")
    if cve.get("has_kb_entries"):
        tags.append("patchable")
    if cve.get("impact") in rules["high_impact"]["impact_values"]:
        tags.append("high_impact")
    if cve.get("impact") in rules["info_leak"]["impact_values"]:
        tags.append("info_leak")

    return sorted(tags)


def score_all(conn: sqlite3.Connection, config_path: str | Path) -> int:
    """Re-score all msrc_cve rows with defense and VR scores, then batch-update."""
    config = load_scoring_config(config_path)
    kev_ids = db.get_kev_cve_ids(conn)
    cve_ids_with_kb = db.get_cve_ids_with_kb(conn)
    rows = db.get_all_msrc_cves(conn)

    scores: list[tuple[str, float, str, float, str, str]] = []
    for cve in rows:
        total, priority, _ = compute_defense_score(cve, kev_ids, config)
        cve["has_kb_entries"] = cve["cve_id"] in cve_ids_with_kb
        vr_total, vr_priority, _ = compute_vr_score(cve, kev_ids, config)
        vr_tags = generate_vr_tags(cve, kev_ids, config)
        scores.append((
            cve["cve_id"], total, priority,
            vr_total, vr_priority, json.dumps(vr_tags),
        ))

    db.update_msrc_cve_vr_scores(conn, scores)
    logger.info("Scored %d CVEs", len(scores))
    return len(scores)
