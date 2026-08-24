"""Tests for threat2signal.config loading functions."""

import os

import pytest
import yaml

from threat2signal.config import load_ioc_allowlist, load_scoring, load_settings


@pytest.mark.unit
def test_load_settings_valid(tmp_config_dir):
    result = load_settings(config_dir=tmp_config_dir)

    assert isinstance(result, dict)
    assert result["deepseek"]["api_key"] == "test-key-not-real"
    assert result["database"]["path"] == "data/threat2signal.db"
    assert result["neo4j"]["uri"] == "bolt://localhost:7687"


@pytest.mark.unit
def test_load_settings_missing_file(tmp_path):
    nonexistent = str(tmp_path / "no_such_config_dir")

    with pytest.raises(FileNotFoundError, match="settings.yaml.example"):
        load_settings(config_dir=nonexistent)


@pytest.mark.unit
def test_load_settings_missing_required_key(tmp_path):
    config_dir = str(tmp_path / "partial_config")
    os.makedirs(config_dir, exist_ok=True)

    incomplete_settings = {
        "database": {
            "path": "data/threat2signal.db",
        },
        "neo4j": {
            "uri": "bolt://localhost:7687",
        },
    }
    with open(os.path.join(config_dir, "settings.yaml"), "w", encoding="utf-8") as f:
        yaml.dump(incomplete_settings, f)

    with pytest.raises(ValueError, match="deepseek.api_key"):
        load_settings(config_dir=config_dir)


@pytest.mark.unit
def test_load_scoring_valid(tmp_config_dir):
    result = load_scoring(config_dir=tmp_config_dir)

    assert isinstance(result, dict)
    assert "component_scores" in result
    assert "priority_thresholds" in result
    assert result["component_scores"]["Windows Kernel"] == 38


@pytest.mark.unit
def test_load_ioc_allowlist_valid(tmp_config_dir):
    result = load_ioc_allowlist(config_dir=tmp_config_dir)

    assert isinstance(result, dict)
    assert "domains" in result
    assert "ips" in result
    assert "hashes" in result
    assert "microsoft.com" in result["domains"]
    assert isinstance(result["hashes"], list)
