"""Shared test fixtures for Threat2Signal."""

import os
import shutil
import tempfile

import pytest
import yaml

from threat2signal.storage.db import get_connection, init_schema


@pytest.fixture
def db_conn():
    """In-memory SQLite connection with full schema applied."""
    conn = get_connection(":memory:")
    init_schema(conn)
    yield conn
    conn.close()


@pytest.fixture
def tmp_config_dir():
    """Temporary directory populated with valid config YAML files."""
    dirpath = tempfile.mkdtemp(prefix="t2s_test_config_")

    settings = {
        "deepseek": {
            "api_key": "test-key-not-real",
            "base_url": "https://api.deepseek.com",
            "model": "deepseek-chat",
            "max_retries": 3,
        },
        "database": {
            "path": "data/threat2signal.db",
        },
        "neo4j": {
            "uri": "bolt://localhost:7687",
            "user": "neo4j",
            "password": "test-password",
            "database": "neo4j",
        },
        "http": {
            "connect_timeout": 30,
            "read_timeout": 60,
        },
    }

    scoring = {
        "component_scores": {
            "Windows Kernel": 38,
            "Win32k": 35,
        },
        "cwe_weights": {
            "CWE-122": 22,
        },
        "impact_weights": {
            "Remote Code Execution": 18,
        },
        "priority_thresholds": {
            "HIGH": 80,
            "MEDIUM": 45,
            "LOW": 15,
        },
    }

    ioc_allowlist = {
        "domains": [
            "microsoft.com",
            "google.com",
            "cisa.gov",
        ],
        "ips": [
            "8.8.8.8",
            "1.1.1.1",
        ],
        "hashes": [],
    }

    for filename, data in [
        ("settings.yaml", settings),
        ("scoring.yaml", scoring),
        ("ioc_allowlist.yaml", ioc_allowlist),
    ]:
        filepath = os.path.join(dirpath, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            yaml.dump(data, f)

    yield dirpath

    shutil.rmtree(dirpath, ignore_errors=True)
