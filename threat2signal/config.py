"""Configuration loading from YAML files."""

import logging
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent

_REQUIRED_SETTINGS_KEYS = [
    "deepseek.api_key",
    "database.path",
    "neo4j.uri",
]


def _load_yaml(file_path: Path) -> dict:
    if not file_path.exists():
        raise FileNotFoundError(f"{file_path}")
    with open(file_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _validate_required_keys(settings: dict, keys: list[str]) -> None:
    """Raise ValueError if any dot-path key is missing from settings."""
    for key_path in keys:
        parts = key_path.split(".")
        current = settings
        for part in parts:
            if not isinstance(current, dict) or part not in current:
                raise ValueError(f"Required setting missing: {key_path}")
            current = current[part]


def load_settings(config_dir: str = "config") -> dict:
    """Load and validate settings.yaml."""
    path = PROJECT_ROOT / config_dir / "settings.yaml"
    if not path.exists():
        raise FileNotFoundError(
            f"settings.yaml not found in {PROJECT_ROOT / config_dir}. "
            "Copy settings.yaml.example to settings.yaml and fill in your API keys."
        )
    settings = _load_yaml(path)
    _validate_required_keys(settings, _REQUIRED_SETTINGS_KEYS)
    logger.info("Loaded settings from %s", path)
    return settings


def load_scoring(config_dir: str = "config") -> dict:
    """Load scoring.yaml."""
    path = PROJECT_ROOT / config_dir / "scoring.yaml"
    result = _load_yaml(path)
    logger.info("Loaded scoring from %s", path)
    return result


def load_ioc_allowlist(config_dir: str = "config") -> dict:
    """Load ioc_allowlist.yaml."""
    path = PROJECT_ROOT / config_dir / "ioc_allowlist.yaml"
    result = _load_yaml(path)
    logger.info("Loaded IOC allowlist from %s", path)
    return result


def validate_auth_config(settings: dict) -> None:
    """Validate the mandatory auth configuration block.

    Raises ValueError if auth config is missing or malformed.
    Called unconditionally at API startup — auth is not optional.
    """
    auth = settings.get("auth")
    if not auth or not isinstance(auth, dict):
        raise ValueError(
            "Required setting missing: auth. "
            "Add an auth block to settings.yaml with secret_key and users. "
            "Run 'python -m threat2signal.cli generate-secret' to create a secret key "
            "and 'python -m threat2signal.cli hash-password' to hash a password."
        )
    if not auth.get("secret_key"):
        raise ValueError(
            "Required setting missing: auth.secret_key. "
            "Run 'python -m threat2signal.cli generate-secret' to create one."
        )
    users = auth.get("users")
    if not users or not isinstance(users, list):
        raise ValueError(
            "Required setting missing: auth.users (must be a non-empty list)"
        )
    seen_usernames: set[str] = set()
    for i, user in enumerate(users):
        if not isinstance(user, dict):
            raise ValueError(f"auth.users[{i}]: must be a dict")
        for field in ("username", "password_hash", "role"):
            if not user.get(field):
                raise ValueError(f"auth.users[{i}]: missing required field '{field}'")
        if "password" in user:
            raise ValueError(
                f"auth.users[{i}]: plaintext 'password' field found. "
                "Use 'password_hash' with a bcrypt hash instead. "
                "Run 'python -m threat2signal.cli hash-password' to generate one."
            )
        ph = user["password_hash"]
        if not isinstance(ph, str) or not ph.startswith(("$2b$", "$2a$")):
            raise ValueError(
                f"auth.users[{i}]: password_hash is not a valid bcrypt hash. "
                "Run 'python -m threat2signal.cli hash-password' to generate one."
            )
        uname = user["username"]
        if uname in seen_usernames:
            raise ValueError(f"auth.users[{i}]: duplicate username '{uname}'")
        seen_usernames.add(uname)
