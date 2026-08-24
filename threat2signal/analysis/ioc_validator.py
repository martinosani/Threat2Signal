"""IOC format validation and allowlist checking."""
import ipaddress
import logging
import re
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

import yaml

logger = logging.getLogger(__name__)

# ccTLDs where the registerable domain is third-level (e.g. example.co.uk).
# Includes the ccTLDs present in the advisory corpus (com.ua, gov.au, ac.jp, ...).
_CC_SECOND_LEVEL = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "ad.jp",
    "co.kr", "or.kr",
    "co.nz", "org.nz",
    "co.za", "org.za",
    "co.in", "org.in",
    "com.au", "org.au", "net.au", "gov.au", "edu.au", "asn.au", "id.au",
    "com.ua", "org.ua", "net.ua", "gov.ua", "edu.ua",
    "com.br", "org.br", "net.br", "gov.br",
    "com.cn", "org.cn", "net.cn", "gov.cn",
    "com.mx", "org.mx",
    "com.tw", "org.tw",
    "com.sg", "org.sg",
    "com.tr", "org.tr", "gov.tr",
})

_HASH_PATTERNS: dict[str, int] = {
    "md5": 32,
    "sha1": 40,
    "sha256": 64,
    "sha512": 128,
}

_SSDEEP_RE = re.compile(r"^\d+:[A-Za-z0-9/+]+:[A-Za-z0-9/+]+$")

# A single DNS label: 1-63 chars, alnum plus hyphen, no leading/trailing hyphen.
_DOMAIN_LABEL_RE = re.compile(r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)$")


def validate_ioc(ioc_type: str, value: str) -> tuple[str, bool]:
    """Validate an IOC and return (validation_status, needs_review)."""
    ioc_type = ioc_type.lower().strip()
    value = value.strip()

    result = _check_format(ioc_type, value)
    if result is not None:
        return result

    if _check_allowlisted(ioc_type, value):
        return ("allowlisted", True)

    # SHA-256 ambiguity: DESIGN Stage 1 flags 64-char hex for human review
    # (documented decision; see report note re: qTox-length premise).
    # filepath IOCs are high false-positive risk (WS-8 B.1) and always need review.
    # mutex IOCs are context-inferred, never format-verified (WS-8 B.2), so they
    # always need review too.
    needs_review = ioc_type in (
        "sha256", "filepath", "mutex", "filename", "command_line",
    )
    return ("verified", needs_review)


def _check_format(ioc_type: str, value: str) -> tuple[str, bool] | None:
    """Return (status, needs_review) if format invalid, else None."""
    # Invalid IOCs always need human review (DESIGN Stage 4).
    if ioc_type in _HASH_PATTERNS:
        # Hashes are case-insensitive hex; normalize before length/charset check.
        if not _validate_hash(value.lower(), _HASH_PATTERNS[ioc_type]):
            return ("invalid", True)
        return None

    if ioc_type == "ssdeep":
        if not _SSDEEP_RE.match(value):
            return ("invalid", True)
        return None

    if ioc_type == "ip":
        return _validate_ip(value)

    if ioc_type == "domain":
        if not _validate_domain(value):
            return ("invalid", True)
        return None

    if ioc_type == "url":
        if not value.startswith(("http://", "https://")):
            return ("invalid", True)
        return None

    if ioc_type == "email":
        if "@" not in value or not value.split("@")[0] or not value.split("@")[1]:
            return ("invalid", True)
        return None

    if ioc_type == "filepath":
        if not _validate_filepath(value):
            return ("invalid", True)
        return None

    if ioc_type == "mutex":
        if not value or len(value) > 1024:
            return ("invalid", True)
        return None

    if ioc_type == "filename":
        if not value or "\0" in value or len(value) > 256:
            return ("invalid", True)
        return None

    if ioc_type == "registry_key":
        if not _validate_registry_key(value):
            return ("invalid", True)
        return None

    if ioc_type == "command_line":
        if not value or len(value) > 4096:
            return ("invalid", True)
        return None

    if ioc_type in ("user_agent", "service_name", "scheduled_task"):
        if not value or len(value) > 1024:
            return ("invalid", True)
        return None

    logger.warning("Unknown IOC type %r for value %r", ioc_type, value)
    return ("pending", True)


def _validate_hash(value: str, expected_length: int) -> bool:
    """Check that value is hex of the expected length (caller lowercases)."""
    if len(value) != expected_length:
        return False
    return re.fullmatch(r"[a-f0-9]+", value) is not None


_REGISTRY_HIVE_PREFIXES = (
    "HKLM\\", "HKCU\\", "HKCR\\", "HKU\\", "HKCC\\",
    "HKEY_LOCAL_MACHINE\\", "HKEY_CURRENT_USER\\",
    "HKEY_CLASSES_ROOT\\", "HKEY_USERS\\",
    "HKEY_CURRENT_CONFIG\\",
)


def _validate_registry_key(value: str) -> bool:
    """Check registry key starts with a valid hive prefix (case-insensitive)."""
    if not value or len(value) > 1024:
        return False
    upper = value.upper()
    return any(upper.startswith(p) for p in _REGISTRY_HIVE_PREFIXES)


def _validate_filepath(value: str) -> bool:
    """Check filepath is non-empty, has no null bytes, is a sane length, and
    contains a path separator (rejects bare tokens with no path structure)."""
    if not value or "\0" in value:
        return False
    if len(value) >= 1024:
        return False
    return "/" in value or "\\" in value


def _validate_ip(value: str) -> tuple[str, bool] | None:
    """Parse IP and reject private ranges; return tuple if invalid, else None."""
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return ("invalid", True)

    if _is_private_ip(addr):
        return ("invalid", True)

    return None


def _is_private_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if address is private, loopback, link-local, reserved, or multicast."""
    return (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_reserved or addr.is_multicast)


def _validate_domain(value: str) -> bool:
    """Check domain has 2+ valid labels, a valid TLD, and total length <=253."""
    # Strip wildcard prefix for validation
    domain = value.lstrip("*.")
    if not domain or len(domain) > 253:
        return False
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    if not all(_DOMAIN_LABEL_RE.match(label) for label in labels):
        return False
    # TLD must be alphabetic or punycode (xn--...). isalpha rejected IDN before.
    tld = labels[-1].lower()
    return tld.isalpha() or tld.startswith("xn--")


def _extract_registerable_domain(domain: str) -> str:
    """Get TLD+1 for allowlist matching (handles ccTLDs like co.uk)."""
    domain = domain.lstrip("*.")
    labels = domain.split(".")
    if len(labels) <= 2:
        return domain.lower()

    # Check if last two labels form a known ccTLD second-level
    candidate = f"{labels[-2]}.{labels[-1]}"
    if candidate.lower() in _CC_SECOND_LEVEL and len(labels) >= 3:
        return ".".join(labels[-3:]).lower()

    return ".".join(labels[-2:]).lower()


@lru_cache(maxsize=1)
def _load_allowlist() -> dict:
    """Load the IOC allowlist from config/ioc_allowlist.yaml (cached once).

    Cached via lru_cache rather than a module-global so there is no mutable
    module state (CODING.md). Config is read-only and load-once per process.
    """
    allowlist_path = (
        Path(__file__).resolve().parents[2] / "config" / "ioc_allowlist.yaml"
    )
    try:
        with open(allowlist_path) as f:
            # Empty YAML file -> safe_load returns None; coerce to empty dict.
            return yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError) as exc:
        logger.error("Failed to load allowlist from %s: %s", allowlist_path, exc)
        return {"domains": [], "ips": [], "hashes": []}


def _check_allowlisted(ioc_type: str, value: str) -> bool:
    """Check if the IOC matches any entry in the allowlist."""
    allowlist = _load_allowlist()

    if ioc_type == "domain":
        reg_domain = _extract_registerable_domain(value)
        return reg_domain in allowlist.get("domains", [])

    if ioc_type == "url":
        return _url_domain_allowlisted(value, allowlist)

    if ioc_type == "ip":
        return value in allowlist.get("ips", [])

    if ioc_type in _HASH_PATTERNS or ioc_type == "ssdeep":
        return value.lower() in allowlist.get("hashes", [])

    return False


def _url_domain_allowlisted(url: str, allowlist: dict) -> bool:
    """Extract domain from URL and check against domain allowlist."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
    except ValueError:
        return False
    reg_domain = _extract_registerable_domain(hostname)
    return reg_domain in allowlist.get("domains", [])


def refang_value(value: str) -> str:
    """Reverse common defanging in an IOC value for search normalization."""
    value = value.replace("[.]", ".").replace("(.)", ".")
    value = value.replace("[:]", ":").replace("(:)", ":")
    value = value.replace("[@]", "@")
    value = re.sub(r"\[dot\]", ".", value, flags=re.I)
    value = re.sub(
        r"hxxps?://",
        lambda m: "https://" if "s" in m.group().lower() else "http://",
        value,
        flags=re.I,
    )
    value = re.sub(r"^(https?)//", r"\1://", value, flags=re.I)
    return value.strip()


def detect_ioc_type(value: str) -> str | None:
    """Auto-detect IOC type from value format."""
    v = value.strip()
    if re.fullmatch(r"[a-f0-9]{128}", v, re.I):
        return "sha512"
    if re.fullmatch(r"[a-f0-9]{64}", v, re.I):
        return "sha256"
    if re.fullmatch(r"[a-f0-9]{40}", v, re.I):
        return "sha1"
    if re.fullmatch(r"[a-f0-9]{32}", v, re.I):
        return "md5"
    if _SSDEEP_RE.match(v):
        return "ssdeep"
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if "@" in v and v.split("@")[0] and v.split("@")[1]:
        return "email"
    if v.startswith(("http://", "https://")):
        return "url"
    if _validate_domain(v):
        return "domain"
    return None
