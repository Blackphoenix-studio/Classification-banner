import hashlib
import hmac
import ipaddress
import json
import re
from pathlib import Path

from .levels import parse_level
from .store import Store

_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_MAX_UPDATE_BYTES = 20 * 1024 * 1024
_MAX_ENTRIES = 100_000


def _canonical(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def apply_signed_update(filename: str, store: Store, key: str) -> int:
    raw = Path(filename).read_bytes()
    if len(raw) > _MAX_UPDATE_BYTES:
        raise ValueError("Update file exceeds 20 MiB")
    package = json.loads(raw)
    if not isinstance(package, dict) or set(package) != {"payload", "signature"}:
        raise ValueError("Update must contain only payload and signature")
    payload = package["payload"]
    signature = package["signature"]
    if not isinstance(payload, dict) or not isinstance(signature, str):
        raise ValueError("Invalid update package")
    if len(key) < 32:
        raise ValueError("CLS_UPDATE_KEY must contain at least 32 characters")
    expected = hmac.new(key.encode(), _canonical(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature.lower()):
        raise ValueError("Invalid update signature")

    if set(payload) != {"version", "file_hashes", "path_rules", "network_rules"}:
        raise ValueError("Unsupported update payload fields")
    version = payload["version"]
    if not isinstance(version, int) or version < 1:
        raise ValueError("Update version must be a positive integer")
    current_version = int(store.get_state("rules_version") or "0")
    if version <= current_version:
        raise ValueError("Update version must be newer than the installed version")

    hashes = payload["file_hashes"]
    paths = payload["path_rules"]
    networks = payload["network_rules"]
    if not all(isinstance(value, list) for value in (hashes, paths, networks)):
        raise ValueError("Rule collections must be lists")
    if sum(map(len, (hashes, paths, networks))) > _MAX_ENTRIES:
        raise ValueError("Update contains too many rules")

    parsed_hashes: list[tuple[str, int]] = []
    for item in hashes:
        if not isinstance(item, dict) or set(item) != {"sha256", "level"}:
            raise ValueError("Invalid file hash rule")
        digest = item["sha256"]
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise ValueError("File hash must be a SHA-256 hex digest")
        parsed_hashes.append((digest.lower(), int(parse_level(item["level"]))))

    parsed_paths: list[tuple[str, int]] = []
    for item in paths:
        if not isinstance(item, dict) or set(item) != {"pattern", "level"}:
            raise ValueError("Invalid path rule")
        pattern = item["pattern"]
        if not isinstance(pattern, str) or not 1 <= len(pattern) <= 1024:
            raise ValueError("Path rule pattern must be 1-1024 characters")
        if any(ord(char) < 32 for char in pattern):
            raise ValueError("Path rule contains control characters")
        parsed_paths.append((pattern.lower(), int(parse_level(item["level"]))))

    parsed_networks: list[tuple[str, str]] = []
    for item in networks:
        if not isinstance(item, dict) or set(item) != {"cidr", "action"}:
            raise ValueError("Invalid network rule")
        network = str(ipaddress.ip_network(item["cidr"], strict=False))
        action = item["action"]
        if action not in ("allow", "deny"):
            raise ValueError("Network action must be allow or deny")
        parsed_networks.append((network, action))

    store.replace_rules(version, parsed_hashes, parsed_paths, parsed_networks)
    return version
