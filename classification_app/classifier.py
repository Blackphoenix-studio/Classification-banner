import fnmatch
import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path

from .levels import Level
from .store import Store

_MARKINGS = (
    (Level.TOP_SECRET, re.compile(rb"(?<![A-Z0-9])TOP[ \t_-]+SECRET(?![A-Z0-9])")),
    (Level.SECRET, re.compile(rb"(?<![A-Z0-9])SECRET(?![A-Z0-9])")),
    (Level.CONFIDENTIAL, re.compile(rb"(?<![A-Z0-9])CONFIDENTIAL(?![A-Z0-9])")),
    (Level.UNCLASS, re.compile(rb"(?<![A-Z0-9])UNCLASSIFIED(?![A-Z0-9])")),
)
_CHUNK_SIZE = 1024 * 1024
_SCAN_HEAD = 4 * 1024 * 1024
_SCAN_TAIL = 1024 * 1024


@dataclass(frozen=True)
class Classification:
    path: str
    sha256: str
    level: Level
    evidence: tuple[str, ...]


def _scan_markings(path: Path) -> tuple[Level | None, list[str]]:
    size = path.stat().st_size
    with path.open("rb") as stream:
        head = stream.read(_SCAN_HEAD)
        tail = b""
        if size > _SCAN_HEAD:
            stream.seek(max(_SCAN_HEAD, size - _SCAN_TAIL))
            tail = stream.read(_SCAN_TAIL)

    content = (head + b"\n" + tail).upper()
    utf16_upper = b"\n".join(
        part.decode("utf-16-le", errors="ignore").upper().encode("ascii", errors="ignore")
        for part in (head, tail)
    )
    found: list[tuple[Level, str]] = []
    for level, pattern in _MARKINGS:
        if pattern.search(content):
            found.append((level, f"content:{level.name.lower()}"))
            continue
        if pattern.search(utf16_upper):
            found.append((level, f"content:utf16-{level.name.lower()}"))

    if not found:
        return None, []
    return max(level for level, _ in found), [evidence for _, evidence in found]


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(_CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def classify_file(filename: str | os.PathLike[str], store: Store) -> Classification:
    path = Path(filename).expanduser().resolve(strict=True)
    if not path.is_file():
        raise ValueError(f"Not a regular file: {path}")
    digest = hash_file(path)
    candidates: list[tuple[Level, str]] = []
    known = store.file_level(digest)
    if known is not None:
        candidates.append((Level(known), "database:sha256"))

    normalized = os.path.normcase(str(path)).replace("\\", "/")
    for pattern, level in store.path_levels():
        if fnmatch.fnmatchcase(normalized, pattern.lower().replace("\\", "/")):
            candidates.append((Level(level), f"database:path:{pattern}"))

    marking, evidence = _scan_markings(path)
    if marking is not None:
        candidates.extend((marking, item) for item in evidence)

    if candidates:
        level = max(item[0] for item in candidates)
        reasons = tuple(item[1] for item in candidates if item[0] == level)
    else:
        level = Level.CONFIDENTIAL
        reasons = ("default:unknown-file-fails-closed",)
    return Classification(str(path), digest, level, reasons)
