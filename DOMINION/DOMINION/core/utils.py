#!/usr/bin/env python3
"""
DOMINION - Utility Functions
Dedup, merge, rate limiting, formatting, file helpers, HTTP helpers.
"""

import hashlib
import ipaddress
import json
import re
import time
from pathlib import Path
from typing import Any, Iterable, List, Optional, Set
from urllib.parse import urlparse

import requests


# ── Deduplication ─────────────────────────────────────────────────────────────

def dedup(items: Iterable[str]) -> List[str]:
    """Return sorted unique non-empty items."""
    return sorted(set(i.strip() for i in items if i.strip()))


def merge_lists(*lists: List[str]) -> List[str]:
    """Merge and deduplicate multiple lists."""
    combined: Set[str] = set()
    for lst in lists:
        combined.update(lst)
    return sorted(combined)


# ── File helpers ──────────────────────────────────────────────────────────────

def read_lines(path: Path) -> List[str]:
    """Read a file and return non-empty stripped lines."""
    if not path.exists():
        return []
    return [l.strip() for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def write_lines(path: Path, lines: Iterable[str]) -> int:
    """Write lines to a file. Returns count written."""
    unique = dedup(lines)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(unique) + "\n", encoding="utf-8")
    return len(unique)


def save_json(path: Path, data: Any, indent: int = 2) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=indent, default=str), encoding="utf-8")


def load_json(path: Path) -> Any:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def append_line(path: Path, line: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(line.strip() + "\n")


# ── URL / domain helpers ──────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def extract_domain(url: str) -> str:
    try:
        return urlparse(normalize_url(url)).netloc
    except Exception:
        return url


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_valid_domain(domain: str) -> bool:
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain))


def strip_wildcard(domain: str) -> str:
    return domain.lstrip("*.").strip()


# ── HTTP helpers ──────────────────────────────────────────────────────────────

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
}


def http_get(
    url: str,
    headers: Optional[dict] = None,
    timeout: int = 15,
    allow_redirects: bool = True,
    verify: bool = False,
) -> Optional[requests.Response]:
    try:
        h = {**DEFAULT_HEADERS, **(headers or {})}
        return requests.get(url, headers=h, timeout=timeout,
                            allow_redirects=allow_redirects, verify=verify)
    except Exception:
        return None


# ── Rate limiter ──────────────────────────────────────────────────────────────

class RateLimiter:
    """Simple token-bucket rate limiter."""

    def __init__(self, calls_per_second: float = 2.0):
        self._interval = 1.0 / calls_per_second
        self._last = 0.0

    def wait(self) -> None:
        now = time.monotonic()
        diff = self._interval - (now - self._last)
        if diff > 0:
            time.sleep(diff)
        self._last = time.monotonic()


# ── Misc ──────────────────────────────────────────────────────────────────────

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def human_count(n: int) -> str:
    if n >= 1_000_000:
        return f"{n/1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n/1_000:.1f}K"
    return str(n)


def elapsed(start: float) -> str:
    s = int(time.monotonic() - start)
    m, s = divmod(s, 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"
