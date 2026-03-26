#!/usr/bin/env python3
"""
DOMINION - Config Loader
Reads config.yml and provides a typed config object.
"""

import os
from pathlib import Path
from typing import Any, Optional

import yaml


class Config:
    """Central configuration object for DOMINION."""

    def __init__(self, config_path: Path):
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")
        with open(config_path, encoding="utf-8") as f:
            self._data: dict = yaml.safe_load(f) or {}

    # ── Generic getter ────────────────────────────────────────────────────────
    def get(self, *keys: str, default: Any = None) -> Any:
        d = self._data
        for k in keys:
            if not isinstance(d, dict):
                return default
            d = d.get(k, default)
        return d

    # ── API Keys ──────────────────────────────────────────────────────────────
    @property
    def shodan_key(self) -> Optional[str]:
        return self.get("api_keys", "shodan") or os.environ.get("SHODAN_API_KEY")

    @property
    def censys_id(self) -> Optional[str]:
        return self.get("api_keys", "censys_id") or os.environ.get("CENSYS_API_ID")

    @property
    def censys_secret(self) -> Optional[str]:
        return self.get("api_keys", "censys_secret") or os.environ.get("CENSYS_API_SECRET")

    @property
    def virustotal_key(self) -> Optional[str]:
        return self.get("api_keys", "virustotal") or os.environ.get("VT_API_KEY")

    @property
    def securitytrails_key(self) -> Optional[str]:
        return self.get("api_keys", "securitytrails") or os.environ.get("SECURITYTRAILS_KEY")

    @property
    def github_token(self) -> Optional[str]:
        return self.get("api_keys", "github_token") or os.environ.get("GITHUB_TOKEN")

    @property
    def openai_key(self) -> Optional[str]:
        return self.get("api_keys", "openai") or os.environ.get("OPENAI_API_KEY")

    @property
    def hunter_key(self) -> Optional[str]:
        return self.get("api_keys", "hunter") or os.environ.get("HUNTER_API_KEY")

    @property
    def hibp_key(self) -> Optional[str]:
        return self.get("api_keys", "hibp") or os.environ.get("HIBP_API_KEY")

    @property
    def fofa_key(self) -> Optional[str]:
        return self.get("api_keys", "fofa") or os.environ.get("FOFA_KEY")

    @property
    def binaryedge_key(self) -> Optional[str]:
        return self.get("api_keys", "binaryedge") or os.environ.get("BINARYEDGE_KEY")

    @property
    def telegram_token(self) -> Optional[str]:
        return self.get("notifications", "telegram_token") or os.environ.get("TELEGRAM_BOT_TOKEN")

    @property
    def telegram_chat_id(self) -> Optional[str]:
        return self.get("notifications", "telegram_chat_id") or os.environ.get("TELEGRAM_CHAT_ID")

    # ── Scanning settings ─────────────────────────────────────────────────────
    @property
    def threads(self) -> int:
        return int(self.get("settings", "threads", default=50))

    @property
    def timeout(self) -> int:
        return int(self.get("settings", "timeout", default=600))

    @property
    def rate_limit(self) -> int:
        return int(self.get("settings", "rate_limit", default=150))

    @property
    def full_port_scan(self) -> bool:
        return bool(self.get("settings", "full_port_scan", default=False))

    @property
    def nuclei_severity(self) -> str:
        return self.get("settings", "nuclei_severity", default="low,medium,high,critical")

    @property
    def wordlist_subdomains(self) -> str:
        return self.get("wordlists", "subdomains", default="wordlists/subdomains.txt")

    @property
    def wordlist_dirs(self) -> str:
        return self.get("wordlists", "directories", default="wordlists/directories.txt")

    @property
    def wordlist_params(self) -> str:
        return self.get("wordlists", "parameters", default="wordlists/parameters.txt")

    @property
    def skip_phases(self) -> list:
        return self.get("settings", "skip_phases", default=[])

    @property
    def ai_model(self) -> str:
        return self.get("settings", "ai_model", default="gpt-4o")


_config_instance: Optional[Config] = None


def load_config(path: Path) -> Config:
    global _config_instance
    _config_instance = Config(path)
    return _config_instance


def get_config() -> Config:
    if _config_instance is None:
        raise RuntimeError("Config not loaded. Call load_config() first.")
    return _config_instance
