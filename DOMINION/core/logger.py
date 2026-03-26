#!/usr/bin/env python3
"""
DOMINION - Logger Module
Colored, structured logging with Rich
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

# ── Custom theme ──────────────────────────────────────────────────────────────
DOMINION_THEME = Theme(
    {
        "info":     "bold cyan",
        "warning":  "bold yellow",
        "error":    "bold red",
        "success":  "bold green",
        "critical": "bold white on red",
        "phase":    "bold magenta",
        "found":    "bold bright_green",
        "dim":      "dim white",
    }
)

console = Console(theme=DOMINION_THEME)


class DominionLogger:
    """Central logger for the DOMINION framework."""

    def __init__(self, domain: str, output_dir: Path, verbose: bool = False):
        self.domain     = domain
        self.output_dir = output_dir
        self.verbose    = verbose
        self._setup_file_logger()

    def _setup_file_logger(self) -> None:
        log_path = self.output_dir / "dominion.log"
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s %(levelname)-8s %(message)s",
            handlers=[
                logging.FileHandler(log_path, encoding="utf-8"),
                RichHandler(console=console, show_path=False, show_time=False),
            ],
        )
        self._logger = logging.getLogger("DOMINION")

    # ── Public helpers ────────────────────────────────────────────────────────

    def info(self, msg: str) -> None:
        console.print(f"[info][*][/info] {msg}")
        self._logger.info(msg)

    def success(self, msg: str) -> None:
        console.print(f"[success][+][/success] {msg}")
        self._logger.info(f"SUCCESS: {msg}")

    def warning(self, msg: str) -> None:
        console.print(f"[warning][!][/warning] {msg}")
        self._logger.warning(msg)

    def error(self, msg: str) -> None:
        console.print(f"[error][✗][/error] {msg}")
        self._logger.error(msg)

    def phase(self, num: int, name: str) -> None:
        console.print(f"\n[phase]══════ PHASE {num:02d}: {name} ══════[/phase]\n")
        self._logger.info(f"--- PHASE {num:02d}: {name} ---")

    def found(self, item: str, value: str = "") -> None:
        suffix = f" [dim]→[/dim] [found]{value}[/found]" if value else ""
        console.print(f"  [found]►[/found] {item}{suffix}")
        self._logger.info(f"FOUND: {item} {value}")

    def debug(self, msg: str) -> None:
        if self.verbose:
            console.print(f"[dim][~] {msg}[/dim]")
        self._logger.debug(msg)

    def command(self, cmd: str) -> None:
        if self.verbose:
            console.print(f"[dim]  $ {cmd}[/dim]")
        self._logger.debug(f"CMD: {cmd}")


# ── Singleton-like factory ────────────────────────────────────────────────────
_logger_instance: Optional[DominionLogger] = None


def get_logger() -> DominionLogger:
    if _logger_instance is None:
        raise RuntimeError("Logger not initialized. Call init_logger() first.")
    return _logger_instance


def init_logger(domain: str, output_dir: Path, verbose: bool = False) -> DominionLogger:
    global _logger_instance
    _logger_instance = DominionLogger(domain, output_dir, verbose)
    return _logger_instance
