#!/usr/bin/env python3
"""
DOMINION - Subprocess Runner
Handles all external tool execution with timeout, error capture, and logging.
"""

import shlex
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

from core.logger import get_logger


def run(
    cmd: str | List[str],
    output_file: Optional[Path] = None,
    timeout: int = 600,
    env: Optional[dict] = None,
    shell: bool = False,
    silent: bool = False,
) -> Tuple[int, str, str]:
    """
    Run an external command.

    Returns:
        (returncode, stdout, stderr)
    """
    log = get_logger()

    if isinstance(cmd, str):
        cmd_str = cmd
        cmd_list = shlex.split(cmd)
    else:
        cmd_str = " ".join(str(c) for c in cmd)
        cmd_list = [str(c) for c in cmd]

    log.command(cmd_str)

    try:
        result = subprocess.run(
            cmd_list if not shell else cmd_str,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            shell=shell,
        )
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        rc     = result.returncode

        if output_file and stdout:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(stdout, encoding="utf-8")

        if rc != 0 and not silent:
            log.debug(f"Command exit {rc}: {stderr[:300]}")

        return rc, stdout, stderr

    except subprocess.TimeoutExpired:
        log.warning(f"Command timed out after {timeout}s: {cmd_str[:80]}...")
        return -1, "", "TIMEOUT"

    except FileNotFoundError:
        tool = cmd_list[0]
        log.error(f"Tool not found: [bold]{tool}[/bold] — run install.sh first")
        return -1, "", f"NOT_FOUND:{tool}"

    except Exception as exc:
        log.error(f"Unexpected error running '{cmd_str[:60]}': {exc}")
        return -1, "", str(exc)


def tool_exists(name: str) -> bool:
    """Check if a tool is available on PATH."""
    import shutil
    return shutil.which(name) is not None


def require_tool(name: str) -> bool:
    """Warn if a tool is missing; return True if present."""
    if not tool_exists(name):
        get_logger().warning(f"Tool [bold]{name}[/bold] not found — skipping related checks")
        return False
    return True


def run_lines(
    cmd: str | List[str],
    timeout: int = 600,
    env: Optional[dict] = None,
) -> List[str]:
    """Run command and return stdout as a list of non-empty lines."""
    _, stdout, _ = run(cmd, timeout=timeout, env=env, silent=True)
    return [line for line in stdout.splitlines() if line.strip()]
