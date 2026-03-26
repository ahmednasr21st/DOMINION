#!/usr/bin/env python3
"""
DOMINION - Ultra-Powered Domain Recon Framework
Main CLI Entry Point
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

# Ensure repo root on sys.path
ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from core.banner import print_banner, print_phase_banner, print_phase_done, print_summary_box
from core.config import load_config
from core.logger import init_logger, get_logger
from core.utils  import is_valid_domain, elapsed, save_json, load_json

# ── Phase registry ────────────────────────────────────────────────────────────
from phases import (
    p01_passive, p02_subdomains, p03_dns, p04_live_hosts,
    p05_ports, p06_crawling, p07_secrets, p08_vulns,
    p09_content, p10_cloud, p11_reporting, p12_ai_summary,
)

PHASES = [
    (1,  "Passive Recon",            p01_passive.PHASE_DESC,  p01_passive),
    (2,  "Subdomain Enumeration",    p02_subdomains.PHASE_DESC, p02_subdomains),
    (3,  "DNS Deep Dive",            p03_dns.PHASE_DESC,       p03_dns),
    (4,  "Live Host Discovery",      p04_live_hosts.PHASE_DESC, p04_live_hosts),
    (5,  "Port Scanning",            p05_ports.PHASE_DESC,     p05_ports),
    (6,  "Web Crawling",             p06_crawling.PHASE_DESC,  p06_crawling),
    (7,  "Secret Detection",         p07_secrets.PHASE_DESC,   p07_secrets),
    (8,  "Vulnerability Scanning",   p08_vulns.PHASE_DESC,     p08_vulns),
    (9,  "Content Discovery",        p09_content.PHASE_DESC,   p09_content),
    (10, "Cloud & Infrastructure",   p10_cloud.PHASE_DESC,     p10_cloud),
    (11, "Screenshot & Reporting",   p11_reporting.PHASE_DESC, p11_reporting),
    (12, "AI Attack Surface Summary",p12_ai_summary.PHASE_DESC, p12_ai_summary),
]

PHASE_KEYS = ["p01","p02","p03","p04","p05","p06","p07","p08","p09","p10","p11","p12"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="dominion",
        description="DOMINION — Ultra-Powered Domain Recon Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python dominion.py -d example.com
  python dominion.py -d example.com --phase 1-6
  python dominion.py -d example.com --phase 3
  python dominion.py -d example.com --skip 5,10 --verbose
  python dominion.py -d example.com --resume
  python dominion.py -d example.com --output /tmp/myrecon
        """,
    )
    parser.add_argument("-d", "--domain",  required=True,  help="Target domain")
    parser.add_argument("-p", "--phase",   default="all",  help="Phase(s) to run: 'all', '1-6', '3', '1,3,5'")
    parser.add_argument("-s", "--skip",    default="",     help="Phases to skip, comma-separated: '5,10'")
    parser.add_argument("-o", "--output",  default="",     help="Output directory (default: output/{domain})")
    parser.add_argument("-c", "--config",  default=str(ROOT / "config.yml"), help="Config file path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--resume",        action="store_true", help="Resume from last completed phase")
    parser.add_argument("--list-phases",   action="store_true", help="List all phases and exit")
    parser.add_argument("--no-ai",         action="store_true", help="Skip Phase 12 (AI summary)")
    parser.add_argument("--full-ports",    action="store_true", help="Full 1-65535 port scan (slow)")
    parser.add_argument("--notify",        action="store_true", help="Send Telegram notification on completion")
    return parser.parse_args()


def parse_phase_selection(phase_arg: str) -> set:
    """Parse '1-6', '3', '1,3,5', 'all' into a set of phase numbers."""
    if phase_arg.lower() == "all":
        return set(range(1, 13))
    selected = set()
    for part in phase_arg.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            selected.update(range(int(a), int(b) + 1))
        elif part.isdigit():
            selected.add(int(part))
    return selected


def list_phases():
    print("\n  DOMINION — Phase Index\n")
    print(f"  {'#':>3}  {'Name':<30}  Description")
    print("  " + "─" * 70)
    for num, name, desc, _ in PHASES:
        print(f"  {num:>3}  {name:<30}  {desc}")
    print()


def save_state(output_dir: Path, completed: dict) -> None:
    save_json(output_dir / ".dominion_state.json", completed)


def load_state(output_dir: Path) -> dict:
    return load_json(output_dir / ".dominion_state.json")


def send_telegram(token: str, chat_id: str, msg: str) -> None:
    from core.utils import http_get
    try:
        import urllib.parse
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        http_get(f"{url}?chat_id={chat_id}&text={urllib.parse.quote(msg)}&parse_mode=Markdown")
    except Exception:
        pass


def main():
    print_banner()
    args = parse_args()

    if args.list_phases:
        list_phases()
        sys.exit(0)

    # ── Validate domain ───────────────────────────────────────────────────────
    domain = args.domain.lower().strip().lstrip("https://").lstrip("http://").rstrip("/")
    if not is_valid_domain(domain):
        print(f"\n[✗] Invalid domain: '{domain}'\n")
        sys.exit(1)

    # ── Load config ───────────────────────────────────────────────────────────
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"[!] Config file not found: {config_path} — using defaults")
        config_path = ROOT / "config.yml"
    cfg = load_config(config_path)

    # Apply CLI overrides
    if args.full_ports:
        cfg._data.setdefault("settings", {})["full_port_scan"] = True

    # ── Setup output directory ────────────────────────────────────────────────
    output_dir = Path(args.output) if args.output else ROOT / "output" / domain
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Init logger ───────────────────────────────────────────────────────────
    log = init_logger(domain, output_dir, verbose=args.verbose)
    log.info(f"Target: {domain}")
    log.info(f"Output: {output_dir}")

    # ── Determine phases to run ───────────────────────────────────────────────
    selected = parse_phase_selection(args.phase)
    skip     = set(int(x) for x in args.skip.split(",") if x.strip().isdigit())
    skip.update(cfg.skip_phases)
    if args.no_ai:
        skip.add(12)

    phases_to_run = sorted(selected - skip)

    # ── Load resume state ─────────────────────────────────────────────────────
    state         = load_state(output_dir) if args.resume else {}
    completed     = state.get("completed", {})
    all_phase_data = state.get("results", {})

    if args.resume and completed:
        done_nums = sorted(int(k) for k in completed.keys())
        log.info(f"Resuming — already completed: phases {done_nums}")
        phases_to_run = [p for p in phases_to_run if str(p) not in completed]

    log.info(f"Phases to run: {phases_to_run}")
    start_time = time.monotonic()
    findings_count = {}

    # ── Run phases ────────────────────────────────────────────────────────────
    for num, name, desc, module in PHASES:
        if num not in phases_to_run:
            continue

        print_phase_banner(num, name, desc)
        t0 = time.monotonic()

        try:
            # Get previous phase data for context
            prev_key = f"p{num-1:02d}"
            prev_data = all_phase_data.get(prev_key, {})

            # Call phase function
            if num == 1:
                result = module.run(domain, output_dir)
            elif num in [2, 3, 4, 5, 6, 7, 8, 9, 10]:
                result = module.run_phase(domain, output_dir, prev_data)
            elif num == 11:
                result = module.run_phase(domain, output_dir, all_phase_data)
            elif num == 12:
                result = module.run_phase(domain, output_dir, all_phase_data)
            else:
                result = {}

            key = f"p{num:02d}"
            all_phase_data[key] = result
            completed[str(num)] = {
                "name": name,
                "elapsed": elapsed(t0),
                "timestamp": datetime.now().isoformat(),
            }

            # Count findings
            fc = _count_findings(num, result)
            findings_count[name] = fc
            print_phase_done(num, name, fc)

            # Save state after each phase
            save_state(output_dir, {"completed": completed, "results": all_phase_data})

        except KeyboardInterrupt:
            log.warning("Interrupted! Progress saved. Use --resume to continue.")
            save_state(output_dir, {"completed": completed, "results": all_phase_data})
            sys.exit(0)
        except Exception as exc:
            log.error(f"Phase {num} failed: {exc}")
            import traceback
            log.debug(traceback.format_exc())
            continue

    # ── Final summary ─────────────────────────────────────────────────────────
    total_elapsed = elapsed(start_time)
    print_summary_box(domain, len(phases_to_run), findings_count)
    log.success(f"Total elapsed: {total_elapsed}")
    log.info(f"Reports: {output_dir}/report.html")

    # ── Telegram notification ─────────────────────────────────────────────────
    if args.notify and cfg.telegram_token and cfg.telegram_chat_id:
        msg = (
            f"🔥 *DOMINION Complete*\n"
            f"Target: `{domain}`\n"
            f"Time: {total_elapsed}\n"
            f"Phases: {len(phases_to_run)}\n"
            f"Report: `{output_dir}/report.html`"
        )
        send_telegram(cfg.telegram_token, cfg.telegram_chat_id, msg)
        log.success("Telegram notification sent")


def _count_findings(num: int, result: dict) -> int:
    """Count meaningful findings per phase."""
    mapping = {
        1:  lambda r: len(r.get("certificates", [])) + len(r.get("hackertarget", [])),
        2:  lambda r: r.get("total_live", 0),
        3:  lambda r: sum(len(v) for v in r.get("records", {}).values()) + len(r.get("takeover_risks", [])),
        4:  lambda r: len(r.get("live_hosts", [])),
        5:  lambda r: sum(len(v) for v in r.get("open_ports", {}).values()),
        6:  lambda r: len(r.get("urls_crawled", [])),
        7:  lambda r: len(r.get("leaks", [])),
        8:  lambda r: r.get("total_vulns", 0),
        9:  lambda r: len(r.get("found_paths", [])),
        10: lambda r: len(r.get("s3_buckets", [])) + len(r.get("firebase", [])),
        11: lambda r: len(r.get("screenshots", [])),
        12: lambda r: 1 if r.get("ai_response") else 0,
    }
    fn = mapping.get(num)
    if fn:
        try:
            return fn(result)
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    main()
