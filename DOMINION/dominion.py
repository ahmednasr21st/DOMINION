#!/usr/bin/env python3
"""
DOMINION - Ultra-Powered Domain Recon Framework
Main CLI Entry Point — v4.0 Clean UX
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from core.banner import print_banner, print_phase_banner, print_phase_done, print_summary_box
from core.config import load_config
from core.logger import init_logger, get_logger
from core.utils  import is_valid_domain, elapsed, save_json, load_json, http_get

from phases import (
    p01_passive, p02_subdomains, p03_dns, p04_live_hosts,
    p05_ports, p06_crawling, p07_secrets, p08_vulns,
    p09_content, p10_cloud, p11_reporting, p12_ai_summary,
)

PHASES = [
    (1,  "Passive Recon",            p01_passive.PHASE_DESC,     p01_passive),
    (2,  "Subdomain Enumeration",    p02_subdomains.PHASE_DESC,  p02_subdomains),
    (3,  "DNS Deep Dive",            p03_dns.PHASE_DESC,         p03_dns),
    (4,  "Live Host Discovery",      p04_live_hosts.PHASE_DESC,  p04_live_hosts),
    (5,  "Port Scanning",            p05_ports.PHASE_DESC,       p05_ports),
    (6,  "Web Crawling",             p06_crawling.PHASE_DESC,    p06_crawling),
    (7,  "Secret Detection",         p07_secrets.PHASE_DESC,     p07_secrets),
    (8,  "Vulnerability Scanning",   p08_vulns.PHASE_DESC,       p08_vulns),
    (9,  "Content Discovery",        p09_content.PHASE_DESC,     p09_content),
    (10, "Cloud & Infrastructure",   p10_cloud.PHASE_DESC,       p10_cloud),
    (11, "Screenshot & HTML Report", p11_reporting.PHASE_DESC,   p11_reporting),
    (12, "AI Attack Surface Summary",p12_ai_summary.PHASE_DESC,  p12_ai_summary),
]

PHASE_KEYS = ["p01","p02","p03","p04","p05","p06","p07","p08","p09","p10","p11","p12"]


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="dominion",
        description="DOMINION — Ultra-Powered Domain Recon Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python dominion.py -d example.com                  # Full scan
  python dominion.py -d example.com --phase 1-6      # Phases 1–6 only
  python dominion.py -d example.com --phase 3        # DNS only
  python dominion.py -d example.com --skip 5,10      # Skip port scan & cloud
  python dominion.py -d example.com --resume         # Continue from last point
  python dominion.py -d example.com --quick          # Quick scan (phases 1-4)
  python dominion.py -d example.com --notify         # Telegram alert on finish
  python dominion.py --list-phases                   # Show all phases

Scan Profiles:
  --quick    Phases 1-4  (passive, subdomains, DNS, live hosts)
  --full     All 12 phases (default)
  --phase N  Specific phase or range
        """,
    )
    parser.add_argument("-d", "--domain",  required=False, help="Target domain (e.g. example.com)")
    parser.add_argument("-p", "--phase",   default="all",  help="Phase(s): 'all', '1-6', '3', '1,3,5'")
    parser.add_argument("-s", "--skip",    default="",     help="Skip phases: '5,10'")
    parser.add_argument("-o", "--output",  default="",     help="Output directory")
    parser.add_argument("-c", "--config",  default=str(ROOT / "config.yml"), help="Config file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--resume",        action="store_true", help="Resume from last phase")
    parser.add_argument("--list-phases",   action="store_true", help="List all phases and exit")
    parser.add_argument("--no-ai",         action="store_true", help="Skip Phase 12 (AI)")
    parser.add_argument("--full-ports",    action="store_true", help="Scan all 65535 ports")
    parser.add_argument("--notify",        action="store_true", help="Telegram notification on finish")
    parser.add_argument("--quick",         action="store_true", help="Quick scan: phases 1-4")
    parser.add_argument("--threads",       type=int, default=0, help="Override thread count")
    return parser.parse_args()


def parse_phase_selection(phase_arg: str) -> set:
    if phase_arg.lower() == "all":
        return set(range(1, 13))
    selected = set()
    for part in phase_arg.split(","):
        part = part.strip()
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                selected.update(range(int(a), int(b) + 1))
            except ValueError:
                pass
        elif part.isdigit():
            selected.add(int(part))
    return selected


def list_phases():
    c = "\033[0;36m"; b = "\033[1m"; r = "\033[0;31m"; nc = "\033[0m"; g = "\033[0;32m"
    print(f"\n{b}  DOMINION — Phase Index{nc}\n")
    print(f"  {'#':>3}  {'Name':<32} Description")
    print("  " + "─" * 80)
    icons = ["🔍","🌐","🔎","🌍","🔌","🕷️ ","🔑","🚨","📂","☁️ ","📸","🤖"]
    for i, (num, name, desc, _) in enumerate(PHASES):
        icon = icons[i] if i < len(icons) else "•"
        print(f"  {num:>3}  {icon} {name:<30} {c}{desc}{nc}")
    print()


def save_state(output_dir: Path, completed: dict) -> None:
    save_json(output_dir / ".dominion_state.json", completed)


def load_state(output_dir: Path) -> dict:
    return load_json(output_dir / ".dominion_state.json")


# ─────────────────────────────────────────────────────────────────────────────
# Notifications
# ─────────────────────────────────────────────────────────────────────────────

def send_telegram(token: str, chat_id: str, msg: str) -> bool:
    """Send Telegram message. Returns True on success."""
    if not token or not chat_id:
        return False
    try:
        import urllib.parse
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        r = http_get(
            f"{url}?chat_id={chat_id}"
            f"&text={urllib.parse.quote(msg, safe='')}"
            f"&parse_mode=Markdown",
            timeout=10,
        )
        return r is not None and r.status_code == 200
    except Exception:
        return False


def notify_critical(cfg, domain: str, finding: str) -> None:
    """Immediately notify on critical finding."""
    if not (cfg.telegram_token and cfg.telegram_chat_id):
        return
    msg = (
        f"🚨 *DOMINION — Critical Finding!*\n"
        f"Target: `{domain}`\n"
        f"Finding: {finding[:200]}"
    )
    send_telegram(cfg.telegram_token, cfg.telegram_chat_id, msg)


# ─────────────────────────────────────────────────────────────────────────────
# Pre-flight checks
# ─────────────────────────────────────────────────────────────────────────────

def preflight_check(domain: str, cfg, log) -> None:
    """Quick sanity checks before scan starts."""
    import shutil

    CRITICAL_TOOLS = ["httpx", "nmap", "nuclei", "subfinder", "katana"]
    missing = [t for t in CRITICAL_TOOLS if not shutil.which(t)]
    if missing:
        log.warning(f"Core tools missing: {', '.join(missing)}")
        log.warning("Run ./install.sh to install them. Scan will continue with reduced coverage.")

    # Config warnings
    if not cfg.shodan_key:
        log.info("Tip: Add shodan_key to config.yml for Shodan integration")
    if not cfg.github_token:
        log.info("Tip: Add github_token to config.yml for GitHub recon")
    if not cfg.openai_key:
        log.info("Tip: Add openai_key to config.yml for AI attack surface analysis")


# ─────────────────────────────────────────────────────────────────────────────
# Finding counter
# ─────────────────────────────────────────────────────────────────────────────

def _count_findings(num: int, result: dict) -> int:
    mapping = {
        1:  lambda r: len(r.get("certificates", [])) + len(r.get("hackertarget", [])),
        2:  lambda r: r.get("total_live", 0),
        3:  lambda r: (sum(len(v) for v in r.get("records",{}).values())
                       + len(r.get("takeover_risks", []))),
        4:  lambda r: len(r.get("live_hosts", [])),
        5:  lambda r: sum(len(v) for v in r.get("open_ports",{}).values()),
        6:  lambda r: len(r.get("urls_crawled", [])),
        7:  lambda r: len(r.get("leaks", [])),
        8:  lambda r: r.get("total_vulns", 0),
        9:  lambda r: len(r.get("found_paths", [])),
        10: lambda r: len(r.get("s3_buckets",[])) + len(r.get("firebase",[])),
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


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print_banner()
    args = parse_args()

    if args.list_phases:
        list_phases()
        sys.exit(0)

    if not args.domain:
        print("\n  Usage: python dominion.py -d example.com\n")
        print("  Run 'python dominion.py --list-phases' to see all phases\n")
        sys.exit(1)

    # ── Validate domain ───────────────────────────────────────────────────────
    domain = (args.domain.lower().strip()
              .removeprefix("https://").removeprefix("http://").rstrip("/"))
    # strip leading 'www.' for consistency but keep original for scanning
    if not is_valid_domain(domain):
        print(f"\n  [✗] Invalid domain: '{domain}'")
        print("  Please provide a valid domain like: example.com\n")
        sys.exit(1)

    # ── Load config ───────────────────────────────────────────────────────────
    config_path = Path(args.config)
    if not config_path.exists():
        config_path = ROOT / "config.yml"
    if not config_path.exists():
        config_path = ROOT / "config.example.yml"
    cfg = load_config(config_path)

    # Apply CLI overrides
    if args.full_ports:
        cfg._data.setdefault("settings", {})["full_port_scan"] = True
    if args.threads > 0:
        cfg._data.setdefault("settings", {})["threads"] = args.threads

    # ── Setup output ──────────────────────────────────────────────────────────
    output_dir = Path(args.output) if args.output else ROOT / "output" / domain
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Init logger ───────────────────────────────────────────────────────────
    log = init_logger(domain, output_dir, verbose=args.verbose)
    log.info(f"Target:  {domain}")
    log.info(f"Output:  {output_dir}")
    log.info(f"Config:  {config_path}")

    # ── Pre-flight ────────────────────────────────────────────────────────────
    preflight_check(domain, cfg, log)

    # ── Phase selection ───────────────────────────────────────────────────────
    if args.quick:
        args.phase = "1-4"
        log.info("Quick mode: running phases 1-4")

    selected = parse_phase_selection(args.phase)
    skip     = set(int(x) for x in args.skip.split(",") if x.strip().isdigit())
    skip.update(cfg.skip_phases)
    if args.no_ai:
        skip.add(12)

    phases_to_run = sorted(selected - skip)

    # ── Resume ────────────────────────────────────────────────────────────────
    state          = load_state(output_dir) if args.resume else {}
    completed      = state.get("completed", {})
    all_phase_data = state.get("results", {})

    if args.resume and completed:
        done_nums = sorted(int(k) for k in completed.keys())
        log.info(f"Resuming — already done: phases {done_nums}")
        phases_to_run = [p for p in phases_to_run if str(p) not in completed]

    log.info(f"Running phases: {phases_to_run}")
    print()

    start_time     = time.monotonic()
    findings_count = {}

    # ── Main loop ─────────────────────────────────────────────────────────────
    for num, name, desc, module in PHASES:
        if num not in phases_to_run:
            continue

        print_phase_banner(num, name, desc)
        t0 = time.monotonic()

        try:
            prev_data = all_phase_data.get(f"p{num-1:02d}", {})

            if num == 1:
                result = module.run(domain, output_dir)
            elif num in range(2, 11):
                result = module.run_phase(domain, output_dir, prev_data)
            elif num in (11, 12):
                result = module.run_phase(domain, output_dir, all_phase_data)
            else:
                result = {}

            key = f"p{num:02d}"
            all_phase_data[key] = result
            completed[str(num)]  = {
                "name":      name,
                "elapsed":   elapsed(t0),
                "timestamp": datetime.now().isoformat(),
            }

            fc = _count_findings(num, result)
            findings_count[name] = fc
            print_phase_done(num, name, fc)

            # Check for criticals in vuln scan phase
            if num == 8 and args.notify:
                crit = result.get("critical_count", 0)
                if crit > 0:
                    notify_critical(
                        cfg, domain,
                        f"{crit} critical vulnerabilities found in Phase 8!"
                    )

            # Auto-notify on leaked secrets
            if num == 7 and args.notify:
                leaks = result.get("leaks", [])
                if leaks:
                    notify_critical(
                        cfg, domain,
                        f"{len(leaks)} secrets leaked! Check phase_07_secrets/"
                    )

            save_state(output_dir, {"completed": completed, "results": all_phase_data})

        except KeyboardInterrupt:
            log.warning("\nInterrupted! Progress saved. Use --resume to continue.")
            save_state(output_dir, {"completed": completed, "results": all_phase_data})
            sys.exit(0)

        except Exception as exc:
            log.error(f"Phase {num} error: {exc}")
            if args.verbose:
                import traceback
                log.debug(traceback.format_exc())
            log.info("Continuing to next phase...")
            continue

    # ── Summary ───────────────────────────────────────────────────────────────
    total_secs = elapsed(start_time)
    print_summary_box(domain, len(phases_to_run), findings_count)

    report_path = output_dir / "report.html"
    log.success(f"Elapsed:    {total_secs}")
    log.success(f"Output dir: {output_dir}")
    if report_path.exists():
        log.success(f"HTML Report: {report_path}")
        print(f"\n  🔥 Open in browser: file://{report_path}\n")

    # ── Final Telegram ─────────────────────────────────────────────────────────
    if args.notify and cfg.telegram_token and cfg.telegram_chat_id:
        p8     = all_phase_data.get("p08", {})
        msg    = (
            f"✅ *DOMINION Complete!*\n"
            f"🎯 Target: `{domain}`\n"
            f"⏱ Time: {total_secs}\n"
            f"🌐 Subdomains: {all_phase_data.get('p02',{}).get('total_live',0)}\n"
            f"🚨 Vulnerabilities: {p8.get('total_vulns',0)} "
            f"({p8.get('critical_count',0)} critical)\n"
            f"🔑 Secrets: {len(all_phase_data.get('p07',{}).get('leaks',[]))}\n"
            f"📄 Report: `{output_dir}/report.html`"
        )
        ok = send_telegram(cfg.telegram_token, cfg.telegram_chat_id, msg)
        if ok:
            log.success("Telegram notification sent ✓")
        else:
            log.warning("Telegram notification failed — check token/chat_id in config.yml")


if __name__ == "__main__":
    main()
