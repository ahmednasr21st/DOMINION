#!/usr/bin/env python3
"""
DOMINION - Phase 07: Secret & Leak Detection
trufflehog · gitleaks · GitHub dorking · Wayback secrets · pastebin hunt
"""

import re
from pathlib import Path
from typing import Any, Dict, List

from core.config import get_config
from core.logger import get_logger
from core.runner import run, require_tool
from core.utils  import save_json, read_lines, write_lines, http_get, RateLimiter

PHASE_NUM  = 7
PHASE_NAME = "Secret & Leak Detection"
PHASE_DESC = "trufflehog · gitleaks · GitHub dorks · Wayback secrets"

GITHUB_DORKS = [
    '"{domain}" password',
    '"{domain}" api_key',
    '"{domain}" secret_key',
    '"{domain}" access_token',
    '"{domain}" credentials',
    '"{domain}" .env',
    '"{domain}" config.yml',
    '"{domain}" db_password',
    '"{domain}" private_key',
    '"{domain}" smtp_password',
    'filename:.env "{domain}"',
    'filename:config.json "{domain}"',
    'filename:credentials "{domain}"',
    'filename:id_rsa "{domain}"',
    'org:{domain_base} secret',
    'org:{domain_base} password',
]

LEAKED_PATTERNS = {
    "AWS Key":          r"AKIA[0-9A-Z]{16}",
    "AWS Secret":       r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}",
    "GitHub Token":     r"ghp_[0-9a-zA-Z]{36}",
    "GitLab Token":     r"glpat-[0-9a-zA-Z\-]{20}",
    "Slack Token":      r"xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}",
    "Stripe Key":       r"sk_live_[0-9a-zA-Z]{24}",
    "Google API":       r"AIza[0-9A-Za-z\-_]{35}",
    "Twilio SID":       r"AC[a-z0-9]{32}",
    "Private Key":      r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY",
    "SendGrid":         r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}",
    "Mailgun":          r"key-[0-9a-zA-Z]{32}",
    "JWT Token":        r"eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+",
    "Bearer Token":     r"[Bb]earer\s+[a-zA-Z0-9\-_\.]{20,}",
    "Basic Auth":       r"[Bb]asic\s+[a-zA-Z0-9\+/]{20,}={0,2}",
    "MongoDB URI":      r"mongodb(\+srv)?://[^\s\"']+",
    "Database URL":     r"(postgres|mysql|redis|jdbc)://[^\s\"']+",
    "Telegram Token":   r"[0-9]{8,10}:[a-zA-Z0-9_\-]{35}",
}


def scan_text_for_leaks(text: str, source: str) -> List[dict]:
    found = []
    for label, pattern in LEAKED_PATTERNS.items():
        for match in re.finditer(pattern, text):
            found.append({
                "type":   label,
                "match":  match.group(0)[:200],
                "source": source,
            })
    return found


def run_phase(domain: str, output_dir: Path, prev_data: dict = None) -> Dict[str, Any]:
    log  = get_logger()
    cfg  = get_config()
    rl   = RateLimiter(calls_per_second=1.0)
    prev = prev_data or {}

    phase_dir = output_dir / "phase_07_secrets"
    phase_dir.mkdir(parents=True, exist_ok=True)

    findings: Dict[str, Any] = {
        "domain":           domain,
        "leaks":            [],
        "github_dorks":     [],
        "wayback_secrets":  [],
        "trufflehog":       [],
        "paste_sites":      [],
    }

    all_leaks: List[dict] = []

    # ── JS File secret scan (from Phase 6) ────────────────────────────────────
    js_file = output_dir / "phase_06_crawling" / "js_files.txt"
    js_urls = read_lines(js_file)[:50]
    if js_urls:
        log.info(f"Deep scanning {len(js_urls)} JS files for secrets...")
        for url in js_urls:
            resp = http_get(url, timeout=15)
            if resp and resp.status_code == 200:
                leaks = scan_text_for_leaks(resp.text, url)
                if leaks:
                    for leak in leaks:
                        log.warning(f"LEAK [{leak['type']}] in {url}: {leak['match'][:60]}...")
                    all_leaks.extend(leaks)
            rl.wait()

    # ── Wayback Machine secret hunt ────────────────────────────────────────────
    log.info("Searching Wayback Machine snapshots for secrets...")
    try:
        # Get juicy URLs from Wayback
        resp = http_get(
            f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
            f"&output=text&fl=original&collapse=urlkey"
            f"&filter=statuscode:200"
            f"&filter=mimetype:text/javascript"
            f"&limit=1000",
            timeout=40,
        )
        if resp and resp.status_code == 200:
            wb_js = [l.strip() for l in resp.text.splitlines() if l.strip()]
            log.info(f"Scanning {min(len(wb_js), 30)} Wayback JS snapshots...")
            for js_url in wb_js[:30]:
                wb_url = f"https://web.archive.org/web/{js_url}"
                wb_resp = http_get(wb_url, timeout=15)
                if wb_resp and wb_resp.status_code == 200:
                    leaks = scan_text_for_leaks(wb_resp.text, f"wayback:{js_url}")
                    if leaks:
                        all_leaks.extend(leaks)
                        findings["wayback_secrets"].extend(leaks)
                rl.wait()
    except Exception as e:
        log.warning(f"Wayback secret hunt failed: {e}")

    rl.wait()

    # ── GitHub Dorking via API ─────────────────────────────────────────────────
    if cfg.github_token:
        log.info("Running GitHub dorks...")
        headers = {"Authorization": f"token {cfg.github_token}"}
        domain_base = domain.split(".")[0]

        for dork_template in GITHUB_DORKS[:10]:
            dork = dork_template.format(domain=domain, domain_base=domain_base)
            try:
                resp = http_get(
                    f"https://api.github.com/search/code?q={dork}&per_page=10",
                    headers=headers, timeout=20,
                )
                if resp and resp.status_code == 200:
                    items = resp.json().get("items", [])
                    for item in items:
                        findings["github_dorks"].append({
                            "dork": dork,
                            "url":  item.get("html_url"),
                            "name": item.get("name"),
                            "repo": item.get("repository", {}).get("full_name"),
                        })
                        log.warning(f"GitHub leak: {item.get('html_url')}")
                rl.wait()
            except Exception as e:
                log.debug(f"GitHub dork failed: {e}")
    else:
        log.warning("No GitHub token — skipping GitHub dorks")

    rl.wait()

    # ── TruffleHog (on cloned GitLab/GitHub repos if available) ───────────────
    if require_tool("trufflehog"):
        log.info(f"Running trufflehog on {domain} live URLs...")
        th_out = phase_dir / "trufflehog.json"
        rc, stdout, _ = run(
            f"trufflehog filesystem {output_dir / 'phase_06_crawling'} "
            f"--json --no-update",
            timeout=300,
        )
        if stdout:
            import json as _json
            for line in stdout.splitlines():
                try:
                    leak = _json.loads(line)
                    findings["trufflehog"].append(leak)
                    log.warning(f"TruffleHog: {leak.get('DetectorName')} — {leak.get('Raw', '')[:80]}")
                    all_leaks.append({
                        "type":   leak.get("DetectorName", "unknown"),
                        "match":  leak.get("Raw", "")[:200],
                        "source": "trufflehog",
                    })
                except Exception:
                    pass
    else:
        log.warning("trufflehog not found — skipping")

    # ── Paste Site Search ──────────────────────────────────────────────────────
    log.info("Searching paste sites...")
    paste_urls = [
        f"https://psbdmp.ws/api/v3/search/{domain}",
        f"https://pastebin.com/search?q={domain}",
    ]
    for purl in paste_urls:
        try:
            resp = http_get(purl, timeout=15)
            if resp and resp.status_code == 200 and domain in resp.text:
                leaks = scan_text_for_leaks(resp.text, purl)
                if leaks:
                    all_leaks.extend(leaks)
                    findings["paste_sites"].extend(leaks)
                    log.warning(f"Paste site hit: {purl}")
            rl.wait()
        except Exception:
            pass

    # ── Dedup and save ─────────────────────────────────────────────────────────
    seen = set()
    unique_leaks = []
    for leak in all_leaks:
        key = f"{leak['type']}:{leak['match'][:50]}"
        if key not in seen:
            seen.add(key)
            unique_leaks.append(leak)

    findings["leaks"] = unique_leaks
    save_json(phase_dir / "phase_07_results.json", findings)

    if unique_leaks:
        log.warning(f"⚠️  {len(unique_leaks)} TOTAL LEAKS FOUND — check phase_07_results.json!")
    log.success(f"Phase 07 complete — {len(unique_leaks)} leaked secrets")
    return findings
