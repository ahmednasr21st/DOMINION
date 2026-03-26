#!/usr/bin/env python3
"""
DOMINION - Phase 04: Live Host Discovery
httpx probe all subdomains: status codes, titles, tech stack, 
response fingerprint, WAF detection, CDN detection, headers.
"""

from pathlib import Path
from typing import Any, Dict, List

from core.config import get_config
from core.logger import get_logger
from core.runner import run, run_lines, require_tool
from core.utils  import save_json, read_lines, write_lines, http_get, RateLimiter

PHASE_NUM  = 4
PHASE_NAME = "Live Host Discovery"
PHASE_DESC = "httpx · Tech detection · WAF · CDN · Status codes · Titles · Screenshots prep"

WAF_SIGNATURES = {
    "Cloudflare":   ["cf-ray", "cloudflare", "__cfduid"],
    "AWS WAF":      ["x-amzn-requestid", "awselb"],
    "Akamai":       ["akamai-origin-hop", "x-check-cacheable"],
    "Imperva":      ["x-iinfo", "incap_ses", "visid_incap"],
    "F5 BIG-IP":    ["bigipserver", "f5-"],
    "Sucuri":       ["x-sucuri-id", "sucuri"],
    "ModSecurity":  ["mod_security", "modsec"],
    "Nginx+Naxsi":  ["naxsi"],
}

CDN_SIGNATURES = {
    "Cloudflare": ["cloudflare"],
    "Fastly":     ["fastly"],
    "Akamai":     ["akamaiedge", "akamai"],
    "CloudFront": ["cloudfront"],
    "Vercel":     ["vercel"],
    "Netlify":    ["netlify"],
    "BunnyCDN":   ["bunny", "bcdn"],
    "KeyCDN":     ["keycdn"],
}


def detect_waf(headers: dict, body: str) -> str:
    h_lower = {k.lower(): v.lower() for k, v in headers.items()}
    all_lower = str(h_lower) + body[:2000].lower()
    for waf, sigs in WAF_SIGNATURES.items():
        if any(s in all_lower for s in sigs):
            return waf
    return ""


def detect_cdn(headers: dict) -> str:
    h_str = str({k.lower(): v.lower() for k, v in headers.items()})
    for cdn, sigs in CDN_SIGNATURES.items():
        if any(s in h_str for s in sigs):
            return cdn
    return ""


def run_phase(domain: str, output_dir: Path, prev_data: dict = None) -> Dict[str, Any]:
    log  = get_logger()
    cfg  = get_config()
    rl   = RateLimiter(calls_per_second=5.0)

    phase_dir = output_dir / "phase_04_live_hosts"
    phase_dir.mkdir(parents=True, exist_ok=True)

    subs_file = output_dir / "subdomains.txt"
    # Also add the apex domain
    subs = read_lines(subs_file)
    if domain not in subs:
        subs.insert(0, domain)

    findings: Dict[str, Any] = {
        "domain":     domain,
        "total_probed": len(subs),
        "live_hosts": [],
        "status_codes": {},
        "technologies": {},
        "wafs":        {},
        "interesting": [],
    }

    live_hosts:    List[Dict] = []
    live_urls_all: List[str]  = []

    # ── httpx batch probe ─────────────────────────────────────────────────────
    if require_tool("httpx"):
        log.info(f"Probing {len(subs)} hosts with httpx...")
        input_file  = phase_dir / "httpx_input.txt"
        output_file = phase_dir / "httpx_output.json"
        write_lines(input_file, subs)

        rc, stdout, _ = run(
            f"httpx -l {input_file} -json -o {output_file} "
            f"-title -status-code -content-length -content-type "
            f"-tech-detect -follow-redirects -threads {cfg.threads} "
            f"-timeout 10 -silent",
            timeout=600,
        )

        import json as _json
        if output_file.exists():
            for line in output_file.read_text(encoding="utf-8").splitlines():
                try:
                    h = _json.loads(line)
                    url    = h.get("url", "")
                    status = h.get("status-code", 0)
                    title  = h.get("title", "")
                    tech   = h.get("tech", [])
                    clen   = h.get("content-length", 0)

                    host_data = {
                        "url":            url,
                        "status":         status,
                        "title":          title,
                        "technology":     tech,
                        "content_length": clen,
                        "content_type":   h.get("content-type", ""),
                        "final_url":      h.get("final-url", url),
                        "ip":             h.get("host", ""),
                        "webserver":      h.get("webserver", ""),
                        "waf":            "",
                        "cdn":            "",
                    }

                    live_hosts.append(host_data)
                    live_urls_all.append(url)

                    # Track status codes
                    sc = str(status)
                    findings["status_codes"][sc] = findings["status_codes"].get(sc, 0) + 1

                    # Track technologies
                    for t in tech:
                        findings["technologies"][t] = findings["technologies"].get(t, 0) + 1

                    # Flag interesting
                    interesting_codes = {200, 201, 301, 302, 401, 403, 500}
                    if status in interesting_codes and url:
                        log.found(url, f"[{status}] {title[:60]}")

                    if status == 401 or status == 403:
                        findings["interesting"].append({**host_data, "reason": f"Auth required ({status})"})

                except _json.JSONDecodeError:
                    pass

        log.success(f"httpx: {len(live_hosts)} live hosts found")
    else:
        # Fallback: manual probe with requests
        log.warning("httpx not available — using Python fallback probe")
        for sub in subs[:300]:
            for scheme in ["https", "http"]:
                url = f"{scheme}://{sub}"
                resp = http_get(url, timeout=8)
                if resp:
                    host_data = {
                        "url":    url,
                        "status": resp.status_code,
                        "title":  _extract_title(resp.text),
                        "technology": [],
                        "content_length": len(resp.content),
                        "content_type":   resp.headers.get("Content-Type", ""),
                        "final_url":      str(resp.url),
                        "webserver":      resp.headers.get("Server", ""),
                        "waf": detect_waf(dict(resp.headers), resp.text),
                        "cdn": detect_cdn(dict(resp.headers)),
                    }
                    live_hosts.append(host_data)
                    live_urls_all.append(url)
                    log.found(url, f"[{resp.status_code}]")
                    break
            rl.wait()

    # ── WAF & CDN Detection (for httpx results w/o it) ────────────────────────
    log.info("Detecting WAF/CDN on live hosts...")
    for host in live_hosts:
        if not host.get("waf"):
            resp = http_get(host["url"], timeout=8)
            if resp:
                host["waf"] = detect_waf(dict(resp.headers), resp.text)
                host["cdn"] = detect_cdn(dict(resp.headers))
                if host["waf"]:
                    log.found("WAF", f"{host['url']} → {host['waf']}")
                    findings["wafs"][host["url"]] = host["waf"]
                if host["cdn"]:
                    log.found("CDN", f"{host['url']} → {host['cdn']}")

    # ── Security Headers Check ────────────────────────────────────────────────
    log.info("Checking security headers on apex...")
    apex_resp = http_get(f"https://{domain}", timeout=15)
    if apex_resp:
        headers_check = {}
        security_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
            "X-XSS-Protection",
        ]
        for hdr in security_headers:
            val = apex_resp.headers.get(hdr, "MISSING")
            headers_check[hdr] = val
            if val == "MISSING":
                log.warning(f"Missing security header: {hdr}")
            else:
                log.found(hdr, val[:80])
        findings["security_headers"] = headers_check
        save_json(phase_dir / "security_headers.json", headers_check)

    # ── Save results ──────────────────────────────────────────────────────────
    findings["live_hosts"] = live_hosts
    save_json(phase_dir / "phase_04_results.json", findings)

    # Write live URLs for downstream phases
    live_urls_file = output_dir / "live_urls.txt"
    write_lines(live_urls_file, live_urls_all)

    log.success(f"Phase 04 complete — {len(live_hosts)} live hosts, {len(findings['wafs'])} WAFs detected")
    return findings


def _extract_title(html: str) -> str:
    import re
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:80] if m else ""
