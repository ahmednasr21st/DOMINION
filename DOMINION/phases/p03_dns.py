#!/usr/bin/env python3
"""
DOMINION - Phase 03: DNS Deep Dive
Full DNS record enumeration, zone transfer attempts, SPF/DMARC/DKIM analysis,
wildcard detection, DNS takeover checks.
"""

from pathlib import Path
from typing import Any, Dict, List

import dns.resolver
import dns.zone
import dns.query
import dns.exception
import dns.reversename

from core.config import get_config
from core.logger import get_logger
from core.utils  import save_json, read_lines, write_lines, RateLimiter

PHASE_NUM  = 3
PHASE_NAME = "DNS Deep Dive"
PHASE_DESC = "All DNS records · Zone transfer · SPF/DMARC/DKIM · Wildcard · Takeover checks"

RECORD_TYPES = [
    "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA",
    "SRV", "PTR", "CAA", "NAPTR", "HINFO",
]

TAKEOVER_SIGNATURES = {
    "GitHub Pages":     "there isn't a github pages site here",
    "Heroku":           "no such app",
    "Shopify":          "sorry, this shop is currently unavailable",
    "Fastly":           "fastly error: unknown domain",
    "Amazon S3":        "nosuchbucket",
    "Azure":            "is not found in the current subscription",
    "Pantheon":         "the gods are wise, but do not know of the url you seek",
    "Tumblr":           "whatever you were looking for doesn't live here",
    "Wordpress":        "do you want to register",
    "Squarespace":      "no such account",
    "Ghost":            "the thing you were looking for is no longer here",
    "Surge":            "project not found",
    "Zendesk":          "help center closed",
    "Bitbucket":        "repository not found",
}


def run_phase(domain: str, output_dir: Path, prev_data: dict = None) -> Dict[str, Any]:
    log  = get_logger()
    cfg  = get_config()
    rl   = RateLimiter(calls_per_second=2.0)
    prev = prev_data or {}

    phase_dir = output_dir / "phase_03_dns"
    phase_dir.mkdir(parents=True, exist_ok=True)

    findings: Dict[str, Any] = {
        "domain":          domain,
        "records":         {},
        "zone_transfer":   [],
        "spf":             "",
        "dmarc":           "",
        "dkim_selectors":  [],
        "wildcard":        False,
        "takeover_risks":  [],
        "subdomain_dns":   {},
    }

    # ── Full record enumeration for apex ─────────────────────────────────────
    log.info("Enumerating DNS records for apex domain...")
    resolver = dns.resolver.Resolver()
    resolver.timeout  = 10
    resolver.lifetime = 15

    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            records = [str(r) for r in answers]
            findings["records"][rtype] = records
            for r in records[:5]:
                log.found(rtype, r[:80])
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            findings["records"][rtype] = []

    rl.wait()

    # ── SPF ────────────────────────────────────────────────────────────────────
    log.info("Analyzing SPF record...")
    for txt in findings["records"].get("TXT", []):
        if "v=spf1" in txt:
            findings["spf"] = txt
            log.found("SPF", txt[:100])
            if "~all" in txt:
                log.warning("SPF uses ~all (softfail) — not fully strict")
            elif "-all" in txt:
                log.success("SPF uses -all (fail) — strict")
            elif "+all" in txt:
                log.warning("SPF uses +all — allows ANYONE to send! Email spoofing risk!")
            break

    # ── DMARC ──────────────────────────────────────────────────────────────────
    log.info("Checking DMARC...")
    try:
        dmarc_answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for r in dmarc_answers:
            s = str(r)
            if "v=DMARC1" in s:
                findings["dmarc"] = s
                log.found("DMARC", s[:120])
                if "p=none" in s:
                    log.warning("DMARC policy is 'none' — no enforcement!")
                elif "p=quarantine" in s:
                    log.info("DMARC policy: quarantine")
                elif "p=reject" in s:
                    log.success("DMARC policy: reject (strict)")
    except Exception:
        log.warning("No DMARC record found — email spoofing possible!")

    rl.wait()

    # ── DKIM (common selectors) ────────────────────────────────────────────────
    log.info("Hunting DKIM selectors...")
    dkim_selectors = [
        "default", "google", "mail", "k1", "k2", "selector1", "selector2",
        "dkim", "email", "s1", "s2", "smtp", "mx", "protonmail", "zoho",
        "sendgrid", "mailchimp", "ses", "mandrill",
    ]
    found_dkim = []
    for sel in dkim_selectors:
        try:
            answers = resolver.resolve(f"{sel}._domainkey.{domain}", "TXT")
            for r in answers:
                s = str(r)
                if "v=DKIM1" in s or "p=" in s:
                    log.found("DKIM", f"{sel}._domainkey.{domain}")
                    found_dkim.append(sel)
                    break
        except Exception:
            pass
    findings["dkim_selectors"] = found_dkim

    rl.wait()

    # ── Zone Transfer ──────────────────────────────────────────────────────────
    log.info("Attempting DNS zone transfers...")
    ns_servers = findings["records"].get("NS", [])
    for ns in ns_servers:
        ns = ns.rstrip(".")
        try:
            z = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=10))
            names = [str(n) for n in z.nodes.keys()]
            if names:
                log.warning(f"ZONE TRANSFER SUCCESS on {ns}! {len(names)} records leaked!")
                findings["zone_transfer"].append({"ns": ns, "records": names})
                (phase_dir / f"zone_transfer_{ns}.txt").write_text(
                    "\n".join(names), encoding="utf-8"
                )
        except Exception:
            log.debug(f"Zone transfer failed on {ns} (expected)")

    rl.wait()

    # ── Wildcard Detection ────────────────────────────────────────────────────
    log.info("Checking for DNS wildcard...")
    import random, string
    random_sub = "".join(random.choices(string.ascii_lowercase, k=12)) + "." + domain
    try:
        resolver.resolve(random_sub, "A")
        findings["wildcard"] = True
        log.warning(f"Wildcard DNS detected! ({random_sub} resolves)")
    except Exception:
        findings["wildcard"] = False
        log.success("No wildcard DNS detected")

    rl.wait()

    # ── Subdomain DNS records ──────────────────────────────────────────────────
    subs_file = output_dir / "subdomains.txt"
    subs      = read_lines(subs_file)[:500]  # limit for speed
    if subs:
        log.info(f"Resolving DNS for {len(subs)} subdomains...")
        sub_dns: Dict[str, dict] = {}
        for sub in subs:
            entry: dict = {}
            for rtype in ["A", "AAAA", "CNAME"]:
                try:
                    answers    = resolver.resolve(sub, rtype)
                    entry[rtype] = [str(r) for r in answers]
                except Exception:
                    entry[rtype] = []
            sub_dns[sub] = entry
            rl.wait()
        findings["subdomain_dns"] = sub_dns
        save_json(phase_dir / "subdomain_dns.json", sub_dns)
        log.success(f"Resolved DNS for {len(sub_dns)} subdomains")

    # ── Subdomain Takeover Checks ─────────────────────────────────────────────
    log.info("Checking for subdomain takeover opportunities...")
    from core.utils import http_get
    takeover_risks = []
    for sub in subs[:200]:
        cname_records = findings.get("subdomain_dns", {}).get(sub, {}).get("CNAME", [])
        if not cname_records:
            continue
        cname = cname_records[0].rstrip(".")
        for service, signature in TAKEOVER_SIGNATURES.items():
            if any(kw in cname for kw in [
                "github", "heroku", "shopify", "fastly", "amazonaws",
                "azure", "pantheon", "tumblr", "wordpress", "squarespace",
                "ghost", "surge", "zendesk", "bitbucket"
            ]):
                resp = http_get(f"https://{sub}", timeout=10)
                if resp and signature.lower() in resp.text.lower():
                    risk = {"subdomain": sub, "cname": cname, "service": service}
                    takeover_risks.append(risk)
                    log.warning(f"TAKEOVER RISK: {sub} → {cname} ({service})")
                break

    findings["takeover_risks"] = takeover_risks
    if takeover_risks:
        log.warning(f"{len(takeover_risks)} potential subdomain takeover(s) found!")
        save_json(phase_dir / "takeover_risks.json", takeover_risks)

    # ── Save ──────────────────────────────────────────────────────────────────
    save_json(phase_dir / "phase_03_results.json", findings)
    log.success("Phase 03 complete — DNS deep dive done")
    return findings
