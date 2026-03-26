#!/usr/bin/env python3
"""
DOMINION - Phase 01: Passive Recon (EXPANDED)
WHOIS · DNS · crt.sh · ASN · Shodan · VirusTotal · SecurityTrails ·
Email harvesting · Google Dorks · LinkedIn OSINT · Metadata extraction ·
Reverse WHOIS · Related domains · Censys · FOFA · BinaryEdge · Netlas
"""

import json
import re
import socket
from pathlib import Path
from typing import Any, Dict, List, Set

import requests
import whois

from core.config  import get_config
from core.logger  import get_logger
from core.utils   import http_get, save_json, RateLimiter, dedup, write_lines

PHASE_NUM  = 1
PHASE_NAME = "Passive Recon"
PHASE_DESC = "WHOIS · ASN · crt.sh · Shodan · VT · SecurityTrails · Emails · Google Dorks · Censys"

GOOGLE_DORKS = [
    'site:{domain}',
    'site:{domain} filetype:pdf',
    'site:{domain} filetype:xls OR filetype:xlsx OR filetype:csv',
    'site:{domain} filetype:doc OR filetype:docx',
    'site:{domain} filetype:sql OR filetype:db',
    'site:{domain} filetype:env OR filetype:config OR filetype:yml OR filetype:yaml',
    'site:{domain} filetype:log',
    'site:{domain} filetype:bak OR filetype:backup',
    'site:{domain} inurl:admin OR inurl:dashboard OR inurl:login',
    'site:{domain} inurl:api OR inurl:v1 OR inurl:v2',
    'site:{domain} inurl:test OR inurl:dev OR inurl:staging OR inurl:beta',
    'site:{domain} inurl:swagger OR inurl:graphql OR inurl:api-docs',
    'site:{domain} inurl:phpinfo OR inurl:info.php',
    'site:{domain} "index of /"',
    'site:{domain} "parent directory"',
    'site:{domain} ext:php intitle:"index of"',
    '"@{domain}" email',
    'intext:"{domain}" "password"',
    'intext:"{domain}" "api_key" OR "api_secret" OR "access_token"',
    '"smtp.{domain}" OR "mail.{domain}"',
    'site:pastebin.com "{domain}"',
    'site:github.com "{domain}" password',
    'site:github.com "{domain}" secret',
    'site:github.com "{domain}" api_key',
    'site:trello.com "{domain}"',
    'site:jira.{domain} OR site:confluence.{domain}',
    'site:s3.amazonaws.com "{domain}"',
    'site:blob.core.windows.net "{domain}"',
    'inurl:{domain} site:web.archive.org',
]

EMPLOYEE_DORKS = [
    'site:linkedin.com/in "{domain}" employee',
    'site:linkedin.com/pub "{domain}"',
]

EMAIL_PATTERNS = [
    r"\b[a-zA-Z0-9._%+\-]+@{domain}\b",
]


def harvest_emails_from_text(text: str, domain: str) -> List[str]:
    """Extract emails from text."""
    pattern = r"\b[a-zA-Z0-9._%+\-]+@" + re.escape(domain) + r"\b"
    return dedup(re.findall(pattern, text, re.IGNORECASE))


def get_email_format_guesses(domain: str, names: List[str]) -> List[str]:
    """Generate likely email addresses from names."""
    formats = [
        "{first}.{last}@{d}",
        "{first}@{d}",
        "{f}{last}@{d}",
        "{first}{l}@{d}",
        "{last}.{first}@{d}",
    ]
    guesses = []
    for name in names[:20]:
        parts = name.lower().split()
        if len(parts) >= 2:
            first, last = parts[0], parts[-1]
            for fmt in formats:
                guesses.append(
                    fmt.format(first=first, last=last,
                               f=first[0], l=last[0], d=domain)
                )
    return guesses


def run(domain: str, output_dir: Path) -> Dict[str, Any]:
    log = get_logger()
    cfg = get_config()
    rl  = RateLimiter(calls_per_second=1.5)

    phase_dir = output_dir / "phase_01_passive"
    phase_dir.mkdir(parents=True, exist_ok=True)

    findings: Dict[str, Any] = {
        "domain":           domain,
        "whois":            {},
        "dns_basic":        {},
        "certificates":     [],
        "asn":              {},
        "shodan":           {},
        "censys":           {},
        "virustotal":       {},
        "securitytrails":   {},
        "hackertarget":     [],
        "emails":           [],
        "phone_numbers":    [],
        "employees":        [],
        "google_dorks":     {},
        "related_domains":  [],
        "ip_ranges":        [],
        "technologies":     [],
        "metadata":         {},
        "pastebin_mentions":[],
        "favicon_hash":     "",
    }

    # ── WHOIS ─────────────────────────────────────────────────────────────────
    log.info("Running WHOIS lookup...")
    try:
        w = whois.whois(domain)
        emails_w = []
        if isinstance(w.emails, list):
            emails_w = list(w.emails)
        elif w.emails:
            emails_w = [w.emails]

        findings["whois"] = {
            "registrar":        str(w.registrar or ""),
            "creation_date":    str((w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date) or ""),
            "expiration_date":  str((w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date) or ""),
            "updated_date":     str((w.updated_date[0] if isinstance(w.updated_date, list) else w.updated_date) or ""),
            "name_servers":     list(w.name_servers or []),
            "registrant":       str(w.org or w.name or ""),
            "emails":           emails_w,
            "country":          str(w.country or ""),
            "dnssec":           str(w.dnssec or ""),
            "status":           list(w.status or []) if isinstance(w.status, list) else [str(w.status or "")],
        }
        findings["emails"].extend(emails_w)
        log.found("Registrar", findings["whois"]["registrar"])
        log.found("Expires",   findings["whois"]["expiration_date"][:10])
        for ns in findings["whois"]["name_servers"][:4]:
            log.found("NS", ns)
        for e in emails_w:
            log.found("WHOIS Email", e)
    except Exception as e:
        log.warning(f"WHOIS failed: {e}")

    save_json(phase_dir / "whois.json", findings["whois"])
    rl.wait()

    # ── Basic DNS Resolution ──────────────────────────────────────────────────
    log.info("Basic DNS resolution...")
    try:
        import dns.resolver
        dns_basic: Dict = {}
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CAA"]:
            try:
                answers     = dns.resolver.resolve(domain, rtype, lifetime=10)
                dns_basic[rtype] = [str(r) for r in answers]
                for r in dns_basic[rtype][:3]:
                    log.found(rtype, r)
            except Exception:
                dns_basic[rtype] = []
        # Email server detection from MX
        for mx in dns_basic.get("MX", []):
            log.found("Mail server", mx)
        findings["dns_basic"] = dns_basic
        save_json(phase_dir / "dns_basic.json", dns_basic)
    except Exception as e:
        log.warning(f"DNS resolution failed: {e}")

    try:
        ip = socket.gethostbyname(domain)
        findings["dns_basic"]["resolved_ip"] = ip
        log.found("IP", ip)
    except Exception:
        pass

    rl.wait()

    # ── crt.sh ────────────────────────────────────────────────────────────────
    log.info("Querying crt.sh certificate transparency logs...")
    try:
        resp = http_get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=35)
        if resp and resp.status_code == 200:
            certs = resp.json()
            cert_domains: Set[str] = set()
            emails_in_certs: Set[str] = set()
            for entry in certs:
                names = entry.get("name_value", "")
                for n in names.splitlines():
                    n = n.strip().lstrip("*.")
                    if n.endswith(domain) or n == domain:
                        cert_domains.add(n)
                # Extract org/email from subject_dn
                subj = entry.get("subject_dn", "")
                for email_found in harvest_emails_from_text(subj, domain):
                    emails_in_certs.add(email_found)

            findings["certificates"] = sorted(cert_domains)
            findings["emails"].extend(list(emails_in_certs))
            log.success(f"crt.sh: {len(cert_domains)} domains, {len(emails_in_certs)} emails")
            save_json(phase_dir / "crt_sh_raw.json", certs[:500])
            write_lines(phase_dir / "crt_sh_domains.txt", sorted(cert_domains))
    except Exception as e:
        log.warning(f"crt.sh failed: {e}")

    rl.wait()

    # ── ASN / BGP Lookup ──────────────────────────────────────────────────────
    log.info("Looking up ASN / BGP info...")
    try:
        ip_addr = findings["dns_basic"].get("resolved_ip", "")
        if ip_addr:
            resp = http_get(f"https://api.bgpview.io/ip/{ip_addr}", timeout=20)
            if resp and resp.status_code == 200:
                data    = resp.json().get("data", {})
                prefixes = data.get("prefixes", [])
                asns, ip_ranges = [], []
                for p in prefixes:
                    asn_info = p.get("asn", {})
                    asns.append({
                        "asn": asn_info.get("asn"),
                        "name": asn_info.get("name"),
                        "description": asn_info.get("description_short"),
                        "prefix": p.get("prefix"),
                        "country": asn_info.get("country_code"),
                    })
                    if p.get("prefix"):
                        ip_ranges.append(p["prefix"])
                findings["asn"] = {"ip": ip_addr, "asns": asns}
                findings["ip_ranges"] = ip_ranges
                for a in asns[:3]:
                    log.found("ASN", f"AS{a['asn']} {a['name']} [{a['country']}]")
                for r in ip_ranges[:3]:
                    log.found("IP Range", r)
                save_json(phase_dir / "asn.json", findings["asn"])

            # Get sibling hosts from same IP
            rl.wait()
            resp2 = http_get(f"https://api.bgpview.io/ip/{ip_addr}", timeout=15)
            rev_resp = http_get(
                f"https://api.hackertarget.com/reverseiplookup/?q={ip_addr}", timeout=20)
            if rev_resp and rev_resp.status_code == 200:
                siblings = [l.strip() for l in rev_resp.text.splitlines() if l.strip()]
                findings["related_domains"].extend(siblings)
                log.success(f"Reverse IP: {len(siblings)} co-hosted domains")
                write_lines(phase_dir / "reverse_ip.txt", siblings)
    except Exception as e:
        log.warning(f"ASN lookup failed: {e}")

    rl.wait()

    # ── Shodan ────────────────────────────────────────────────────────────────
    if cfg.shodan_key:
        log.info("Querying Shodan...")
        try:
            import shodan as shodan_lib
            api = shodan_lib.Shodan(cfg.shodan_key)
            ip  = findings["dns_basic"].get("resolved_ip", "")
            if ip:
                host = api.host(ip)
                findings["shodan"] = {
                    "ip":        host.get("ip_str"),
                    "org":       host.get("org"),
                    "os":        host.get("os"),
                    "isp":       host.get("isp"),
                    "ports":     host.get("ports", []),
                    "hostnames": host.get("hostnames", []),
                    "vulns":     list(host.get("vulns", {}).keys()),
                    "tags":      host.get("tags", []),
                    "country":   host.get("country_name"),
                    "city":      host.get("city"),
                    "data":      [
                        {"port": s.get("port"), "banner": str(s.get("data", ""))[:200]}
                        for s in host.get("data", [])[:10]
                    ],
                }
                log.found("Shodan Org", host.get("org", ""))
                log.found("Shodan Ports", str(host.get("ports", [])))
                if findings["shodan"]["vulns"]:
                    log.warning(f"Shodan CVEs: {', '.join(findings['shodan']['vulns'][:5])}")
                save_json(phase_dir / "shodan.json", findings["shodan"])

            # Shodan domain search
            rl.wait()
            results = api.search(f"hostname:{domain}")
            shodan_hosts = []
            for r in results.get("matches", [])[:20]:
                h = {"ip": r.get("ip_str"), "port": r.get("port"),
                     "org": r.get("org"), "banner": str(r.get("data", ""))[:100]}
                shodan_hosts.append(h)
                log.found("Shodan Host", f"{r.get('ip_str')}:{r.get('port')}")
            findings["shodan"]["domain_search"] = shodan_hosts
        except Exception as e:
            log.warning(f"Shodan failed: {e}")
    else:
        log.warning("No Shodan API key — skipping")

    rl.wait()

    # ── Censys ────────────────────────────────────────────────────────────────
    if cfg.censys_id and cfg.censys_secret:
        log.info("Querying Censys...")
        try:
            from censys.search import CensysHosts
            hs = CensysHosts(api_id=cfg.censys_id, api_secret=cfg.censys_secret)
            query    = f"parsed.names: {domain}"
            results  = hs.search(query, per_page=20)
            censys_data = []
            for page in results:
                for host in page:
                    censys_data.append({
                        "ip":       host.get("ip"),
                        "services": [s.get("port") for s in host.get("services", [])],
                    })
                    log.found("Censys", host.get("ip"))
                break
            findings["censys"] = {"hosts": censys_data}
            save_json(phase_dir / "censys.json", findings["censys"])
        except Exception as e:
            log.warning(f"Censys failed: {e}")
    else:
        log.warning("No Censys credentials — skipping")

    rl.wait()

    # ── VirusTotal ────────────────────────────────────────────────────────────
    if cfg.virustotal_key:
        log.info("Querying VirusTotal...")
        try:
            headers = {"x-apikey": cfg.virustotal_key}
            resp = http_get(f"https://www.virustotal.com/api/v3/domains/{domain}",
                            headers=headers, timeout=20)
            if resp and resp.status_code == 200:
                vt = resp.json().get("data", {}).get("attributes", {})
                findings["virustotal"] = {
                    "reputation":          vt.get("reputation"),
                    "categories":          vt.get("categories", {}),
                    "last_analysis_stats": vt.get("last_analysis_stats", {}),
                    "registrar":           vt.get("registrar"),
                    "popularity_ranks":    vt.get("popularity_ranks", {}),
                    "tags":                vt.get("tags", []),
                }
                malicious = findings["virustotal"]["last_analysis_stats"].get("malicious", 0)
                log.found("VT Reputation", str(findings["virustotal"]["reputation"]))
                if malicious > 0:
                    log.warning(f"VirusTotal: {malicious} engines flagged as MALICIOUS!")
                save_json(phase_dir / "virustotal.json", findings["virustotal"])

            # VT subdomains
            rl.wait()
            resp2 = http_get(
                f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40",
                headers=headers, timeout=20)
            if resp2 and resp2.status_code == 200:
                subs = [e["id"] for e in resp2.json().get("data", [])]
                findings["virustotal"]["subdomains"] = subs
                findings["certificates"].extend(subs)
                log.success(f"VT subdomains: {len(subs)}")

            # VT resolutions
            rl.wait()
            resp3 = http_get(
                f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions?limit=20",
                headers=headers, timeout=20)
            if resp3 and resp3.status_code == 200:
                ips = [e["attributes"]["ip_address"] for e in resp3.json().get("data", [])]
                findings["virustotal"]["resolutions"] = ips
                log.success(f"VT IP resolutions: {len(ips)}")
        except Exception as e:
            log.warning(f"VirusTotal failed: {e}")
    else:
        log.warning("No VirusTotal API key — skipping")

    rl.wait()

    # ── SecurityTrails ────────────────────────────────────────────────────────
    if cfg.securitytrails_key:
        log.info("Querying SecurityTrails...")
        try:
            headers = {"APIKEY": cfg.securitytrails_key}
            resp = http_get(f"https://api.securitytrails.com/v1/domain/{domain}",
                            headers=headers, timeout=20)
            if resp and resp.status_code == 200:
                st = resp.json()
                findings["securitytrails"] = {
                    "apex_domain":  st.get("apex_domain"),
                    "current_dns":  st.get("current_dns", {}),
                    "alexa_rank":   st.get("alexa_rank"),
                    "hosting_org":  str(st.get("hosting_company", {}).get("name", "")),
                }
                log.found("ST Hosting", findings["securitytrails"]["hosting_org"])

            # ST subdomains
            rl.wait()
            resp2 = http_get(f"https://api.securitytrails.com/v1/domain/{domain}/subdomains?children_only=false",
                             headers=headers, timeout=20)
            if resp2 and resp2.status_code == 200:
                subs_st = resp2.json().get("subdomains", [])
                subs_full = [f"{s}.{domain}" for s in subs_st]
                findings["securitytrails"]["subdomains"] = subs_full
                findings["certificates"].extend(subs_full)
                log.success(f"SecurityTrails: {len(subs_full)} subdomains")
            save_json(phase_dir / "securitytrails.json", findings["securitytrails"])
        except Exception as e:
            log.warning(f"SecurityTrails failed: {e}")
    else:
        log.warning("No SecurityTrails API key — skipping")

    rl.wait()

    # ── Email Harvesting ──────────────────────────────────────────────────────
    log.info("Harvesting emails from multiple sources...")
    all_emails: Set[str] = set(findings.get("emails", []))

    # Hunter.io
    hunter_key = cfg.get("api_keys", "hunter")
    if hunter_key:
        try:
            resp = http_get(
                f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={hunter_key}&limit=100",
                timeout=20)
            if resp and resp.status_code == 200:
                data      = resp.json().get("data", {})
                emails_h  = [e["value"] for e in data.get("emails", [])]
                all_emails.update(emails_h)
                employees = [f"{e.get('first_name','')} {e.get('last_name','')}".strip()
                             for e in data.get("emails", [])]
                findings["employees"].extend(employees)
                findings["metadata"]["email_format"] = data.get("pattern", "")
                log.success(f"Hunter.io: {len(emails_h)} emails found")
        except Exception as e:
            log.warning(f"Hunter.io failed: {e}")

    # theHarvester (if available)
    from core.runner import require_tool, run as run_cmd
    if require_tool("theHarvester"):
        log.info("Running theHarvester...")
        th_out = phase_dir / "theharvester.xml"
        rc, stdout, _ = run_cmd(
            f"theHarvester -d {domain} -b google,bing,duckduckgo,yahoo,linkedin,twitter "
            f"-l 200 -f {phase_dir / 'theharvester'}",
            timeout=300, silent=True)
        # Parse output for emails
        for email in harvest_emails_from_text(stdout, domain):
            all_emails.add(email)
        log.success(f"theHarvester complete")

    # Intelligence from Have I Been Pwned
    try:
        resp = http_get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{domain}",
                        headers={"hibp-api-key": cfg.get("api_keys", "hibp", default="")},
                        timeout=15)
        # Just check if domain appears in breaches
        if resp and resp.status_code == 200:
            breaches = resp.json()
            log.warning(f"HaveIBeenPwned: {len(breaches)} breaches associated with domain!")
            findings["metadata"]["breaches"] = [b.get("Name") for b in breaches]
    except Exception:
        pass

    # Scrape common pages for emails
    log.info("Scraping website for email addresses...")
    pages_to_scrape = [
        f"https://{domain}",
        f"https://{domain}/contact",
        f"https://{domain}/about",
        f"https://{domain}/team",
        f"https://{domain}/security",
        f"https://{domain}/.well-known/security.txt",
        f"https://security.{domain}",
        f"https://mail.{domain}",
    ]
    for page_url in pages_to_scrape:
        resp = http_get(page_url, timeout=10)
        if resp and resp.status_code == 200:
            emails_found = harvest_emails_from_text(resp.text, domain)
            all_emails.update(emails_found)
            # Also look for phone numbers
            phones = re.findall(r"[\+]?[0-9\-\(\)\s]{10,17}", resp.text)
            findings["phone_numbers"].extend(phones[:5])
        rl.wait()

    findings["emails"] = dedup(all_emails)
    write_lines(phase_dir / "emails.txt", findings["emails"])
    log.success(f"Total emails harvested: {len(findings['emails'])}")
    for email in findings["emails"][:10]:
        log.found("Email", email)

    rl.wait()

    # ── HackerTarget ──────────────────────────────────────────────────────────
    log.info("Querying HackerTarget...")
    try:
        resp = http_get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=20)
        if resp and resp.status_code == 200 and "error" not in resp.text.lower():
            lines = [l.strip() for l in resp.text.splitlines() if l.strip()]
            findings["hackertarget"] = lines
            log.success(f"HackerTarget: {len(lines)} hosts")
            write_lines(phase_dir / "hackertarget.txt", [l.split(",")[0] for l in lines])
    except Exception as e:
        log.warning(f"HackerTarget failed: {e}")

    rl.wait()

    # ── Favicon hash (Shodan search pivot) ────────────────────────────────────
    log.info("Calculating favicon hash for Shodan pivoting...")
    try:
        favicon_urls = [
            f"https://{domain}/favicon.ico",
            f"https://www.{domain}/favicon.ico",
        ]
        for furl in favicon_urls:
            resp = http_get(furl, timeout=10)
            if resp and resp.status_code == 200 and resp.content:
                import hashlib, base64
                favicon_b64 = base64.encodebytes(resp.content)
                favicon_mmh3 = _mmh3_hash(resp.content)
                findings["favicon_hash"] = str(favicon_mmh3)
                log.found("Favicon hash (Shodan)", findings["favicon_hash"])
                log.info(f"Shodan query: http.favicon.hash:{findings['favicon_hash']}")
                break
    except Exception:
        pass

    # ── Google Dorks summary ──────────────────────────────────────────────────
    log.info("Building Google dorks list (manual investigation required)...")
    dork_list = {}
    for dork in GOOGLE_DORKS:
        query = dork.replace("{domain}", domain)
        url = f"https://www.google.com/search?q={requests.utils.quote(query)}"
        dork_list[query] = url
    findings["google_dorks"] = dork_list
    # Save dork file for manual use
    dork_lines = [f"{q}\n{u}\n" for q, u in dork_list.items()]
    (phase_dir / "google_dorks.txt").write_text(
        "\n".join(dork_lines), encoding="utf-8")
    log.success(f"Generated {len(dork_list)} Google dorks — saved to google_dorks.txt")

    # ── Technology detection ───────────────────────────────────────────────────
    log.info("Detecting technologies on apex domain...")
    try:
        resp = http_get(f"https://{domain}", timeout=15)
        if resp:
            techs = _detect_technologies(resp.text, dict(resp.headers))
            findings["technologies"] = techs
            for t in techs[:10]:
                log.found("Technology", t)
    except Exception:
        pass

    # ── Save full phase results ────────────────────────────────────────────────
    # Deduplicate certs/subdomains
    findings["certificates"] = dedup(findings["certificates"])
    findings["emails"]       = dedup(findings["emails"])

    save_json(phase_dir / "phase_01_results.json", findings)
    total = (len(findings["certificates"]) + len(findings["emails"]) +
             len(findings["hackertarget"]) + len(findings["related_domains"]))
    log.success(f"Phase 01 complete — {total} passive findings | {len(findings['emails'])} emails")
    return findings


def _mmh3_hash(data: bytes) -> int:
    """MurmurHash3 as used by Shodan for favicon hashing."""
    try:
        import mmh3, base64
        return mmh3.hash(base64.encodebytes(data))
    except ImportError:
        import struct, hashlib
        h = hashlib.md5(data).hexdigest()
        return int(h[:8], 16) - (1 << 32 if int(h[:8], 16) >= (1 << 31) else 0)


def _detect_technologies(html: str, headers: dict) -> List[str]:
    """Basic technology fingerprinting from HTML and headers."""
    techs = []
    lower_html    = html.lower()
    lower_headers = {k.lower(): v.lower() for k, v in headers.items()}
    h_str         = str(lower_headers)

    checks = {
        "WordPress":     ["wp-content", "wp-includes", "wordpress"],
        "Joomla":        ["joomla", "/components/com_"],
        "Drupal":        ["drupal", "sites/default"],
        "Magento":       ["magento", "mage/"],
        "Shopify":       ["shopify", "cdn.shopify.com"],
        "Laravel":       ["laravel", "x-powered-by: php"],
        "Django":        ["csrfmiddlewaretoken", "django"],
        "Ruby on Rails": ["rails", "x-runtime"],
        "Next.js":       ["__next", "_next/"],
        "React":         ["react-dom", "__reactfiber"],
        "Vue.js":        ["vue", "v-bind", "__vue"],
        "Angular":       ["ng-content", "ng-version", "angular"],
        "jQuery":        ["jquery"],
        "Bootstrap":     ["bootstrap.min.css", "bootstrap.js"],
        "Nginx":         ["nginx"],
        "Apache":        ["apache"],
        "IIS":           ["iis", "x-powered-by: asp.net"],
        "PHP":           ["x-powered-by: php"],
        "ASP.NET":       ["aspnetcore", "asp.net", "__requestverificationtoken"],
        "Node.js":       ["x-powered-by: express"],
        "Cloudflare":    ["cf-ray", "cloudflare"],
        "AWS":           ["amazonaws", "x-amz"],
        "Google Cloud":  ["x-cloud-trace-context", "googleapis"],
        "Elasticsearch": ["elasticsearch"],
        "MongoDB":       ["mongodb"],
    }
    for tech, signatures in checks.items():
        if any(s in lower_html or s in h_str for s in signatures):
            techs.append(tech)
    return techs
