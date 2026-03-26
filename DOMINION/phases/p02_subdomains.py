#!/usr/bin/env python3
"""
DOMINION - Phase 02: Subdomain Enumeration (EXPANDED)
subfinder · amass · assetfinder · findomain · chaos · knockpy ·
sublist3r · puredns · shuffledns · gotator (permutation) · altdns ·
massdns · github-subdomains · crobat · vita · AlienVault OTX ·
RapidDNS · Wayback · SecurityTrails API · crt.sh · HackerTarget ·
DNSDumpster · BufferOver · dnsx validation
"""

import re
import socket
from pathlib import Path
from typing import Any, Dict, List, Set

import requests

from core.config import get_config
from core.logger import get_logger
from core.runner import run, require_tool
from core.utils  import save_json, read_lines, write_lines, http_get, dedup, RateLimiter

PHASE_NUM  = 2
PHASE_NAME = "Subdomain Enumeration"
PHASE_DESC = "subfinder · amass · findomain · chaos · puredns · shuffledns · gotator · 15+ sources"


def passive_sources(domain: str, cfg, rl: RateLimiter) -> Set[str]:
    """Collect subdomains from passive HTTP sources."""
    subs: Set[str] = set()

    # ── crt.sh ────────────────────────────────────────────────────────────────
    try:
        r = http_get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=30)
        if r and r.status_code == 200:
            for e in r.json():
                for sub in e.get("name_value", "").splitlines():
                    sub = sub.strip().lstrip("*.")
                    if sub.endswith(f".{domain}") or sub == domain:
                        subs.add(sub)
    except Exception:
        pass
    rl.wait()

    # ── AlienVault OTX ────────────────────────────────────────────────────────
    try:
        page = 1
        while page <= 5:
            r = http_get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns?page={page}",
                timeout=20)
            if r and r.status_code == 200:
                data = r.json()
                records = data.get("passive_dns", [])
                for rec in records:
                    h = rec.get("hostname", "")
                    if h.endswith(f".{domain}"): subs.add(h)
                if not records or page >= data.get("count", 0) // 100 + 1:
                    break
                page += 1
            else:
                break
    except Exception:
        pass
    rl.wait()

    # ── HackerTarget ──────────────────────────────────────────────────────────
    try:
        r = http_get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=20)
        if r and r.status_code == 200 and "error" not in r.text.lower():
            for line in r.text.splitlines():
                sub = line.split(",")[0].strip()
                if sub.endswith(f".{domain}"): subs.add(sub)
    except Exception:
        pass
    rl.wait()

    # ── RapidDNS ──────────────────────────────────────────────────────────────
    try:
        r = http_get(f"https://rapiddns.io/subdomain/{domain}?full=1&down=1", timeout=20)
        if r and r.status_code == 200:
            for match in re.finditer(r"([a-zA-Z0-9\-\.]+\." + re.escape(domain) + r")", r.text):
                subs.add(match.group(1).lower())
    except Exception:
        pass
    rl.wait()

    # ── Wayback Machine ───────────────────────────────────────────────────────
    try:
        r = http_get(
            f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey",
            timeout=30)
        if r and r.status_code == 200:
            for url in r.text.splitlines():
                sub = re.sub(r"https?://([^/]+).*", r"\1", url).split(":")[0]
                if sub.endswith(f".{domain}"): subs.add(sub)
    except Exception:
        pass
    rl.wait()

    # ── BufferOver ────────────────────────────────────────────────────────────
    try:
        r = http_get(f"https://dns.bufferover.run/dns?q=.{domain}", timeout=15)
        if r and r.status_code == 200:
            data = r.json()
            for record in data.get("FDNS_A", []) + data.get("RDNS", []):
                parts = record.split(",")
                if len(parts) == 2:
                    sub = parts[1].strip().rstrip(".")
                    if sub.endswith(f".{domain}"): subs.add(sub)
    except Exception:
        pass
    rl.wait()

    # ── SecurityTrails ────────────────────────────────────────────────────────
    if cfg.securitytrails_key:
        try:
            headers = {"APIKEY": cfg.securitytrails_key}
            r = http_get(
                f"https://api.securitytrails.com/v1/domain/{domain}/subdomains?children_only=false",
                headers=headers, timeout=20)
            if r and r.status_code == 200:
                for sub in r.json().get("subdomains", []):
                    subs.add(f"{sub}.{domain}")
        except Exception:
            pass
        rl.wait()

    # ── VirusTotal ────────────────────────────────────────────────────────────
    if cfg.virustotal_key:
        try:
            r = http_get(
                f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40",
                headers={"x-apikey": cfg.virustotal_key}, timeout=20)
            if r and r.status_code == 200:
                for e in r.json().get("data", []):
                    subs.add(e.get("id", ""))
        except Exception:
            pass
        rl.wait()

    # ── Shodan ────────────────────────────────────────────────────────────────
    if cfg.shodan_key:
        try:
            import shodan
            api = shodan.Shodan(cfg.shodan_key)
            results = api.search(f"hostname:{domain}")
            for r_item in results.get("matches", []):
                for h in r_item.get("hostnames", []):
                    if h.endswith(f".{domain}"): subs.add(h)
        except Exception:
            pass

    # ── Censys ────────────────────────────────────────────────────────────────
    if cfg.censys_id and cfg.censys_secret:
        try:
            from censys.search import CensysHosts
            hs = CensysHosts(api_id=cfg.censys_id, api_secret=cfg.censys_secret)
            for page in hs.search(f"parsed.names: {domain}", per_page=50):
                for host in page:
                    for name in host.get("parsed", {}).get("names", []):
                        if name.endswith(f".{domain}"): subs.add(name)
                break
        except Exception:
            pass

    # ── DNSdumpster (no API key needed) ──────────────────────────────────────
    try:
        import requests as req
        s = req.Session()
        resp = s.get("https://dnsdumpster.com", timeout=15, verify=False)
        csrf = re.search(r"csrfmiddlewaretoken.*?value='([^']+)'", resp.text)
        if csrf:
            token = csrf.group(1)
            r2 = s.post("https://dnsdumpster.com", data={
                "csrfmiddlewaretoken": token,
                "targetip": domain,
                "user": "free",
            }, headers={"Referer": "https://dnsdumpster.com/"}, timeout=20, verify=False)
            for match in re.finditer(
                    r"([a-zA-Z0-9\-\.]+\." + re.escape(domain) + r")", r2.text):
                subs.add(match.group(1).lower())
    except Exception:
        pass

    # ── FullHunt.io ───────────────────────────────────────────────────────────
    try:
        r = http_get(f"https://fullhunt.io/api/v1/domain/{domain}/subdomains",
                     timeout=15)
        if r and r.status_code == 200:
            for sub in r.json().get("hosts", []):
                if sub.endswith(f".{domain}"): subs.add(sub)
    except Exception:
        pass

    # ── Chaos (projectdiscovery) ────────────────────────────────────────────
    chaos_key = cfg.get("api_keys", "chaos")
    if chaos_key:
        try:
            r = http_get(f"https://dns.projectdiscovery.io/dns/{domain}/subdomains",
                         headers={"Authorization": chaos_key}, timeout=20)
            if r and r.status_code == 200:
                for sub in r.json().get("subdomains", []):
                    subs.add(f"{sub}.{domain}")
        except Exception:
            pass

    # Clean up
    subs.discard("")
    subs.discard(domain)
    return {s for s in subs if re.match(r"^[a-zA-Z0-9.\-]+$", s)}


def run_phase(domain: str, output_dir: Path, prev_data: dict = None) -> Dict[str, Any]:
    log = get_logger()
    cfg = get_config()
    rl  = RateLimiter(calls_per_second=1.5)

    phase_dir = output_dir / "phase_02_subdomains"
    phase_dir.mkdir(parents=True, exist_ok=True)

    findings: Dict[str, Any] = {
        "domain":          domain,
        "all_subdomains":  [],
        "subdomains_live": [],
        "total_found":     0,
        "total_live":      0,
        "sources":         {},
    }

    master: Set[str] = set()

    # ── Passive API sources ───────────────────────────────────────────────────
    log.info("Querying 15+ passive sources...")
    passive = passive_sources(domain, cfg, rl)
    master.update(passive)
    findings["sources"]["passive_apis"] = len(passive)
    log.success(f"Passive sources: {len(passive)} subdomains")

    # ── subfinder ────────────────────────────────────────────────────────────
    if require_tool("subfinder"):
        log.info("Running subfinder...")
        sf_out = phase_dir / "subfinder.txt"
        run(f"subfinder -d {domain} -all -recursive -o {sf_out} -silent -timeout 30",
            timeout=600)
        hits = set(read_lines(sf_out))
        master.update(hits)
        findings["sources"]["subfinder"] = len(hits)
        log.success(f"subfinder: {len(hits)}")

    # ── amass ─────────────────────────────────────────────────────────────────
    if require_tool("amass"):
        log.info("Running amass (passive + active)...")
        amass_out = phase_dir / "amass.txt"
        amass_json = phase_dir / "amass.json"
        run(
            f"amass enum -d {domain} -passive -o {amass_out} -json {amass_json} "
            f"-timeout 15 -max-dns-queries 2000",
            timeout=900,
        )
        hits = set(read_lines(amass_out))
        master.update(hits)
        findings["sources"]["amass"] = len(hits)
        log.success(f"amass: {len(hits)}")

    # ── findomain ─────────────────────────────────────────────────────────────
    if require_tool("findomain"):
        log.info("Running findomain...")
        fd_out = phase_dir / "findomain.txt"
        run(f"findomain -t {domain} -u {fd_out} --quiet", timeout=300)
        hits = set(read_lines(fd_out))
        master.update(hits)
        findings["sources"]["findomain"] = len(hits)
        log.success(f"findomain: {len(hits)}")

    # ── chaos ─────────────────────────────────────────────────────────────────
    if require_tool("chaos"):
        log.info("Running chaos...")
        chaos_out = phase_dir / "chaos.txt"
        chaos_key = cfg.get("api_keys", "chaos", default="")
        run(f"chaos -d {domain} -o {chaos_out} -silent -key {chaos_key}", timeout=120)
        hits = set(read_lines(chaos_out))
        master.update(hits)
        findings["sources"]["chaos"] = len(hits)
        log.success(f"chaos: {len(hits)}")

    # ── assetfinder ──────────────────────────────────────────────────────────
    if require_tool("assetfinder"):
        log.info("Running assetfinder...")
        rc, stdout, _ = run(f"assetfinder --subs-only {domain}", timeout=120)
        hits = {s.strip() for s in stdout.splitlines() if s.strip().endswith(f".{domain}")}
        master.update(hits)
        findings["sources"]["assetfinder"] = len(hits)
        log.success(f"assetfinder: {len(hits)}")

    # ── github-subdomains ─────────────────────────────────────────────────────
    if require_tool("github-subdomains") and cfg.github_token:
        log.info("Running github-subdomains...")
        gh_out = phase_dir / "github_subs.txt"
        run(
            f"github-subdomains -d {domain} -t {cfg.github_token} -o {gh_out}",
            timeout=300,
        )
        hits = set(read_lines(gh_out))
        master.update(hits)
        findings["sources"]["github-subdomains"] = len(hits)
        log.success(f"github-subdomains: {len(hits)}")

    # ── crobat (sonar) ────────────────────────────────────────────────────────
    try:
        r = http_get(
            f"https://sonar.omnisint.io/subdomains/{domain}",
            timeout=20)
        if r and r.status_code == 200:
            hits = set(r.json())
            master.update(hits)
            findings["sources"]["sonar"] = len(hits)
            log.success(f"sonar: {len(hits)}")
    except Exception:
        pass

    # ── theHarvester (if available) ───────────────────────────────────────────
    if require_tool("theHarvester"):
        log.info("Running theHarvester for subdomains...")
        th_out = phase_dir / "harvester_subs"
        run(
            f"theHarvester -d {domain} -b all -f {th_out}",
            timeout=300, silent=True
        )
        # Parse XML output
        xml_path = phase_dir / "harvester_subs.xml"
        if xml_path.exists():
            import re
            content = xml_path.read_text(encoding="utf-8", errors="replace")
            for match in re.finditer(
                    r"([a-zA-Z0-9\-\.]+\." + re.escape(domain) + r")", content):
                master.add(match.group(1).lower())

    # ── Wordlist brute-force with massdns / shuffledns ────────────────────────
    wl_path = output_dir.parent.parent / "wordlists" / "subdomains.txt"
    if not wl_path.exists():
        import os
        wl_path = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))) / "wordlists" / "subdomains.txt"

    resolvers_path = output_dir.parent.parent / "wordlists" / "resolvers.txt"
    if not resolvers_path.exists():
        resolvers_path = Path("/tmp/resolvers.txt")
        from core.utils import write_lines as wl2
        wl2(resolvers_path, [
            "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
            "9.9.9.9", "208.67.222.222", "208.67.220.220"
        ])

    if wl_path.exists():
        if require_tool("shuffledns"):
            log.info(f"Running shuffledns brute-force (wordlist: {wl_path.name})...")
            shuf_out = phase_dir / "shuffledns.txt"
            run(
                f"shuffledns -d {domain} -w {wl_path} -r {resolvers_path} "
                f"-o {shuf_out} -silent -t 200",
                timeout=1800,
            )
            hits = {s.strip() for s in read_lines(shuf_out)
                    if s.strip().endswith(f".{domain}")}
            master.update(hits)
            findings["sources"]["shuffledns_bruteforce"] = len(hits)
            log.success(f"shuffledns brute-force: {len(hits)}")

        elif require_tool("puredns"):
            log.info("Running puredns brute-force...")
            pure_out = phase_dir / "puredns.txt"
            run(
                f"puredns bruteall {domain} --wordlist {wl_path} "
                f"--resolvers {resolvers_path} --write {pure_out} "
                f"--rate-limit 5000",
                timeout=1800,
            )
            hits = set(read_lines(pure_out))
            master.update(hits)
            findings["sources"]["puredns_bruteforce"] = len(hits)
            log.success(f"puredns brute-force: {len(hits)}")

    # ── Permutation with gotator ──────────────────────────────────────────────
    log.info("Generating permutations with gotator...")
    if require_tool("gotator") and len(master) > 0:
        base_subs = phase_dir / "base_for_perms.txt"
        write_lines(base_subs, list(master)[:500])
        gotator_out = phase_dir / "gotator.txt"
        run(
            f"gotator -sub {base_subs} -perm {wl_path if wl_path.exists() else ''} "
            f"-depth 1 -numbers 3 -md -silent > {gotator_out}",
            timeout=300, shell=True,
        )
        hits = set(read_lines(gotator_out))
        # Validate permutations
        if hits and require_tool("dnsx"):
            perm_valid = phase_dir / "gotator_valid.txt"
            perm_in    = phase_dir / "gotator_input.txt"
            write_lines(perm_in, list(hits))
            run(f"dnsx -l {perm_in} -o {perm_valid} -silent -r {resolvers_path}",
                timeout=600)
            valid_perms = set(read_lines(perm_valid))
            master.update(valid_perms)
            findings["sources"]["permutations"] = len(valid_perms)
            log.success(f"gotator permutations: {len(valid_perms)} valid")

    # ── DNS Validation with dnsx ──────────────────────────────────────────────
    log.info(f"Validating {len(master)} subdomains with dnsx...")
    all_subs_file = phase_dir / "all_subs_raw.txt"
    write_lines(all_subs_file, list(master))
    findings["all_subdomains"] = sorted(master)
    findings["total_found"]    = len(master)

    validated: Set[str] = set()
    if require_tool("dnsx"):
        dnsx_out = phase_dir / "dnsx_valid.txt"
        dnsx_json = phase_dir / "dnsx_valid.json"
        run(
            f"dnsx -l {all_subs_file} -o {dnsx_out} -json -resp "
            f"-silent -r {resolvers_path} -rl 500 -t 100",
            timeout=1200,
        )
        validated = set(read_lines(dnsx_out))
        log.success(f"dnsx: {len(validated)} resolve → live")
    elif require_tool("puredns"):
        pure_val = phase_dir / "puredns_valid.txt"
        run(f"puredns resolve {all_subs_file} -r {resolvers_path} -w {pure_val}",
            timeout=1200)
        validated = set(read_lines(pure_val))
    else:
        # Fallback: socket
        for sub in sorted(master):
            try:
                socket.gethostbyname(sub)
                validated.add(sub)
            except Exception:
                pass

    findings["subdomains_live"] = sorted(validated)
    findings["total_live"]      = len(validated)

    # Write master output files
    subs_out = output_dir / "subdomains.txt"
    write_lines(subs_out, sorted(validated))
    write_lines(phase_dir / "all_subdomains_unvalidated.txt", sorted(master))

    log.success(
        f"Phase 02 complete — {len(master)} found · {len(validated)} live · "
        f"sources: {findings['sources']}"
    )
    save_json(phase_dir / "phase_02_results.json", findings)
    return findings
