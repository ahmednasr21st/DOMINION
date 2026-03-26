#!/usr/bin/env python3
"""
DOMINION - Phase 06: Web Crawling & URL Discovery (EXPANDED)
katana · gospider · hakrawler · gau · gauplus · waybackurls ·
waymore · meg · photon · paramspider · arjun · linkfinder ·
secretfinder · gf (patterns) · relative-url-extractor ·
Wayback CDX API · Common Crawl · robots.txt parsing ·
sitemap.xml parsing · JS dependency extraction
"""

import json
import re
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Set

from core.config import get_config
from core.logger import get_logger
from core.runner import run, require_tool
from core.utils  import save_json, read_lines, write_lines, http_get, dedup, RateLimiter

PHASE_NUM  = 6
PHASE_NAME = "Web Crawling & URL Discovery"
PHASE_DESC = "katana · gospider · hakrawler · gau · waybackurls · paramspider · arjun · linkfinder · 15+ tools"

INTERESTING_EXTENSIONS = {
    "sensitive": [".env", ".config", ".yml", ".yaml", ".json", ".xml", ".sql",
                  ".bak", ".backup", ".zip", ".tar", ".gz", ".log", ".key", ".pem"],
    "code":      [".php", ".asp", ".aspx", ".jsp", ".py", ".rb", ".go", ".js"],
    "docs":      [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv"],
    "media":     [".jpg", ".png", ".gif", ".mp4", ".mp3"],
}

GF_PATTERNS = [
    "xss", "sqli", "ssrf", "idor", "redirect", "lfi", "rce",
    "ssti", "debug", "upload", "env", "aws-keys", "php-errors",
    "interestingparams", "interestingsubdomains",
]


def crawl_robots_sitemap(base_urls: List[str], rl: RateLimiter) -> Set[str]:
    found: Set[str] = set()
    for base in base_urls[:20]:
        base = base.rstrip("/")
        # robots.txt
        r = http_get(f"{base}/robots.txt", timeout=10)
        if r and r.status_code == 200:
            for line in r.text.splitlines():
                for kw in ["Disallow:", "Allow:", "Sitemap:"]:
                    if line.startswith(kw):
                        path = line.replace(kw, "").strip()
                        if path.startswith("/"):
                            found.add(f"{base}{path}")
                        elif path.startswith("http"):
                            found.add(path)
        rl.wait()
        # sitemap.xml
        for sm in ["/sitemap.xml", "/sitemap_index.xml", "/sitemap.php"]:
            r = http_get(f"{base}{sm}", timeout=10)
            if r and r.status_code == 200:
                urls = re.findall(r"<loc>(https?://[^<]+)</loc>", r.text)
                found.update(urls)
        rl.wait()
    return found


def extract_js_urls(base_urls: List[str], output_dir: Path, rl: RateLimiter) -> Set[str]:
    """Recursively find all JS files and extract embedded URLs."""
    js_urls: Set[str] = set()
    all_js_files: Set[str] = set()

    for url in base_urls[:30]:
        r = http_get(url, timeout=10)
        if r:
            # Find JS files
            for js_match in re.finditer(
                    r'(?:src|href)=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', r.text):
                js_path = js_match.group(1)
                js_full = urllib.parse.urljoin(url, js_path)
                all_js_files.add(js_full)
        rl.wait()

    js_dir = output_dir / "js_files"
    js_dir.mkdir(exist_ok=True)

    for js_url in list(all_js_files)[:100]:
        r = http_get(js_url, timeout=10)
        if r and r.status_code == 200:
            # Extract URLs from JS
            for match in re.finditer(r'["\`\'](/[a-zA-Z0-9_\-/]+)["\`\']', r.text):
                path = match.group(1)
                if len(path) > 2 and not path.startswith("//"):
                    js_urls.add(path)
            # Extract API endpoints
            for match in re.finditer(
                    r'(?:fetch|axios|get|post|put|delete)\s*\(\s*["\`\']([^"\'`]+)["\`\']',
                    r.text):
                endpoint = match.group(1)
                if endpoint.startswith("/") or endpoint.startswith("http"):
                    js_urls.add(endpoint)
            # Save JS file for deeper analysis
            safe_name = re.sub(r"[^\w]", "_", js_url)[:100] + ".js"
            (js_dir / safe_name).write_bytes(r.content[:1_000_000])
        rl.wait()

    return js_urls


def run_linkfinder(js_files: List[str], phase_dir: Path) -> List[str]:
    """Run linkfinder on collected JS files."""
    results = []
    if not require_tool("linkfinder"):
        return results
    for js_url in js_files[:50]:
        out_path = phase_dir / "linkfinder_out.txt"
        rc, stdout, _ = run(
            f"python3 /opt/linkfinder/linkfinder.py -i {js_url} -o cli",
            timeout=60, silent=True
        )
        for line in stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                results.append(line)
    return results


def run_secretfinder(js_files: List[str], phase_dir: Path) -> List[Dict]:
    """Run secretfinder on JS files to extract secrets."""
    secrets = []
    if not require_tool("secretfinder"):
        return secrets
    for js_url in js_files[:30]:
        rc, stdout, _ = run(
            f"python3 /opt/secretfinder/SecretFinder.py -i {js_url} -o cli",
            timeout=60, silent=True
        )
        for line in stdout.splitlines():
            if line.strip() and "Found" in line:
                secrets.append({"source": js_url, "finding": line.strip()})
    return secrets


def run_phase(domain: str, output_dir: Path, prev_data: dict = None) -> Dict[str, Any]:
    log  = get_logger()
    cfg  = get_config()
    rl   = RateLimiter(calls_per_second=3.0)
    prev = prev_data or {}

    phase_dir = output_dir / "phase_06_crawling"
    phase_dir.mkdir(parents=True, exist_ok=True)

    subs_file = output_dir / "subdomains.txt"
    live_urls = read_lines(output_dir / "live_urls.txt") if \
                (output_dir / "live_urls.txt").exists() else \
                [f"https://{domain}", f"http://{domain}"]

    if not live_urls:
        live_urls = [f"https://{domain}"]

    # Build input file
    urls_input_file = phase_dir / "input_urls.txt"
    write_lines(urls_input_file, live_urls[:200])

    findings: Dict[str, Any] = {
        "domain":        domain,
        "urls_crawled":  [],
        "js_files":      [],
        "parameters":    [],
        "forms":         [],
        "emails":        [],
        "js_endpoints":  [],
        "js_secrets":    [],
        "wordlist_gen":  [],
        "source_counts": {},
    }

    all_urls: Set[str]   = set()
    all_params: Set[str] = set()
    js_file_urls: Set[str] = set()

    # ── katana ────────────────────────────────────────────────────────────────
    if require_tool("katana"):
        log.info("Running katana (active crawl + JS parsing)...")
        katana_out = phase_dir / "katana.txt"
        run(
            f"katana -list {urls_input_file} -jc -jsl -hl -kf all "
            f"-d 5 -c {min(cfg.threads, 20)} -timeout 15 "
            f"-o {katana_out} -silent -nc -ef css,png,jpg,gif,svg,ico,woff",
            timeout=900,
        )
        hits = set(read_lines(katana_out))
        all_urls.update(hits)
        js_file_urls.update(u for u in hits if ".js" in u.lower())
        findings["source_counts"]["katana"] = len(hits)
        log.success(f"katana: {len(hits)} URLs")

    # ── gospider ─────────────────────────────────────────────────────────────
    if require_tool("gospider"):
        log.info("Running gospider...")
        gs_out = phase_dir / "gospider_raw.txt"
        run(
            f"gospider -S {urls_input_file} -o {phase_dir}/gospider "
            f"-c {min(cfg.threads, 20)} -d 3 --include-subs --include-other-source "
            f"-a -w -r --no-redirect --timeout 15 -q 2>{gs_out}",
            timeout=600,
        )
        for gs_file in (phase_dir / "gospider").glob("*"):
            for line in read_lines(gs_file):
                url_match = re.search(r"https?://[^\s\]\"']+", line)
                if url_match:
                    all_urls.add(url_match.group(0))
        findings["source_counts"]["gospider"] = len(all_urls)
        log.success(f"gospider: accumulated {len(all_urls)} URLs")

    # ── hakrawler ─────────────────────────────────────────────────────────────
    if require_tool("hakrawler"):
        log.info("Running hakrawler...")
        hak_out = phase_dir / "hakrawler.txt"
        run(
            f"cat {urls_input_file} | hakrawler -subs -u -insecure -t 8 "
            f"-d 3 -h 'User-Agent: Mozilla/5.0' > {hak_out}",
            timeout=600, shell=True
        )
        hits = set(read_lines(hak_out))
        all_urls.update(hits)
        findings["source_counts"]["hakrawler"] = len(hits)
        log.success(f"hakrawler: {len(hits)}")

    # ── gau (Get All URLs) ────────────────────────────────────────────────────
    if require_tool("gau"):
        log.info("Running gau (Wayback + Common Crawl + OTX + URLScan)...")
        gau_out = phase_dir / "gau.txt"
        run(
            f"echo {domain} | gau --threads {min(cfg.threads, 30)} "
            f"--subs --retries 3 --o {gau_out}",
            timeout=900,
        )
        hits = set(read_lines(gau_out))
        all_urls.update(hits)
        findings["source_counts"]["gau"] = len(hits)
        log.success(f"gau: {len(hits)}")

    # ── waybackurls ───────────────────────────────────────────────────────────
    if require_tool("waybackurls"):
        log.info("Running waybackurls...")
        wb_out = phase_dir / "waybackurls.txt"
        run(
            f"echo {domain} | waybackurls > {wb_out}",
            timeout=600, shell=True
        )
        hits = set(read_lines(wb_out))
        all_urls.update(hits)
        findings["source_counts"]["waybackurls"] = len(hits)
        log.success(f"waybackurls: {len(hits)}")

    # ── gauplus (extra sources) ───────────────────────────────────────────────
    if require_tool("gauplus"):
        log.info("Running gauplus...")
        gauplus_out = phase_dir / "gauplus.txt"
        run(f"gauplus -t {min(cfg.threads, 10)} {domain} -o {gauplus_out}", timeout=300)
        hits = set(read_lines(gauplus_out))
        all_urls.update(hits)
        findings["source_counts"]["gauplus"] = len(hits)

    # ── Wayback CDX API (direct) ───────────────────────────────────────────────
    log.info("Querying Wayback CDX API directly...")
    try:
        r = http_get(
            f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
            f"&output=text&fl=original&collapse=urlkey&limit=50000",
            timeout=60)
        if r and r.status_code == 200:
            wb_api_urls = set(r.text.splitlines())
            all_urls.update(wb_api_urls)
            findings["source_counts"]["wayback_cdx"] = len(wb_api_urls)
            log.success(f"Wayback CDX: {len(wb_api_urls)}")
    except Exception:
        pass

    # ── robots.txt + sitemap.xml ──────────────────────────────────────────────
    log.info("Crawling robots.txt and sitemaps...")
    extra_from_robots = crawl_robots_sitemap(live_urls[:20], rl)
    all_urls.update(extra_from_robots)

    # ── JS Analysis ───────────────────────────────────────────────────────────
    log.info("Extracting URLs from JavaScript files...")
    js_urls_embedded = extract_js_urls(live_urls[:15], phase_dir, rl)
    findings["js_endpoints"] = sorted(js_urls_embedded)

    # Detect all JS files from crawled URLs  
    js_file_urls.update(u for u in all_urls if re.search(r"\.js(\?|$)", u))
    findings["js_files"] = sorted(js_file_urls)[:200]
    log.success(f"JS files identified: {len(js_file_urls)}")

    # LinkFinder on JS
    log.info("Running linkfinder on JS files...")
    lf_results = run_linkfinder(list(js_file_urls)[:50], phase_dir)
    all_urls.update(u for u in lf_results if u.startswith("http"))

    # SecretFinder on JS
    log.info("Running secretfinder on JS files...")
    sf_results = run_secretfinder(list(js_file_urls)[:30], phase_dir)
    findings["js_secrets"] = sf_results
    if sf_results:
        log.warning(f"SecretFinder: {len(sf_results)} secrets in JS!")

    # ── Parameter Discovery with ParamSpider ──────────────────────────────────
    if require_tool("paramspider"):
        log.info("Running paramspider (discovering parameters from all sources)...")
        paramspider_out = phase_dir / "paramspider"
        paramspider_out.mkdir(exist_ok=True)
        run(
            f"paramspider -d {domain} --subs True --level high "
            f"--quiet --output {paramspider_out / 'params.txt'}",
            timeout=600, silent=True
        )
        for ps_file in paramspider_out.glob("*.txt"):
            param_urls = set(read_lines(ps_file))
            all_urls.update(param_urls)
            log.success(f"paramspider: {len(param_urls)} parameterized URLs")

    # ── Parameter Discovery with Arjun ────────────────────────────────────────
    if require_tool("arjun"):
        log.info("Running arjun (deep parameter mining)...")
        arjun_dir = phase_dir / "arjun"
        arjun_dir.mkdir(exist_ok=True)
        for url in live_urls[:15]:
            arjun_out = arjun_dir / f"{re.sub(r'[^\\w]', '_', url)[:50]}.json"
            rc, stdout, _ = run(
                f"arjun -u {url} -oJ {arjun_out} --rate-limit 30 -q",
                timeout=120, silent=True
            )
            if arjun_out.exists():
                try:
                    data = json.loads(arjun_out.read_text())
                    for ep, params in data.items():
                        for p in params:
                            all_params.add(p)
                        all_urls.add(ep)
                except Exception:
                    pass

    # ── GF Pattern matching ────────────────────────────────────────────────────
    if require_tool("gf"):
        log.info("Running gf patterns on all URLs...")
        all_urls_file = phase_dir / "all_urls_for_gf.txt"
        write_lines(all_urls_file, sorted(all_urls))
        gf_dir = phase_dir / "gf_patterns"
        gf_dir.mkdir(exist_ok=True)
        for pattern in GF_PATTERNS:
            gf_out = gf_dir / f"{pattern}.txt"
            run(
                f"cat {all_urls_file} | gf {pattern} > {gf_out}",
                timeout=60, shell=True, silent=True
            )
            hits = read_lines(gf_out)
            if hits:
                log.found(f"gf/{pattern}", f"{len(hits)} URLs")
        log.success("GF patterns complete")

    # ── Extract parameters from all URLs ──────────────────────────────────────
    log.info("Extracting unique parameters...")
    for url in all_urls:
        try:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            all_params.update(params.keys())
        except Exception:
            pass

    # Add params from wordlist
    params_wl = output_dir.parent.parent / "wordlists" / "parameters.txt"
    if not params_wl.exists():
        import os
        params_wl = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))) / "wordlists" / "parameters.txt"
    if params_wl.exists():
        all_params.update(read_lines(params_wl)[:5000])

    # Filter interesting extensions
    interesting_urls = [
        u for u in all_urls
        if any(ext in u.lower() for exts in INTERESTING_EXTENSIONS.values() for ext in exts)
    ]
    log.found("Interesting URLs", str(len(interesting_urls)))

    # ── Email extraction ───────────────────────────────────────────────────────
    emails: Set[str] = set()
    for url in list(all_urls)[:200]:
        r = http_get(url, timeout=8)
        if r:
            for match in re.finditer(
                    r"\b[a-zA-Z0-9._%+\-]+@" + re.escape(domain) + r"\b",
                    r.text, re.IGNORECASE):
                emails.add(match.group(0).lower())
        rl.wait()
    findings["emails"] = sorted(emails)

    # ── Save results ──────────────────────────────────────────────────────────
    all_urls_sorted = sorted(all_urls)
    findings["urls_crawled"] = all_urls_sorted
    findings["parameters"]   = sorted(all_params)

    write_lines(phase_dir / "all_urls.txt", all_urls_sorted)
    write_lines(phase_dir / "parameters.txt", sorted(all_params))
    write_lines(phase_dir / "interesting_urls.txt", interesting_urls)
    write_lines(phase_dir / "js_files.txt", sorted(js_file_urls))
    write_lines(phase_dir / "emails.txt", sorted(emails))

    # Write live_urls.txt for use in later phases
    http_urls = [u for u in all_urls_sorted if u.startswith("http")]
    base_urls  = {urllib.parse.urlparse(u).scheme + "://" + urllib.parse.urlparse(u).netloc
                  for u in http_urls if urllib.parse.urlparse(u).netloc}
    write_lines(output_dir / "live_urls.txt",
                sorted(base_urls | set(read_lines(output_dir / "live_urls.txt"))))

    save_json(phase_dir / "phase_06_results.json", findings)
    log.success(
        f"Phase 06 complete — {len(all_urls_sorted)} URLs · "
        f"{len(all_params)} params · {len(js_file_urls)} JS files · "
        f"{len(emails)} emails"
    )
    return findings
