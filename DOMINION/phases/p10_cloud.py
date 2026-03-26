#!/usr/bin/env python3
"""
DOMINION - Phase 10: Cloud & Infrastructure
S3 bucket enumeration · Azure/GCP asset discovery · Cloud misconfiguration
CDN bypass · ASN range · IP history · Firebase/Heroku/Vercel exposure
"""

import re
from pathlib import Path
from typing import Any, Dict, List

from core.config import get_config
from core.logger import get_logger
from core.runner import run, require_tool
from core.utils  import save_json, read_lines, http_get, RateLimiter

PHASE_NUM  = 10
PHASE_NAME = "Cloud & Infrastructure"
PHASE_DESC = "S3 · Azure Blob · GCS · Firebase · Cloudinary · CDN Origin · IP history"

S3_PATTERNS = [
    "{domain}",
    "{domain}-backup",
    "{domain}-assets",
    "{domain}-static",
    "{domain}-media",
    "{domain}-uploads",
    "{domain}-files",
    "{domain}-dev",
    "{domain}-staging",
    "{base}",
    "{base}-bucket",
    "{base}-data",
    "{base}-backup",
    "{base}-prod",
    "{base}-s3",
    "{base}.s3",
]

AZURE_SUFFIXES = [
    ".blob.core.windows.net",
    ".azurewebsites.net",
    ".cloudapp.azure.com",
    ".azurecontainer.io",
]

GCP_PATTERNS = [
    "storage.googleapis.com/{domain}",
    "storage.googleapis.com/{base}",
    "{base}.appspot.com",
    "{base}.firebaseio.com",
]

FIREBASE_TESTS = [
    "{base}.firebaseio.com/.json",
    "{base}-default-rtdb.firebaseio.com/.json",
]

CLOUDINARY_PATTERNS = [
    "https://res.cloudinary.com/{base}",
]


def check_s3(bucket_name: str, rl: RateLimiter) -> Dict:
    """Test if an S3 bucket exists and is open."""
    urls = [
        f"https://{bucket_name}.s3.amazonaws.com/",
        f"https://s3.amazonaws.com/{bucket_name}/",
    ]
    for url in urls:
        resp = http_get(url, timeout=10)
        if resp:
            if resp.status_code == 200:
                return {"bucket": bucket_name, "url": url, "status": "OPEN", "code": 200}
            elif resp.status_code == 403:
                return {"bucket": bucket_name, "url": url, "status": "EXISTS_PRIVATE", "code": 403}
            elif resp.status_code == 301:
                return {"bucket": bucket_name, "url": url, "status": "REDIRECT", "code": 301}
        rl.wait()
    return {}


def check_firebase(base: str, rl: RateLimiter) -> Dict:
    """Test Firebase real-time database exposure."""
    for url_tpl in FIREBASE_TESTS:
        url = url_tpl.format(base=base)
        resp = http_get(url, timeout=10)
        if resp:
            if resp.status_code == 200 and resp.text not in ["null", ""]:
                return {"url": url, "status": "OPEN", "data_preview": resp.text[:200]}
            elif resp.status_code == 401:
                return {"url": url, "status": "EXISTS_AUTH_REQUIRED"}
        rl.wait()
    return {}


def run_phase(domain: str, output_dir: Path, prev_data: dict = None) -> Dict[str, Any]:
    log  = get_logger()
    cfg  = get_config()
    rl   = RateLimiter(calls_per_second=2.0)
    prev = prev_data or {}

    phase_dir = output_dir / "phase_10_cloud"
    phase_dir.mkdir(parents=True, exist_ok=True)

    base = domain.split(".")[0]

    findings: Dict[str, Any] = {
        "domain":         domain,
        "s3_buckets":     [],
        "azure_storage":  [],
        "gcp_buckets":    [],
        "firebase":       [],
        "cdn_origins":    [],
        "ip_history":     [],
        "exposed_cloud":  [],
    }

    # ── S3 Bucket Enum ─────────────────────────────────────────────────────────
    log.info("Enumerating S3 buckets...")
    bucket_names = set()
    for pattern in S3_PATTERNS:
        bucket_names.add(pattern.format(domain=domain, base=base))

    # Also check from JS files / URLs
    crawled = read_lines(output_dir / "phase_06_crawling" / "all_urls.txt")
    s3_regex = re.compile(r"[\w\-\.]+\.s3[\.\-][\w\-]+\.amazonaws\.com|s3\.amazonaws\.com/[\w\-\.]+")
    for url in crawled:
        for m in s3_regex.findall(url):
            bname = m.split(".")[0] if ".s3" in m else m.split("/")[-1]
            bucket_names.add(bname)

    log.info(f"Testing {len(bucket_names)} S3 bucket names...")
    for bname in bucket_names:
        result = check_s3(bname, rl)
        if result:
            findings["s3_buckets"].append(result)
            if result["status"] == "OPEN":
                log.warning(f"🪣 OPEN S3 BUCKET: {result['url']}")
                findings["exposed_cloud"].append(result)
            elif result["status"] == "EXISTS_PRIVATE":
                log.found("Private S3", bname)

    if require_tool("cloudbrute"):
        log.info("Running cloudbrute for extended cloud storage enum...")
        cb_out = phase_dir / "cloudbrute.txt"
        rc, stdout, _ = run(
            f"cloudbrute -d {domain} -k {cfg.wordlist_dirs} -o {cb_out} -t {cfg.threads} -q",
            timeout=300,
        )
        if stdout:
            for line in stdout.splitlines():
                if "http" in line:
                    findings["s3_buckets"].append({"url": line.strip(), "source": "cloudbrute"})
                    log.found("Cloud storage", line.strip())

    # ── Azure Blob ────────────────────────────────────────────────────────────
    log.info("Checking Azure Blob storage...")
    azure_names = [base, domain.replace(".", "-"), base + "storage"]
    for name in azure_names:
        for suffix in AZURE_SUFFIXES:
            url = f"https://{name}{suffix}"
            resp = http_get(url, timeout=10)
            if resp and resp.status_code in [200, 403, 400]:
                entry = {
                    "url":    url,
                    "status": resp.status_code,
                    "type":   "azure",
                }
                findings["azure_storage"].append(entry)
                if resp.status_code == 200:
                    log.warning(f"Azure exposed: {url}")
                    findings["exposed_cloud"].append(entry)
                else:
                    log.found("Azure asset", url)
            rl.wait()

    # ── Firebase ──────────────────────────────────────────────────────────────
    log.info("Checking Firebase databases...")
    firebase_bases = [base, domain.replace(".", "-"), base + "-app", base + "-prod"]
    for fb_base in firebase_bases:
        result = check_firebase(fb_base, rl)
        if result:
            findings["firebase"].append({**result, "base": fb_base})
            if result["status"] == "OPEN":
                log.warning(f"🔥 OPEN FIREBASE: {result['url']} — {result.get('data_preview', '')[:60]}")
                findings["exposed_cloud"].append(result)
            else:
                log.found("Firebase", f"{fb_base} — {result['status']}")

    # ── GCP / App Engine ──────────────────────────────────────────────────────
    log.info("Checking GCP / App Engine...")
    for tpl in GCP_PATTERNS:
        url = "https://" + tpl.format(domain=domain, base=base)
        resp = http_get(url, timeout=10)
        if resp and resp.status_code not in [404, 410]:
            entry = {"url": url, "status": resp.status_code, "type": "gcp"}
            findings["gcp_buckets"].append(entry)
            if resp.status_code == 200:
                log.warning(f"GCP exposed: {url}")
                findings["exposed_cloud"].append(entry)
            else:
                log.found("GCP asset", f"[{resp.status_code}] {url}")
        rl.wait()

    # ── IP History (CDN origin reveal) ────────────────────────────────────────
    log.info("Looking up IP history to find CDN origin IPs...")
    ip_history_sources = [
        f"https://ipinfo.io/{domain}/json",
        f"https://api.hackertarget.com/reverseiplookup/?q={domain}",
        f"https://viewdns.info/iphistory/?domain={domain}",
        f"https://securitytrails.com/domain/{domain}/history/a",
    ]
    for src_url in ip_history_sources[:2]:
        resp = http_get(src_url, timeout=15)
        if resp and resp.status_code == 200:
            ips = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", resp.text)
            for ip in set(ips):
                if not ip.startswith(("127.", "10.", "192.168.", "172.")):
                    findings["ip_history"].append(ip)
                    log.found("Historical IP", ip)
        rl.wait()

    # ── CDN Origin Detection ──────────────────────────────────────────────────
    log.info("Attempting CDN origin bypass...")
    live_hosts = prev.get("live_hosts", [])
    for host in live_hosts[:10]:
        url    = host.get("url", "")
        cdn    = host.get("cdn", "")
        if cdn and url:
            for hist_ip in findings["ip_history"][:5]:
                resp = http_get(
                    f"https://{hist_ip}",
                    headers={"Host": domain},
                    timeout=10,
                )
                if resp and resp.status_code in [200, 301, 302]:
                    findings["cdn_origins"].append({
                        "domain": domain,
                        "origin_ip": hist_ip,
                        "cdn": cdn,
                        "status": resp.status_code,
                    })
                    log.warning(f"CDN Origin leaked: {domain} → {hist_ip} ({cdn})")
            rl.wait()

    # ── Save ──────────────────────────────────────────────────────────────────
    save_json(phase_dir / "phase_10_results.json", findings)
    log.success(
        f"Phase 10 complete — "
        f"{len(findings['s3_buckets'])} S3 | "
        f"{len(findings['firebase'])} Firebase | "
        f"{len(findings['exposed_cloud'])} exposed"
    )
    return findings
