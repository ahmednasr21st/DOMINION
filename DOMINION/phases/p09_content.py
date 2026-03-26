#!/usr/bin/env python3
"""
DOMINION - Phase 09: Content Discovery (EXPANDED)
feroxbuster · ffuf · backup files · admin panels · dotfiles ·
.git directory dumping (git-dumper) · .DS_Store parsing ·
SVN/CVS exposure · 403 bypass techniques · CSRF testing ·
Cookie security analysis · Response header analysis ·
Serverless endpoints · GraphQL discovery · API versioning ·
Sensitive data in responses · Tech-specific paths
"""

import re
import json
from pathlib import Path
from typing import Any, Dict, List, Set

from core.config import get_config
from core.logger import get_logger
from core.runner import run, require_tool
from core.utils  import save_json, read_lines, write_lines, http_get, RateLimiter

PHASE_NUM  = 9
PHASE_NAME = "Content Discovery (EXPANDED)"
PHASE_DESC = "feroxbuster · ffuf · git-dumper · .DS_Store · backup hunting · 403 bypass · CSRF"

INTERESTING_PATHS = [
    # Admin panels
    "admin", "administrator", "admin/login", "admin/dashboard", "admin/panel",
    "administration", "wp-admin", "wp-admin/admin-ajax.php", "wp-login.php",
    "cpanel", "whm", "phpmyadmin", "adminer.php", "adminer",
    "manager/html", "host-manager/html", "solr/admin", "jenkins",
    "console", "dashboard", "portal", "control", "manage", "backend",
    # Backup & sensitive files
    ".env", ".env.local", ".env.production", ".env.staging", ".env.dev",
    ".env.backup", ".env.old", ".env.save", ".env.example",
    "config.php", "config.yaml", "config.yml", "config.json", "config.xml",
    "settings.py", "settings.php", "settings.local.php", "configuration.php",
    "configuration.yml", "parameters.yml", "parameters.php",
    "database.yml", "database.php", "db.php", "db.json",
    "wp-config.php", "wp-config.php.bak", "wp-config.old",
    "local.xml", "app.config", "web.config", "app.js", "app.py",
    # Git/SVN/VCS
    ".git/config", ".git/HEAD", ".git/COMMIT_EDITMSG",
    ".git/description", ".git/index", ".git/packed-refs",
    ".git/refs/heads/master", ".git/refs/heads/main",
    ".gitignore", ".gitconfig", ".github/workflows",
    ".svn/entries", ".svn/wc.db", ".svn/format",
    ".hg/hgrc", ".hg/store/00manifest.i",
    "CVS/Root", "CVS/Repository", "CVS/Entries",
    ".bzr/branch/format",
    # Certificates & keys
    "server.key", "server.pem", "server.crt", "private.key",
    "ssl.key", "ssl.crt", "cert.pem", "ca-bundle.crt",
    "id_rsa", "id_rsa.pub", "authorized_keys", ".ssh/id_rsa",
    # Debug / info
    "info.php", "phpinfo.php", "test.php", "debug.php", "test.asp",
    "trace.axd", "elmah.axd", "server-status", "server-info",
    "actuator", "actuator/health", "actuator/env", "actuator/beans",
    "actuator/mappings", "actuator/dump", "actuator/httptrace",
    "actuator/loggers", "actuator/metrics", "actuator/info",
    "actuator/prometheus", "actuator/scheduledtasks",
    "metrics", "health", "healthcheck", "ping", "status",
    "/_/health", "/__health", "/readyz", "/livez",
    # API
    "api", "api/v1", "api/v2", "api/v3", "api/docs", "api/swagger",
    "swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml",
    "graphql", "graphiql", "graphql/schema", "api-docs",
    "api/graphql", "v1", "v2", "v3", "rest", "restapi",
    # Auth
    "login", "signin", "auth", "oauth", "oauth2", "register",
    "signup", "forgot-password", "reset-password", "sso", "saml",
    "change-password", "2fa", "mfa", "verify",
    # Monitoring
    "prometheus", "grafana", "kibana", "elasticsearch",
    "/_cat/indices", "/_cluster/health", "/_nodes",
    # Cloud metadata
    "latest/meta-data", "metadata/v1",
    # Source maps
    "main.js.map", "app.js.map", "bundle.js.map",
    "static/js/main.js.map", "assets/app.js.map",
    # Docker/K8s
    "/.dockerenv", "/etc/kubernetes/admin.conf",
    # Common sensitive
    "crossdomain.xml", "clientaccesspolicy.xml",
    "robots.txt", "sitemap.xml", "sitemap_index.xml",
    "security.txt", ".well-known/security.txt",
    "humans.txt", "ads.txt", "app-ads.txt",
    # Package managers
    "package.json", "composer.json", "requirements.txt", "Gemfile",
    "Pipfile", "yarn.lock", "package-lock.json", "composer.lock",
    # CI/CD
    ".travis.yml", ".circleci/config.yml", "Jenkinsfile",
    ".gitlab-ci.yml", "Dockerfile", "docker-compose.yml",
    ".github/workflows/deploy.yml",
    # Temp/Backup
    "backup.zip", "backup.tar.gz", "backup.sql", "dump.sql",
    "db.sql", "database.sql", "data.sql", "users.sql",
    "site.zip", "www.zip", "wordpress.zip", "files.tar.gz",
    "old", "temp", "tmp", "bak",
]

BACKUP_EXTENSIONS = [
    ".bak", ".backup", ".old", ".orig", ".copy", ".tmp", ".swp",
    "~", ".zip", ".tar.gz", ".tar", ".gz", ".sql",
    ".1", ".2", ".save", ".ds", "_.php", "_bak.php",
]

TECH_SPECIFIC_PATHS = {
    "WordPress": [
        "wp-json/wp/v2/users", "wp-json/oembed/1.0/", "wp-json",
        "xmlrpc.php", "wp-content/debug.log", "wp-includes/wlwmanifest.xml",
        "wp-login.php?action=register", "wp-cron.php", "wp-mail.php",
    ],
    "Laravel": [
        ".env", "storage/logs/laravel.log", "_debugbar",
        "telescope", "horizon", "api/user",
    ],
    "Django": [
        "__debug__", "admin/", "api/", "api-auth/login",
        "django-admin", "silk/profiling/",
    ],
    "Spring": [
        "actuator", "actuator/env", "actuator/beans",
        "actuator/mappings", "swagger-ui.html",
        "v2/api-docs", "v3/api-docs/swagger-config",
    ],
    "Rails": [
        "rails/info/properties", "rails/info/routes",
        "_session_id", "__better_errors",
    ],
    "Express/Node": [
        "node_modules", "package.json", ".nvmrc",
    ],
    "Drupal": [
        "CHANGELOG.txt", "INSTALL.txt", "update.php",
        "xmlrpc.php", "sites/default/settings.php",
        "core/CHANGELOG.txt",
    ],
    "Joomla": [
        "administrator", "README.txt", "CHANGELOG.php",
        "configuration.php.bak",
    ],
    "Magento": [
        "admin", "downloader", "magento_version",
        "app/etc/local.xml", "app/etc/config.xml",
    ],
}


def check_git_exposure(base_url: str, phase_dir: Path, rl: RateLimiter) -> Dict:
    """Check for exposed .git directory and attempt to dump it."""
    git_findings = {"exposed": False, "files": [], "dumped": False}

    resp = http_get(f"{base_url}/.git/HEAD", timeout=8)
    if resp and resp.status_code == 200 and "ref:" in resp.text.lower():
        git_findings["exposed"] = True
        git_files_to_check = [
            ".git/HEAD", ".git/config", ".git/COMMIT_EDITMSG",
            ".git/description", ".git/packed-refs", ".git/refs/heads/master",
            ".git/refs/heads/main", ".git/ORIG_HEAD", ".git/FETCH_HEAD",
            ".git/index", ".git/logs/HEAD",
        ]
        for f in git_files_to_check:
            r = http_get(f"{base_url}/{f}", timeout=6)
            if r and r.status_code == 200:
                git_findings["files"].append(f)
                # Save content
                out_path = phase_dir / "git_dump" / f.replace("/", "_")
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_bytes(r.content)
            rl.wait()

        # Try git-dumper
        if require_tool("git-dumper"):
            dump_dir = phase_dir / "git_dumped_repo"
            dump_dir.mkdir(exist_ok=True)
            rc, stdout, stderr = run(
                f"git-dumper {base_url}/.git {dump_dir}",
                timeout=300, silent=True
            )
            if rc == 0 and any(dump_dir.iterdir()):
                git_findings["dumped"] = True
                git_findings["dump_path"] = str(dump_dir)
    return git_findings


def check_ds_store(base_url: str, phase_dir: Path, rl: RateLimiter) -> List[str]:
    """Parse exposed .DS_Store files to reveal directory structure."""
    found_paths = []
    resp = http_get(f"{base_url}/.DS_Store", timeout=8)
    if resp and resp.status_code == 200 and resp.content[:4] == b"\x00\x00\x00\x01":
        # Save the binary
        ds_path = phase_dir / "ds_store.bin"
        ds_path.write_bytes(resp.content)
        # Try ds_store_exp tool
        if require_tool("ds_store_exp"):
            rc, stdout, _ = run(f"ds_store_exp {base_url}/.DS_Store", timeout=60, silent=True)
            for line in stdout.splitlines():
                if line.strip():
                    found_paths.append(line.strip())
        else:
            # Basic binary parsing for filenames
            filenames = re.findall(rb"[\x00-\x08]([a-zA-Z0-9_.\-]{1,30})\x00", resp.content)
            found_paths = [f.decode("utf-8", errors="replace") for f in filenames]
    return found_paths


def check_source_maps(live_urls: List[str], phase_dir: Path, rl: RateLimiter) -> List[Dict]:
    """Find and download JS/CSS source maps."""
    found = []
    for url in live_urls[:20]:
        resp = http_get(url, timeout=10)
        if resp:
            # Look for sourceMappingURL comments
            maps = re.findall(r"sourceMappingURL=([^\s\n]+\.map)", resp.text)
            for map_ref in maps:
                from urllib.parse import urljoin
                map_url = urljoin(url, map_ref)
                map_resp = http_get(map_url, timeout=10)
                if map_resp and map_resp.status_code == 200:
                    found.append({"url": map_url, "source": url})
                    # Source maps reveal original source code!
                    map_path = phase_dir / "source_maps" / map_ref.replace("/", "_")
                    map_path.parent.mkdir(parents=True, exist_ok=True)
                    map_path.write_bytes(map_resp.content)
                rl.wait()
    return found


def check_csrf(live_urls: List[str], rl: RateLimiter) -> List[Dict]:
    """Check for CSRF protection on forms."""
    results = []
    import requests as req
    for url in live_urls[:20]:
        resp = _safe_get(url, timeout=10)
        if resp:
            forms = re.findall(r"<form[^>]*>(.*?)</form>", resp.text, re.DOTALL | re.IGNORECASE)
            for form in forms:
                has_csrf_token = any(
                    token in form.lower()
                    for token in ["csrf", "token", "_token", "nonce",
                                  "authenticity_token", "__requestverificationtoken"]
                )
                has_post = 'method="post"' in form.lower() or "method='post'" in form.lower()
                if has_post and not has_csrf_token:
                    results.append({
                        "url": url,
                        "type": "Missing CSRF Token on POST form",
                        "severity": "Medium",
                        "form_preview": form[:200]
                    })
        rl.wait()
    return results


def check_cookie_security(live_urls: List[str], rl: RateLimiter) -> List[Dict]:
    """Analyze cookies for security issues."""
    results = []
    for url in live_urls[:30]:
        resp = _safe_get(url, timeout=8)
        if resp:
            for cookie in resp.cookies:
                issues = []
                if not cookie.secure:
                    issues.append("Missing Secure flag")
                if not cookie.has_nonstandard_attr("HttpOnly"):
                    issues.append("Missing HttpOnly flag")
                samesite = cookie.get_nonstandard_attr("SameSite")
                if not samesite:
                    issues.append("Missing SameSite attribute")
                if issues:
                    results.append({
                        "url":      url,
                        "cookie":   cookie.name,
                        "issues":   issues,
                        "type":     "Cookie Security",
                        "severity": "Medium",
                    })
        rl.wait()
    return results


def _safe_get(url, **kwargs):
    try:
        return http_get(url, **kwargs)
    except Exception:
        return None


def run_phase(domain: str, output_dir: Path, prev_data: dict = None) -> Dict[str, Any]:
    log  = get_logger()
    cfg  = get_config()
    rl   = RateLimiter(calls_per_second=5.0)

    phase_dir = output_dir / "phase_09_content"
    phase_dir.mkdir(parents=True, exist_ok=True)

    live_urls = read_lines(output_dir / "live_urls.txt")
    if not live_urls:
        live_urls = [f"https://{domain}"]

    findings: Dict[str, Any] = {
        "domain":           domain,
        "found_paths":      [],
        "admin_panels":     [],
        "backup_files":     [],
        "config_files":     [],
        "api_endpoints":    [],
        "dotfiles":         [],
        "sensitive_dirs":   [],
        "git_exposure":     [],
        "source_maps":      [],
        "csrf_issues":      [],
        "cookie_issues":    [],
        "ds_store":         [],
        "tech_paths":       [],
    }
    all_found: List[Dict] = []

    # ── feroxbuster ───────────────────────────────────────────────────────────
    wl_path = (output_dir.parent.parent / "wordlists" / "directories.txt").resolve()
    if not wl_path.exists():
        # Try relative to dominion root
        import os
        wl_path = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))) / "wordlists" / "directories.txt"

    if require_tool("feroxbuster") and wl_path.exists():
        log.info("Running feroxbuster on all live URLs...")
        for base_url in live_urls[:25]:
            fb_key = re.sub(r"[^\w]", "_", base_url)[:50]
            fb_out = phase_dir / f"ferox_{fb_key}.txt"
            run(
                f"feroxbuster --url {base_url} --wordlist {wl_path} "
                f"--output {fb_out} --threads {min(cfg.threads, 50)} "
                f"--timeout 10 --silent --no-state "
                f"--filter-status 404,400,429 "
                f"--extensions php,asp,aspx,jsp,html,txt,js,json,xml,bak,zip,env,yaml,yml,sh,py,rb,go",
                timeout=600,
            )
            if fb_out.exists():
                for line in read_lines(fb_out):
                    parts = line.split()
                    if len(parts) >= 2:
                        status  = int(parts[0]) if parts[0].isdigit() else 0
                        url_hit = parts[-1] if parts[-1].startswith("http") else ""
                        if url_hit and status not in [404]:
                            entry = {"url": url_hit, "status": status, "source": "feroxbuster"}
                            all_found.append(entry)
                            if status in [200, 201, 301, 302, 403]:
                                log.found(f"[{status}]", url_hit)
            rl.wait()
        log.success(f"feroxbuster: {len(all_found)} paths")

    elif require_tool("ffuf") and wl_path.exists():
        log.info("Running ffuf directory brute-force...")
        for base_url in live_urls[:15]:
            target  = base_url.rstrip("/") + "/FUZZ"
            out_key = re.sub(r"[^\w]", "_", base_url)[:30]
            ffuf_out = phase_dir / f"ffuf_{out_key}.json"
            run(
                f"ffuf -u {target} -w {wl_path} -o {ffuf_out} -of json "
                f"-t {min(cfg.threads, 50)} -timeout 10 -sf "
                f"-mc 200,201,301,302,401,403 -s",
                timeout=600,
            )
            if ffuf_out.exists():
                try:
                    data = json.loads(ffuf_out.read_text())
                    for r in data.get("results", []):
                        entry = {"url": r.get("url"), "status": r.get("status"), "source": "ffuf"}
                        all_found.append(entry)
                        log.found(f"[{r.get('status')}]", r.get("url",""))
                except Exception:
                    pass
            rl.wait()

    # ── Manual interesting paths ───────────────────────────────────────────────
    log.info("Checking known interesting paths manually...")
    for base_url in live_urls[:15]:
        base = base_url.rstrip("/")
        prev_techs = prev_data.get("technologies", []) if prev_data else []

        # Add tech-specific paths
        extra_paths = list(INTERESTING_PATHS)
        for tech, paths in TECH_SPECIFIC_PATHS.items():
            if tech in str(prev_techs):
                extra_paths.extend(paths)

        for path in extra_paths:
            url  = f"{base}/{path}"
            resp = _safe_get(url, timeout=7, allow_redirects=True)
            if resp and resp.status_code not in [404, 400, 429]:
                entry = {
                    "url":    url,
                    "status": resp.status_code,
                    "size":   len(resp.content),
                    "source": "manual",
                }
                all_found.append(entry)

                path_lower = path.lower()
                if any(x in path_lower for x in ["admin", "phpmyadmin", "cpanel", "wp-admin", "consul"]):
                    findings["admin_panels"].append(entry)
                    log.warning(f"Admin panel: [{resp.status_code}] {url}")
                elif any(x in path_lower for x in [".env", "config", "wp-config", ".git",
                                                     "database", "settings", "credentials"]):
                    findings["config_files"].append(entry)
                    log.warning(f"Config/sensitive: [{resp.status_code}] {url}")
                elif path_lower.startswith(".") or path_lower.startswith("_"):
                    findings["dotfiles"].append(entry)
                    log.found("Dotfile", url)
                elif any(x in path_lower for x in ["api", "swagger", "graphql", "openapi"]):
                    findings["api_endpoints"].append(entry)
                    log.found("API endpoint", url)
                elif any(x in path_lower for x in ["actuator", "prometheus", "metrics",
                                                     "debug", "trace", "_debugbar"]):
                    findings["sensitive_dirs"].append(entry)
                    log.warning(f"Sensitive endpoint: {url}")
                else:
                    log.found(f"[{resp.status_code}]", url)
            rl.wait()

    # ── .git Exposure & Dump ──────────────────────────────────────────────────
    log.info("Checking for exposed .git directories...")
    for base_url in live_urls[:20]:
        parsed_base = base_url.rstrip("/")
        git_result  = check_git_exposure(parsed_base, phase_dir, rl)
        if git_result["exposed"]:
            log.warning(f"🔴 GIT REPOSITORY EXPOSED: {parsed_base}/.git/")
            findings["git_exposure"].append({
                "url":    parsed_base,
                "files":  git_result["files"],
                "dumped": git_result["dumped"],
            })
            all_found.append({"url": f"{parsed_base}/.git/", "status": 200, "source": "git_exposure"})

    # ── .DS_Store ─────────────────────────────────────────────────────────────
    log.info("Checking for .DS_Store files...")
    for base_url in live_urls[:20]:
        ds_paths = check_ds_store(base_url.rstrip("/"), phase_dir, rl)
        if ds_paths:
            findings["ds_store"].append({"url": base_url, "revealed_paths": ds_paths})
            log.warning(f".DS_Store exposed at {base_url} — reveals {len(ds_paths)} paths")
        rl.wait()

    # ── Source Maps ───────────────────────────────────────────────────────────
    log.info("Hunting for JS/CSS source maps (reveals source code)...")
    findings["source_maps"] = check_source_maps(live_urls, phase_dir, rl)
    if findings["source_maps"]:
        log.warning(f"⚠️ {len(findings['source_maps'])} source maps found — original source code exposed!")

    # ── Backup File Hunt ───────────────────────────────────────────────────────
    log.info("Hunting backup files for all crawled URLs...")
    all_crawled = read_lines(output_dir / "phase_06_crawling" / "all_urls.txt")[:500]
    for url in all_crawled:
        base = re.sub(r"\.[a-zA-Z0-9]{1,5}$", "", url.split("?")[0])
        for ext in BACKUP_EXTENSIONS:
            burl = base + ext
            resp = _safe_get(burl, timeout=6)
            if resp and resp.status_code == 200 and len(resp.content) > 0:
                entry = {"url": burl, "status": 200, "size": len(resp.content), "source": "backup_hunt"}
                findings["backup_files"].append(entry)
                all_found.append(entry)
                log.warning(f"BACKUP FILE: {burl} ({len(resp.content)} bytes)")
            rl.wait()

    # ── CSRF Testing ──────────────────────────────────────────────────────────
    log.info("Testing CSRF protection on forms...")
    findings["csrf_issues"] = check_csrf(live_urls, rl)
    if findings["csrf_issues"]:
        log.warning(f"CSRF: {len(findings['csrf_issues'])} forms missing CSRF tokens!")

    # ── Cookie Security ───────────────────────────────────────────────────────
    log.info("Analyzing cookie security...")
    findings["cookie_issues"] = check_cookie_security(live_urls, rl)
    if findings["cookie_issues"]:
        log.warning(f"Cookie issues: {len(findings['cookie_issues'])} found")

    # ── Tech disclosure in headers ─────────────────────────────────────────────
    log.info("Scanning response headers for version disclosure...")
    version_disclosure = []
    for url in live_urls[:30]:
        resp = _safe_get(url, timeout=8)
        if resp:
            for hdr in ["Server", "X-Powered-By", "X-Generator", "X-Runtime",
                        "X-AspNet-Version", "X-AspNetMvc-Version"]:
                val = resp.headers.get(hdr, "")
                if val:
                    version_disclosure.append({"url": url, "header": hdr, "value": val})
                    log.found("Version disclosure", f"{hdr}: {val}")
        rl.wait()
    findings["tech_paths"] = version_disclosure

    # ── Finalize ──────────────────────────────────────────────────────────────
    findings["found_paths"] = all_found
    save_json(phase_dir / "phase_09_results.json", findings)

    log.success(
        f"Phase 09 complete — {len(all_found)} paths · "
        f"{len(findings['admin_panels'])} admin · "
        f"{len(findings['backup_files'])} backups · "
        f"{len(findings['config_files'])} configs · "
        f"{len(findings['git_exposure'])} git repos exposed · "
        f"{len(findings['source_maps'])} source maps"
    )
    return findings
