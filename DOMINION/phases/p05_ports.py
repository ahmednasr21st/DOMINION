#!/usr/bin/env python3
"""
DOMINION - Phase 05: Port Scanning (EXPANDED)
naabu fast scan · masscan · nmap service+version+script detection ·
DEFAULT CREDENTIAL TESTING on discovered services ·
Redis/MongoDB/Elasticsearch/Memcached/Docker/Kubernetes/Jupyter no-auth checks ·
Banner grabbing · SSL/TLS service analysis
"""

import json
import socket
import ssl
import time
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

from core.config import get_config
from core.logger import get_logger
from core.runner import run, require_tool
from core.utils  import save_json, read_lines, write_lines, http_get, dedup, RateLimiter

PHASE_NUM  = 5
PHASE_NAME = "Port Scanning & Service Analysis"
PHASE_DESC = "naabu · masscan · nmap · default creds · Redis/Mongo/ES/Docker/K8s exposure"

INTERESTING_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    69: "TFTP", 79: "Finger", 80: "HTTP", 110: "POP3", 111: "portmap",
    135: "MSRPC", 137: "NetBIOS", 139: "NetBIOS-SMB", 143: "IMAP",
    161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 512: "rexec",
    513: "rlogin", 514: "rsh", 554: "RTSP", 636: "LDAPS",
    873: "rsync", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1099: "Java-RMI", 1433: "MSSQL", 1521: "Oracle",
    1883: "MQTT", 2049: "NFS", 2375: "Docker-API-UNENCRYPTED",
    2376: "Docker-API-TLS", 2379: "etcd", 2380: "etcd-peer",
    3000: "Grafana/NodeJS", 3268: "LDAP-GC", 3306: "MySQL",
    3389: "RDP", 4040: "Spark-UI", 4848: "GlassFish",
    5000: "Flask/Docker-Registry", 5432: "PostgreSQL",
    5601: "Kibana", 5672: "RabbitMQ", 5900: "VNC",
    6379: "Redis", 6443: "Kubernetes-API",
    7001: "WebLogic", 7077: "Spark", 8009: "AJP",
    8080: "HTTP-Alt", 8161: "ActiveMQ", 8443: "HTTPS-Alt",
    8500: "Consul", 8888: "Jupyter", 8983: "Solr",
    9000: "SonarQube/PHP-FPM", 9090: "Prometheus",
    9200: "Elasticsearch", 9300: "Elasticsearch-Transport",
    10250: "Kubernetes-Kubelet", 10255: "Kubernetes-Readonly",
    11211: "Memcached", 15672: "RabbitMQ-HTTP",
    27017: "MongoDB", 27018: "MongoDB", 50070: "Hadoop-NameNode",
    50075: "Hadoop-DataNode", 61616: "ActiveMQ",
}


def check_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        return result == 0
    except Exception:
        return False


def grab_banner(host: str, port: int, timeout: float = 3.0) -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = s.recv(1024).decode("utf-8", errors="replace")
        s.close()
        return banner.strip()[:300]
    except Exception:
        return ""


def check_redis_noauth(host: str, port: int = 6379) -> Dict:
    """Check Redis for unauthenticated access."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, port))
        s.send(b"PING\r\n")
        resp = s.recv(128).decode("utf-8", errors="replace")
        s.close()
        if "+PONG" in resp:
            # Try INFO command
            s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s2.settimeout(5)
            s2.connect((host, port))
            s2.send(b"INFO server\r\n")
            info = s2.recv(4096).decode("utf-8", errors="replace")
            s2.close()
            return {"vulnerable": True, "host": host, "port": port,
                    "detail": "UNAUTHENTICATED REDIS", "info": info[:300]}
    except Exception:
        pass
    return {}


def check_mongodb_noauth(host: str, port: int = 27017) -> Dict:
    """Check MongoDB for unauthenticated access."""
    try:
        import subprocess
        result = subprocess.run(
            ["mongosh", "--host", host, "--port", str(port), "--eval",
             "db.runCommand({listDatabases:1})", "--quiet", "--norc"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and "databases" in result.stdout.lower():
            return {"vulnerable": True, "host": host, "port": port,
                    "detail": "UNAUTHENTICATED MONGODB", "output": result.stdout[:300]}
    except Exception:
        pass
    # Raw check
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, port))
        # MongoDB wire protocol isMaster query (minimal)
        query = b"\x41\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x1b\x00\x00\x00\x01isMaster\x00\x00\x00\x00\x00\x00\x00\xf0\x3f\x00"
        s.send(query)
        resp = s.recv(512)
        s.close()
        if resp and len(resp) > 20:
            return {"vulnerable": True, "host": host, "port": port,
                    "detail": "MONGODB OPEN (raw check)"}
    except Exception:
        pass
    return {}


def check_elasticsearch_noauth(host: str, port: int = 9200) -> Dict:
    """Check Elasticsearch for unauthenticated access."""
    resp = http_get(f"http://{host}:{port}/", timeout=8)
    if resp and resp.status_code == 200:
        try:
            data = resp.json()
            if "cluster_name" in data or "version" in data:
                # Check indices
                indices_resp = http_get(f"http://{host}:{port}/_cat/indices?v", timeout=8)
                indices = indices_resp.text[:500] if indices_resp else ""
                return {"vulnerable": True, "host": host, "port": port,
                        "detail": "UNAUTHENTICATED ELASTICSEARCH",
                        "cluster": data.get("cluster_name", ""),
                        "version": data.get("version", {}).get("number", ""),
                        "indices": indices}
        except Exception:
            pass
    return {}


def check_kibana_noauth(host: str, port: int = 5601) -> Dict:
    resp = http_get(f"http://{host}:{port}/api/status", timeout=8)
    if resp and resp.status_code == 200:
        return {"vulnerable": True, "host": host, "port": port,
                "detail": "UNAUTHENTICATED KIBANA"}
    return {}


def check_memcached_noauth(host: str, port: int = 11211) -> Dict:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, port))
        s.send(b"stats\r\n")
        resp = s.recv(2048).decode("utf-8", errors="replace")
        s.close()
        if "STAT " in resp:
            return {"vulnerable": True, "host": host, "port": port,
                    "detail": "UNAUTHENTICATED MEMCACHED", "stats": resp[:300]}
    except Exception:
        pass
    return {}


def check_docker_api(host: str, port: int = 2375) -> Dict:
    resp = http_get(f"http://{host}:{port}/version", timeout=8)
    if resp and resp.status_code == 200:
        try:
            data = resp.json()
            if "ApiVersion" in data or "Version" in data:
                # List containers
                c_resp = http_get(f"http://{host}:{port}/containers/json", timeout=8)
                containers = c_resp.json() if c_resp and c_resp.status_code == 200 else []
                return {"vulnerable": True, "host": host, "port": port,
                        "detail": "UNAUTHENTICATED DOCKER API ⚠️ CRITICAL",
                        "version": data.get("Version", ""),
                        "containers": len(containers)}
        except Exception:
            pass
    return {}


def check_kubernetes_api(host: str, port: int = 6443) -> Dict:
    resp = http_get(f"https://{host}:{port}/api/v1/namespaces", timeout=10, verify=False)
    if resp and resp.status_code == 200:
        return {"vulnerable": True, "host": host, "port": port,
                "detail": "UNAUTHENTICATED KUBERNETES API ⚠️ CRITICAL"}
    # Anonymous access check
    resp2 = http_get(f"https://{host}:{port}/version", timeout=8, verify=False)
    if resp2 and resp2.status_code == 200:
        return {"vulnerable": True, "host": host, "port": port,
                "detail": "K8s API accessible (version endpoint exposed)",
                "partial": True}
    return {}


def check_kubernetes_kubelet(host: str, port: int = 10255) -> Dict:
    resp = http_get(f"http://{host}:{port}/pods", timeout=8)
    if resp and resp.status_code == 200:
        return {"vulnerable": True, "host": host, "port": port,
                "detail": "UNAUTHENTICATED KUBELET READ-ONLY PORT ⚠️"}
    return {}


def check_jupyter_noauth(host: str, port: int = 8888) -> Dict:
    resp = http_get(f"http://{host}:{port}/api/kernels", timeout=8)
    if resp and resp.status_code == 200:
        return {"vulnerable": True, "host": host, "port": port,
                "detail": "UNAUTHENTICATED JUPYTER NOTEBOOK ⚠️ RCE POSSIBLE"}
    resp2 = http_get(f"http://{host}:{port}/tree", timeout=8)
    if resp2 and resp2.status_code == 200 and "jupyter" in resp2.text.lower():
        return {"vulnerable": True, "host": host, "port": port,
                "detail": "OPEN JUPYTER DASHBOARD"}
    return {}


def check_consul_noauth(host: str, port: int = 8500) -> Dict:
    resp = http_get(f"http://{host}:{port}/v1/catalog/services", timeout=8)
    if resp and resp.status_code == 200:
        return {"vulnerable": True, "host": host, "port": port,
                "detail": "UNAUTHENTICATED CONSUL API"}
    return {}


def check_etcd_noauth(host: str, port: int = 2379) -> Dict:
    resp = http_get(f"http://{host}:{port}/v3/keys", timeout=8)
    if resp and resp.status_code == 200:
        return {"vulnerable": True, "host": host, "port": port,
                "detail": "UNAUTHENTICATED etcd ⚠️ CRITICAL — all cluster secrets exposed"}
    resp2 = http_get(f"http://{host}:{port}/version", timeout=8)
    if resp2 and resp2.status_code == 200:
        return {"vulnerable": True, "host": host, "port": port,
                "detail": "etcd version endpoint exposed", "partial": True}
    return {}


def check_ftp_anonymous(host: str, port: int = 21) -> Dict:
    try:
        import ftplib
        ftp = ftplib.FTP(timeout=8)
        ftp.connect(host, port)
        ftp.login("anonymous", "anonymous@example.com")
        files = []
        ftp.retrlines("LIST", lambda l: files.append(l))
        ftp.quit()
        return {"vulnerable": True, "host": host, "port": port,
                "detail": "FTP ANONYMOUS LOGIN ALLOWED",
                "files_preview": files[:10]}
    except Exception:
        pass
    return {}


def check_rsync_noauth(host: str, port: int = 873) -> Dict:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, port))
        banner = s.recv(256).decode("utf-8", errors="replace")
        if "rsync" in banner.lower():
            s.send(b"\n")
            resp = s.recv(2048).decode("utf-8", errors="replace")
            s.close()
            return {"vulnerable": True, "host": host, "port": port,
                    "detail": "RSYNC OPEN", "modules": resp[:300]}
    except Exception:
        pass
    return {}


def check_prometheus_noauth(host: str, port: int = 9090) -> Dict:
    resp = http_get(f"http://{host}:{port}/api/v1/targets", timeout=8)
    if resp and resp.status_code == 200 and "data" in resp.text:
        return {"vulnerable": True, "host": host, "port": port,
                "detail": "UNAUTHENTICATED PROMETHEUS — internal infra exposed"}
    return {}


def check_rabbitmq_noauth(host: str, port: int = 15672) -> Dict:
    import base64
    for creds in [("guest", "guest"), ("admin", "admin"), ("rabbitmq", "rabbitmq")]:
        b64 = base64.b64encode(f"{creds[0]}:{creds[1]}".encode()).decode()
        resp = http_get(f"http://{host}:{port}/api/overview",
                        headers={"Authorization": f"Basic {b64}"}, timeout=8)
        if resp and resp.status_code == 200:
            return {"vulnerable": True, "host": host, "port": port,
                    "detail": f"RABBITMQ DEFAULT CREDS: {creds[0]}:{creds[1]}"}
    return {}


def check_solr_noauth(host: str, port: int = 8983) -> Dict:
    resp = http_get(f"http://{host}:{port}/solr/admin/cores?action=STATUS", timeout=8)
    if resp and resp.status_code == 200 and "responseHeader" in resp.text:
        return {"vulnerable": True, "host": host, "port": port,
                "detail": "UNAUTHENTICATED SOLR ADMIN"}
    return {}


def check_hadoop_noauth(host: str, port: int = 50070) -> Dict:
    resp = http_get(f"http://{host}:{port}/webhdfs/v1/?op=LISTSTATUS", timeout=8)
    if resp and resp.status_code in [200, 403]:
        return {"vulnerable": True, "host": host, "port": port,
                "detail": "HADOOP NAMENODE UI EXPOSED"}
    return {}


def check_phpmyadmin(host: str, port: int = 80) -> Dict:
    for path in ["/phpmyadmin", "/phpMyAdmin", "/pma", "/phpmyadmin2"]:
        resp = http_get(f"http://{host}:{port}{path}", timeout=8)
        if resp and resp.status_code == 200 and "phpmyadmin" in resp.text.lower():
            return {"vulnerable": True, "host": host, "port": port,
                    "detail": f"phpMyAdmin exposed at {path}"}
    return {}


def check_weblogic(host: str, port: int = 7001) -> Dict:
    resp = http_get(f"http://{host}:{port}/console/login/LoginForm.jsp", timeout=8)
    if resp and resp.status_code == 200 and "weblogic" in resp.text.lower():
        # Check T3 protocol exposure
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((host, port))
            s.send(b"t3 12.2.1\nAS:255\nHL:19\nMS:10000000\n\n")
            resp_t3 = s.recv(256).decode("utf-8", errors="replace")
            s.close()
            if "HELO" in resp_t3:
                return {"vulnerable": True, "host": host, "port": port,
                        "detail": "WEBLOGIC console + T3 protocol exposed ⚠️"}
        except Exception:
            pass
        return {"vulnerable": True, "host": host, "port": port,
                "detail": "WEBLOGIC Admin Console exposed"}
    return {}


def check_activemq_noauth(host: str, port: int = 8161) -> Dict:
    import base64
    for creds in [("admin", "admin"), ("admin", "password")]:
        b64 = base64.b64encode(f"{creds[0]}:{creds[1]}".encode()).decode()
        resp = http_get(f"http://{host}:{port}/admin",
                        headers={"Authorization": f"Basic {b64}"}, timeout=8)
        if resp and resp.status_code == 200 and "activemq" in resp.text.lower():
            return {"vulnerable": True, "host": host, "port": port,
                    "detail": f"ACTIVEMQ DEFAULT CREDS: {creds[0]}:{creds[1]}"}
    return {}


def check_snmp(host: str, port: int = 161) -> Dict:
    """SNMP community string check."""
    try:
        from subprocess import run as srun, PIPE
        for community in ["public", "private", "community", "manager"]:
            r = srun(["snmpwalk", "-v", "1", "-c", community, host, "1.3.6.1"],
                     capture_output=True, text=True, timeout=8)
            if r.returncode == 0 and r.stdout:
                return {"vulnerable": True, "host": host, "port": port,
                        "detail": f"SNMP community '{community}' works",
                        "output": r.stdout[:200]}
    except Exception:
        pass
    return {}



def check_weblogic_wrap(host: str, port: int) -> Dict:
    return check_weblogic(host, port)


SERVICE_CHECKS = {
    6379:  check_redis_noauth,
    27017: check_mongodb_noauth,
    9200:  check_elasticsearch_noauth,
    5601:  check_kibana_noauth,
    11211: check_memcached_noauth,
    2375:  check_docker_api,
    6443:  check_kubernetes_api,
    10255: check_kubernetes_kubelet,
    8888:  check_jupyter_noauth,
    8500:  check_consul_noauth,
    2379:  check_etcd_noauth,
    21:    check_ftp_anonymous,
    873:   check_rsync_noauth,
    9090:  check_prometheus_noauth,
    15672: check_rabbitmq_noauth,
    8983:  check_solr_noauth,
    50070: check_hadoop_noauth,
    7001:  check_weblogic_wrap,
    8161:  check_activemq_noauth,
    161:   check_snmp,
}



def _extract_ips(prev_data: dict, domain: str, subs_file: Path) -> Set[str]:
    ips: Set[str] = set()
    for h in prev_data.get("live_hosts", []):
        ip = h.get("ip", "")
        try:
            socket.inet_aton(ip)
            ips.add(ip)
        except Exception:
            pass
    subs = [domain] + read_lines(subs_file)[:150]
    for s in subs:
        try:
            ips.add(socket.gethostbyname(s))
        except Exception:
            pass
    return {ip for ip in ips if ip and not ip.startswith(("127.", "169.254."))}


def run_phase(domain: str, output_dir: Path, prev_data: dict = None) -> Dict[str, Any]:
    log  = get_logger()
    cfg  = get_config()
    rl   = RateLimiter(calls_per_second=3.0)
    prev = prev_data or {}

    phase_dir = output_dir / "phase_05_ports"
    phase_dir.mkdir(parents=True, exist_ok=True)

    ips = _extract_ips(prev, domain, output_dir / "subdomains.txt")
    log.info(f"Scanning {len(ips)} unique IPs...")

    findings: Dict[str, Any] = {
        "domain":            domain,
        "ips_scanned":       list(ips),
        "open_ports":        {},
        "services":          {},
        "interesting":       [],
        "critical_services": [],  # unauthenticated services
        "nmap_results":      {},
        "ssl_info":          {},
    }

    if not ips:
        log.warning("No IPs to scan — skipping port scan")
        save_json(phase_dir / "phase_05_results.json", findings)
        return findings

    ips_file = phase_dir / "ips.txt"
    write_lines(ips_file, list(ips))

    # ── masscan (ultra-fast) ───────────────────────────────────────────────────
    if require_tool("masscan"):
        log.info("Running masscan for ultra-fast port discovery...")
        masscan_out = phase_dir / "masscan.json"
        ports_arg   = "0-65535" if cfg.full_port_scan else "1-10000"
        rc, stdout, _ = run(
            f"masscan -iL {ips_file} -p {ports_arg} --rate {min(cfg.rate_limit, 10000)} "
            f"-oJ {masscan_out} --open-only",
            timeout=900,
        )
        if masscan_out.exists():
            try:
                masscan_data = json.loads("[" + masscan_out.read_text(encoding="utf-8").strip().rstrip(",") + "]")
                for entry in masscan_data:
                    ip   = entry.get("ip")
                    for port_data in entry.get("ports", []):
                        port = port_data.get("port")
                        if ip and port:
                            if ip not in findings["open_ports"]:
                                findings["open_ports"][ip] = []
                            findings["open_ports"][ip].append(port)
                            svc = INTERESTING_PORTS.get(port, "")
                            if svc:
                                log.found(f"{ip}:{port}", svc)
                                findings["interesting"].append({"ip": ip, "port": port, "service": svc})
            except Exception as e:
                log.debug(f"masscan parse error: {e}")
        log.success(f"masscan complete: {sum(len(v) for v in findings['open_ports'].values())} open ports")

    # ── naabu fallback ─────────────────────────────────────────────────────────
    if not findings["open_ports"] and require_tool("naabu"):
        log.info("Running naabu port discovery...")
        naabu_out = phase_dir / "naabu.txt"
        ports_arg = "1-65535" if cfg.full_port_scan else "1-10000"
        rc, stdout, _ = run(
            f"naabu -l {ips_file} -p {ports_arg} -o {naabu_out} "
            f"-silent -rate {cfg.rate_limit} -timeout 5",
            timeout=900,
        )
        for line in read_lines(naabu_out):
            if ":" in line:
                parts = line.rsplit(":", 1)
                if len(parts) == 2 and parts[1].isdigit():
                    ip, port = parts[0], int(parts[1])
                    findings["open_ports"].setdefault(ip, []).append(port)
                    svc = INTERESTING_PORTS.get(port, "")
                    if svc:
                        log.found(f"{ip}:{port}", svc)
                        findings["interesting"].append({"ip": ip, "port": port, "service": svc})
        log.success(f"naabu: {sum(len(v) for v in findings['open_ports'].values())} ports")

    # ── nmap deep scan ─────────────────────────────────────────────────────────
    if require_tool("nmap"):
        all_ports: Set[int] = set()
        for ports in findings["open_ports"].values():
            all_ports.update(ports)
        if not all_ports:
            all_ports = set(INTERESTING_PORTS.keys())

        log.info(f"Running nmap on {len(all_ports)} ports with script detection...")
        ports_str   = ",".join(str(p) for p in sorted(all_ports))
        nmap_xml    = phase_dir / "nmap.xml"
        nmap_txt    = phase_dir / "nmap.txt"
        rc, stdout, _ = run(
            f"nmap -sV -sC -O --script=banner,http-title,http-server-header,"
            f"ssl-cert,ssl-enum-ciphers,http-methods,http-auth-finder,"
            f"smtp-commands,ftp-anon,mongodb-info,redis-info,"
            f"mysql-empty-password,ms-sql-empty-password "
            f"-p {ports_str} -iL {ips_file} "
            f"-oX {nmap_xml} -oN {nmap_txt} "
            f"--open -T4 --max-retries 2 --host-timeout 300s",
            timeout=1800,
        )
        if nmap_txt.exists():
            import re
            nmap_content = nmap_txt.read_text(encoding="utf-8")
            findings["nmap_results"]["raw_text"] = nmap_content
            for line in nmap_content.splitlines():
                m = re.match(r"\s*(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line)
                if m:
                    port    = int(m.group(1))
                    service = m.group(2)
                    banner  = m.group(3).strip()
                    findings["services"][port] = {"service": service, "banner": banner[:150]}
                    log.found(f"Port {port}/tcp", f"{service} {banner[:60]}")
        log.success("nmap deep scan complete")

    # ── SSL/TLS Analysis ────────────────────────────────────────────────────────
    log.info("Analyzing SSL/TLS certificates on HTTPS ports...")
    https_ports = [443, 8443, 4443, 8080, 8888]
    for ip in list(ips)[:10]:
        for port in https_ports:
            if port in findings["open_ports"].get(ip, []) or port == 443:
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode   = ssl.CERT_NONE
                    conn = ctx.wrap_socket(
                        socket.socket(socket.AF_INET),
                        server_hostname=domain
                    )
                    conn.settimeout(8)
                    conn.connect((ip, port))
                    cert = conn.getpeercert()
                    conn.close()
                    findings["ssl_info"][f"{ip}:{port}"] = {
                        "subject":      dict(x[0] for x in cert.get("subject", [])),
                        "issuer":       dict(x[0] for x in cert.get("issuer", [])),
                        "valid_from":   cert.get("notBefore"),
                        "valid_to":     cert.get("notAfter"),
                        "san":          cert.get("subjectAltName", []),
                        "version":      cert.get("version"),
                    }
                    # Extract more subdomains from SAN
                    for _, san_val in cert.get("subjectAltName", []):
                        if domain in san_val:
                            log.found("SAN subdomain", san_val)
                except Exception:
                    pass

    # ── Default Credential & No-Auth Checks ───────────────────────────────────
    log.info("Checking for unauthenticated/default credential services...")
    critical_findings = []

    all_open = set()
    for ip, ports in findings["open_ports"].items():
        for p in ports:
            all_open.add((ip, p))

    # Also do targeted checks on common sensitive ports across all IPs
    for ip in list(ips)[:20]:
        for port, check_fn in SERVICE_CHECKS.items():
            # Only check if port is open (or do quick check for critical services)
            try:
                result = check_fn(ip, port)
                if result and result.get("vulnerable"):
                    critical_findings.append(result)
                    severity_label = "🔴 CRITICAL" if any(
                        kw in result["detail"] for kw in
                        ["CRITICAL", "RCE", "DOCKER", "KUBERNETES", "etcd"]
                    ) else "⚠️  HIGH"
                    log.warning(f"{severity_label}: {result['detail']} @ {ip}:{port}")
                rl.wait()
            except Exception as e:
                log.debug(f"Service check error {ip}:{port} — {e}")

    findings["critical_services"] = critical_findings

    if critical_findings:
        write_lines(
            phase_dir / "CRITICAL_unauthenticated_services.txt",
            [f"{r['host']}:{r['port']} — {r['detail']}" for r in critical_findings]
        )
        log.warning(f"⚠️  {len(critical_findings)} UNAUTHENTICATED SERVICES FOUND!")

    # ── Save ───────────────────────────────────────────────────────────────────
    save_json(phase_dir / "phase_05_results.json", findings)
    total_ports = sum(len(v) for v in findings["open_ports"].values())
    log.success(
        f"Phase 05 complete — {total_ports} open ports · "
        f"{len(findings['critical_services'])} critical · "
        f"{len(findings['interesting'])} interesting"
    )
    return findings
