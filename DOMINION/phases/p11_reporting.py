#!/usr/bin/env python3
"""
DOMINION - Phase 11: HTML Report + Screenshots
Generates a professional HTML report with all findings, charts, and screenshots.
Uses gowitness / aquatone for screenshots, then embeds everything into one HTML file.
"""

import base64
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from core.config import get_config
from core.logger import get_logger
from core.runner import run, require_tool
from core.utils  import save_json, read_lines, write_lines, elapsed

PHASE_NUM  = 11
PHASE_NAME = "Screenshot & HTML Report"
PHASE_DESC = "gowitness · aquatone · Professional HTML report · Full findings summary"


# ─────────────────────────────────────────────────────────────────────────────
# Screenshot helpers
# ─────────────────────────────────────────────────────────────────────────────

def take_screenshots(live_urls: List[str], phase_dir: Path, cfg) -> List[Dict]:
    """Take screenshots of live URLs. Returns list of {url, path} dicts."""
    screenshots = []
    shot_dir = phase_dir / "screenshots"
    shot_dir.mkdir(parents=True, exist_ok=True)

    if not live_urls:
        return screenshots

    urls_file = phase_dir / "screenshot_targets.txt"
    write_lines(urls_file, live_urls[:200])

    # ── gowitness ──────────────────────────────────────────────────────────────
    if require_tool("gowitness"):
        get_logger().info(f"gowitness: screenshotting {len(live_urls[:200])} URLs...")
        run(
            f"gowitness scan file -f {urls_file} "
            f"--screenshot-path {shot_dir} "
            f"--timeout 15 --threads {min(cfg.threads, 10)} "
            f"--disable-db 2>/dev/null",
            timeout=900,
        )
    # ── aquatone fallback ──────────────────────────────────────────────────────
    elif require_tool("aquatone"):
        get_logger().info("aquatone: screenshotting...")
        run(
            f"cat {urls_file} | aquatone "
            f"-out {shot_dir} -threads {min(cfg.threads, 5)} "
            f"-timeout 15000 -screenshot-timeout 30000 2>/dev/null",
            timeout=600, shell=True,
        )

    # Collect screenshot files
    for img_path in sorted(shot_dir.glob("*.png")) or sorted(shot_dir.glob("*.jpg")):
        # Guess URL from filename (gowitness format: http_example_com_.png)
        url_guess = img_path.stem.replace("_", "/").replace("http/", "http://").replace("https/", "https://")
        screenshots.append({"url": url_guess, "path": str(img_path)})

    return screenshots[:100]


def img_to_b64(path: str) -> str:
    """Embed image as base64 data URI."""
    try:
        data = Path(path).read_bytes()
        ext  = Path(path).suffix.lstrip(".").lower() or "png"
        mime = "image/jpeg" if ext in ("jpg", "jpeg") else "image/png"
        return f"data:{mime};base64,{base64.b64encode(data).decode()}"
    except Exception:
        return ""


# ─────────────────────────────────────────────────────────────────────────────
# HTML Report Builder
# ─────────────────────────────────────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DOMINION Report — {domain}</title>
<style>
  :root {{
    --bg: #0d1117; --card: #161b22; --border: #30363d;
    --accent: #f85149; --accent2: #58a6ff; --accent3: #3fb950;
    --warn: #d29922; --text: #e6edf3; --muted: #8b949e;
    --critical: #f85149; --high: #ff7b72; --medium: #d29922;
    --low: #3fb950; --info: #58a6ff;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; }}
  a {{ color: var(--accent2); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}

  /* Nav */
  nav {{
    background: var(--card); border-bottom: 1px solid var(--border);
    padding: 1rem 2rem; display: flex; align-items: center; gap: 2rem;
    position: sticky; top: 0; z-index: 100;
  }}
  nav .logo {{ font-size: 1.4rem; font-weight: 700; color: var(--accent); letter-spacing: 2px; }}
  nav .domain {{ color: var(--muted); font-size: 0.9rem; }}
  nav .nav-links {{ display: flex; gap: 1rem; margin-left: auto; }}
  nav .nav-links a {{ color: var(--muted); font-size: 0.85rem; padding: 0.3rem 0.7rem;
    border-radius: 4px; transition: all .2s; }}
  nav .nav-links a:hover {{ background: var(--border); color: var(--text); }}

  /* Hero stats */
  .hero {{ padding: 2rem; background: linear-gradient(135deg, #0d1117 0%, #161b22 100%);
    border-bottom: 1px solid var(--border); }}
  .hero h1 {{ font-size: 1.8rem; margin-bottom: 0.3rem; }}
  .hero .meta {{ color: var(--muted); font-size: 0.9rem; margin-bottom: 1.5rem; }}
  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; }}
  .stat-card {{
    background: var(--card); border: 1px solid var(--border); border-radius: 8px;
    padding: 1.2rem; text-align: center; position: relative; overflow: hidden;
    transition: transform .2s, box-shadow .2s;
  }}
  .stat-card:hover {{ transform: translateY(-2px); box-shadow: 0 8px 24px rgba(0,0,0,.5); }}
  .stat-card .num {{ font-size: 2.2rem; font-weight: 700; }}
  .stat-card .label {{ color: var(--muted); font-size: 0.8rem; margin-top: 0.3rem; }}
  .stat-card.critical {{ border-color: var(--critical); }}
  .stat-card.critical .num {{ color: var(--critical); }}
  .stat-card.warn {{ border-color: var(--warn); }}
  .stat-card.warn .num {{ color: var(--warn); }}
  .stat-card.good {{ border-color: var(--accent3); }}
  .stat-card.good .num {{ color: var(--accent3); }}
  .stat-card.blue {{ border-color: var(--accent2); }}
  .stat-card.blue .num {{ color: var(--accent2); }}

  /* Main content */
  .container {{ max-width: 1400px; margin: 0 auto; padding: 2rem; }}
  .section {{ margin-bottom: 2.5rem; }}
  .section-title {{
    font-size: 1.1rem; font-weight: 600; margin-bottom: 1rem;
    display: flex; align-items: center; gap: 0.5rem;
    padding-bottom: 0.5rem; border-bottom: 1px solid var(--border);
  }}

  /* Severity badges */
  .badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px;
    font-size: 0.72rem; font-weight: 600; text-transform: uppercase; }}
  .badge.critical {{ background: rgba(248,81,73,.2); color: var(--critical); border: 1px solid var(--critical); }}
  .badge.high {{ background: rgba(255,123,114,.2); color: var(--high); border: 1px solid var(--high); }}
  .badge.medium {{ background: rgba(210,153,34,.2); color: var(--warn); border: 1px solid var(--warn); }}
  .badge.low {{ background: rgba(63,185,80,.2); color: var(--low); border: 1px solid var(--low); }}
  .badge.info {{ background: rgba(88,166,255,.2); color: var(--info); border: 1px solid var(--info); }}

  /* Tables */
  .table-wrap {{ overflow-x: auto; border-radius: 8px; border: 1px solid var(--border); }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  th {{ background: var(--card); color: var(--muted); padding: 0.7rem 1rem;
    text-align: left; font-weight: 600; text-transform: uppercase; font-size: 0.75rem;
    border-bottom: 1px solid var(--border); }}
  td {{ padding: 0.6rem 1rem; border-bottom: 1px solid rgba(48,54,61,.5); }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: rgba(255,255,255,.02); }}

  /* Finding cards */
  .finding-card {{
    background: var(--card); border: 1px solid var(--border); border-radius: 8px;
    padding: 1rem; margin-bottom: 0.7rem; display: flex; gap: 1rem; align-items: flex-start;
  }}
  .finding-card .fc-body {{ flex: 1; min-width: 0; }}
  .finding-card .fc-title {{ font-weight: 600; margin-bottom: 0.3rem; }}
  .finding-card .fc-url {{ color: var(--muted); font-size: 0.8rem;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
  .finding-card.critical {{ border-left: 3px solid var(--critical); }}
  .finding-card.high {{ border-left: 3px solid var(--high); }}
  .finding-card.medium {{ border-left: 3px solid var(--warn); }}
  .finding-card.low {{ border-left: 3px solid var(--low); }}

  /* Screenshots */
  .shot-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(280px,1fr)); gap: 1rem; }}
  .shot-card {{
    background: var(--card); border: 1px solid var(--border); border-radius: 8px;
    overflow: hidden; transition: transform .2s;
  }}
  .shot-card:hover {{ transform: translateY(-2px); }}
  .shot-card img {{ width: 100%; height: 160px; object-fit: cover; display: block; }}
  .shot-card .shot-url {{ padding: 0.5rem 0.7rem; font-size: 0.78rem;
    color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}

  /* Accordion */
  details {{ background: var(--card); border: 1px solid var(--border);
    border-radius: 8px; margin-bottom: 0.5rem; }}
  summary {{ padding: 0.8rem 1rem; cursor: pointer; font-weight: 600;
    list-style: none; display: flex; align-items: center; gap: 0.5rem; }}
  summary::-webkit-details-marker {{ display: none; }}
  summary::before {{ content: '▶'; font-size: 0.7rem; transition: transform .2s; color: var(--muted); }}
  details[open] summary::before {{ transform: rotate(90deg); }}
  details .inner {{ padding: 0.5rem 1rem 1rem; }}

  /* Code */
  code {{ font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 0.82rem;
    background: rgba(0,0,0,.4); padding: 0.1rem 0.4rem; border-radius: 3px; color: #e6edf3; }}
  pre {{ background: #010409; border: 1px solid var(--border); border-radius: 6px;
    padding: 1rem; overflow-x: auto; font-size: 0.8rem; }}

  /* Timeline */
  .timeline {{ position: relative; padding-left: 2rem; }}
  .timeline::before {{ content: ''; position: absolute; left: 0.4rem; top: 0; bottom: 0;
    width: 2px; background: var(--border); }}
  .tl-item {{ position: relative; margin-bottom: 1rem; }}
  .tl-item::before {{ content: ''; position: absolute; left: -1.65rem; top: 0.3rem;
    width: 10px; height: 10px; border-radius: 50%; background: var(--accent2);
    border: 2px solid var(--bg); }}
  .tl-item.done::before {{ background: var(--accent3); }}
  .tl-name {{ font-weight: 600; }}
  .tl-meta {{ color: var(--muted); font-size: 0.8rem; }}

  /* AI report */
  .ai-box {{ background: var(--card); border: 1px solid var(--border);
    border-radius: 8px; padding: 1.5rem; white-space: pre-wrap;
    font-size: 0.9rem; line-height: 1.6; max-height: 600px; overflow-y: auto; }}

  /* Footer */
  footer {{ text-align: center; padding: 2rem; color: var(--muted); font-size: 0.8rem;
    border-top: 1px solid var(--border); margin-top: 3rem; }}

  /* Responsive */
  @media (max-width: 768px) {{
    .stats-grid {{ grid-template-columns: repeat(2, 1fr); }}
    nav .nav-links {{ display: none; }}
  }}
</style>
</head>
<body>

<nav>
  <span class="logo">⚡ DOMINION</span>
  <span class="domain">{domain}</span>
  <div class="nav-links">
    <a href="#overview">Overview</a>
    <a href="#vulnerabilities">Vulnerabilities</a>
    <a href="#subdomains">Subdomains</a>
    <a href="#ports">Ports</a>
    <a href="#secrets">Secrets</a>
    <a href="#cloud">Cloud</a>
    <a href="#screenshots">Screenshots</a>
    <a href="#ai">AI Analysis</a>
  </div>
</nav>

<div class="hero" id="overview">
  <h1>🔥 {domain}</h1>
  <div class="meta">Scan completed: {scan_date} &nbsp;·&nbsp; Duration: {duration} &nbsp;·&nbsp; Phases: {num_phases}</div>
  <div class="stats-grid">
    <div class="stat-card critical"><div class="num">{total_vulns}</div><div class="label">Vulnerabilities</div></div>
    <div class="stat-card critical"><div class="num">{critical_count}</div><div class="label">Critical</div></div>
    <div class="stat-card blue"><div class="num">{num_subs}</div><div class="label">Subdomains</div></div>
    <div class="stat-card blue"><div class="num">{num_live}</div><div class="label">Live Hosts</div></div>
    <div class="stat-card warn"><div class="num">{num_ports}</div><div class="label">Open Ports</div></div>
    <div class="stat-card warn"><div class="num">{num_secrets}</div><div class="label">Secrets Leaked</div></div>
    <div class="stat-card warn"><div class="num">{num_cloud}</div><div class="label">Cloud Exposed</div></div>
    <div class="stat-card good"><div class="num">{num_urls}</div><div class="label">URLs Crawled</div></div>
  </div>
</div>

<div class="container">

<!-- PHASE TIMELINE -->
<div class="section">
  <div class="section-title">📋 Scan Timeline</div>
  <div class="timeline">
{timeline_html}
  </div>
</div>

<!-- VULNERABILITIES -->
<div class="section" id="vulnerabilities">
  <div class="section-title">🚨 Vulnerabilities <span class="badge critical">{total_vulns} total</span></div>
{vuln_html}
</div>

<!-- SUBDOMAINS -->
<div class="section" id="subdomains">
  <div class="section-title">🌐 Subdomains <span class="badge info">{num_subs} found · {num_live} live</span></div>
  <details>
    <summary>All Live Subdomains ({num_live})</summary>
    <div class="inner">
      <div class="table-wrap"><table>
        <tr><th>Subdomain</th><th>Actions</th></tr>
{subdomain_rows}
      </table></div>
    </div>
  </details>
</div>

<!-- PORTS -->
<div class="section" id="ports">
  <div class="section-title">🔌 Open Ports & Services <span class="badge medium">{num_ports} ports</span></div>
{port_html}
</div>

<!-- SECRETS -->
<div class="section" id="secrets">
  <div class="section-title">🔑 Leaked Secrets <span class="badge high">{num_secrets} found</span></div>
{secrets_html}
</div>

<!-- CLOUD -->
<div class="section" id="cloud">
  <div class="section-title">☁️ Cloud Exposure <span class="badge medium">{num_cloud} resources</span></div>
{cloud_html}
</div>

<!-- CONTENT DISCOVERY -->
<div class="section" id="content">
  <div class="section-title">📂 Sensitive Content Found</div>
{content_html}
</div>

<!-- DNS -->
<div class="section" id="dns">
  <div class="section-title">🔍 DNS Analysis</div>
{dns_html}
</div>

<!-- SCREENSHOTS -->
<div class="section" id="screenshots">
  <div class="section-title">📸 Screenshots <span class="badge info">{num_shots} captured</span></div>
  <div class="shot-grid">
{screenshots_html}
  </div>
</div>

<!-- AI ANALYSIS -->
<div class="section" id="ai">
  <div class="section-title">🤖 AI Attack Surface Analysis</div>
  <div class="ai-box">{ai_report}</div>
</div>

</div><!-- /container -->

<footer>
  Generated by <strong>DOMINION</strong> — Elite Domain Recon Framework &nbsp;·&nbsp;
  {scan_date} &nbsp;·&nbsp; Target: <code>{domain}</code>
</footer>

<script>
// Make URLs in tables clickable on click
document.querySelectorAll('td').forEach(td => {{
  const txt = td.textContent.trim();
  if (txt.startsWith('http') && !td.querySelector('a')) {{
    const a = document.createElement('a');
    a.href = txt; a.target = '_blank'; a.textContent = txt;
    td.textContent = ''; td.appendChild(a);
  }}
}});
</script>
</body>
</html>"""


def _badge(sev: str) -> str:
    s = sev.lower() if sev else "info"
    return f'<span class="badge {s}">{s.upper()}</span>'


def _build_vuln_html(all_data: dict) -> str:
    p8 = all_data.get("p08", {})
    cards = []

    def add_card(sev: str, vtype: str, url: str, detail: str = ""):
        cls = sev.lower()
        cards.append(
            f'<div class="finding-card {cls}">'
            f'{_badge(sev)}'
            f'<div class="fc-body">'
            f'<div class="fc-title">{vtype}</div>'
            f'<div class="fc-url">{url[:120]}</div>'
            f'{f"<code>{detail[:200]}</code>" if detail else ""}'
            f'</div></div>'
        )

    for n in p8.get("nuclei", [])[:50]:
        info = n.get("info", {})
        add_card(info.get("severity", "info"), info.get("name", "?"),
                 n.get("matched-at", ""), info.get("description", "")[:100])

    for v in p8.get("sqli", [])[:20]:
        add_card("critical", f"SQL Injection — {v.get('type','SQLi')}",
                 v.get("url", ""), f"param={v.get('param','')} payload={v.get('payload','')[:50]}")

    for v in p8.get("ssti", [])[:20]:
        add_card("critical", f"SSTI ({v.get('engine','')})", v.get("url", ""),
                 f"param={v.get('param','')} payload={v.get('payload','')[:50]}")

    for v in p8.get("lfi", [])[:20]:
        add_card("critical", "Local File Inclusion", v.get("url", ""),
                 f"payload={v.get('payload','')[:80]}")

    for v in p8.get("ssrf", [])[:10]:
        add_card("critical", "SSRF", v.get("url", ""))

    for v in p8.get("xss", [])[:20]:
        add_card("high", f"Cross-Site Scripting — {v.get('type','XSS')}",
                 v.get("url", v.get("evidence", ""))[:120])

    for v in p8.get("xxe", [])[:10]:
        add_card("high", "XXE Injection", v.get("url", ""))

    for v in p8.get("http_smuggling", [])[:10]:
        add_card("high", "HTTP Request Smuggling", v.get("url", ""), v.get("note", ""))

    for v in p8.get("cors", [])[:15]:
        sev = "critical" if "credentials" in v.get("type", "").lower() else "medium"
        add_card(sev, f"CORS Misconfiguration", v.get("url", ""),
                 v.get("type", ""))

    for v in p8.get("bypass_403", [])[:10]:
        add_card("high", "403/401 Bypass", v.get("url", ""), v.get("method", ""))

    for v in p8.get("jwt", [])[:10]:
        add_card("high", f"JWT Vulnerability — {v.get('attack','')}", v.get("token_source", ""))

    for v in p8.get("open_redirect", [])[:10]:
        add_card("medium", "Open Redirect", v.get("url", ""))

    for v in p8.get("crlf_injection", [])[:10]:
        add_card("medium", "CRLF Injection", v.get("url", ""))

    for v in p8.get("clickjacking", [])[:5]:
        add_card("medium", "Clickjacking", v.get("url", ""))

    for v in p8.get("graphql", [])[:5]:
        add_card("medium", v.get("type", "GraphQL Issue"), v.get("url", ""))

    if not cards:
        return '<div class="finding-card"><div class="fc-body"><div class="fc-title">No vulnerabilities detected in automated scan</div></div></div>'

    return "\n".join(cards)


def _build_port_html(all_data: dict) -> str:
    p5 = all_data.get("p05", {})
    open_ports = p5.get("open_ports", {})
    interesting = p5.get("interesting_services", {})
    if not open_ports:
        return "<p style='color:var(--muted)'>No open ports found.</p>"

    rows = []
    for ip, ports in list(open_ports.items())[:50]:
        port_str = ", ".join(str(p) for p in sorted(ports)[:20])
        flags = []
        for svc, hosts in interesting.items():
            if ip in hosts:
                flags.append(f'<span class="badge high">{svc}</span>')
        rows.append(
            f"<tr><td><code>{ip}</code></td>"
            f"<td>{port_str}</td>"
            f"<td>{' '.join(flags) or '—'}</td></tr>"
        )
    return (
        '<div class="table-wrap"><table>'
        '<tr><th>Host/IP</th><th>Open Ports</th><th>Flags</th></tr>'
        + "".join(rows) + "</table></div>"
    )


def _build_secrets_html(all_data: dict) -> str:
    leaks = all_data.get("p07", {}).get("leaks", [])
    if not leaks:
        return "<p style='color:var(--muted)'>No secrets detected.</p>"
    rows = []
    for leak in leaks[:100]:
        t   = leak.get("type", "?")
        src = leak.get("source_file", leak.get("url", "?"))[:80]
        val = str(leak.get("value", leak.get("match", "?")))[:80]
        rows.append(f"<tr><td>{_badge('high')}</td><td><code>{t}</code></td>"
                    f"<td>{src}</td><td><code>{val}</code></td></tr>")
    return (
        '<div class="table-wrap"><table>'
        '<tr><th>Severity</th><th>Type</th><th>Source</th><th>Value (truncated)</th></tr>'
        + "".join(rows) + "</table></div>"
    )


def _build_cloud_html(all_data: dict) -> str:
    p10 = all_data.get("p10", {})
    items = []
    for bucket in p10.get("s3_buckets", []):
        items.append({"type": "S3 Bucket", "url": bucket.get("name", "?"),
                      "status": bucket.get("status", "?"), "sev": "high"})
    for fb in p10.get("firebase", []):
        items.append({"type": "Firebase DB", "url": fb.get("url", "?"),
                      "status": "Exposed", "sev": "critical"})
    for blob in p10.get("azure_blobs", []):
        items.append({"type": "Azure Blob", "url": blob, "status": "Accessible", "sev": "high"})
    for bucket in p10.get("gcs", []):
        items.append({"type": "GCS Bucket", "url": bucket, "status": "Accessible", "sev": "high"})
    if not items:
        return "<p style='color:var(--muted)'>No exposed cloud resources found.</p>"
    rows = "".join(
        f"<tr><td>{_badge(i['sev'])}</td><td>{i['type']}</td>"
        f"<td><code>{i['url']}</code></td><td>{i['status']}</td></tr>"
        for i in items[:50]
    )
    return (
        '<div class="table-wrap"><table>'
        '<tr><th>Severity</th><th>Type</th><th>Resource</th><th>Status</th></tr>'
        + rows + "</table></div>"
    )


def _build_content_html(all_data: dict) -> str:
    p9 = all_data.get("p09", {})
    sections = []

    def section(title: str, items: list, key: str = "url"):
        if not items:
            return ""
        rows = "".join(
            f"<tr><td><a href='{i.get(key,i) if isinstance(i,dict) else i}' target='_blank'>"
            f"{str(i.get(key,i) if isinstance(i,dict) else i)[:100]}</a></td>"
            f"<td><code>{i.get('status', '') if isinstance(i,dict) else ''}</code></td></tr>"
            for i in items[:30]
        )
        return (
            f"<details><summary>{title} ({len(items)})</summary>"
            f"<div class='inner'><div class='table-wrap'><table>"
            f"<tr><th>URL</th><th>Status</th></tr>{rows}</table></div></div></details>"
        )

    sections.append(section("🔐 Admin Panels", p9.get("admin_panels", [])))
    sections.append(section("💾 Backup Files", p9.get("backup_files", [])))
    sections.append(section("⚙️  Config Files", p9.get("config_files", [])))
    sections.append(section("📦 Git Exposure", p9.get("git_exposure", [])))
    sections.append(section("📁 Sensitive Paths", p9.get("found_paths", [])))

    result = "".join(s for s in sections if s)
    return result or "<p style='color:var(--muted)'>No sensitive content discovered.</p>"


def _build_dns_html(all_data: dict) -> str:
    p3 = all_data.get("p03", {})
    rows = [
        ("SPF",         p3.get("spf", "Not found")),
        ("DMARC",       p3.get("dmarc", "Not found")),
        ("DKIM",        p3.get("dkim", "Unchecked")),
        ("Zone Transfer", f"{len(p3.get('zone_transfer',[]))} succeeded!" if p3.get("zone_transfer") else "None"),
        ("Wildcard DNS", "⚠️  Yes" if p3.get("wildcard") else "No"),
        ("Takeover Risks", str(len(p3.get("takeover_risks", [])))),
    ]
    rows_html = "".join(
        f"<tr><td><strong>{k}</strong></td><td><code>{v}</code></td></tr>"
        for k, v in rows
    )
    return (
        '<div class="table-wrap"><table>'
        '<tr><th>Record</th><th>Value</th></tr>'
        + rows_html + "</table></div>"
    )


def _build_timeline_html(completed: dict) -> str:
    lines = []
    for num_str in sorted(completed.keys(), key=lambda x: int(x)):
        phase = completed[num_str]
        name  = phase.get("name", f"Phase {num_str}")
        dur   = phase.get("elapsed", "?")
        ts    = phase.get("timestamp", "")[:19]
        lines.append(
            f'<div class="tl-item done">'
            f'<div class="tl-name">Phase {num_str}: {name}</div>'
            f'<div class="tl-meta">⏱ {dur} &nbsp; 📅 {ts}</div>'
            f'</div>'
        )
    return "\n".join(lines) if lines else "<div>No phase data</div>"


def _build_screenshot_html(screenshots: list) -> str:
    html = []
    for shot in screenshots[:80]:
        img_src = img_to_b64(shot.get("path", ""))
        if not img_src:
            continue
        url = shot.get("url", "?")
        html.append(
            f'<div class="shot-card">'
            f'<a href="{url}" target="_blank">'
            f'<img src="{img_src}" alt="{url}" loading="lazy"></a>'
            f'<div class="shot-url" title="{url}">{url}</div>'
            f'</div>'
        )
    return "\n".join(html) if html else "<p style='color:var(--muted)'>No screenshots captured.</p>"


def run_phase(domain: str, output_dir: Path, all_phase_data: Dict[str, Any]) -> Dict[str, Any]:
    log = get_logger()
    cfg = get_config()
    t0  = time.monotonic()

    phase_dir = output_dir / "phase_11_reporting"
    phase_dir.mkdir(parents=True, exist_ok=True)

    p2 = all_phase_data.get("p02", {})
    p4 = all_phase_data.get("p04", {})
    p5 = all_phase_data.get("p05", {})
    p7 = all_phase_data.get("p07", {})
    p8 = all_phase_data.get("p08", {})
    p10 = all_phase_data.get("p10", {})
    p12 = all_phase_data.get("p12", {})

    live_urls = read_lines(output_dir / "live_urls.txt")

    # ── Screenshots ────────────────────────────────────────────────────────────
    log.info("Taking screenshots of live URLs...")
    screenshots = take_screenshots(live_urls, phase_dir, cfg)
    log.success(f"Screenshots: {len(screenshots)} captured")

    # ── Load completed phase state for timeline ─────────────────────────────────
    state_file = output_dir / ".dominion_state.json"
    completed  = {}
    if state_file.exists():
        try:
            state    = json.loads(state_file.read_text(encoding="utf-8"))
            completed = state.get("completed", {})
        except Exception:
            pass

    # ── Compute stats ─────────────────────────────────────────────────────────
    open_ports    = p5.get("open_ports", {})
    total_ports   = sum(len(v) for v in open_ports.values())
    total_vulns   = p8.get("total_vulns", 0)
    critical_count = p8.get("critical_count", 0)
    num_subs      = p2.get("total_found", 0)
    num_live      = p2.get("total_live", 0)
    num_secrets   = len(p7.get("leaks", []))
    num_cloud     = (len(p10.get("s3_buckets", [])) + len(p10.get("firebase", [])) +
                     len(p10.get("azure_blobs", [])) + len(p10.get("gcs", [])))
    num_urls      = len(all_phase_data.get("p06", {}).get("urls_crawled", []))
    scan_date     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    duration      = elapsed(t0)

    # ── Build HTML ────────────────────────────────────────────────────────────
    log.info("Generating HTML report...")

    # Subdomain rows
    live_subs = p2.get("subdomains_live", live_urls[:100])
    sub_rows = "\n".join(
        f"<tr><td><a href='https://{s}' target='_blank'>{s}</a></td>"
        f"<td><a href='https://{s}' target='_blank'>Visit ↗</a></td></tr>"
        for s in sorted(live_subs)[:500]
    ) or "<tr><td colspan='2'>No live subdomains</td></tr>"

    ai_report = (p12.get("ai_response", "") or
                 "AI analysis not run. Add OpenAI/Gemini key to config.yml and run Phase 12.") \
        .replace("<", "&lt;").replace(">", "&gt;")

    html = HTML_TEMPLATE.format(
        domain=domain,
        scan_date=scan_date,
        duration=duration,
        num_phases=len(completed),
        total_vulns=total_vulns,
        critical_count=critical_count,
        num_subs=num_subs,
        num_live=num_live,
        num_ports=total_ports,
        num_secrets=num_secrets,
        num_cloud=num_cloud,
        num_urls=num_urls,
        num_shots=len(screenshots),
        timeline_html=_build_timeline_html(completed),
        vuln_html=_build_vuln_html(all_phase_data),
        subdomain_rows=sub_rows,
        port_html=_build_port_html(all_phase_data),
        secrets_html=_build_secrets_html(all_phase_data),
        cloud_html=_build_cloud_html(all_phase_data),
        content_html=_build_content_html(all_phase_data),
        dns_html=_build_dns_html(all_phase_data),
        screenshots_html=_build_screenshot_html(screenshots),
        ai_report=ai_report,
    )

    # ── Save HTML ─────────────────────────────────────────────────────────────
    html_path = output_dir / "report.html"
    html_path.write_text(html, encoding="utf-8")
    log.success(f"HTML Report: {html_path}")

    # ── Save JSON summary ─────────────────────────────────────────────────────
    findings = {
        "domain":          domain,
        "scan_date":       scan_date,
        "total_vulns":     total_vulns,
        "critical_count":  critical_count,
        "num_subdomains":  num_subs,
        "num_live":        num_live,
        "num_ports":       total_ports,
        "num_secrets":     num_secrets,
        "num_cloud":       num_cloud,
        "num_urls":        num_urls,
        "screenshots":     len(screenshots),
        "report_path":     str(html_path),
        "phase_elapsed":   elapsed(t0),
    }
    save_json(phase_dir / "phase_11_results.json", findings)

    log.success(
        f"Phase 11 complete — "
        f"{total_vulns} vulns · {num_secrets} secrets · "
        f"{len(screenshots)} screenshots · Report: {html_path}"
    )
    return findings
