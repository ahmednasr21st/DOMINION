#!/usr/bin/env python3
"""
DOMINION - Phase 11: Screenshot & Reporting
gowitness screenshots all live hosts · generates HTML + JSON + Markdown report
"""

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from core.config import get_config
from core.logger import get_logger
from core.runner import run, require_tool
from core.utils  import save_json, read_lines, write_lines, load_json

PHASE_NUM  = 11
PHASE_NAME = "Screenshot & Reporting"
PHASE_DESC = "gowitness screenshots · HTML report · JSON export · Markdown summary"

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DOMINION Report – {domain}</title>
<style>
  :root {{
    --bg: #0d0d0d; --surface: #161616; --border: #2a2a2a;
    --red: #ff3b3b; --green: #00e676; --yellow: #ffcc00;
    --blue: #00b0ff; --purple: #bb86fc; --text: #e0e0e0;
    --dim: #888; --critical: #ff1744; --high: #ff5722;
    --medium: #ff9800; --low: #4caf50; --info: #2196f3;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', monospace; font-size: 14px; }}
  a {{ color: var(--blue); text-decoration: none; }}
  a:hover {{ color: var(--red); }}

  header {{
    background: linear-gradient(135deg, #1a0000, #0d0d0d);
    padding: 2rem 3rem;
    border-bottom: 2px solid var(--red);
  }}
  header h1 {{ font-size: 2.5rem; color: var(--red); letter-spacing: 4px; font-weight: 900; }}
  header .subtitle {{ color: var(--dim); margin-top: .4rem; }}
  header .meta {{ margin-top: 1rem; display: flex; gap: 2rem; flex-wrap: wrap; }}
  .badge {{ background: var(--surface); border: 1px solid var(--border); border-radius: 6px;
            padding: .3rem .8rem; font-size: .85rem; }}
  .badge span {{ color: var(--yellow); font-weight: bold; }}

  nav {{
    background: var(--surface); border-bottom: 1px solid var(--border);
    padding: .8rem 3rem; display: flex; gap: .5rem; flex-wrap: wrap;
    position: sticky; top: 0; z-index: 100;
  }}
  nav a {{
    padding: .4rem .9rem; border-radius: 5px; font-size: .85rem;
    border: 1px solid var(--border); color: var(--text);
    transition: all .2s;
  }}
  nav a:hover {{ background: var(--red); color: #fff; border-color: var(--red); }}

  .container {{ max-width: 1400px; margin: 0 auto; padding: 2rem 3rem; }}

  .stats-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 1rem; margin-bottom: 2rem;
  }}
  .stat-card {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 10px; padding: 1.2rem; text-align: center;
    transition: transform .2s;
  }}
  .stat-card:hover {{ transform: translateY(-3px); border-color: var(--red); }}
  .stat-card .value {{ font-size: 2rem; font-weight: 900; color: var(--red); }}
  .stat-card .label {{ color: var(--dim); font-size: .8rem; margin-top: .3rem; text-transform: uppercase; letter-spacing: 1px; }}

  section {{ margin-bottom: 3rem; }}
  h2 {{
    font-size: 1.2rem; color: var(--red); text-transform: uppercase;
    letter-spacing: 2px; padding: .8rem 0; border-bottom: 1px solid var(--border);
    margin-bottom: 1.2rem;
  }}
  h2::before {{ content: "● "; }}

  table {{ width: 100%; border-collapse: collapse; }}
  thead tr {{ background: #1e1e1e; }}
  th {{ text-align: left; padding: .7rem 1rem; color: var(--dim); font-weight: 600;
        text-transform: uppercase; font-size: .8rem; letter-spacing: 1px;
        border-bottom: 1px solid var(--border); }}
  td {{ padding: .6rem 1rem; border-bottom: 1px solid #1a1a1a; }}
  tr:hover td {{ background: #1c1c1c; }}

  .tag {{
    display: inline-block; padding: .2rem .6rem; border-radius: 4px;
    font-size: .75rem; font-weight: bold; text-transform: uppercase;
  }}
  .tag-critical {{ background: var(--critical); color: #fff; }}
  .tag-high     {{ background: var(--high); color: #fff; }}
  .tag-medium   {{ background: var(--medium); color: #000; }}
  .tag-low      {{ background: var(--low); color: #000; }}
  .tag-info     {{ background: var(--info); color: #fff; }}
  .tag-open     {{ background: var(--red); color: #fff; }}
  .tag-private  {{ background: #555; color: #fff; }}

  .code {{ background: #111; border: 1px solid var(--border); border-radius: 5px;
           padding: .8rem 1rem; font-family: monospace; font-size: .85rem;
           overflow-x: auto; white-space: pre-wrap; word-break: break-all; }}

  .screenshots {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 1rem; }}
  .screenshot-card {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; overflow: hidden; transition: transform .2s;
  }}
  .screenshot-card:hover {{ transform: scale(1.02); border-color: var(--red); }}
  .screenshot-card img {{ width: 100%; height: 180px; object-fit: cover; display: block; }}
  .screenshot-card .info {{ padding: .6rem; font-size: .8rem; color: var(--dim); word-break: break-all; }}

  footer {{
    text-align: center; padding: 2rem; border-top: 1px solid var(--border);
    color: var(--dim); font-size: .85rem;
  }}

  .vuln-list {{ list-style: none; }}
  .vuln-list li {{ padding: .5rem 0; border-bottom: 1px solid #1a1a1a; display: flex; gap: 1rem; align-items: center; }}

  .progress-bar {{ height: 4px; background: #222; border-radius: 2px; margin-bottom: 1rem; }}
  .progress-bar .fill {{ height: 100%; background: var(--red); border-radius: 2px; }}
</style>
</head>
<body>
<header>
  <h1>DOMINION</h1>
  <div class="subtitle">Domain Intelligence & Attack Surface Report</div>
  <div class="meta">
    <div class="badge">Target: <span>{domain}</span></div>
    <div class="badge">Generated: <span>{generated}</span></div>
    <div class="badge">Phases: <span>{phases}</span></div>
  </div>
</header>

<nav>
  <a href="#summary">Summary</a>
  <a href="#subdomains">Subdomains</a>
  <a href="#dns">DNS</a>
  <a href="#ports">Ports</a>
  <a href="#vulns">Vulnerabilities</a>
  <a href="#secrets">Secrets</a>
  <a href="#cloud">Cloud</a>
  <a href="#content">Content</a>
  <a href="#screenshots">Screenshots</a>
</nav>

<div class="container">

<section id="summary">
  <h2>Executive Summary</h2>
  <div class="stats-grid">
    {stat_cards}
  </div>
</section>

{sections}

</div>
<footer>Generated by DOMINION · {generated}</footer>
</body>
</html>"""


def make_stat(value: int, label: str, color: str = "") -> str:
    style = f"border-top: 3px solid {color};" if color else ""
    return f"""<div class="stat-card" style="{style}">
      <div class="value">{value}</div>
      <div class="label">{label}</div>
    </div>"""


def make_table(headers: List[str], rows: List[List[str]]) -> str:
    th = "".join(f"<th>{h}</th>" for h in headers)
    trs = ""
    for row in rows:
        tds = "".join(f"<td>{c}</td>" for c in row)
        trs += f"<tr>{tds}</tr>"
    return f"<table><thead><tr>{th}</tr></thead><tbody>{trs}</tbody></table>"


def sev_tag(sev: str) -> str:
    sev = sev.lower()
    cls_map = {
        "critical": "tag-critical", "high": "tag-high",
        "medium": "tag-medium", "low": "tag-low",
        "info": "tag-info", "informational": "tag-info"
    }
    cls = cls_map.get(sev, "tag-info")
    return f'<span class="tag {cls}">{sev.upper()}</span>'


def run_phase(domain: str, output_dir: Path, all_phase_data: Dict[str, Any]) -> Dict[str, Any]:
    log = get_logger()
    cfg = get_config()

    phase_dir = output_dir / "phase_11_reporting"
    phase_dir.mkdir(parents=True, exist_ok=True)

    # ── gowitness screenshots ─────────────────────────────────────────────────
    screenshots_dir = phase_dir / "screenshots"
    screenshots_dir.mkdir(exist_ok=True)
    screenshot_map: Dict[str, str] = {}

    if require_tool("gowitness"):
        log.info("Taking screenshots with gowitness...")
        live_file = output_dir / "live_urls.txt"
        db_path   = phase_dir / "gowitness.sqlite3"
        rc, stdout, _ = run(
            f"gowitness file -f {live_file} --screenshot-path {screenshots_dir} "
            f"--db-path {db_path} --threads {min(cfg.threads, 10)} --timeout 15 -q",
            timeout=900,
        )
        shots = list(screenshots_dir.glob("*.png")) + list(screenshots_dir.glob("*.jpeg"))
        log.success(f"gowitness: {len(shots)} screenshots captured")
        for s in shots:
            url = s.stem.replace("_", "/").replace("http//", "http://").replace("https//", "https://")
            screenshot_map[url] = str(s)
    else:
        log.warning("gowitness not found — no screenshots")

    # ── Aggregate all phase data ───────────────────────────────────────────────
    p1 = all_phase_data.get("p01", {})
    p2 = all_phase_data.get("p02", {})
    p3 = all_phase_data.get("p03", {})
    p4 = all_phase_data.get("p04", {})
    p5 = all_phase_data.get("p05", {})
    p6 = all_phase_data.get("p06", {})
    p7 = all_phase_data.get("p07", {})
    p8 = all_phase_data.get("p08", {})
    p9 = all_phase_data.get("p09", {})
    p10= all_phase_data.get("p10", {})

    subdomains   = p2.get("subdomains_live", [])
    live_hosts   = p4.get("live_hosts", [])
    open_ports   = p5.get("open_ports", {})
    total_ports  = sum(len(v) for v in open_ports.values())
    nuclei_hits  = p8.get("nuclei", [])
    xss_hits     = p8.get("xss", [])
    sqli_hits    = p8.get("sqli", [])
    leaks        = p7.get("leaks", [])
    s3_buckets   = p10.get("s3_buckets", [])
    exposed_cloud= p10.get("exposed_cloud", [])
    takeovers    = p3.get("takeover_risks", [])
    admin_panels = p9.get("admin_panels", [])
    total_vulns  = p8.get("total_vulns", 0)
    urls_found   = len(p6.get("urls_crawled", []))

    # ── Build HTML sections ───────────────────────────────────────────────────
    stat_cards = "\n".join([
        make_stat(len(subdomains),   "Subdomains",   "#00b0ff"),
        make_stat(len(live_hosts),   "Live Hosts",   "#00e676"),
        make_stat(total_ports,       "Open Ports",   "#ffcc00"),
        make_stat(total_vulns,       "Vulns Found",  "#ff3b3b"),
        make_stat(len(leaks),        "Secrets Leaked","#ff5722"),
        make_stat(len(exposed_cloud),"Cloud Exposed", "#bb86fc"),
        make_stat(len(takeovers),    "Takeovers",    "#ff1744"),
        make_stat(urls_found,        "URLs Crawled", "#888"),
    ])

    sections = []

    # Subdomains section
    sub_rows = [[f'<a href="https://{s}" target="_blank">{s}</a>'] for s in subdomains[:200]]
    sections.append(f"""<section id="subdomains">
      <h2>Subdomains ({len(subdomains)})</h2>
      {make_table(['Subdomain'], sub_rows)}
    </section>""")

    # DNS section
    dns_records = p3.get("records", {})
    dns_rows = []
    for rtype, vals in dns_records.items():
        for v in vals:
            dns_rows.append([rtype, v])
    spf   = p3.get("spf", "Not found")
    dmarc = p3.get("dmarc", "Not found")
    wtf   = "YES ⚠️" if p3.get("wildcard") else "No"
    zt    = f"{len(p3.get('zone_transfer', []))} found ⚠️" if p3.get("zone_transfer") else "None"
    sections.append(f"""<section id="dns">
      <h2>DNS Records</h2>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1rem;">
        <div class="code" style="border-color:#555">SPF: {spf}</div>
        <div class="code" style="border-color:#555">DMARC: {dmarc}</div>
      </div>
      <div style="display:flex;gap:1rem;margin-bottom:1rem;">
        <div class="badge">Wildcard DNS: <span>{wtf}</span></div>
        <div class="badge">Zone Transfer: <span>{zt}</span></div>
      </div>
      {make_table(['Type', 'Value'], dns_rows[:50])}
    </section>""")

    # Ports section
    port_rows = []
    for ip, ports in open_ports.items():
        services = p5.get("services", {})
        for p in ports:
            svc = services.get(p, {}).get("service", "")
            banner = services.get(p, {}).get("banner", "")[:60]
            port_rows.append([ip, str(p), svc, banner])
    sections.append(f"""<section id="ports">
      <h2>Open Ports ({total_ports})</h2>
      {make_table(['IP', 'Port', 'Service', 'Banner'], port_rows[:100])}
    </section>""")

    # Vulnerabilities section
    vuln_html = "<ul class='vuln-list'>"
    for n in nuclei_hits[:100]:
        info = n.get("info", {})
        sev  = info.get("severity", "info")
        name = info.get("name", "?")
        url  = n.get("matched-at", "?")
        vuln_html += f"<li>{sev_tag(sev)} <strong>{name}</strong> <span style='color:#888'>{url[:80]}</span></li>"
    for x in xss_hits[:30]:
        vuln_html += f"<li>{sev_tag('high')} <strong>XSS</strong> <span style='color:#888'>{x['url'][:80]}</span></li>"
    for s in sqli_hits[:30]:
        vuln_html += f"<li>{sev_tag('critical')} <strong>SQL Injection</strong> <span style='color:#888'>{s['url'][:80]}</span></li>"
    for t in takeovers:
        vuln_html += f"<li>{sev_tag('critical')} <strong>Subdomain Takeover</strong> <span style='color:#888'>{t.get('subdomain')} → {t.get('service')}</span></li>"
    vuln_html += "</ul>"
    sections.append(f"<section id='vulns'><h2>Vulnerabilities ({total_vulns})</h2>{vuln_html}</section>")

    # Secrets section
    secrets_rows = [[l["type"], l["match"][:80], l["source"][:60]] for l in leaks[:100]]
    sections.append(f"""<section id="secrets">
      <h2>Leaked Secrets ({len(leaks)})</h2>
      {make_table(['Type', 'Value', 'Source'], secrets_rows)}
    </section>""")

    # Cloud section
    cloud_rows = []
    for b in s3_buckets:
        status_tag = f'<span class="tag tag-open">OPEN</span>' if b.get("status") == "OPEN" else f'<span class="tag tag-private">PRIVATE</span>'
        cloud_rows.append(["S3", b.get("url", b.get("bucket", "")), status_tag])
    for e in p10.get("firebase", []):
        stag = f'<span class="tag tag-open">OPEN</span>' if e.get("status") == "OPEN" else f'<span class="tag tag-private">{e.get("status")}</span>'
        cloud_rows.append(["Firebase", e.get("url", ""), stag])
    for e in p10.get("azure_storage", []):
        cloud_rows.append(["Azure", e.get("url", ""), str(e.get("status"))])
    sections.append(f"""<section id="cloud">
      <h2>Cloud Assets</h2>
      {make_table(['Type', 'URL', 'Status'], cloud_rows)}
    </section>""")

    # Content section
    content_rows = [[
        e.get("url", "")[:80],
        str(e.get("status", "")),
        e.get("source", ""),
    ] for e in (admin_panels + p9.get("config_files", []) + p9.get("backup_files", []))[:100]]
    sections.append(f"""<section id="content">
      <h2>Content Discovery</h2>
      {make_table(['URL', 'Status', 'Source'], content_rows)}
    </section>""")

    # Screenshots section
    shots_html = "<div class='screenshots'>"
    for shots_path in list(screenshots_dir.glob("*.png"))[:50] + list(screenshots_dir.glob("*.jpeg"))[:50]:
        rel = shots_path.relative_to(output_dir)
        shots_html += f"""<div class="screenshot-card">
          <img src="../{rel}" alt="{shots_path.stem}" loading="lazy">
          <div class="info">{shots_path.stem[:80]}</div>
        </div>"""
    shots_html += "</div>"
    sections.append(f"<section id='screenshots'><h2>Screenshots</h2>{shots_html}</section>")

    html = HTML_TEMPLATE.format(
        domain=domain,
        generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        phases=12,
        stat_cards=stat_cards,
        sections="\n".join(sections),
    )

    report_html = output_dir / "report.html"
    report_html.write_text(html, encoding="utf-8")
    log.success(f"HTML report saved: {report_html}")

    # ── JSON export ───────────────────────────────────────────────────────────
    full_json = {
        "meta": {
            "domain": domain,
            "generated": datetime.now().isoformat(),
            "tool": "DOMINION",
        },
        **all_phase_data,
    }
    report_json = output_dir / "report.json"
    save_json(report_json, full_json)
    log.success(f"JSON report saved: {report_json}")

    # ── Markdown summary ──────────────────────────────────────────────────────
    md = f"""# DOMINION Report — {domain}

Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}

## Summary

| Metric | Count |
|--------|-------|
| Subdomains | {len(subdomains)} |
| Live Hosts | {len(live_hosts)} |
| Open Ports | {total_ports} |
| Vulnerabilities | {total_vulns} |
| Secrets Leaked | {len(leaks)} |
| Cloud Exposed | {len(exposed_cloud)} |
| Subdomain Takeovers | {len(takeovers)} |
| URLs Crawled | {urls_found} |

## Critical Findings

"""
    if leaks:
        md += f"### ⚠️ {len(leaks)} Leaked Secrets Found\n"
        for l in leaks[:5]:
            md += f"- **{l['type']}**: `{l['match'][:60]}` (source: {l['source']})\n"
    if takeovers:
        md += f"\n### ⚠️ {len(takeovers)} Subdomain Takeover Opportunities\n"
        for t in takeovers:
            md += f"- {t['subdomain']} → {t['cname']} ({t['service']})\n"
    if exposed_cloud:
        md += f"\n### ⚠️ {len(exposed_cloud)} Exposed Cloud Resources\n"
        for c in exposed_cloud[:5]:
            md += f"- {c.get('url', '')} [{c.get('status')}]\n"

    (output_dir / "report.md").write_text(md, encoding="utf-8")
    log.success("Markdown report saved")

    findings = {
        "report_html": str(report_html),
        "report_json": str(report_json),
        "screenshots": list(screenshot_map.keys()),
    }
    save_json(phase_dir / "phase_11_results.json", findings)
    log.success("Phase 11 complete — all reports generated")
    return findings
