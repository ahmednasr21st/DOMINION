#!/usr/bin/env python3
"""
DOMINION - Phase 12: AI-Powered Attack Surface Summary
Uses GPT-4o / Gemini to generate a prioritized attack surface analysis
with recommended next steps for the red team.
"""

import json
from pathlib import Path
from typing import Any, Dict

from core.config import get_config
from core.logger import get_logger
from core.utils  import save_json, load_json

PHASE_NUM  = 12
PHASE_NAME = "AI-Powered Attack Surface Summary"
PHASE_DESC = "GPT-4o / Gemini analysis · Priority findings · Red team recommendations"

SYSTEM_PROMPT = """You are an elite red team expert and penetration testing analyst.
You have just completed a comprehensive automated reconnaissance scan using DOMINION.
Your job is to analyze the findings and produce a professional, actionable report.

Focus on:
1. The most critical vulnerabilities that should be exploited first
2. Attack chains that combine multiple findings
3. Quick wins vs. complex attacks
4. Specific recommended next steps for each critical finding
5. Risk rating for the overall target

Be specific, technical, and actionable. Format your response in clean markdown."""

USER_PROMPT_TEMPLATE = """I just completed a full recon scan of **{domain}**.
Here are the aggregated findings across all 11 phases:

## Target Statistics
- Subdomains found: {num_subs}
- Live hosts: {num_live}
- Open ports: {num_ports}
- Total vulnerabilities: {num_vulns}
- Leaked secrets: {num_leaks}
- Exposed cloud resources: {num_cloud}
- Subdomain takeover candidates: {num_takeovers}
- URLs crawled: {num_urls}

## Critical Findings Summary

### Vulnerabilities (Top 15)
{vuln_summary}

### Leaked Secrets (Top 10)
{secrets_summary}

### Subdomain Takeover Opportunities
{takeover_summary}

### Exposed Cloud Resources
{cloud_summary}

### Open Sensitive Ports
{port_summary}

### DNS Issues
- SPF: {spf}
- DMARC: {dmarc}
- Wildcard DNS: {wildcard}
- Zone Transfer: {zone_transfer}

### Interesting Content Found
{content_summary}

Based on all of this, provide:
1. **Executive Risk Summary** (2-3 sentences)
2. **Critical Finding Priority List** (ranked, with CVSS-like scores)
3. **Attack Chain Analysis** (how findings combine for maximum impact)
4. **Quick Win Exploits** (things to try immediately)
5. **Recommended Next Steps** (specific commands/approaches)
6. **Overall Risk Score** (1-10 with justification)
"""


def _truncate_list(items: list, n: int = 15, key: str = None) -> str:
    if not items:
        return "None found"
    shown = items[:n]
    lines = []
    for item in shown:
        if isinstance(item, dict):
            if key:
                lines.append(f"- {item.get(key, str(item))}")
            else:
                lines.append(f"- {json.dumps(item, default=str)[:120]}")
        else:
            lines.append(f"- {str(item)[:120]}")
    if len(items) > n:
        lines.append(f"... and {len(items) - n} more")
    return "\n".join(lines)


def run_phase(domain: str, output_dir: Path, all_phase_data: Dict[str, Any]) -> Dict[str, Any]:
    log = get_logger()
    cfg = get_config()

    phase_dir = output_dir / "phase_12_ai_summary"
    phase_dir.mkdir(parents=True, exist_ok=True)

    p2 = all_phase_data.get("p02", {})
    p3 = all_phase_data.get("p03", {})
    p4 = all_phase_data.get("p04", {})
    p5 = all_phase_data.get("p05", {})
    p6 = all_phase_data.get("p06", {})
    p7 = all_phase_data.get("p07", {})
    p8 = all_phase_data.get("p08", {})
    p9 = all_phase_data.get("p09", {})
    p10= all_phase_data.get("p10", {})

    open_ports   = p5.get("open_ports", {})
    total_ports  = sum(len(v) for v in open_ports.values())
    leaks        = p7.get("leaks", [])
    exposed_cloud= p10.get("exposed_cloud", [])
    takeovers    = p3.get("takeover_risks", [])

    # Build vuln summary for prompt
    vulns = []
    for n in p8.get("nuclei", [])[:10]:
        info = n.get("info", {})
        vulns.append(f"[{info.get('severity','?').upper()}] {info.get('name','?')} @ {n.get('matched-at','?')}")
    for x in p8.get("xss", [])[:5]:
        vulns.append(f"[HIGH] XSS @ {x['url'][:60]} param={x['param']}")
    for s in p8.get("sqli", [])[:5]:
        vulns.append(f"[CRITICAL] SQLi @ {s['url'][:60]} param={s['param']}")
    for c in p8.get("cors", [])[:5]:
        vulns.append(f"[MEDIUM] CORS Misconfiguration @ {c['url'][:60]}")

    # Build port summary
    port_lines = []
    for ip, ports in list(open_ports.items())[:5]:
        sensitive = [p5.get("interesting", [])][0]
        svc_ports = [f"{p}" for p in ports[:10]]
        port_lines.append(f"- {ip}: {', '.join(svc_ports)}")

    # Admin panels / content
    content_items = []
    for e in p9.get("admin_panels", [])[:5]:
        content_items.append(f"- Admin: {e.get('url', '')} [{e.get('status')}]")
    for e in p9.get("backup_files", [])[:5]:
        content_items.append(f"- Backup: {e.get('url', '')} [{e.get('status')}]")
    for e in p9.get("config_files", [])[:5]:
        content_items.append(f"- Config: {e.get('url', '')} [{e.get('status')}]")

    user_prompt = USER_PROMPT_TEMPLATE.format(
        domain=domain,
        num_subs=len(p2.get("subdomains_live", [])),
        num_live=len(p4.get("live_hosts", [])),
        num_ports=total_ports,
        num_vulns=p8.get("total_vulns", 0),
        num_leaks=len(leaks),
        num_cloud=len(exposed_cloud),
        num_takeovers=len(takeovers),
        num_urls=len(p6.get("urls_crawled", [])),
        vuln_summary="\n".join(vulns) or "None detected",
        secrets_summary=_truncate_list(leaks, 10, key="type"),
        takeover_summary=_truncate_list(takeovers, 10, key="subdomain"),
        cloud_summary=_truncate_list(exposed_cloud, 10, key="url"),
        port_summary="\n".join(port_lines) or "None detected",
        spf=p3.get("spf", "Not found") or "Not found",
        dmarc=p3.get("dmarc", "Not found") or "Not found",
        wildcard="Yes ⚠️" if p3.get("wildcard") else "No",
        zone_transfer=f"{len(p3.get('zone_transfer', []))} transfers succeeded!" if p3.get("zone_transfer") else "None",
        content_summary="\n".join(content_items) or "None notable",
    )

    ai_response = ""
    ai_model    = cfg.ai_model

    # ── OpenAI ────────────────────────────────────────────────────────────────
    if cfg.openai_key:
        log.info(f"Querying OpenAI ({ai_model}) for attack surface analysis...")
        try:
            import openai
            client  = openai.OpenAI(api_key=cfg.openai_key)
            chat    = client.chat.completions.create(
                model=ai_model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user",   "content": user_prompt},
                ],
                max_tokens=3000,
                temperature=0.4,
            )
            ai_response = chat.choices[0].message.content
            log.success("AI analysis complete (OpenAI)")
        except Exception as e:
            log.error(f"OpenAI API failed: {e}")

    # ── Google Gemini fallback ─────────────────────────────────────────────────
    if not ai_response:
        try:
            import google.generativeai as genai
            import os
            gemini_key = os.environ.get("GEMINI_API_KEY")
            if gemini_key:
                log.info("Querying Google Gemini for attack surface analysis...")
                genai.configure(api_key=gemini_key)
                model    = genai.GenerativeModel("gemini-1.5-pro")
                response = model.generate_content(f"{SYSTEM_PROMPT}\n\n{user_prompt}")
                ai_response = response.text
                log.success("AI analysis complete (Gemini)")
        except Exception as e:
            log.warning(f"Gemini fallback failed: {e}")

    if not ai_response:
        log.warning("No AI API configured — generating basic summary")
        ai_response = f"""# DOMINION Attack Surface Report — {domain}

> No AI API key configured. Add openai or gemini key to config.yml for full AI analysis.

## Quick Summary

- **{len(p2.get('subdomains_live', []))}** live subdomains discovered
- **{total_ports}** open ports across all hosts
- **{p8.get('total_vulns', 0)}** vulnerabilities found
- **{len(leaks)}** secrets leaked
- **{len(exposed_cloud)}** cloud resources exposed
- **{len(takeovers)}** potential subdomain takeovers

## Priority Findings

{_truncate_list(vulns, 20)}

## Recommended Next Steps
1. Exploit any SQLi/XSS findings immediately
2. Investigate leaked secrets for valid credentials
3. Attempt subdomain takeover on identified candidates
4. Access exposed cloud resources
5. Check exposed admin panels with default credentials
"""

    # ── Save ──────────────────────────────────────────────────────────────────
    ai_md = phase_dir / "ai_summary.md"
    ai_md.write_text(ai_response, encoding="utf-8")
    log.success(f"AI summary saved: {ai_md}")

    # Append to main report
    main_report = output_dir / "report.md"
    if main_report.exists():
        with open(main_report, "a", encoding="utf-8") as f:
            f.write(f"\n\n---\n\n{ai_response}")

    findings = {
        "domain":      domain,
        "ai_model":    ai_model,
        "ai_response": ai_response,
        "prompt_used": user_prompt,
    }
    save_json(phase_dir / "phase_12_results.json", findings)
    log.success("Phase 12 complete — AI attack surface analysis done")
    return findings
