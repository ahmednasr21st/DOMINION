<div align="center">

```
██████╗  ██████╗ ███╗   ███╗██╗███╗   ██╗██╗ ██████╗ ███╗   ██╗
██╔══██╗██╔═══██╗████╗ ████║██║████╗  ██║██║██╔═══██╗████╗  ██║
██║  ██║██║   ██║██╔████╔██║██║██╔██╗ ██║██║██║   ██║██╔██╗ ██║
██║  ██║██║   ██║██║╚██╔╝██║██║██║╚██╗██║██║██║   ██║██║╚██╗██║
██████╔╝╚██████╔╝██║ ╚═╝ ██║██║██║ ╚████║██║╚██████╔╝██║ ╚████║
╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝
```

**Ultra-Powered Domain Recon Framework · 12 Phases · Zero Mercy**

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-red?style=flat-square)
![Phase](https://img.shields.io/badge/Phases-12-orange?style=flat-square)
![Status](https://img.shields.io/badge/Status-Beast%20Mode-red?style=flat-square)

</div>

---

## ⚡ What is DOMINION?

**DOMINION** is an ultra-powered, fully automated domain reconnaissance and attack surface discovery framework. You give it a domain — it gives you a complete attack map.

Built to be **stronger, faster, and more organized than reconftw**, with 12 sequential phases, AI-powered analysis, and a stunning dark-themed HTML report.

---

## 🔥 Features

| Feature | Description |
|---------|-------------|
| 🎯 12 Phases | From passive recon to AI analysis — fully automated |
| 🤖 AI Summary | GPT-4o/Gemini attack surface analysis after all phases |
| 📊 Rich Reports | Dark-themed HTML + JSON + Markdown output |
| 📸 Screenshots | gowitness screenshots all live hosts |
| ⏩ Resume | Restart from any phase with `--resume` |
| 🔔 Notifications | Telegram/Slack on completion |
| ⚙️ Config-Driven | All settings in `config.yml` |
| 🧩 Modular | Run any single phase independently |

---

## 📋 The 12 Phases

```
● PHASE 01  Passive Recon        WHOIS · DNS · crt.sh · ASN · Shodan · VirusTotal
● PHASE 02  Subdomain Enum       subfinder · amass · assetfinder · RapidDNS · Wayback
● PHASE 03  DNS Deep Dive        All records · Zone transfer · SPF/DMARC/DKIM · Takeovers
● PHASE 04  Live Host Discovery  httpx probe · WAF/CDN detection · Security headers
● PHASE 05  Port Scanning        naabu fast scan · nmap service+script detection
● PHASE 06  Web Crawling         katana · gospider · Wayback URLs · JS extraction
● PHASE 07  Secret Detection     TruffleHog · GitHub dorks · Wayback secrets · Pastes
● PHASE 08  Vulnerability Scan   nuclei · XSS · SQLi · SSRF · CORS · Header injection
● PHASE 09  Content Discovery    feroxbuster · admin panels · backup files · dotfiles
● PHASE 10  Cloud & Infra        S3 · Azure · GCP · Firebase · CDN origin bypass
● PHASE 11  Screenshot & Report  gowitness · HTML report · JSON + Markdown export
● PHASE 12  AI Analysis          GPT-4o/Gemini attack surface analysis & priorities
```

---

## 🚀 Installation

### Prerequisites
- Linux / macOS (Kali Linux recommended)
- Python 3.10+
- Go 1.20+

### One-Line Install
```bash
git clone https://github.com/YourUser/DOMINION.git
cd DOMINION
chmod +x install.sh
./install.sh
```

The installer will:
- Install all Go tools (subfinder, httpx, nuclei, katana, naabu, dnsx, gowitness, etc.)
- Set up Python virtual environment
- Download SecLists wordlists (110K+ subdomains, large directory list)
- Update Nuclei templates

---

## ⚙️ Configuration

Copy and edit the config file:
```bash
cp config.yml config.yml
nano config.yml
```

Add your API keys for maximum coverage:

```yaml
api_keys:
  shodan:         "your-shodan-key"
  virustotal:     "your-vt-key"
  securitytrails: "your-st-key"
  github_token:   "your-gh-token"
  openai:         "sk-..."          # For Phase 12 AI analysis
```

---

## 🎯 Usage

### Full Scan (All 12 Phases)
```bash
source .venv/bin/activate
python dominion.py -d example.com
```

### Specific Phases
```bash
# Run only phases 1-3
python dominion.py -d example.com --phase 1-3

# Run a single phase
python dominion.py -d example.com --phase 7

# Run selected phases
python dominion.py -d example.com --phase 1,2,4,8
```

### Options
```bash
python dominion.py -d example.com --skip 5,10    # Skip port scan + cloud
python dominion.py -d example.com --resume       # Resume from last phase
python dominion.py -d example.com --full-ports   # Full 65535 port scan
python dominion.py -d example.com --no-ai        # Skip AI summary
python dominion.py -d example.com --verbose      # Verbose output
python dominion.py -d example.com --notify       # Telegram notification
python dominion.py --list-phases                 # Show all phases
```

---

## 📁 Output Structure

```
output/
└── example.com/
    ├── phase_01_passive/       ← WHOIS, crt.sh, Shodan, VT results
    ├── phase_02_subdomains/    ← All subdomain sources + validated list
    ├── phase_03_dns/           ← DNS deep dive + zone transfer + takeovers
    ├── phase_04_live_hosts/    ← httpx JSON, security headers, WAF info
    ├── phase_05_ports/         ← naabu results, nmap XML/TXT
    ├── phase_06_crawling/      ← All URLs, JS files, params, forms
    ├── phase_07_secrets/       ← Leaked secrets, GitHub dorks, Wayback
    ├── phase_08_vulns/         ← nuclei results, XSS/SQLi/SSRF findings
    ├── phase_09_content/       ← feroxbuster results, admin/backup files
    ├── phase_10_cloud/         ← S3/Firebase/Azure/GCP findings
    ├── phase_11_reporting/     ← Screenshots, HTML/JSON/MD reports
    ├── phase_12_ai_summary/    ← AI analysis markdown
    ├── subdomains.txt          ← Master live subdomain list
    ├── live_urls.txt           ← All live HTTP(S) URLs
    ├── report.html             ← 🔥 Full dark-theme HTML report
    ├── report.json             ← Complete JSON data export
    ├── report.md               ← Markdown summary + AI analysis
    └── dominion.log            ← Full run log
```

---

## 📸 Report Preview

The HTML report features:
- 🌑 Dark theme with red accents
- 📊 Stats grid (subdomains, ports, vulns, secrets, etc.)
- 🖼️ Screenshot gallery
- 📋 All findings organized by phase
- 🏷️ Severity tags (CRITICAL / HIGH / MEDIUM / LOW)
- 🔗 Clickable URLs throughout

---

## 🛠️ Tools Used

**Go Tools:** `subfinder` `amass` `assetfinder` `dnsx` `httpx` `naabu` `nuclei` `katana` `gospider` `gowitness` `feroxbuster` `ffuf` `trufflehog` `gitleaks` `cloudbrute`

**Python Libs:** `rich` `requests` `dnspython` `python-whois` `shodan` `openai` `google-generativeai` `pyyaml` `jinja2`

**APIs:** Shodan · VirusTotal · SecurityTrails · GitHub · crt.sh · AlienVault OTX · HackerTarget · RapidDNS · Wayback Machine · BGPView

---

## ⚠️ Legal Disclaimer

> DOMINION is intended for **authorized penetration testing and security research only**.  
> Always obtain **written permission** before scanning any domain.  
> The authors are not responsible for any misuse.

---

## 📝 License

MIT License — see [LICENSE](LICENSE)

---

<div align="center">
Made with ❤️ and ☕ for the red team community<br>
<strong>DOMINION — The Domain Falls Before Us</strong>
</div>
