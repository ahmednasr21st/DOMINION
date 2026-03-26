# ⚡ DOMINION — Elite Domain Recon Framework

> **The most complete, automated domain reconnaissance and attack surface analysis tool.**  
> Point it at a domain — it does everything else.

```
██████╗  ██████╗ ███╗   ███╗██╗███╗   ██╗██╗ ██████╗ ███╗   ██╗
██╔══██╗██╔═══██╗████╗ ████║██║████╗  ██║██║██╔═══██╗████╗  ██║
██║  ██║██║   ██║██╔████╔██║██║██╔██╗ ██║██║██║   ██║██╔██╗ ██║
██║  ██║██║   ██║██║╚██╔╝██║██║██║╚██╗██║██║██║   ██║██║╚██╗██║
██████╔╝╚██████╔╝██║ ╚═╝ ██║██║██║ ╚████║██║╚██████╔╝██║ ╚████║
╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝
```

---

## 🚀 Quick Start (3 Steps)

```bash
# 1. Clone & install (one-time setup)
git clone https://github.com/YOUR/DOMINION.git && cd DOMINION
chmod +x install.sh && ./install.sh

# 2. Configure (optional — add API keys for deeper results)
cp config.example.yml config.yml
nano config.yml

# 3. Run!
source .venv/bin/activate
python dominion.py -d example.com
```

---

## 📋 All 12 Phases

| # | Phase | What it does | Key Tools |
|---|-------|-------------|-----------|
| 1 | 🔍 **Passive Recon** | WHOIS, certificates, ASN, OSINT | crt.sh, OTX, BuiltWith |
| 2 | 🌐 **Subdomain Enum** | Passive + active + permutations | subfinder, amass, puredns, gotator |
| 3 | 🔎 **DNS Deep Dive** | Records, zone transfer, SPF/DMARC, takeover | dnsx, dnsrecon, fierce |
| 4 | 🌍 **Live Hosts** | HTTP/HTTPS probing, WAF detection, tech stack | httpx, whatweb, wafw00f |
| 5 | 🔌 **Port Scanning** | TCP/UDP, service fingerprint, no-auth checks | nmap, masscan, naabu, rustscan |
| 6 | 🕷️ **Web Crawling** | URLs, params, JS analysis, secrets pattern | katana, gau, hakrawler, arjun |
| 7 | 🔑 **Secret Detection** | API keys, tokens, credentials in code | trufflehog, gitleaks, git-dumper |
| 8 | 🚨 **Vuln Scanning** | 19+ vuln classes + 55+ tools | nuclei, sqlmap, dalfox, commix, smuggler |
| 9 | 📂 **Content Discovery** | Admin panels, backups, configs, git exposure | feroxbuster, ffuf, dirsearch |
| 10 | ☁️ **Cloud & Infra** | S3, Firebase, Azure, GCP, default creds | cloudbrute, s3scanner, cloud_enum |
| 11 | 📸 **HTML Report** | Professional dark-mode report + screenshots | gowitness, aquatone |
| 12 | 🤖 **AI Analysis** | Attack surface analysis + recommendations | GPT-4o / Gemini |

---

## 💻 Usage

```bash
# Full scan (all 12 phases)
python dominion.py -d target.com

# Quick scan (passive → subdomains → DNS → live hosts)
python dominion.py -d target.com --quick

# Specific phases
python dominion.py -d target.com --phase 1-6
python dominion.py -d target.com --phase 8       # Vuln scan only

# Skip phases
python dominion.py -d target.com --skip 5,10     # Skip ports & cloud

# Resume interrupted scan
python dominion.py -d target.com --resume

# Verbose + custom output dir
python dominion.py -d target.com -v -o /tmp/myrecon

# Full port scan + Telegram alerts
python dominion.py -d target.com --full-ports --notify

# No AI (faster)
python dominion.py -d target.com --no-ai

# List all phases
python dominion.py --list-phases
```

---

## ⚙️ Configuration (`config.yml`)

```yaml
# API Keys (optional but recommended)
api_keys:
  shodan:          ""    # shodan.io -> More exposed services
  virustotal:      ""    # virustotal.com -> More subdomains
  securitytrails:  ""    # securitytrails.com -> Historical DNS
  censys:          ""    # censys.io -> Internet-wide scanning
  github:          ""    # github.com -> Source code secrets
  hunter:          ""    # hunter.io -> Email enumeration
  openai:          ""    # openai.com -> AI attack surface analysis
  chaos:           ""    # chaos.projectdiscovery.io -> Subdomain data

# Notifications
telegram:
  token:   ""            # Bot token from @BotFather
  chat_id: ""            # Your Telegram chat ID

# AI Model
ai:
  model: "gpt-4o"        # gpt-4o | gpt-4-turbo | gemini-1.5-pro

# Scan settings
settings:
  threads:        20
  rate_limit:     150    # Requests per second
  timeout:        15     # HTTP timeout
  full_port_scan: false  # Scan all 65535 ports
  skip_phases:    []     # Always skip these phases
```

---

## 📁 Output Structure

```
output/
└── example.com/
    ├── report.html              ← 🔥 Open this in your browser!
    ├── phase_01_passive/
    ├── phase_02_subdomains/
    │   ├── subdomains_all.txt   ← All discovered subdomains
    │   └── subdomains_live.txt  ← Live subdomains only
    ├── phase_03_dns/
    ├── phase_04_live_hosts/
    │   └── live_hosts.txt       ← All live HTTP/HTTPS hosts
    ├── phase_05_ports/
    ├── phase_06_crawling/
    │   ├── urls_crawled.txt     ← All crawled URLs
    │   └── param_urls.txt       ← URLs with parameters
    ├── phase_07_secrets/
    │   └── secrets_found.json   ← Leaked secrets
    ├── phase_08_vulns/
    │   └── phase_08_results.json
    ├── phase_09_content/
    ├── phase_10_cloud/
    ├── phase_11_reporting/
    │   └── screenshots/
    ├── phase_12_ai_summary/
    │   └── ai_summary.md        ← AI red team analysis
    └── .dominion_state.json     ← Resume state
```

---

## 🛡️ Vulnerability Coverage (Phase 8)

| Category | Tools | Details |
|----------|-------|---------|
| SQL Injection | sqlmap, custom | 5 types: Error, Boolean, Time, Union, OOB |
| XSS | dalfox, XSStrike | Reflected, Stored, DOM |
| SSTI | custom | 7 engines: Jinja2, Twig, Mako, Freemarker... |
| LFI | wfuzz, custom | Path traversal, PHP wrappers |
| SSRF | custom | Internal + metadata bypass payloads |
| XXE | custom | External entities, blind XXE |
| HTTP Smuggling | smuggler | CL.TE, TE.CL, TE.TE |
| JWT Attacks | jwt_tool | None alg, weak secret, kid injection |
| CORS | corsy, custom | Null origin, wildcard, credentials |
| 403 Bypass | nomore403 | 20+ techniques |
| CRLF Injection | crlfuzz | Header injection |
| Command Injection | commix | OS command injection |
| Open Redirect | custom | 15+ payloads |
| GraphQL | graphw00f | Introspection, batching, injection |
| Default Creds | custom | 50+ systems |
| Clickjacking | custom | X-Frame-Options check |
| WAF Detection | wafw00f | Automatic bypass suggestions |
| General Scan | nuclei | 8000+ templates (Updated daily) |
| Web Scanner | nikto | 6700+ checks |

---

## 🔧 Requirements

- **OS**: Kali Linux / ParrotOS / Ubuntu 20.04+
- **Python**: 3.10+
- **Go**: 1.21+ (auto-installed)
- **RAM**: 4GB+ recommended
- **Disk**: 20GB+ (wordlists + SecLists)

---

## ⚠️ Legal Disclaimer

DOMINION is for **authorized security testing only**.  
Only use against systems you **own** or have **explicit written permission** to test.  
The authors are not responsible for any misuse.

---

## 🤝 Contributing

PRs welcome! See [CONTRIBUTING.md](.github/CONTRIBUTING.md).

---

*Made with ❤️ for the security community*
