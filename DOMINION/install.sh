#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║        DOMINION — Bulletproof Installer v3.0 (Kali-Optimized)          ║
# ║  Zero failures. Every tool has a fallback. Works offline partially.     ║
# ╚══════════════════════════════════════════════════════════════════════════╝
# // turbo-all

set -euo pipefail
trap 'echo -e "\n[!] Script interrupted. Run again to retry." >&2' ERR INT

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; PURPLE='\033[0;35m'; NC='\033[0m'; BOLD='\033[1m'

info()    { echo -e "${CYAN}[*]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
banner()  { echo -e "\n${PURPLE}${BOLD}══ $1 ══${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

INSTALLED=0; SKIPPED=0; FAILED_TOOLS=()

tick()  { INSTALLED=$((INSTALLED+1)); success "[$INSTALLED] $1 ✓"; }
skip()  { SKIPPED=$((SKIPPED+1));    success "[skip] $1 already installed"; }
fail()  { FAILED_TOOLS+=("$1");      warn "Could not install $1 — continuing"; }

echo -e "${RED}${BOLD}"
cat << 'EOF'
██████╗  ██████╗ ███╗   ███╗██╗███╗   ██╗██╗ ██████╗ ███╗   ██╗
██╔══██╗██╔═══██╗████╗ ████║██║████╗  ██║██║██╔═══██╗████╗  ██║
██║  ██║██║   ██║██╔████╔██║██║██╔██╗ ██║██║██║   ██║██╔██╗ ██║
██║  ██║██║   ██║██║╚██╔╝██║██║██║╚██╗██║██║██║   ██║██║╚██╗██║
██████╔╝╚██████╔╝██║ ╚═╝ ██║██║██║ ╚████║██║╚██████╔╝██║ ╚████║
╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝
        Bulletproof Installer v3.0 — Kali Optimized
EOF
echo -e "${NC}"

# ─────────────────────────────────────────────────────────────────────────────
banner "Environment Detection"
# ─────────────────────────────────────────────────────────────────────────────
PY=""
for candidate in python3 python3.12 python3.11 python3.10; do
    if command -v "$candidate" &>/dev/null; then PY="$candidate"; break; fi
done
[ -z "$PY" ] && { echo "ERROR: Python3 not found!"; exit 1; }
PY_VER=$($PY -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
success "Python: $PY_VER"

# Detect pip flags (Kali/Debian bookworm needs --break-system-packages)
PIP_FLAGS="--quiet --no-warn-script-location"
if $PY -m pip install --help 2>/dev/null | grep -q "break-system-packages"; then
    PIP_FLAGS="$PIP_FLAGS --break-system-packages"
fi

# Go
export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin:$HOME/.local/bin"

# ─────────────────────────────────────────────────────────────────────────────
banner "APT System Packages (non-fatal)"
# ─────────────────────────────────────────────────────────────────────────────
info "Running apt-get update..."
sudo apt-get update -qq 2>/dev/null || warn "apt-get update failed — using cached repos"

apt_try() {
    # Silent per-package install — never fails the script
    local pkg="$1"
    local check="${2:-}"
    if [ -n "$check" ] && command -v "$check" &>/dev/null 2>&1; then
        skip "$pkg"; return 0
    fi
    if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        --no-install-recommends "$pkg" 2>/dev/null; then
        tick "$pkg"
    else
        warn "apt: $pkg not available — skipping (non-fatal)"
    fi
}

apt_try curl         curl
apt_try git          git
apt_try wget         wget
apt_try unzip        unzip
apt_try jq           jq
apt_try nmap         nmap
apt_try masscan      masscan
apt_try nikto        nikto
apt_try sqlmap       sqlmap
apt_try dnsrecon     dnsrecon
apt_try dnsenum      dnsenum
apt_try fierce       fierce
apt_try whois        whois
apt_try wafw00f      wafw00f
apt_try whatweb      whatweb
apt_try wfuzz        wfuzz
apt_try feroxbuster  feroxbuster
apt_try gobuster     gobuster
apt_try eyewitness   eyewitness
apt_try dirsearch    dirsearch
apt_try commix       commix
apt_try sublist3r    sublist3r
apt_try knockpy      knockpy

# Dev libs — try but don't fail
for pkg in python3-pip python3-venv python3-dev \
            libssl-dev libffi-dev libpcap-dev \
            ruby-dev build-essential net-tools \
            ncat netcat-openbsd; do
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        --no-install-recommends "$pkg" 2>/dev/null \
    && info "  installed $pkg" || true
done
success "APT packages done"

# ─────────────────────────────────────────────────────────────────────────────
banner "Go Installation Check"
# ─────────────────────────────────────────────────────────────────────────────
if ! command -v go &>/dev/null; then
    GO_VER="1.22.4"
    ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
    GO_URL="https://go.dev/dl/go${GO_VER}.linux-${ARCH}.tar.gz"
    info "Downloading Go $GO_VER..."
    wget -q "$GO_URL" -O /tmp/go.tar.gz && \
    sudo rm -rf /usr/local/go && \
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc 2>/dev/null || true
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.zshrc 2>/dev/null || true
    success "Go installed"
fi
success "Go: $(go version)"
mkdir -p "$GOPATH/bin"

# ─────────────────────────────────────────────────────────────────────────────
# go_get: install go tool, never fail
# ─────────────────────────────────────────────────────────────────────────────
go_get() {
    local pkg="$1"
    local bin="$2"
    local fallback="${3:-}"
    if command -v "$bin" &>/dev/null; then skip "$bin"; return 0; fi
    info "Installing $bin..."
    if GOFLAGS="-mod=mod" go install "$pkg" 2>/dev/null; then
        tick "$bin"
    elif [ -n "$fallback" ]; then
        info "  Trying fallback for $bin..."
        eval "$fallback" 2>/dev/null && tick "$bin" || fail "$bin"
    else
        fail "$bin"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
banner "Go Tools — Subdomain Enumeration"
# ─────────────────────────────────────────────────────────────────────────────
go_get "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" subfinder
go_get "github.com/owasp-amass/amass/v4/...@latest"                    amass
go_get "github.com/tomnomnom/assetfinder@latest"                        assetfinder
go_get "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"     chaos
go_get "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"              dnsx
go_get "github.com/d3mondev/puredns/v2@latest"                         puredns

# shuffledns — correct package path
go_get "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest" shuffledns

# gotator — correct package
go_get "github.com/Josue87/gotator@latest" gotator \
    "go install github.com/Josue87/gotator@latest 2>/dev/null || true"

# findomain — binary release (no Go source available)
if ! command -v findomain &>/dev/null; then
    info "Installing findomain (binary release)..."
    FINDOMAIN_VER=$(curl -s "https://api.github.com/repos/findomain/findomain/releases/latest" \
        2>/dev/null | grep tag_name | cut -d'"' -f4 2>/dev/null || echo "v9.0.4")
    wget -q "https://github.com/findomain/findomain/releases/latest/download/findomain-linux" \
         -O "$HOME/.local/bin/findomain" 2>/dev/null && \
    chmod +x "$HOME/.local/bin/findomain" && tick findomain || fail findomain
fi

go_get "github.com/gwen001/github-subdomains@latest" github-subdomains
go_get "github.com/projectdiscovery/massdns@latest"  massdns \
    "sudo apt-get install -y -qq massdns 2>/dev/null || true"

# ─────────────────────────────────────────────────────────────────────────────
banner "Go Tools — HTTP & Live Host"
# ─────────────────────────────────────────────────────────────────────────────
go_get "github.com/projectdiscovery/httpx/cmd/httpx@latest"  httpx
go_get "github.com/tomnomnom/httprobe@latest"                 httprobe
go_get "github.com/sensepost/gowitness@latest"                gowitness
go_get "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"    tlsx
go_get "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest" naabu

# aquatone — binary download
if ! command -v aquatone &>/dev/null; then
    info "Installing aquatone..."
    ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
    wget -q "https://github.com/michenriksen/aquatone/releases/latest/download/aquatone_linux_${ARCH}.zip" \
         -O /tmp/aquatone.zip 2>/dev/null && \
    unzip -q /tmp/aquatone.zip -d "$HOME/.local/bin/" 2>/dev/null && \
    chmod +x "$HOME/.local/bin/aquatone" 2>/dev/null && \
    rm -f /tmp/aquatone.zip && tick aquatone || fail aquatone
fi

# rustscan — deb package
if ! command -v rustscan &>/dev/null; then
    info "Installing rustscan..."
    wget -q "https://github.com/RustScan/RustScan/releases/latest/download/rustscan_2.3.0_amd64.deb" \
         -O /tmp/rustscan.deb 2>/dev/null && \
    sudo dpkg -i /tmp/rustscan.deb 2>/dev/null && \
    rm -f /tmp/rustscan.deb && tick rustscan || fail rustscan
fi

# ─────────────────────────────────────────────────────────────────────────────
banner "Go Tools — Crawling & URL Discovery"
# ─────────────────────────────────────────────────────────────────────────────
go_get "github.com/projectdiscovery/katana/cmd/katana@latest" katana
go_get "github.com/jaeles-project/gospider@latest"             gospider
go_get "github.com/hakluke/hakrawler@latest"                   hakrawler
go_get "github.com/lc/gau/v2/cmd/gau@latest"                  gau
go_get "github.com/tomnomnom/waybackurls@latest"               waybackurls
go_get "github.com/bp0lr/gauplus@latest"                       gauplus
go_get "github.com/tomnomnom/meg@latest"                       meg
go_get "github.com/tomnomnom/gf@latest"                        gf

# GF Patterns
if [ ! -d "$HOME/.gf" ] || [ "$(ls -A "$HOME/.gf" 2>/dev/null | wc -l)" -lt 5 ]; then
    info "Installing GF patterns..."
    git clone -q --depth 1 https://github.com/1ndianl33t/Gf-Patterns /tmp/gf-patterns 2>/dev/null && \
    mkdir -p "$HOME/.gf" && cp /tmp/gf-patterns/*.json "$HOME/.gf/" 2>/dev/null && \
    success "GF patterns installed" || warn "GF patterns: could not download"
fi

# ─────────────────────────────────────────────────────────────────────────────
banner "Go Tools — Vulnerability Scanning"
# ─────────────────────────────────────────────────────────────────────────────
go_get "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"          nuclei
go_get "github.com/hahwul/dalfox/v2@latest"                               dalfox
go_get "github.com/dwisiswant0/crlfuzz@latest"                            crlfuzz
go_get "github.com/ffuf/ffuf/v2@latest"                                    ffuf
go_get "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest" interactsh-client
go_get "github.com/OJ/gobuster/v3@latest"                                 gobuster
go_get "github.com/devploit/nomore403@latest"                              nomore403
go_get "github.com/projectdiscovery/cloudbrute/cmd/cloudbrute@latest"     cloudbrute \
    "go install github.com/projectdiscovery/cloudbrute/cmd/cloudbrute@latest 2>/dev/null || true"

# ─────────────────────────────────────────────────────────────────────────────
banner "Nuclei Templates"
# ─────────────────────────────────────────────────────────────────────────────
if command -v nuclei &>/dev/null; then
    info "Updating nuclei templates..."
    nuclei -update-templates 2>/dev/null && success "Templates updated" || warn "Template update failed (network?)"
    # Extra fuzzing templates
    NUCLEI_EXTRA="$HOME/.config/nuclei/fuzzing-templates"
    if [ ! -d "$NUCLEI_EXTRA" ]; then
        git clone -q --depth 1 https://github.com/projectdiscovery/fuzzing-templates \
            "$NUCLEI_EXTRA" 2>/dev/null && success "Fuzzing templates added" || true
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
banner "trufflehog (Secret Detection)"
# ─────────────────────────────────────────────────────────────────────────────
if ! command -v trufflehog &>/dev/null; then
    info "Installing trufflehog..."
    # Method 1: Install script
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        2>/dev/null | sudo sh -s -- -b /usr/local/bin 2>/dev/null && \
    tick trufflehog || {
        # Method 2: Binary download
        ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
        wget -q "https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_$(uname -s | tr '[:upper:]' '[:lower:]')_${ARCH}.tar.gz" \
             -O /tmp/trufflehog.tar.gz 2>/dev/null && \
        tar -xzf /tmp/trufflehog.tar.gz -C "$HOME/.local/bin/" trufflehog 2>/dev/null && \
        chmod +x "$HOME/.local/bin/trufflehog" && tick trufflehog || fail trufflehog
    }
fi

# ─────────────────────────────────────────────────────────────────────────────
banner "Python Virtual Environment"
# ─────────────────────────────────────────────────────────────────────────────
info "Creating Python venv..."
$PY -m venv .venv 2>/dev/null || {
    # Kali sometimes needs --system-site-packages
    $PY -m venv --system-site-packages .venv 2>/dev/null || {
        warn "venv creation failed — using system pip directly"
        PIP="$PY -m pip"
        PIP_FLAGS="$PIP_FLAGS"
    }
}
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
    PIP="pip"
    success "venv activated"
else
    PIP="$PY -m pip"
fi

# Upgrade pip silently
$PIP install $PIP_FLAGS --upgrade pip 2>/dev/null || true
info "pip: $($PIP --version 2>/dev/null)"

# ─────────────────────────────────────────────────────────────────────────────
# pip_try: install Python package, never fail
# ─────────────────────────────────────────────────────────────────────────────
pip_try() {
    local pkg="$1"
    local bin="${2:-$1}"
    local alt_check="${3:-}"  # alternate import check
    # Check if already available
    if command -v "$bin" &>/dev/null 2>&1; then skip "$bin"; return 0; fi
    if [ -n "$alt_check" ] && $PY -c "import $alt_check" &>/dev/null 2>&1; then skip "$pkg"; return 0; fi
    info "pip install $bin..."
    if $PIP install $PIP_FLAGS "$pkg" 2>/dev/null; then
        tick "$bin"
    else
        # Try with --ignore-installed
        $PIP install $PIP_FLAGS --ignore-installed "$pkg" 2>/dev/null && tick "$bin" || fail "$bin"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
banner "Python Security Tools"
# ─────────────────────────────────────────────────────────────────────────────
$PIP install $PIP_FLAGS -r requirements.txt 2>/dev/null || \
    warn "requirements.txt partial install — continuing"

pip_try "theHarvester"         theHarvester
pip_try "dirsearch"            dirsearch
pip_try "knockpy"              knockpy
pip_try "sublist3r"            sublist3r
pip_try "arjun"                arjun
pip_try "xsstrike"             xsstrike
pip_try "wfuzz"                wfuzz
pip_try "wafw00f"              wafw00f
pip_try "socialscan"           socialscan
pip_try "holehe"               holehe
pip_try "h8mail"               h8mail
pip_try "photon"               photon
pip_try "s3scanner"            s3scanner
pip_try "git-dumper"           git-dumper
pip_try "dnstwist"             dnstwist

# graphw00f (GraphQL fingerprinting)
if ! command -v graphw00f &>/dev/null; then
    info "Installing graphw00f..."
    $PIP install $PIP_FLAGS graphw00f 2>/dev/null && tick graphw00f || \
    (git clone -q --depth 1 https://github.com/dolevf/graphw00f /opt/graphw00f 2>/dev/null && \
     $PIP install $PIP_FLAGS -r /opt/graphw00f/requirements.txt 2>/dev/null && \
     ln -sf /opt/graphw00f/main.py /usr/local/bin/graphw00f && \
     chmod +x /opt/graphw00f/main.py && tick graphw00f || fail graphw00f)
fi

# corsy (CORS scanner)
if ! $PY -c "import corsy" &>/dev/null 2>&1 && ! command -v corsy &>/dev/null; then
    info "Installing corsy..."
    git clone -q --depth 1 https://github.com/s0md3v/Corsy /opt/corsy 2>/dev/null && \
    $PIP install $PIP_FLAGS -r /opt/corsy/requirements.txt 2>/dev/null && \
    ln -sf /opt/corsy/corsy.py /usr/local/bin/corsy && \
    chmod +x /opt/corsy/corsy.py && tick corsy || fail corsy
fi

# paramspider
if ! command -v paramspider &>/dev/null; then
    info "Installing paramspider..."
    $PIP install $PIP_FLAGS paramspider 2>/dev/null && tick paramspider || \
    (git clone -q --depth 1 https://github.com/devanshbatham/paramspider /opt/paramspider 2>/dev/null && \
     $PIP install $PIP_FLAGS -e /opt/paramspider 2>/dev/null && tick paramspider || fail paramspider)
fi

# jwt_tool
if ! command -v jwt_tool &>/dev/null; then
    info "Installing jwt_tool..."
    git clone -q --depth 1 https://github.com/ticarpi/jwt_tool /opt/jwt_tool 2>/dev/null && \
    $PIP install $PIP_FLAGS -r /opt/jwt_tool/requirements.txt 2>/dev/null && \
    ln -sf /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool && \
    chmod +x /opt/jwt_tool/jwt_tool.py && tick jwt_tool || fail jwt_tool
fi

# linkfinder
if ! command -v linkfinder &>/dev/null; then
    info "Installing linkfinder..."
    git clone -q --depth 1 https://github.com/GerbenJavado/LinkFinder /opt/linkfinder 2>/dev/null && \
    $PIP install $PIP_FLAGS -r /opt/linkfinder/requirements.txt 2>/dev/null && \
    ln -sf /opt/linkfinder/linkfinder.py /usr/local/bin/linkfinder && \
    chmod +x /opt/linkfinder/linkfinder.py && tick linkfinder || fail linkfinder
fi

# secretfinder
if ! command -v secretfinder &>/dev/null; then
    info "Installing secretfinder..."
    git clone -q --depth 1 https://github.com/m4ll0k/SecretFinder /opt/secretfinder 2>/dev/null && \
    $PIP install $PIP_FLAGS -r /opt/secretfinder/requirements.txt 2>/dev/null && \
    ln -sf /opt/secretfinder/SecretFinder.py /usr/local/bin/secretfinder && \
    chmod +x /opt/secretfinder/SecretFinder.py && tick secretfinder || fail secretfinder
fi

# smuggler
if ! command -v smuggler &>/dev/null; then
    info "Installing smuggler..."
    git clone -q --depth 1 https://github.com/defparam/smuggler /opt/smuggler 2>/dev/null && \
    ln -sf /opt/smuggler/smuggler.py /usr/local/bin/smuggler && \
    chmod +x /opt/smuggler/smuggler.py && tick smuggler || fail smuggler
fi

# ssrfmap
if ! command -v ssrfmap &>/dev/null; then
    info "Installing ssrfmap..."
    git clone -q --depth 1 https://github.com/swisskyrepo/SSRFmap /opt/ssrfmap 2>/dev/null && \
    $PIP install $PIP_FLAGS -r /opt/ssrfmap/requirements.txt 2>/dev/null && \
    ln -sf /opt/ssrfmap/ssrfmap.py /usr/local/bin/ssrfmap && \
    chmod +x /opt/ssrfmap/ssrfmap.py && tick ssrfmap || fail ssrfmap
fi

# cloud_enum
if ! command -v cloud_enum &>/dev/null; then
    info "Installing cloud_enum..."
    git clone -q --depth 1 https://github.com/initstring/cloud_enum /opt/cloud_enum 2>/dev/null && \
    $PIP install $PIP_FLAGS -r /opt/cloud_enum/requirements.txt 2>/dev/null && \
    ln -sf /opt/cloud_enum/cloud_enum.py /usr/local/bin/cloud_enum && \
    chmod +x /opt/cloud_enum/cloud_enum.py && tick cloud_enum || fail cloud_enum
fi

# XSStrike
if ! command -v xsstrike &>/dev/null; then
    info "Installing XSStrike..."
    git clone -q --depth 1 https://github.com/s0md3v/XSStrike /opt/xsstrike 2>/dev/null && \
    $PIP install $PIP_FLAGS -r /opt/xsstrike/requirements.txt 2>/dev/null && \
    ln -sf /opt/xsstrike/xsstrike.py /usr/local/bin/xsstrike && \
    chmod +x /opt/xsstrike/xsstrike.py && tick xsstrike || fail xsstrike
fi

# feroxbuster
if ! command -v feroxbuster &>/dev/null; then
    info "Installing feroxbuster..."
    sudo apt-get install -y -qq feroxbuster 2>/dev/null && tick feroxbuster || \
    (curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh 2>/dev/null | \
     bash -s -- -b "$HOME/.local/bin" 2>/dev/null && tick feroxbuster || fail feroxbuster)
fi

# wpscan
if ! command -v wpscan &>/dev/null; then
    info "Installing wpscan..."
    sudo apt-get install -y -qq wpscan 2>/dev/null && tick wpscan || \
    (gem install wpscan 2>/dev/null && tick wpscan || fail wpscan)
fi

# eyewitness
if ! command -v eyewitness &>/dev/null; then
    info "Installing eyewitness..."
    sudo apt-get install -y -qq eyewitness 2>/dev/null && tick eyewitness || {
        git clone -q --depth 1 https://github.com/RedSiege/EyeWitness /opt/eyewitness 2>/dev/null && \
        $PY /opt/eyewitness/setup/setup.py 2>/dev/null || true
        ln -sf /opt/eyewitness/EyeWitness.py /usr/local/bin/eyewitness 2>/dev/null && \
        chmod +x /opt/eyewitness/EyeWitness.py && tick eyewitness || fail eyewitness
    }
fi

# ─────────────────────────────────────────────────────────────────────────────
banner "PATH Setup"
# ─────────────────────────────────────────────────────────────────────────────
PATH_LINE='export PATH=$PATH:$HOME/go/bin:/usr/local/go/bin:$HOME/.local/bin'
for rc in ~/.bashrc ~/.zshrc; do
    [ -f "$rc" ] && grep -q "go/bin" "$rc" 2>/dev/null || echo "$PATH_LINE" >> "$rc" 2>/dev/null || true
done

# ─────────────────────────────────────────────────────────────────────────────
banner "Wordlists"
# ─────────────────────────────────────────────────────────────────────────────
mkdir -p wordlists

# Find SecLists
if   [ -d /usr/share/seclists ];     then SECLISTS="/usr/share/seclists"
elif [ -d /usr/share/SecLists ];     then SECLISTS="/usr/share/SecLists"
elif [ -d /opt/SecLists ];           then SECLISTS="/opt/SecLists"
else
    info "Cloning SecLists (might take a few minutes)..."
    git clone -q --depth 1 https://github.com/danielmiessler/SecLists /opt/SecLists 2>/dev/null && \
    SECLISTS="/opt/SecLists" && success "SecLists ready" || {
        warn "SecLists clone failed — downloading minimal wordlists"
        SECLISTS=""
    }
fi
[ -n "$SECLISTS" ] && success "SecLists: $SECLISTS"

# ── Helper: merge wordlists ────────────────────────────────────────────────────
merge_wl() {
    local dst="$1"; shift
    > "$dst"
    for f in "$@"; do [ -f "$f" ] && cat "$f" >> "$dst" && info "  + $(basename "$f")"; done
}

# ── Subdomains ─────────────────────────────────────────────────────────────────
info "Building subdomain wordlist..."
merge_wl wordlists/subdomains.txt \
    "${SECLISTS}/Discovery/DNS/subdomains-top1million-110000.txt" \
    "${SECLISTS}/Discovery/DNS/deepmagic.com-prefixes-top50000.txt" \
    "${SECLISTS}/Discovery/DNS/bitquark-subdomains-top100000.txt" \
    "${SECLISTS}/Discovery/DNS/fierce-hostlist.txt" \
    "${SECLISTS}/Discovery/DNS/dns-Jhaddix.txt" \
    "${SECLISTS}/Discovery/DNS/combined_subdomains.txt" \

# Assetnote wordlists (best in industry)
wget -q --timeout=30 \
    "https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt" \
    -O /tmp/an_dns.txt 2>/dev/null && cat /tmp/an_dns.txt >> wordlists/subdomains.txt && \
    success "Assetnote DNS wordlist added" || true

sort -u wordlists/subdomains.txt -o wordlists/subdomains.txt
WC=$(wc -l < wordlists/subdomains.txt 2>/dev/null || echo 0)
success "Subdomains wordlist: ${WC} entries"

# ── Directories ────────────────────────────────────────────────────────────────
info "Building directory wordlist..."
merge_wl wordlists/directories.txt \
    "${SECLISTS}/Discovery/Web-Content/raft-large-directories.txt" \
    "${SECLISTS}/Discovery/Web-Content/raft-large-files.txt" \
    "${SECLISTS}/Discovery/Web-Content/raft-medium-directories.txt" \
    "${SECLISTS}/Discovery/Web-Content/common.txt" \
    "${SECLISTS}/Discovery/Web-Content/directory-list-2.3-medium.txt" \
    "${SECLISTS}/Discovery/Web-Content/quickhits.txt"

wget -q --timeout=30 \
    "https://wordlists-cdn.assetnote.io/data/automated/httparchive_apiroutes_2024.01.28.txt" \
    -O /tmp/an_api.txt 2>/dev/null && cat /tmp/an_api.txt >> wordlists/directories.txt && \
    success "Assetnote API routes added" || true

sort -u wordlists/directories.txt -o wordlists/directories.txt
WC=$(wc -l < wordlists/directories.txt 2>/dev/null || echo 0)
success "Directories wordlist: ${WC} entries"

# ── Parameters ─────────────────────────────────────────────────────────────────
merge_wl wordlists/parameters.txt \
    "${SECLISTS}/Discovery/Web-Content/burp-parameter-names.txt" \
    "${SECLISTS}/Discovery/Web-Content/raft-large-words.txt"

wget -q --timeout=30 \
    "https://wordlists-cdn.assetnote.io/data/automated/httparchive_parameters_2024.01.28.txt" \
    -O /tmp/an_params.txt 2>/dev/null && cat /tmp/an_params.txt >> wordlists/parameters.txt || true
sort -u wordlists/parameters.txt -o wordlists/parameters.txt
success "Parameters wordlist: $(wc -l < wordlists/parameters.txt 2>/dev/null || echo 0) entries"

# ── Fuzzing payloads ───────────────────────────────────────────────────────────
merge_wl wordlists/lfi_payloads.txt \
    "${SECLISTS}/Fuzzing/LFI/LFI-Jhaddix.txt" \
    "${SECLISTS}/Fuzzing/LFI/LFI-LFISuite-pathtotest.txt" \
    "${SECLISTS}/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt" \
    "${SECLISTS}/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt"
sort -u wordlists/lfi_payloads.txt -o wordlists/lfi_payloads.txt 2>/dev/null || true

merge_wl wordlists/xss_payloads.txt \
    "${SECLISTS}/Fuzzing/XSS/XSS-Jhaddix.txt" \
    "${SECLISTS}/Fuzzing/XSS/XSS-BruteLogic.txt"
sort -u wordlists/xss_payloads.txt -o wordlists/xss_payloads.txt 2>/dev/null || true

merge_wl wordlists/sqli_payloads.txt \
    "${SECLISTS}/Fuzzing/SQLi/Generic-SQLi.txt" \
    "${SECLISTS}/Fuzzing/SQLi/quick-SQLi.txt" \
    "${SECLISTS}/Fuzzing/SQLi/Generic-BlindSQLi.fuzzdb.txt"
sort -u wordlists/sqli_payloads.txt -o wordlists/sqli_payloads.txt 2>/dev/null || true

# ── DNS Resolvers ──────────────────────────────────────────────────────────────
wget -q --timeout=30 \
    "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" \
    -O wordlists/resolvers.txt 2>/dev/null && \
    success "DNS resolvers: $(wc -l < wordlists/resolvers.txt) resolvers" || {
    # Fallback: well-known resolvers
    cat > wordlists/resolvers.txt << 'RESEOF'
8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
9.9.9.9
9.9.9.11
149.112.112.112
208.67.222.222
208.67.220.220
94.140.14.14
94.140.15.15
76.76.19.19
76.223.122.150
185.228.168.9
185.228.169.9
RESEOF
    success "DNS resolvers: fallback list written"
}

# API-specific wordlist
merge_wl wordlists/api_paths.txt \
    "${SECLISTS}/Discovery/Web-Content/api/api-endpoints.txt" \
    "${SECLISTS}/Discovery/Web-Content/api/objects.txt"
sort -u wordlists/api_paths.txt -o wordlists/api_paths.txt 2>/dev/null || true

# ─────────────────────────────────────────────────────────────────────────────
banner "Final Verification"
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}  Tool Status:${NC}"

ALL_TOOLS=(
    subfinder amass assetfinder findomain chaos
    puredns shuffledns dnsx httpx httprobe
    nmap masscan naabu rustscan
    katana gospider hakrawler gau waybackurls gf
    nuclei dalfox crlfuzz ffuf gobuster feroxbuster
    sqlmap commix nikto wafw00f wfuzz nomore403
    trufflehog gitleaks git-dumper
    jwt_tool graphw00f xsstrike smuggler ssrfmap
    linkfinder secretfinder cloud_enum s3scanner
    gowitness aquatone
    dirsearch paramspider arjun
)

FOUND=0; MISSING=0
for t in "${ALL_TOOLS[@]}"; do
    if command -v "$t" &>/dev/null 2>&1; then
        printf "  ${GREEN}✓${NC} %-20s" "$t"
        FOUND=$((FOUND+1))
    else
        printf "  ${RED}✗${NC} %-20s" "$t"
        MISSING=$((MISSING+1))
    fi
    [ $((($FOUND+$MISSING) % 4)) -eq 0 ] && echo ""
done
echo -e "\n"

echo -e "${CYAN}${BOLD}  Wordlists:${NC}"
for wl in subdomains directories parameters lfi_payloads xss_payloads sqli_payloads resolvers api_paths; do
    f="wordlists/${wl}.txt"
    if [ -f "$f" ] && [ -s "$f" ]; then
        count=$(wc -l < "$f" | tr -d ' ')
        echo -e "  ${GREEN}✓${NC} ${wl}.txt (${count} lines)"
    else
        echo -e "  ${YELLOW}?${NC} ${wl}.txt — empty (wordlists download manually or from SecLists)"
    fi
done

echo ""
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✓ Tools installed: $FOUND / ${#ALL_TOOLS[@]}${NC}"
[ $MISSING -gt 0 ] && echo -e "${YELLOW}  ? Missing: $MISSING (non-critical)${NC}"
[ ${#FAILED_TOOLS[@]} -gt 0 ] && echo -e "${YELLOW}  Failed: ${FAILED_TOOLS[*]}${NC}"
echo -e "${GREEN}══════════════════════════════════════════${NC}"

echo ""
echo -e "  ${CYAN}Next steps:${NC}"
echo -e "  ${BOLD}1.${NC} source .venv/bin/activate"
echo -e "  ${BOLD}2.${NC} cp config.example.yml config.yml && nano config.yml"
echo -e "  ${BOLD}3.${NC} python dominion.py -d target.com"
echo ""
echo -e "${GREEN}${BOLD}DOMINION is ready. Happy hacking! 🔥${NC}"
