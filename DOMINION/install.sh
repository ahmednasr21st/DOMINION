#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║     DOMINION — Zero-Error Installer v4.0  (Universal Linux)            ║
# ║  NEVER crashes. Every tool has multiple fallbacks. Idempotent.          ║
# ╚══════════════════════════════════════════════════════════════════════════╝
# // turbo-all

# ── NO set -e. We handle every error manually. ─────────────────────────────
set -uo pipefail 2>/dev/null || set -u   # -u warns on unset vars; NO -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; PURPLE='\033[0;35m'; BOLD='\033[1m'; NC='\033[0m'

_info()    { echo -e "${CYAN}[*]${NC} $*"; }
_ok()      { echo -e "${GREEN}[+]${NC} $*"; }
_warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
_banner()  { echo -e "\n${PURPLE}${BOLD}══ $* ══${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
cd "$SCRIPT_DIR" 2>/dev/null || true

echo -e "${RED}${BOLD}"
cat << 'EOF'
██████╗  ██████╗ ███╗   ███╗██╗███╗   ██╗██╗ ██████╗ ███╗   ██╗
██╔══██╗██╔═══██╗████╗ ████║██║████╗  ██║██║██╔═══██╗████╗  ██║
██║  ██║██║   ██║██╔████╔██║██║██╔██╗ ██║██║██║   ██║██╔██╗ ██║
██║  ██║██║   ██║██║╚██╔╝██║██║██║╚██╗██║██║██║   ██║██║╚██╗██║
██████╔╝╚██████╔╝██║ ╚═╝ ██║██║██║ ╚████║██║╚██████╔╝██║ ╚████║
╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝
        Zero-Error Installer v4.0 — Universal Linux
EOF
echo -e "${NC}"

# ─────────────────────────────────────────────────────────────────────────────
# Core environment setup
# ─────────────────────────────────────────────────────────────────────────────
GOPATH="${GOPATH:-$HOME/go}"
mkdir -p "$GOPATH/bin" "$HOME/.local/bin" 2>/dev/null || true
export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin:$HOME/.local/bin"

# Find Python
PY=""
for _py in python3 python3.13 python3.12 python3.11 python3.10; do
    command -v "$_py" &>/dev/null && PY="$_py" && break
done
[ -z "$PY" ] && { _warn "Python3 not found — install it first"; PY="python3"; }
PY_VER=$($PY -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "?")
_ok "Python $PY_VER"

# Detect pip flags for newer pip (Kali/Debian need --break-system-packages)
PIP_FLAGS="--quiet --no-warn-script-location"
$PY -m pip install --help 2>/dev/null | grep -q "break-system-packages" \
    && PIP_FLAGS="$PIP_FLAGS --break-system-packages"

# Stats
T_FOUND=0; T_SKIP=0; declare -a MISS=()
_tick() { T_FOUND=$((T_FOUND+1)); _ok "$1 ✓"; }
_skip() { T_SKIP=$((T_SKIP+1));   _ok "$1 already installed ✓"; }
_miss() { MISS+=("$1");           _warn "$1 — could not install (continuing)"; }

# ─────────────────────────────────────────────────────────────────────────────
# Universal tool-check
# ─────────────────────────────────────────────────────────────────────────────
_has() { command -v "$1" &>/dev/null 2>&1; }

# ─────────────────────────────────────────────────────────────────────────────
# APT install — truly non-fatal
# ─────────────────────────────────────────────────────────────────────────────
_apt() {
    local pkg="$1" check="${2:-$1}"
    if _has "$check"; then _skip "$pkg"; return 0; fi
    _info "apt: $pkg"
    DEBIAN_FRONTEND=noninteractive sudo apt-get install -y -qq \
        --no-install-recommends --ignore-missing "$pkg" \
        </dev/null 2>/dev/null \
    && _tick "$pkg" || _warn "apt: $pkg unavailable (non-fatal)"
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# Go install — non-fatal with CGO disabled
# ─────────────────────────────────────────────────────────────────────────────
_go() {
    local pkg="$1" bin="$2"
    if _has "$bin"; then _skip "$bin"; return 0; fi
    _info "go install: $bin"
    ( CGO_ENABLED=0 GOFLAGS="-mod=mod" go install "$pkg" 2>/dev/null ) \
    && _tick "$bin" || _miss "$bin"
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# pip install — non-fatal
# ─────────────────────────────────────────────────────────────────────────────
_pip() {
    local pkg="$1" bin="${2:-$1}"
    if _has "$bin"; then _skip "$bin"; return 0; fi
    _info "pip: $pkg"
    $PY -m pip install $PIP_FLAGS "$pkg" 2>/dev/null \
    && _tick "$bin" \
    || { $PY -m pip install $PIP_FLAGS --ignore-installed "$pkg" 2>/dev/null \
    && _tick "$bin" || _miss "$bin"; }
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# git-clone install — non-fatal
# ─────────────────────────────────────────────────────────────────────────────
_git_install() {
    # Usage: _git_install BIN REPO DEST [REQ_FILE] [ENTRY_SCRIPT]
    local bin="$1" repo="$2" dest="$3"
    local req="${4:-}" entry="${5:-}"
    if _has "$bin"; then _skip "$bin"; return 0; fi
    _info "git clone: $bin"
    rm -rf "/opt/${bin}_tmp" 2>/dev/null || true
    if git clone -q --depth 1 "$repo" "/opt/${bin}_tmp" 2>/dev/null; then
        mv "/opt/${bin}_tmp" "$dest" 2>/dev/null || true
        # Install requirements
        if [ -n "$req" ] && [ -f "${dest}/${req}" ]; then
            $PY -m pip install $PIP_FLAGS -r "${dest}/${req}" 2>/dev/null || true
        fi
        # Create symlink for entry script
        if [ -n "$entry" ] && [ -f "${dest}/${entry}" ]; then
            chmod +x "${dest}/${entry}" 2>/dev/null || true
            ln -sf "${dest}/${entry}" "$HOME/.local/bin/${bin}" 2>/dev/null \
            || sudo ln -sf "${dest}/${entry}" "/usr/local/bin/${bin}" 2>/dev/null \
            || true
        fi
        _has "$bin" && _tick "$bin" || {
            # symlink to home/.local/bin even if sudo failed
            [ -n "$entry" ] && [ -f "${dest}/${entry}" ] \
            && ln -sf "${dest}/${entry}" "$HOME/.local/bin/${bin}" 2>/dev/null && _tick "$bin" \
            || _miss "$bin"
        }
    else
        rm -rf "/opt/${bin}_tmp" 2>/dev/null || true
        _miss "$bin"
    fi
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# Binary download install — non-fatal
# ─────────────────────────────────────────────────────────────────────────────
_bin_dl() {
    local bin="$1" url="$2" archive_type="${3:-raw}"
    if _has "$bin"; then _skip "$bin"; return 0; fi
    _info "download: $bin"
    local tmp="/tmp/dominion_${bin}_dl"
    mkdir -p "$tmp" 2>/dev/null || true
    if wget -q --timeout=30 "$url" -O "${tmp}/dl" 2>/dev/null; then
        case "$archive_type" in
            zip)
                unzip -q "${tmp}/dl" -d "$tmp" 2>/dev/null || true
                local extracted
                extracted=$(find "$tmp" -maxdepth 2 -type f -name "$bin" 2>/dev/null | head -1)
                [ -z "$extracted" ] && extracted=$(find "$tmp" -maxdepth 2 -type f -perm /111 ! -name "*.zip" 2>/dev/null | head -1)
                if [ -n "$extracted" ]; then
                    cp "$extracted" "$HOME/.local/bin/$bin" 2>/dev/null && chmod +x "$HOME/.local/bin/$bin"
                fi
                ;;
            tar.gz)
                tar -xzf "${tmp}/dl" -C "$tmp" 2>/dev/null || true
                local extracted
                extracted=$(find "$tmp" -maxdepth 3 -type f -name "$bin" 2>/dev/null | head -1)
                if [ -n "$extracted" ]; then
                    cp "$extracted" "$HOME/.local/bin/$bin" 2>/dev/null && chmod +x "$HOME/.local/bin/$bin"
                fi
                ;;
            deb)
                sudo dpkg -i "${tmp}/dl" 2>/dev/null || true
                ;;
            *)
                cp "${tmp}/dl" "$HOME/.local/bin/$bin" 2>/dev/null || true
                chmod +x "$HOME/.local/bin/$bin" 2>/dev/null || true
                ;;
        esac
    fi
    rm -rf "$tmp" 2>/dev/null || true
    _has "$bin" && _tick "$bin" || _miss "$bin"
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
_banner "System Packages"
# ─────────────────────────────────────────────────────────────────────────────
_info "apt-get update..."
DEBIAN_FRONTEND=noninteractive sudo apt-get update -qq </dev/null 2>/dev/null || \
    _warn "apt update failed (continuing with cached repos)"

for _pkg in curl git wget unzip jq nmap masscan nikto sqlmap dnsrecon \
            dnsenum fierce whois wafw00f whatweb wfuzz gobuster \
            dirsearch commix sublist3r feroxbuster eyewitness wpscan \
            python3-pip python3-venv python3-dev \
            libssl-dev libffi-dev libpcap-dev ruby-dev \
            build-essential net-tools ncat netcat-openbsd; do
    _apt "$_pkg" 2>/dev/null || true
done

# ─────────────────────────────────────────────────────────────────────────────
_banner "Go"
# ─────────────────────────────────────────────────────────────────────────────
if ! _has go; then
    ARCH=$(uname -m 2>/dev/null | sed 's/x86_64/amd64/;s/aarch64/arm64/' || echo amd64)
    GO_VER="1.22.4"
    _info "Downloading Go $GO_VER..."
    wget -q --timeout=60 "https://go.dev/dl/go${GO_VER}.linux-${ARCH}.tar.gz" \
         -O /tmp/go.tar.gz 2>/dev/null \
    && sudo rm -rf /usr/local/go \
    && sudo tar -C /usr/local -xzf /tmp/go.tar.gz 2>/dev/null \
    && export PATH="$PATH:/usr/local/go/bin" \
    && _tick "Go $GO_VER" \
    || _warn "Go download failed — install Go manually then re-run"
    rm -f /tmp/go.tar.gz 2>/dev/null || true
fi
_has go && _ok "Go: $(go version 2>/dev/null)" || _warn "Go unavailable — skipping Go tools"

PATH_EXPORT='export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin'
for _rc in ~/.bashrc ~/.zshrc; do
    [ -f "$_rc" ] && grep -q "go/bin" "$_rc" 2>/dev/null \
    || echo "$PATH_EXPORT" >> "$_rc" 2>/dev/null || true
done

# ─────────────────────────────────────────────────────────────────────────────
_banner "Go Tools — Subdomain Enumeration"
# ─────────────────────────────────────────────────────────────────────────────
_go "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"        subfinder
_go "github.com/owasp-amass/amass/v4/...@latest"                           amass
_go "github.com/tomnomnom/assetfinder@latest"                              assetfinder
_go "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"            chaos
_go "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"                    dnsx
_go "github.com/d3mondev/puredns/v2@latest"                               puredns

# shuffledns — try multiple known paths
if ! _has shuffledns; then
    _info "shuffledns: trying multiple paths..."
    CGO_ENABLED=0 go install "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest" 2>/dev/null \
    && _tick shuffledns \
    || { CGO_ENABLED=0 go install "github.com/projectdiscovery/shuffledns@latest" 2>/dev/null \
    && _tick shuffledns \
    || _miss shuffledns; }
fi

# gotator
if ! _has gotator; then
    _info "gotator..."
    CGO_ENABLED=0 go install "github.com/Josue87/gotator@latest" 2>/dev/null \
    && _tick gotator || _miss gotator
fi

# findomain — binary release only (no Go source)
if ! _has findomain; then
    _info "findomain binary..."
    ARCH=$(uname -m 2>/dev/null | sed 's/x86_64/amd64/;s/aarch64/arm64/' || echo amd64)
    # Try apt first
    DEBIAN_FRONTEND=noninteractive sudo apt-get install -y -qq findomain </dev/null 2>/dev/null \
    && _tick findomain \
    || _bin_dl findomain \
        "https://github.com/findomain/findomain/releases/latest/download/findomain-linux" \
        raw
fi

_go "github.com/gwen001/github-subdomains@latest"                          github-subdomains

# massdns — apt or build from source
if ! _has massdns; then
    DEBIAN_FRONTEND=noninteractive sudo apt-get install -y -qq massdns </dev/null 2>/dev/null \
    && _tick massdns \
    || { _info "Building massdns from source..."
         rm -rf /tmp/massdns_src 2>/dev/null || true
         git clone -q --depth 1 https://github.com/blechschmidt/massdns \
             /tmp/massdns_src 2>/dev/null \
         && make -C /tmp/massdns_src 2>/dev/null \
         && cp /tmp/massdns_src/bin/massdns "$HOME/.local/bin/" 2>/dev/null \
         && _tick massdns || _miss massdns
         rm -rf /tmp/massdns_src 2>/dev/null || true; }
fi

# ─────────────────────────────────────────────────────────────────────────────
_banner "Go Tools — HTTP & Probing"
# ─────────────────────────────────────────────────────────────────────────────
_go "github.com/projectdiscovery/httpx/cmd/httpx@latest"                   httpx
_go "github.com/tomnomnom/httprobe@latest"                                 httprobe
_go "github.com/sensepost/gowitness@latest"                                gowitness
_go "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"                    tlsx
_go "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"               naabu

# aquatone — zip binary
if ! _has aquatone; then
    ARCH=$(uname -m 2>/dev/null | sed 's/x86_64/amd64/;s/aarch64/arm64/' || echo amd64)
    _bin_dl aquatone \
        "https://github.com/michenriksen/aquatone/releases/latest/download/aquatone_linux_${ARCH}.zip" \
        zip
fi

# rustscan — deb package
if ! _has rustscan; then
    _info "rustscan deb..."
    _bin_dl rustscan \
        "https://github.com/RustScan/RustScan/releases/latest/download/rustscan_2.3.0_amd64.deb" \
        deb
fi

# ─────────────────────────────────────────────────────────────────────────────
_banner "Go Tools — Crawling"
# ─────────────────────────────────────────────────────────────────────────────
_go "github.com/projectdiscovery/katana/cmd/katana@latest"                 katana
_go "github.com/jaeles-project/gospider@latest"                            gospider
_go "github.com/hakluke/hakrawler@latest"                                  hakrawler
_go "github.com/lc/gau/v2/cmd/gau@latest"                                 gau
_go "github.com/tomnomnom/waybackurls@latest"                              waybackurls
_go "github.com/bp0lr/gauplus@latest"                                      gauplus
_go "github.com/tomnomnom/meg@latest"                                      meg
_go "github.com/tomnomnom/gf@latest"                                       gf

# GF patterns
if [ ! -d "$HOME/.gf" ] || [ "$(find "$HOME/.gf" -name '*.json' 2>/dev/null | wc -l)" -lt 5 ]; then
    _info "GF patterns..."
    mkdir -p "$HOME/.gf" 2>/dev/null || true
    git clone -q --depth 1 https://github.com/1ndianl33t/Gf-Patterns \
        /tmp/gf_patterns_dl 2>/dev/null \
    && cp /tmp/gf_patterns_dl/*.json "$HOME/.gf/" 2>/dev/null \
    && _ok "GF patterns installed" || _warn "GF patterns: download failed (non-fatal)"
    rm -rf /tmp/gf_patterns_dl 2>/dev/null || true
fi

# ─────────────────────────────────────────────────────────────────────────────
_banner "Go Tools — Vulnerability Scanning"
# ─────────────────────────────────────────────────────────────────────────────
_go "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"              nuclei
_go "github.com/hahwul/dalfox/v2@latest"                                   dalfox
_go "github.com/dwisiswant0/crlfuzz@latest"                                crlfuzz
_go "github.com/ffuf/ffuf/v2@latest"                                        ffuf
_go "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"  interactsh-client
_go "github.com/OJ/gobuster/v3@latest"                                     gobuster
_go "github.com/devploit/nomore403@latest"                                  nomore403
_go "github.com/projectdiscovery/cloudbrute/cmd/cloudbrute@latest"         cloudbrute

# ─────────────────────────────────────────────────────────────────────────────
_banner "Nuclei Templates"
# ─────────────────────────────────────────────────────────────────────────────
if _has nuclei; then
    _info "Updating nuclei templates..."
    nuclei -update-templates 2>/dev/null && _ok "Templates updated" \
    || _warn "Template update failed (network issue), continuing"
    # Fuzzing templates
    FUZZ_DIR="$HOME/.config/nuclei/fuzzing-templates"
    if [ ! -d "$FUZZ_DIR" ]; then
        git clone -q --depth 1 https://github.com/projectdiscovery/fuzzing-templates \
            "$FUZZ_DIR" 2>/dev/null && _ok "Fuzzing templates added" || true
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
_banner "trufflehog"
# ─────────────────────────────────────────────────────────────────────────────
if ! _has trufflehog; then
    # Method 1: Official install script
    curl -sSfL --max-time 30 \
        https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        2>/dev/null | sudo sh -s -- -b "$HOME/.local/bin" 2>/dev/null \
    && _has trufflehog && _tick trufflehog || {
        # Method 2: wget binary
        ARCH=$(uname -m 2>/dev/null | sed 's/x86_64/amd64/;s/aarch64/arm64/' || echo amd64)
        OS=$(uname -s 2>/dev/null | tr '[:upper:]' '[:lower:]' || echo linux)
        TRUF_URL="https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_${OS}_${ARCH}.tar.gz"
        _bin_dl trufflehog "$TRUF_URL" tar.gz
    }
fi

_go "github.com/gitleaks/gitleaks/v8@latest" gitleaks

# ─────────────────────────────────────────────────────────────────────────────
_banner "Python Virtual Environment"
# ─────────────────────────────────────────────────────────────────────────────
_info "Setting up Python venv..."
if $PY -m venv .venv 2>/dev/null; then
    # shellcheck disable=SC1091
    source .venv/bin/activate 2>/dev/null && _ok "venv activated" || true
elif $PY -m venv --system-site-packages .venv 2>/dev/null; then
    source .venv/bin/activate 2>/dev/null && _ok "venv activated (system-site-packages)" || true
else
    _warn "venv failed — using system pip directly (still OK on Kali)"
fi

# Prefer venv pip, fallback to python -m pip
if _has pip; then PIP_CMD="pip"
elif _has pip3; then PIP_CMD="pip3"
else PIP_CMD="$PY -m pip"; fi

_ok "Pip: $($PIP_CMD --version 2>/dev/null | head -1)"

# Upgrade pip
$PIP_CMD install $PIP_FLAGS --upgrade pip 2>/dev/null || true

# ─────────────────────────────────────────────────────────────────────────────
_banner "Python Security Tools"
# ─────────────────────────────────────────────────────────────────────────────
# Install requirements.txt first
$PIP_CMD install $PIP_FLAGS -r requirements.txt 2>/dev/null \
    || _warn "requirements.txt partial install (continuing)"

# Shorthand pip install using PIP_CMD
_pip2() {
    local pkg="$1" bin="${2:-$1}"
    _has "$bin" && { _skip "$bin"; return 0; }
    _info "pip: $pkg"
    $PIP_CMD install $PIP_FLAGS "$pkg" 2>/dev/null \
    && _tick "$bin" \
    || { $PIP_CMD install $PIP_FLAGS --ignore-installed "$pkg" 2>/dev/null \
    && _tick "$bin" || _miss "$bin"; }
    return 0
}

_pip2 theHarvester   theHarvester
_pip2 dirsearch      dirsearch
_pip2 knockpy        knockpy
_pip2 sublist3r      sublist3r
_pip2 arjun          arjun
_pip2 xsstrike       xsstrike
_pip2 wfuzz          wfuzz
_pip2 wafw00f        wafw00f
_pip2 socialscan     socialscan
_pip2 holehe         holehe
_pip2 h8mail         h8mail
_pip2 photon         photon
_pip2 s3scanner      s3scanner
_pip2 dnstwist       dnstwist
_pip2 shodan         shodan

# git-dumper
_has git-dumper || _pip2 git-dumper git-dumper

# ─────────────────────────────────────────────────────────────────────────────
_banner "Tools via Git Clone"
# ─────────────────────────────────────────────────────────────────────────────

# graphw00f
if ! _has graphw00f; then
    _pip2 graphw00f graphw00f 2>/dev/null || \
    _git_install graphw00f \
        https://github.com/dolevf/graphw00f \
        /opt/graphw00f \
        "requirements.txt" \
        "main.py"
fi

# corsy
if ! _has corsy; then
    _git_install corsy \
        https://github.com/s0md3v/Corsy \
        /opt/corsy \
        "requirements.txt" \
        "corsy.py"
fi

# paramspider
if ! _has paramspider; then
    _pip2 paramspider paramspider 2>/dev/null || \
    _git_install paramspider \
        https://github.com/devanshbatham/ParamSpider \
        /opt/paramspider \
        "requirements.txt" \
        "paramspider/main.py"
fi

# jwt_tool
if ! _has jwt_tool; then
    _git_install jwt_tool \
        https://github.com/ticarpi/jwt_tool \
        /opt/jwt_tool \
        "requirements.txt" \
        "jwt_tool.py"
fi

# linkfinder
if ! _has linkfinder; then
    _git_install linkfinder \
        https://github.com/GerbenJavado/LinkFinder \
        /opt/linkfinder \
        "requirements.txt" \
        "linkfinder.py"
fi

# secretfinder
if ! _has secretfinder; then
    _git_install secretfinder \
        https://github.com/m4ll0k/SecretFinder \
        /opt/secretfinder \
        "requirements.txt" \
        "SecretFinder.py"
fi

# smuggler
if ! _has smuggler; then
    _git_install smuggler \
        https://github.com/defparam/smuggler \
        /opt/smuggler \
        "" \
        "smuggler.py"
fi

# ssrfmap
if ! _has ssrfmap; then
    _git_install ssrfmap \
        https://github.com/swisskyrepo/SSRFmap \
        /opt/ssrfmap \
        "requirements.txt" \
        "ssrfmap.py"
fi

# cloud_enum
if ! _has cloud_enum; then
    _git_install cloud_enum \
        https://github.com/initstring/cloud_enum \
        /opt/cloud_enum \
        "requirements.txt" \
        "cloud_enum.py"
fi

# XSStrike
if ! _has xsstrike; then
    _git_install xsstrike \
        https://github.com/s0md3v/XSStrike \
        /opt/xsstrike \
        "requirements.txt" \
        "xsstrike.py"
fi

# EyeWitness
if ! _has eyewitness; then
    _git_install eyewitness \
        https://github.com/RedSiege/EyeWitness \
        /opt/eyewitness \
        "Python/setup/requirements.txt" \
        "EyeWitness.py"
fi

# feroxbuster — curl install script
if ! _has feroxbuster; then
    _info "feroxbuster via install script..."
    curl -sL --max-time 30 \
        https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh \
        2>/dev/null \
    | bash -s -- -b "$HOME/.local/bin" 2>/dev/null \
    && _has feroxbuster && _tick feroxbuster \
    || _bin_dl feroxbuster \
        "https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.zip" \
        zip
fi

# wpscan — gem
if ! _has wpscan && _has gem; then
    _info "wpscan..."
    gem install wpscan 2>/dev/null && _tick wpscan || _miss wpscan
fi

# ─────────────────────────────────────────────────────────────────────────────
_banner "Wordlists"
# ─────────────────────────────────────────────────────────────────────────────
mkdir -p wordlists 2>/dev/null || true

# Find an existing SecLists
SECLISTS=""
for _sl in /usr/share/seclists /usr/share/SecLists /opt/SecLists; do
    [ -d "$_sl" ] && { SECLISTS="$_sl"; _ok "SecLists found: $_sl"; break; }
done

if [ -z "$SECLISTS" ]; then
    _info "No SecLists found — trying apt..."
    DEBIAN_FRONTEND=noninteractive sudo apt-get install -y -qq seclists </dev/null 2>/dev/null \
    && { for _sl in /usr/share/seclists /usr/share/SecLists; do
             [ -d "$_sl" ] && { SECLISTS="$_sl"; _ok "SecLists via apt: $_sl"; break; }
         done; } \
    || true
fi

if [ -z "$SECLISTS" ]; then
    _info "Cloning SecLists (shallow — might take 2-3 minutes)..."
    git clone -q --depth 1 --filter=blob:none \
        https://github.com/danielmiessler/SecLists /opt/SecLists 2>/dev/null \
    && SECLISTS="/opt/SecLists" && _ok "SecLists cloned" \
    || _warn "SecLists clone failed — wordlists will be minimal (tool still works!)"
fi

# Helper: safely concatenate files to destination
_merge() {
    local dst="$1"; shift
    : > "$dst" 2>/dev/null || true      # clear / create
    for _src in "$@"; do
        [ -f "$_src" ] && wc -c < "$_src" 2>/dev/null | grep -qv '^0$' \
        && cat "$_src" >> "$dst" 2>/dev/null && _info "  + $(basename "$_src")"
    done
    return 0
}

# ── Subdomain wordlist ────────────────────────────────────────────────────────
_info "Subdomain wordlist..."
_merge wordlists/subdomains.txt \
    "${SECLISTS}/Discovery/DNS/subdomains-top1million-110000.txt" \
    "${SECLISTS}/Discovery/DNS/deepmagic.com-prefixes-top50000.txt" \
    "${SECLISTS}/Discovery/DNS/bitquark-subdomains-top100000.txt" \
    "${SECLISTS}/Discovery/DNS/fierce-hostlist.txt" \
    "${SECLISTS}/Discovery/DNS/dns-Jhaddix.txt" \
    "${SECLISTS}/Discovery/DNS/combined_subdomains.txt"

# Assetnote — best in the industry
wget -q --timeout=40 \
    "https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt" \
    -O /tmp/an_dns.txt 2>/dev/null \
&& cat /tmp/an_dns.txt >> wordlists/subdomains.txt 2>/dev/null \
&& _ok "Assetnote DNS added" || true
rm -f /tmp/an_dns.txt 2>/dev/null || true

# Deduplicate
[ -s wordlists/subdomains.txt ] \
    && sort -u wordlists/subdomains.txt -o wordlists/subdomains.txt 2>/dev/null || true
SUB_WC=$(wc -l < wordlists/subdomains.txt 2>/dev/null || echo 0)
_ok "Subdomains wordlist: ${SUB_WC} entries"

# Fallback: minimal list if all else failed
if [ "$SUB_WC" -lt 100 ] 2>/dev/null; then
    _warn "Generating minimal subdomain wordlist..."
    printf "www\nmail\napi\nadmin\ndev\nstaging\nblog\nshop\napp\nmobile\ntest\nlb\ncdn\nns1\nns2\nvpn\nftp\ncp\nwebmail\nm\n" \
        > wordlists/subdomains.txt
fi

# ── Directory wordlist ─────────────────────────────────────────────────────────
_info "Directory wordlist..."
_merge wordlists/directories.txt \
    "${SECLISTS}/Discovery/Web-Content/raft-large-directories.txt" \
    "${SECLISTS}/Discovery/Web-Content/raft-large-files.txt" \
    "${SECLISTS}/Discovery/Web-Content/raft-medium-directories.txt" \
    "${SECLISTS}/Discovery/Web-Content/common.txt" \
    "${SECLISTS}/Discovery/Web-Content/directory-list-2.3-medium.txt" \
    "${SECLISTS}/Discovery/Web-Content/quickhits.txt"

wget -q --timeout=40 \
    "https://wordlists-cdn.assetnote.io/data/automated/httparchive_apiroutes_2024.01.28.txt" \
    -O /tmp/an_api.txt 2>/dev/null \
&& cat /tmp/an_api.txt >> wordlists/directories.txt 2>/dev/null && _ok "Assetnote API routes added" || true
rm -f /tmp/an_api.txt 2>/dev/null || true

[ -s wordlists/directories.txt ] \
    && sort -u wordlists/directories.txt -o wordlists/directories.txt 2>/dev/null || true
DIR_WC=$(wc -l < wordlists/directories.txt 2>/dev/null || echo 0)
_ok "Directories wordlist: ${DIR_WC} entries"

if [ "$DIR_WC" -lt 100 ] 2>/dev/null; then
    _warn "Generating minimal directory wordlist..."
    printf "admin\napi\nlogin\nupload\nbackup\n.env\n.git\nconfig\ntest\ndev\nv1\nv2\nwp-admin\nphpinfo.php\n" \
        > wordlists/directories.txt
fi

# ── Parameters wordlist ───────────────────────────────────────────────────────
_info "Parameters wordlist..."
_merge wordlists/parameters.txt \
    "${SECLISTS}/Discovery/Web-Content/burp-parameter-names.txt" \
    "${SECLISTS}/Discovery/Web-Content/raft-large-words.txt"
wget -q --timeout=40 \
    "https://wordlists-cdn.assetnote.io/data/automated/httparchive_parameters_2024.01.28.txt" \
    -O /tmp/an_p.txt 2>/dev/null \
&& cat /tmp/an_p.txt >> wordlists/parameters.txt 2>/dev/null || true
rm -f /tmp/an_p.txt 2>/dev/null || true
[ -s wordlists/parameters.txt ] \
    && sort -u wordlists/parameters.txt -o wordlists/parameters.txt 2>/dev/null || true
_ok "Parameters: $(wc -l < wordlists/parameters.txt 2>/dev/null || echo 0) entries"

# ── Fuzzing payloads ──────────────────────────────────────────────────────────
_info "Fuzzing payloads..."
_merge wordlists/lfi_payloads.txt \
    "${SECLISTS}/Fuzzing/LFI/LFI-Jhaddix.txt" \
    "${SECLISTS}/Fuzzing/LFI/LFI-LFISuite-pathtotest.txt" \
    "${SECLISTS}/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt" \
    "${SECLISTS}/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt"
[ -s wordlists/lfi_payloads.txt ] \
    && sort -u wordlists/lfi_payloads.txt -o wordlists/lfi_payloads.txt 2>/dev/null || true

_merge wordlists/xss_payloads.txt \
    "${SECLISTS}/Fuzzing/XSS/XSS-Jhaddix.txt" \
    "${SECLISTS}/Fuzzing/XSS/XSS-BruteLogic.txt"
[ -s wordlists/xss_payloads.txt ] \
    && sort -u wordlists/xss_payloads.txt -o wordlists/xss_payloads.txt 2>/dev/null || true

_merge wordlists/sqli_payloads.txt \
    "${SECLISTS}/Fuzzing/SQLi/Generic-SQLi.txt" \
    "${SECLISTS}/Fuzzing/SQLi/quick-SQLi.txt" \
    "${SECLISTS}/Fuzzing/SQLi/Generic-BlindSQLi.fuzzdb.txt"
[ -s wordlists/sqli_payloads.txt ] \
    && sort -u wordlists/sqli_payloads.txt -o wordlists/sqli_payloads.txt 2>/dev/null || true

_info "Fallback payloads..."
# LFI fallback
[ -s wordlists/lfi_payloads.txt ] || printf \
    "../../etc/passwd\n../../../etc/passwd\n../../../../etc/passwd\nphp://filter/read=convert.base64-encode/resource=/etc/passwd\n/etc/passwd\n" \
    > wordlists/lfi_payloads.txt
# XSS fallback
[ -s wordlists/xss_payloads.txt ] || printf \
    '<script>alert(1)</script>\n"><script>alert(1)</script>\n<svg/onload=alert(1)>\n' \
    > wordlists/xss_payloads.txt
# SQLi fallback
[ -s wordlists/sqli_payloads.txt ] || printf \
    "' OR 1=1--\n\" OR 1=1--\n' AND SLEEP(5)--\n1 UNION SELECT NULL--\n" \
    > wordlists/sqli_payloads.txt

_ok "LFI payloads: $(wc -l < wordlists/lfi_payloads.txt 2>/dev/null || echo built-in)"
_ok "XSS payloads: $(wc -l < wordlists/xss_payloads.txt 2>/dev/null || echo built-in)"
_ok "SQLi payloads: $(wc -l < wordlists/sqli_payloads.txt 2>/dev/null || echo built-in)"

# ── DNS Resolvers ──────────────────────────────────────────────────────────────
if ! [ -s wordlists/resolvers.txt ]; then
    wget -q --timeout=20 \
        "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" \
        -O wordlists/resolvers.txt 2>/dev/null || true
fi
if ! [ -s wordlists/resolvers.txt ]; then
    # Built-in fallback — always works
    cat > wordlists/resolvers.txt << 'EOF'
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
EOF
    _ok "DNS resolvers: built-in fallback (15 resolvers)"
else
    _ok "DNS resolvers: $(wc -l < wordlists/resolvers.txt) entries"
fi

# ── API paths ──────────────────────────────────────────────────────────────────
_merge wordlists/api_paths.txt \
    "${SECLISTS}/Discovery/Web-Content/api/api-endpoints.txt" \
    "${SECLISTS}/Discovery/Web-Content/api/objects.txt"
[ -s wordlists/api_paths.txt ] || printf \
    "/api/v1/users\n/api/v2/users\n/api/admin\n/api/config\n/api/health\n/api/debug\n" \
    > wordlists/api_paths.txt

# ─────────────────────────────────────────────────────────────────────────────
_banner "Final Check"
# ─────────────────────────────────────────────────────────────────────────────
echo ""
ALL=(
    subfinder amass assetfinder findomain chaos
    puredns shuffledns dnsx massdns
    httpx httprobe naabu rustscan
    katana gospider hakrawler gau waybackurls gf
    nuclei dalfox crlfuzz ffuf gobuster feroxbuster
    sqlmap commix nikto wafw00f wfuzz nomore403
    trufflehog gitleaks git-dumper
    jwt_tool graphw00f xsstrike smuggler
    linkfinder secretfinder cloud_enum s3scanner
    gowitness paramspider arjun
)

printf "  %-22s %-22s %-22s %-22s\n" "TOOL" "STATUS" "TOOL" "STATUS"
printf "  %s\n" "$(printf '%.0s─' {1..88})"
FOUND=0; MISSING=0
for i in "${!ALL[@]}"; do
    t="${ALL[$i]}"
    if _has "$t"; then
        printf "  ${GREEN}✓${NC} %-20s" "$t"; FOUND=$((FOUND+1))
    else
        printf "  ${RED}✗${NC} %-20s" "$t"; MISSING=$((MISSING+1))
    fi
    [ $(( (i+1) % 2 )) -eq 0 ] && echo ""
done
echo -e "\n"

echo -e "${CYAN}  Wordlists:${NC}"
for _wl in subdomains directories parameters lfi_payloads xss_payloads sqli_payloads resolvers api_paths; do
    _f="wordlists/${_wl}.txt"
    if [ -s "$_f" ]; then
        _n=$(wc -l < "$_f" 2>/dev/null || echo "?")
        echo -e "  ${GREEN}✓${NC} ${_wl}.txt (${_n} lines)"
    else
        echo -e "  ${YELLOW}!${NC} ${_wl}.txt — empty"
    fi
done

echo ""
echo -e "${GREEN}${BOLD}════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  Tools ready : $FOUND / ${#ALL[@]}${NC}"
[ $MISSING -gt 0 ] && echo -e "${YELLOW}  Unavailable : $MISSING (all optional, tool still runs)${NC}"
[ ${#MISS[@]} -gt 0 ] && echo -e "${YELLOW}  Could not install: ${MISS[*]}${NC}"
echo -e "${GREEN}${BOLD}════════════════════════════════════════════${NC}"
echo ""
echo -e "${CYAN}  Next steps:${NC}"
echo -e "  ${BOLD}1.${NC} source .venv/bin/activate"
echo -e "  ${BOLD}2.${NC} cp config.example.yml config.yml && nano config.yml"
echo -e "  ${BOLD}3.${NC} python dominion.py -d example.com"
echo ""
echo -e "${GREEN}${BOLD}DOMINION ready. Zero crashes. Full power. 🔥${NC}"
