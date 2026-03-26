#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║     DOMINION — Zero-Error Installer v5.0  (Universal Linux)            ║
# ║  Every tool has binary+pip+git fallback. Works offline partially.       ║
# ╚══════════════════════════════════════════════════════════════════════════╝
# // turbo-all
#
# ROOT CAUSE FIXES v5.0:
#  - git-clone → $HOME/tools/ (no sudo needed, works for any user)
#  - shuffledns/aquatone → ProjectDiscovery binary releases
#  - cloudbrute → sudo apt install cloudbrute (Kali package)
#  - Wordlists → direct raw.githubusercontent.com file downloads
#    (no SecLists full clone needed!)
#  - feroxbuster → correct binary download with proper path
#  - python3-pip/venv → pipx + get-pip.py fallback on Kali
#  - All git-clone tools: no sudo, no /opt, use ~/tools

set -uo pipefail 2>/dev/null || true  # ← NO -e flag ever

# ── Colors ─────────────────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
C='\033[0;36m'; P='\033[0;35m'; B='\033[1m'; N='\033[0m'
_i()  { echo -e "${C}[*]${N} $*"; }
_ok() { echo -e "${G}[+]${N} $*"; }
_w()  { echo -e "${Y}[!]${N} $*"; }
_b()  { echo -e "\n${P}${B}══ $* ══${N}"; }

# ── Dirs ───────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
cd "$SCRIPT_DIR" 2>/dev/null || true
TOOLS_DIR="$HOME/tools"          # ← All git-cloned tools go here (no sudo!)
BIN_DIR="$HOME/.local/bin"
mkdir -p "$TOOLS_DIR" "$BIN_DIR" 2>/dev/null || true

GOPATH="${GOPATH:-$HOME/go}"
mkdir -p "$GOPATH/bin" 2>/dev/null || true
export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin:$BIN_DIR"

# ── Stats ──────────────────────────────────────────────────────────────────
declare -a MISS=()
_tick() { _ok "$1 ✓"; }
_skip() { _ok "$1 already installed ✓"; }
_miss() { MISS+=("$1"); _w "$1 — could not install (non-fatal)"; }
_has()  { command -v "$1" &>/dev/null 2>&1; }

echo -e "${R}${B}"
cat << 'EOF'
██████╗  ██████╗ ███╗   ███╗██╗███╗   ██╗██╗ ██████╗ ███╗   ██╗
██╔══██╗██╔═══██╗████╗ ████║██║████╗  ██║██║██╔═══██╗████╗  ██║
██║  ██║██║   ██║██╔████╔██║██║██╔██╗ ██║██║██║   ██║██╔██╗ ██║
██║  ██║██║   ██║██║╚██╔╝██║██║██║╚██╗██║██║██║   ██║██║╚██╗██║
██████╔╝╚██████╔╝██║ ╚═╝ ██║██║██║ ╚████║██║╚██████╔╝██║ ╚████║
╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝
        Zero-Error Installer v5.0 — Universal Linux
EOF
echo -e "${N}"

# ─────────────────────────────────────────────────────────────────────────────
# Detect Python
# ─────────────────────────────────────────────────────────────────────────────
PY=""
for _p in python3 python3.13 python3.12 python3.11 python3.10; do
    _has "$_p" && PY="$_p" && break
done
[ -z "$PY" ] && PY="python3"
PY_VER=$($PY -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "?")
_ok "Python $PY_VER"

# pip flags — --break-system-packages for Kali Python 3.12+
PIP_FLAGS="--quiet --no-warn-script-location"
$PY -m pip install --help 2>/dev/null | grep -q "break-system-packages" \
    && PIP_FLAGS="$PIP_FLAGS --break-system-packages"

# ─────────────────────────────────────────────────────────────────────────────
# ── APT ──────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
_b "System Packages"
_i "apt-get update..."
DEBIAN_FRONTEND=noninteractive sudo apt-get update -qq </dev/null 2>/dev/null || \
    _w "apt update failed — using cached repos"

_apt() {
    local pkg="$1" check="${2:-$1}"
    _has "$check" && { _skip "$pkg"; return 0; }
    _i "apt: $pkg"
    DEBIAN_FRONTEND=noninteractive sudo apt-get install -y -qq \
        --no-install-recommends --ignore-missing "$pkg" </dev/null 2>/dev/null \
    && _tick "$pkg" || _w "apt: $pkg unavailable (non-fatal)"
    return 0
}

# Core security tools
for p in curl git wget unzip jq nmap masscan nikto sqlmap \
          dnsrecon dnsenum fierce whois wafw00f whatweb wfuzz \
          gobuster dirsearch commix sublist3r feroxbuster eyewitness \
          wpscan cloudbrute cloud-enum seclists; do
    _apt "$p" 2>/dev/null || true
done

# Dev libs (silently — needed for building some tools)
for p in python3-pip python3-venv python3-dev libssl-dev libffi-dev \
          libpcap-dev ruby-dev build-essential net-tools ncat netcat-openbsd; do
    DEBIAN_FRONTEND=noninteractive sudo apt-get install -y -qq \
        --no-install-recommends "$p" </dev/null 2>/dev/null || true
done

# ─────────────────────────────────────────────────────────────────────────────
# ── GO ───────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
_b "Go"
if ! _has go; then
    ARCH=$(uname -m 2>/dev/null | sed 's/x86_64/amd64/;s/aarch64/arm64/' || echo amd64)
    GO_VER="1.22.5"
    _i "Downloading Go $GO_VER..."
    wget -q --timeout=60 "https://go.dev/dl/go${GO_VER}.linux-${ARCH}.tar.gz" \
         -O /tmp/go.tar.gz 2>/dev/null \
    && sudo rm -rf /usr/local/go \
    && sudo tar -C /usr/local -xzf /tmp/go.tar.gz 2>/dev/null \
    && export PATH="$PATH:/usr/local/go/bin" \
    && _tick "Go $GO_VER" || _w "Go download failed — install manually"
    rm -f /tmp/go.tar.gz 2>/dev/null || true
fi
_has go && _ok "Go: $(go version 2>/dev/null)" || _w "Go unavailable"

# PATH line
PATH_EXPORT='export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin'
for _rc in ~/.bashrc ~/.zshrc; do
    [ -f "$_rc" ] && grep -q "go/bin" "$_rc" 2>/dev/null \
    || echo "$PATH_EXPORT" >> "$_rc" 2>/dev/null || true
done

# ─────────────────────────────────────────────────────────────────────────────
# ── ProjectDiscovery binary installer (pdtm) ──────────────────────────────────
# Installs all PD tools at once: httpx, subfinder, nuclei, etc.
# ─────────────────────────────────────────────────────────────────────────────
_b "ProjectDiscovery Tools (pdtm)"
if ! _has pdtm; then
    _i "Installing pdtm (ProjectDiscovery Tool Manager)..."
    _pdtm_url="https://github.com/projectdiscovery/pdtm/releases/latest/download"
    ARCH=$(uname -m 2>/dev/null | sed 's/x86_64/amd64/;s/aarch64/arm64/' || echo amd64)
    wget -q --timeout=30 "${_pdtm_url}/pdtm_linux_${ARCH}.zip" -O /tmp/pdtm.zip 2>/dev/null \
    && unzip -q /tmp/pdtm.zip -d /tmp/pdtm_extract 2>/dev/null \
    && cp /tmp/pdtm_extract/pdtm "$BIN_DIR/" 2>/dev/null \
    && chmod +x "$BIN_DIR/pdtm" 2>/dev/null \
    && rm -rf /tmp/pdtm.zip /tmp/pdtm_extract 2>/dev/null \
    && _tick pdtm || true
fi

if _has pdtm; then
    _i "Installing all ProjectDiscovery tools via pdtm..."
    pdtm --install-all 2>/dev/null && _ok "All PD tools installed via pdtm" \
    || { _i "Installing individual PD tools via pdtm..."
         for t in subfinder httpx nuclei dnsx katana naabu tlsx interactsh-client \
                  shuffledns puredns chaos dalfox crlfuzz nomore403 cloudbrute; do
             pdtm -i "$t" 2>/dev/null && _ok "pdtm: $t ✓" || true
         done; }
fi

# ─────────────────────────────────────────────────────────────────────────────
# ── Go individual installs (fallback for tools pdtm may not cover) ────────────
# ─────────────────────────────────────────────────────────────────────────────
_go() {
    local pkg="$1" bin="$2"
    _has "$bin" && { _skip "$bin"; return 0; }
    _i "go install: $bin"
    CGO_ENABLED=0 GOFLAGS="-mod=mod" go install "$pkg" 2>/dev/null \
    && _tick "$bin" || _miss "$bin"
    return 0
}

# PD tools (go install fallback)
_b "Go Tools — Enumeration"
_go "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"     subfinder
_go "github.com/owasp-amass/amass/v4/...@latest"                        amass
_go "github.com/tomnomnom/assetfinder@latest"                           assetfinder
_go "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"         chaos
_go "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"                 dnsx
_go "github.com/d3mondev/puredns/v2@latest"                            puredns
_go "github.com/gwen001/github-subdomains@latest"                       github-subdomains

# shuffledns — binary release
if ! _has shuffledns; then
    _i "shuffledns binary release..."
    ARCH=$(uname -m 2>/dev/null | sed 's/x86_64/amd64/;s/aarch64/arm64/' || echo amd64)
    _VER=$(wget -q --timeout=10 -O- \
        "https://api.github.com/repos/projectdiscovery/shuffledns/releases/latest" \
        2>/dev/null | grep '"tag_name"' | cut -d'"' -f4 2>/dev/null || echo "v1.1.0")
    wget -q --timeout=30 \
        "https://github.com/projectdiscovery/shuffledns/releases/latest/download/shuffledns_${_VER#v}_linux_${ARCH}.zip" \
        -O /tmp/shuffledns.zip 2>/dev/null \
    && unzip -q /tmp/shuffledns.zip shuffledns -d "$BIN_DIR/" 2>/dev/null \
    && chmod +x "$BIN_DIR/shuffledns" 2>/dev/null \
    && rm -f /tmp/shuffledns.zip 2>/dev/null \
    && { _has shuffledns && _tick shuffledns || true; } \
    || { CGO_ENABLED=0 go install \
           "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest" \
           2>/dev/null && _tick shuffledns || _miss shuffledns; }
fi

# gotator
_go "github.com/Josue87/gotator@latest" gotator

# findomain — binary
if ! _has findomain; then
    _i "findomain binary..."
    _apt findomain findomain 2>/dev/null || \
    wget -q --timeout=30 \
        "https://github.com/findomain/findomain/releases/latest/download/findomain-linux" \
        -O "$BIN_DIR/findomain" 2>/dev/null \
    && chmod +x "$BIN_DIR/findomain" 2>/dev/null \
    && _has findomain && _tick findomain || _miss findomain
fi

# massdns — apt or source
if ! _has massdns; then
    _apt massdns massdns 2>/dev/null || {
        _i "Building massdns from source..."
        rm -rf "$TOOLS_DIR/massdns" 2>/dev/null || true
        git clone -q --depth 1 https://github.com/blechschmidt/massdns \
            "$TOOLS_DIR/massdns" 2>/dev/null \
        && make -C "$TOOLS_DIR/massdns" 2>/dev/null \
        && cp "$TOOLS_DIR/massdns/bin/massdns" "$BIN_DIR/" 2>/dev/null \
        && _tick massdns || _miss massdns
    }
fi

_b "Go Tools — HTTP & Probing"
_go "github.com/projectdiscovery/httpx/cmd/httpx@latest"                httpx
_go "github.com/tomnomnom/httprobe@latest"                              httprobe
_go "github.com/sensepost/gowitness@latest"                              gowitness
_go "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"                 tlsx
_go "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"            naabu

# aquatone — binary release (different URL structure)
if ! _has aquatone; then
    _i "aquatone binary..."
    ARCH=$(uname -m 2>/dev/null | sed 's/x86_64/amd64/;s/aarch64/arm64/' || echo amd64)
    wget -q --timeout=30 \
        "https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_${ARCH}_1.7.0.zip" \
        -O /tmp/aquatone.zip 2>/dev/null \
    && unzip -q /tmp/aquatone.zip -d /tmp/aquatone_extract 2>/dev/null \
    && find /tmp/aquatone_extract -type f -name "aquatone" -exec cp {} "$BIN_DIR/" \; 2>/dev/null \
    && chmod +x "$BIN_DIR/aquatone" 2>/dev/null \
    && rm -rf /tmp/aquatone.zip /tmp/aquatone_extract 2>/dev/null \
    && { _has aquatone && _tick aquatone || _miss aquatone; } || _miss aquatone
fi

# rustscan
if ! _has rustscan; then
    DEBIAN_FRONTEND=noninteractive sudo apt-get install -y -qq rustscan </dev/null 2>/dev/null \
    && _tick rustscan \
    || { _i "rustscan deb download..."
         wget -q --timeout=30 \
             "https://github.com/RustScan/RustScan/releases/latest/download/rustscan_2.3.0_amd64.deb" \
             -O /tmp/rustscan.deb 2>/dev/null \
         && sudo dpkg -i /tmp/rustscan.deb 2>/dev/null \
         && rm -f /tmp/rustscan.deb 2>/dev/null \
         && _has rustscan && _tick rustscan || _miss rustscan; }
fi

_b "Go Tools — Crawling"
_go "github.com/projectdiscovery/katana/cmd/katana@latest"              katana
_go "github.com/jaeles-project/gospider@latest"                         gospider
_go "github.com/hakluke/hakrawler@latest"                               hakrawler
_go "github.com/lc/gau/v2/cmd/gau@latest"                              gau
_go "github.com/tomnomnom/waybackurls@latest"                           waybackurls
_go "github.com/bp0lr/gauplus@latest"                                   gauplus
_go "github.com/tomnomnom/meg@latest"                                   meg
_go "github.com/tomnomnom/gf@latest"                                    gf

# GF patterns
if [ "$(find "$HOME/.gf" -name '*.json' 2>/dev/null | wc -l)" -lt 5 ]; then
    _i "GF patterns..."
    mkdir -p "$HOME/.gf" 2>/dev/null || true
    git clone -q --depth 1 https://github.com/1ndianl33t/Gf-Patterns \
        "$TOOLS_DIR/gf-patterns" 2>/dev/null \
    && cp "$TOOLS_DIR/gf-patterns/"*.json "$HOME/.gf/" 2>/dev/null \
    && _ok "GF patterns installed" || true
fi

_b "Go Tools — Vulnerability Scanning"
_go "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"           nuclei
_go "github.com/hahwul/dalfox/v2@latest"                                dalfox
_go "github.com/dwisiswant0/crlfuzz@latest"                             crlfuzz
_go "github.com/ffuf/ffuf/v2@latest"                                     ffuf
_go "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest" interactsh-client
_go "github.com/OJ/gobuster/v3@latest"                                  gobuster
_go "github.com/devploit/nomore403@latest"                               nomore403

# cloudbrute — apt → Go → binary release
if ! _has cloudbrute; then
    DEBIAN_FRONTEND=noninteractive sudo apt-get install -y -qq cloudbrute </dev/null 2>/dev/null \
    && _tick cloudbrute || {
        CGO_ENABLED=0 go install \
            github.com/projectdiscovery/cloudbrute/cmd/cloudbrute@latest \
            2>/dev/null && _tick cloudbrute || {
            _i "cloudbrute binary download..."
            _CB_ARCH=$(uname -m 2>/dev/null | sed 's/x86_64/amd64/;s/aarch64/arm64/' || echo amd64)
            wget -q --timeout=30 \
                "https://github.com/0xsha/CloudBrute/releases/latest/download/cloudbrute_linux_${_CB_ARCH}" \
                -O "$BIN_DIR/cloudbrute" 2>/dev/null \
            && chmod +x "$BIN_DIR/cloudbrute" 2>/dev/null \
            && _has cloudbrute && _tick cloudbrute || _miss cloudbrute
        }
    }
fi

# ─────────────────────────────────────────────────────────────────────────────
# Nuclei Templates
# ─────────────────────────────────────────────────────────────────────────────
_b "Nuclei Templates"
if _has nuclei; then
    _i "Updating nuclei templates..."
    nuclei -update-templates 2>/dev/null && _ok "Templates updated" \
    || _w "Template update failed (network)"
    [ ! -d "$HOME/.config/nuclei/fuzzing-templates" ] && \
    git clone -q --depth 1 \
        https://github.com/projectdiscovery/fuzzing-templates \
        "$HOME/.config/nuclei/fuzzing-templates" 2>/dev/null \
    && _ok "Fuzzing templates added" || true
fi

# ─────────────────────────────────────────────────────────────────────────────
# trufflehog
# ─────────────────────────────────────────────────────────────────────────────
_b "trufflehog"
if ! _has trufflehog; then
    _i "trufflehog install script..."
    curl -sSfL --max-time 30 \
        https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        2>/dev/null | sudo sh -s -- -b "$BIN_DIR" 2>/dev/null \
    && _has trufflehog && _tick trufflehog || {
        # Binary fallback
        ARCH=$(uname -m 2>/dev/null | sed 's/x86_64/amd64/;s/aarch64/arm64/' || echo amd64)
        OS="linux"
        wget -q --timeout=30 \
            "https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_${OS}_${ARCH}.tar.gz" \
            -O /tmp/trufflehog.tar.gz 2>/dev/null \
        && tar -xzf /tmp/trufflehog.tar.gz -C "$BIN_DIR/" trufflehog 2>/dev/null \
        && chmod +x "$BIN_DIR/trufflehog" 2>/dev/null \
        && rm -f /tmp/trufflehog.tar.gz 2>/dev/null \
        && { _has trufflehog && _tick trufflehog || _miss trufflehog; }
    }
fi
_go "github.com/gitleaks/gitleaks/v8@latest" gitleaks

# ─────────────────────────────────────────────────────────────────────────────
# feroxbuster
# ─────────────────────────────────────────────────────────────────────────────
_b "feroxbuster"
if ! _has feroxbuster; then
    DEBIAN_FRONTEND=noninteractive sudo apt-get install -y -qq feroxbuster </dev/null 2>/dev/null \
    && _tick feroxbuster || {
        _i "feroxbuster binary download..."
        ARCH=$(uname -m 2>/dev/null || echo x86_64)
        wget -q --timeout=30 \
            "https://github.com/epi052/feroxbuster/releases/latest/download/${ARCH}-linux-feroxbuster.zip" \
            -O /tmp/feroxbuster.zip 2>/dev/null \
        && unzip -q /tmp/feroxbuster.zip -d /tmp/ferox_extract 2>/dev/null \
        && find /tmp/ferox_extract -type f -name "feroxbuster" \
               -exec cp {} "$BIN_DIR/feroxbuster" \; 2>/dev/null \
        && chmod +x "$BIN_DIR/feroxbuster" 2>/dev/null \
        && rm -rf /tmp/feroxbuster.zip /tmp/ferox_extract 2>/dev/null \
        && { _has feroxbuster && _tick feroxbuster || _miss feroxbuster; }
    }
fi

# ─────────────────────────────────────────────────────────────────────────────
# Python venv
# ─────────────────────────────────────────────────────────────────────────────
_b "Python Virtual Environment"
_i "Creating venv..."
if $PY -m venv .venv 2>/dev/null; then
    source .venv/bin/activate 2>/dev/null && _ok "venv activated"
elif $PY -m venv --system-site-packages .venv 2>/dev/null; then
    source .venv/bin/activate 2>/dev/null && _ok "venv (system-site-packages) activated"
else
    _w "venv failed — using system pip"
fi

PIP="$($VIRTUAL_ENV/bin/pip 2>/dev/null || echo "$PY -m pip")"
_has pip && PIP="pip"
_ok "Pip: $($PIP --version 2>/dev/null | head -1)"
$PIP install $PIP_FLAGS --upgrade pip 2>/dev/null || true

# ─────────────────────────────────────────────────────────────────────────────
# Python pip tools
# ─────────────────────────────────────────────────────────────────────────────
_b "Python Security Tools"
$PIP install $PIP_FLAGS -r requirements.txt 2>/dev/null \
    || _w "requirements.txt partial install"

_pip() {
    local pkg="$1" bin="${2:-$1}"
    _has "$bin" && { _skip "$bin"; return 0; }
    _i "pip: $pkg"
    $PIP install $PIP_FLAGS "$pkg" 2>/dev/null \
    && _tick "$bin" \
    || { $PIP install $PIP_FLAGS --ignore-installed "$pkg" 2>/dev/null \
    && _tick "$bin" || _miss "$bin"; }
    return 0
}

_pip theHarvester   theHarvester
_pip dirsearch      dirsearch
_pip knockpy        knockpy
_pip sublist3r      sublist3r
_pip arjun          arjun
_pip xsstrike       xsstrike
_pip wfuzz          wfuzz
_pip wafw00f        wafw00f
_pip socialscan     socialscan
_pip holehe         holehe
_pip h8mail         h8mail
_pip photon         photon
_pip s3scanner      s3scanner
_pip dnstwist       dnstwist
_pip shodan         shodan
_pip git-dumper     git-dumper
_pip dnstwist       dnstwist

# ─────────────────────────────────────────────────────────────────────────────
# Git-clone tools — to $HOME/tools/ (no sudo required)
# ─────────────────────────────────────────────────────────────────────────────
_b "Tools via Git Clone (no sudo needed)"

# ── Universal git-clone installer ─────────────────────────────────────────────
_clone() {
    local bin="$1" repo="$2"
    local req="${3:-}"       # requirements file (relative to clone dir)
    local entry="${4:-}"     # entry script (relative to clone dir)
    local dest="$TOOLS_DIR/$bin"

    _has "$bin" && { _skip "$bin"; return 0; }
    _i "git clone: $bin"

    # Remove stale failed clone
    rm -rf "${dest}_tmp" 2>/dev/null || true

    if git clone -q --depth 1 "$repo" "${dest}_tmp" 2>/dev/null; then
        rm -rf "$dest" 2>/dev/null || true
        mv "${dest}_tmp" "$dest" 2>/dev/null || { rm -rf "${dest}_tmp"; _miss "$bin"; return 0; }

        # Install requirements
        if [ -n "$req" ] && [ -f "$dest/$req" ]; then
            $PIP install $PIP_FLAGS -r "$dest/$req" 2>/dev/null || true
        fi

        # Setup entry point
        if [ -n "$entry" ] && [ -f "$dest/$entry" ]; then
            chmod +x "$dest/$entry" 2>/dev/null || true
            # Create wrapper script in BIN_DIR (no sudo)
            cat > "$BIN_DIR/$bin" << WRAPPER
#!/usr/bin/env bash
exec "$VIRTUAL_ENV/bin/python" "$dest/$entry" "\$@"
WRAPPER
            chmod +x "$BIN_DIR/$bin" 2>/dev/null || true
        fi

        _has "$bin" && _tick "$bin" || _miss "$bin"
    else
        rm -rf "${dest}_tmp" 2>/dev/null || true
        _miss "$bin"
    fi
    return 0
}

# Also try pip first for some tools (faster)
_pip_then_clone() {
    local bin="$1" pip_name="$2" repo="$3" req="${4:-}" entry="${5:-}"
    _has "$bin" && { _skip "$bin"; return 0; }
    _i "pip: $pip_name"
    $PIP install $PIP_FLAGS "$pip_name" 2>/dev/null && _tick "$bin" && return 0
    _clone "$bin" "$repo" "$req" "$entry"
}

# graphw00f
_pip_then_clone graphw00f graphw00f \
    https://github.com/dolevf/graphw00f \
    "requirements.txt" "main.py"

# corsy
_clone corsy \
    https://github.com/s0md3v/Corsy \
    "requirements.txt" "corsy.py"

# paramspider — try newer fork if original fails
_pip_then_clone paramspider paramspider \
    https://github.com/devanshbatham/ParamSpider \
    "requirements.txt" "paramspider/main.py"

if ! _has paramspider; then
    _pip_then_clone paramspider "paramspider>=2.0" \
        https://github.com/0xKayala/ParamSpider \
        "requirements.txt" "paramspider/main.py"
fi

# jwt_tool
_clone jwt_tool \
    https://github.com/ticarpi/jwt_tool \
    "requirements.txt" "jwt_tool.py"

# linkfinder
_clone linkfinder \
    https://github.com/GerbenJavado/LinkFinder \
    "requirements.txt" "linkfinder.py"

# secretfinder
_clone secretfinder \
    https://github.com/m4ll0k/SecretFinder \
    "requirements.txt" "SecretFinder.py"

# smuggler (no requirements)
_clone smuggler \
    https://github.com/defparam/smuggler \
    "" "smuggler.py"

# ssrfmap
_clone ssrfmap \
    https://github.com/swisskyrepo/SSRFmap \
    "requirements.txt" "ssrfmap.py"

# cloud_enum — pip → apt → git clone
if ! _has cloud_enum; then
    _i "cloud_enum..."
    $PIP install $PIP_FLAGS cloud-enum 2>/dev/null && _tick cloud_enum \
    || DEBIAN_FRONTEND=noninteractive sudo apt-get install -y -qq cloud-enum </dev/null 2>/dev/null \
    && _tick cloud_enum \
    || _clone cloud_enum \
        https://github.com/initstring/cloud_enum \
        "requirements.txt" "cloud_enum.py"
fi

# XSStrike
_clone xsstrike \
    https://github.com/s0md3v/XSStrike \
    "requirements.txt" "xsstrike.py"

# EyeWitness
if ! _has eyewitness; then
    _apt eyewitness eyewitness 2>/dev/null || \
    _clone eyewitness \
        https://github.com/RedSiege/EyeWitness \
        "Python/setup/requirements.txt" "EyeWitness.py"
fi

# wpscan
if ! _has wpscan && _has gem; then
    _i "wpscan gem..."
    gem install wpscan 2>/dev/null && _tick wpscan || _miss wpscan
fi

# ─────────────────────────────────────────────────────────────────────────────
# ── WORDLISTS — Direct File Downloads (no SecLists clone!) ────────────────────
# Download individual files from raw.githubusercontent.com
# Much faster than cloning the entire SecLists repo!
# ─────────────────────────────────────────────────────────────────────────────
_b "Wordlists"
mkdir -p wordlists 2>/dev/null || true

# ── Base URL for SecLists raw files ─────────────────────────────────────
SL="https://raw.githubusercontent.com/danielmiessler/SecLists/master"

# ── Download helper — silent, never fails ──────────────────────────────────
_dlwl() {
    local url="$1" dst="$2"
    [ -s "$dst" ] && return 0  # already exists
    wget -q --timeout=60 "$url" -O "$dst" 2>/dev/null || true
}

# ── Subdomain wordlist ──────────────────────────────────────────────────────
_i "Subdomain wordlist..."
_dlwl "$SL/Discovery/DNS/subdomains-top1million-110000.txt" \
    wordlists/sub_seclists_110k.txt
_dlwl "$SL/Discovery/DNS/deepmagic.com-prefixes-top50000.txt" \
    wordlists/sub_deepmagic.txt
_dlwl "$SL/Discovery/DNS/bitquark-subdomains-top100000.txt" \
    wordlists/sub_bitquark.txt
_dlwl "$SL/Discovery/DNS/dns-Jhaddix.txt" \
    wordlists/sub_jhaddix.txt

# Assetnote DNS (best quality)
_dlwl "https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt" \
    wordlists/sub_assetnote.txt

# Merge and dedup subdomains
cat wordlists/sub_*.txt 2>/dev/null | sort -u > wordlists/subdomains.txt 2>/dev/null || true
SUB_C=$(wc -l < wordlists/subdomains.txt 2>/dev/null || echo 0)

if [ "${SUB_C:-0}" -lt 100 ] 2>/dev/null; then
    _w "Subdomain download failed — using minimal built-in list"
    printf "www\nmail\napi\nadmin\ndev\nstaging\nblog\nshop\napp\nmobile\ntest\nvpn\nftp\ncp\nwebmail\nm\nns1\nns2\ncdn\nlb\n" \
        > wordlists/subdomains.txt
fi
_ok "Subdomains: $(wc -l < wordlists/subdomains.txt 2>/dev/null || echo 0) entries"
rm -f wordlists/sub_*.txt 2>/dev/null || true

# ── Directory wordlist ──────────────────────────────────────────────────────
_i "Directory wordlist..."
_dlwl "$SL/Discovery/Web-Content/raft-large-directories.txt" \
    wordlists/dir_raft_large.txt
_dlwl "$SL/Discovery/Web-Content/raft-medium-directories.txt" \
    wordlists/dir_raft_medium.txt
_dlwl "$SL/Discovery/Web-Content/common.txt" \
    wordlists/dir_common.txt
_dlwl "$SL/Discovery/Web-Content/directory-list-2.3-medium.txt" \
    wordlists/dir_dirmedium.txt
_dlwl "$SL/Discovery/Web-Content/quickhits.txt" \
    wordlists/dir_quickhits.txt

# Assetnote API routes
_dlwl "https://wordlists-cdn.assetnote.io/data/automated/httparchive_apiroutes_2024.01.28.txt" \
    wordlists/dir_api_assetnote.txt

cat wordlists/dir_*.txt 2>/dev/null | sort -u > wordlists/directories.txt 2>/dev/null || true
DIR_C=$(wc -l < wordlists/directories.txt 2>/dev/null || echo 0)

if [ "${DIR_C:-0}" -lt 100 ] 2>/dev/null; then
    _w "Directory download failed — using minimal built-in list"
    printf "admin\napi\nlogin\nupload\nbackup\n.env\n.git\nconfig\ntest\ndev\nv1\nv2\nwp-admin\nphpinfo.php\ndashboard\npanel\nconsole\nserver-status\n" \
        > wordlists/directories.txt
fi
_ok "Directories: $(wc -l < wordlists/directories.txt 2>/dev/null || echo 0) entries"
rm -f wordlists/dir_*.txt 2>/dev/null || true

# ── Parameters wordlist ─────────────────────────────────────────────────────
_i "Parameters wordlist..."
_dlwl "$SL/Discovery/Web-Content/burp-parameter-names.txt" \
    wordlists/params_burp.txt
_dlwl "https://wordlists-cdn.assetnote.io/data/automated/httparchive_parameters_2024.01.28.txt" \
    wordlists/params_assetnote.txt

cat wordlists/params_*.txt 2>/dev/null | sort -u > wordlists/parameters.txt 2>/dev/null || true
PARAM_C=$(wc -l < wordlists/parameters.txt 2>/dev/null || echo 0)
if [ "${PARAM_C:-0}" -lt 10 ] 2>/dev/null; then
    printf "id\nname\nuser\npage\nq\nsearch\ntoken\nkey\nurl\ncallback\nredirect\npath\nfile\ncmd\nexec\n" \
        > wordlists/parameters.txt
fi
_ok "Parameters: $(wc -l < wordlists/parameters.txt 2>/dev/null || echo 0) entries"
rm -f wordlists/params_*.txt 2>/dev/null || true

# ─────────────────────────────────────────────────────────────────────────────
# IMPORTANT: All temp wordlist files go to /tmp/ to avoid glob collision!
# e.g. rm -f /tmp/wl_lfi_*.txt will NEVER delete wordlists/lfi_payloads.txt
# ─────────────────────────────────────────────────────────────────────────────
WL_TMP="/tmp/dominion_wl_$$"    # unique temp prefix per run
mkdir -p "$WL_TMP" 2>/dev/null || WL_TMP="/tmp/dominion_wl"

# ── LFI payloads ─────────────────────────────────────────────────────────────
_i "LFI payloads..."
_dlwl "$SL/Fuzzing/LFI/LFI-Jhaddix.txt"                 "$WL_TMP/lfi_1.txt"
_dlwl "$SL/Fuzzing/LFI/LFI-LFISuite-pathtotest.txt"      "$WL_TMP/lfi_2.txt"
_dlwl "$SL/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt"   "$WL_TMP/lfi_3.txt"
cat "$WL_TMP"/lfi_*.txt 2>/dev/null | sort -u > wordlists/lfi_payloads.txt 2>/dev/null || true
if ! [ -s wordlists/lfi_payloads.txt ]; then
    cat > wordlists/lfi_payloads.txt << 'EOFL'
../../etc/passwd
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd
php://filter/read=convert.base64-encode/resource=/etc/passwd
/etc/passwd
/etc/shadow
/proc/self/environ
/proc/self/cmdline
/etc/hosts
/etc/issue
EOFL
fi
rm -rf "$WL_TMP"/lfi_*.txt 2>/dev/null || true
_ok "LFI payloads: $(wc -l < wordlists/lfi_payloads.txt 2>/dev/null || echo 0)"

# ── XSS payloads ─────────────────────────────────────────────────────────────
_i "XSS payloads..."
_dlwl "$SL/Fuzzing/XSS/XSS-Jhaddix.txt"                             "$WL_TMP/xss_1.txt"
_dlwl "$SL/Fuzzing/XSS/XSS-BruteLogic.txt"                          "$WL_TMP/xss_2.txt"
_dlwl "$SL/Fuzzing/XSS/xss-without-parentheses-semi-colons.txt"     "$WL_TMP/xss_3.txt"
cat "$WL_TMP"/xss_*.txt 2>/dev/null | sort -u > wordlists/xss_payloads.txt 2>/dev/null || true
if ! [ -s wordlists/xss_payloads.txt ]; then
    cat > wordlists/xss_payloads.txt << 'EOFX'
<script>alert(1)</script>
"><script>alert(1)</script>
<svg/onload=alert(1)>
<img src=x onerror=alert(1)>
<body onload=alert(1)>
javascript:alert(1)
'><script>alert(1)</script>
<iframe src=javascript:alert(1)>
EOFX
fi
rm -rf "$WL_TMP"/xss_*.txt 2>/dev/null || true
_ok "XSS payloads: $(wc -l < wordlists/xss_payloads.txt 2>/dev/null || echo 0)"

# ── SQLi payloads ─────────────────────────────────────────────────────────────
_i "SQLi payloads..."
_dlwl "$SL/Fuzzing/SQLi/Generic-SQLi.txt"              "$WL_TMP/sqli_1.txt"
_dlwl "$SL/Fuzzing/SQLi/quick-SQLi.txt"                "$WL_TMP/sqli_2.txt"
_dlwl "$SL/Fuzzing/SQLi/Generic-BlindSQLi.fuzzdb.txt" "$WL_TMP/sqli_3.txt"
cat "$WL_TMP"/sqli_*.txt 2>/dev/null | sort -u > wordlists/sqli_payloads.txt 2>/dev/null || true
if ! [ -s wordlists/sqli_payloads.txt ]; then
    cat > wordlists/sqli_payloads.txt << 'EOFS'
' OR '1'='1
' OR 1=1--
" OR 1=1--
' AND SLEEP(5)--
") OR ("1"="1
1 UNION SELECT NULL--
1 UNION SELECT NULL,NULL--
1 ORDER BY 1--
EOFS
fi
rm -rf "$WL_TMP"/sqli_*.txt 2>/dev/null || true
_ok "SQLi payloads: $(wc -l < wordlists/sqli_payloads.txt 2>/dev/null || echo 0)"

# ── SSTI payloads ─────────────────────────────────────────────────────────────
if ! [ -s wordlists/ssti_payloads.txt ]; then
    cat > wordlists/ssti_payloads.txt << 'EOFST'
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
*{7*7}
{{config}}
{{self}}
{{request}}
${{7*7}}
@(7*7)
EOFST
fi

# ── SSRF payloads ─────────────────────────────────────────────────────────────
if ! [ -s wordlists/ssrf_payloads.txt ]; then
    cat > wordlists/ssrf_payloads.txt << 'EOFSS'
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://127.0.0.1/admin
http://localhost/admin
http://0.0.0.0/admin
http://[::1]/admin
http://2130706433/admin
dict://127.0.0.1:6379/info
ftp://127.0.0.1/
file:///etc/passwd
EOFSS
fi

# ── API paths ─────────────────────────────────────────────────────────────────
_dlwl "$SL/Discovery/Web-Content/api/api-endpoints.txt" "$WL_TMP/api_1.txt"
_dlwl "$SL/Discovery/Web-Content/api/objects.txt"        "$WL_TMP/api_2.txt"
cat "$WL_TMP"/api_*.txt 2>/dev/null | sort -u > wordlists/api_paths.txt 2>/dev/null || true
if ! [ -s wordlists/api_paths.txt ]; then
    cat > wordlists/api_paths.txt << 'EOFA'
/api/v1/users
/api/v2/users
/api/admin
/api/config
/api/health
/api/debug
/api/token
/api/login
/api/register
/graphql
/rest/
/swagger.json
/.well-known/
EOFA
fi
rm -rf "$WL_TMP" 2>/dev/null || true

# ── DNS Resolvers ─────────────────────────────────────────────────────────────
if ! [ -s wordlists/resolvers.txt ]; then
    _dlwl "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" \
        wordlists/resolvers.txt
fi
if ! [ -s wordlists/resolvers.txt ]; then
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
    _ok "DNS resolvers: built-in (15 resolvers)"
else
    _ok "DNS resolvers: $(wc -l < wordlists/resolvers.txt) entries"
fi

# ─────────────────────────────────────────────────────────────────────────────
# PATH setup
# ─────────────────────────────────────────────────────────────────────────────
for _rc in ~/.bashrc ~/.zshrc; do
    [ -f "$_rc" ] && grep -q "local/bin" "$_rc" 2>/dev/null \
    || echo 'export PATH=$PATH:$HOME/.local/bin:$HOME/go/bin' >> "$_rc" 2>/dev/null || true
done

# ─────────────────────────────────────────────────────────────────────────────
# Final Summary
# ─────────────────────────────────────────────────────────────────────────────
_b "Final Check"
echo ""

ALL=(
    subfinder amass assetfinder findomain chaos
    puredns shuffledns dnsx massdns github-subdomains
    httpx httprobe naabu rustscan gowitness aquatone
    katana gospider hakrawler gau waybackurls gf
    nuclei dalfox crlfuzz ffuf gobuster feroxbuster nomore403
    sqlmap commix nikto wafw00f wfuzz
    trufflehog gitleaks git-dumper
    jwt_tool graphw00f xsstrike smuggler ssrfmap
    linkfinder secretfinder cloud_enum cloudbrute s3scanner
    paramspider arjun
)

printf "\n  %-22s %-22s %-22s\n" "TOOL" "STATUS" "TOOL"
printf "  %s\n" "$(printf '%.0s─' {1..70})"
FOUND=0; MISSED=0
for i in "${!ALL[@]}"; do
    t="${ALL[$i]}"
    if _has "$t"; then
        printf "  ${G}✓${N} %-22s" "$t"
        FOUND=$((FOUND+1))
    else
        printf "  ${R}✗${N} %-22s" "$t"
        MISSED=$((MISSED+1))
    fi
    [ $(( (i+1) % 3 )) -eq 0 ] && echo ""
done
echo -e "\n"

echo -e "${C}  Wordlists:${N}"
for _wl in subdomains directories parameters lfi_payloads xss_payloads \
           sqli_payloads ssti_payloads ssrf_payloads resolvers api_paths; do
    _f="wordlists/${_wl}.txt"
    if [ -s "$_f" ]; then
        _n=$(wc -l < "$_f" 2>/dev/null | tr -d ' ' || echo "?")
        echo -e "  ${G}✓${N} ${_wl}.txt (${_n} lines)"
    else
        echo -e "  ${Y}!${N} ${_wl}.txt — empty"
    fi
done

echo ""
echo -e "${G}${B}════════════════════════════════════════════${N}"
echo -e "${G}${B}  Tools ready : $FOUND / ${#ALL[@]}${N}"
[ $MISSED -gt 0 ] && echo -e "${Y}  Unavailable : $MISSED (all optional — tool still runs)${N}"
[ ${#MISS[@]} -gt 0 ] && echo -e "${Y}  Could not install: ${MISS[*]}${N}"
echo -e "${G}${B}════════════════════════════════════════════${N}"
echo ""
echo -e "  ${C}Next steps:${N}"
echo -e "  ${B}1.${N} source .venv/bin/activate"
echo -e "  ${B}2.${N} cp config.example.yml config.yml && nano config.yml"
echo -e "  ${B}3.${N} python dominion.py -d target.com"
echo ""
echo -e "${G}${B}DOMINION ready. Zero crashes. 🔥${N}"
