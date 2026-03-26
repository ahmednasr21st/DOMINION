#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║           DOMINION — Complete Auto Installer v2.0                      ║
# ║  Installs 50+ security tools, Python deps, and large wordlists          ║
# ╚══════════════════════════════════════════════════════════════════════════╝
# // turbo-all

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; PURPLE='\033[0;35m'; NC='\033[0m'
BOLD='\033[1m'

info()    { echo -e "${CYAN}[*]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[✗]${NC} $1"; }
header()  { echo -e "\n${PURPLE}${BOLD}══ $1 ══${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

INSTALLED=0
FAILED=0

tick()  { INSTALLED=$((INSTALLED+1)); success "[$INSTALLED] $1 ✓"; }
cross() { FAILED=$((FAILED+1));    warn "FAILED: $1 — skipping"; }

banner() {
echo -e "${RED}${BOLD}"
cat << 'EOF'
██████╗  ██████╗ ███╗   ███╗██╗███╗   ██╗██╗ ██████╗ ███╗   ██╗
██╔══██╗██╔═══██╗████╗ ████║██║████╗  ██║██║██╔═══██╗████╗  ██║
██║  ██║██║   ██║██╔████╔██║██║██╔██╗ ██║██║██║   ██║██╔██╗ ██║
██║  ██║██║   ██║██║╚██╔╝██║██║██║╚██╗██║██║██║   ██║██║╚██╗██║
██████╔╝╚██████╔╝██║ ╚═╝ ██║██║██║ ╚████║██║╚██████╔╝██║ ╚████║
╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝
             Ultra Installer v2.0 — 50+ Tools
EOF
echo -e "${NC}"
}
banner

# ─────────────────────────────────────────────────────────────────────────────
header "System Detection"
# ─────────────────────────────────────────────────────────────────────────────
if [ -f /etc/kali_version ] || grep -qi "kali" /etc/os-release 2>/dev/null; then
    OS="kali"
elif [ -f /etc/debian_version ]; then
    OS="debian"
elif [ -f /etc/fedora-release ]; then
    OS="fedora"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    OS="unknown"
fi
success "Detected OS: $OS"

install_pkg() {
    if [ "$OS" = "macos" ]; then
        brew install "$@" 2>/dev/null || true
    elif [ "$OS" = "fedora" ]; then
        sudo dnf install -y "$@" 2>/dev/null || true
    else
        sudo apt-get install -y "$@" 2>/dev/null || true
    fi
}

go_install() {
    local pkg="$1"
    local name="$2"
    if command -v "$name" &>/dev/null; then
        success "[$name] already installed — skipping"
        INSTALLED=$((INSTALLED+1))
    else
        info "Installing $name..."
        go install "$pkg" 2>/dev/null && tick "$name" || cross "$name"
    fi
}

pip_install() {
    local pkg="$1"
    local name="${2:-$1}"
    if command -v "$name" &>/dev/null || python3 -c "import ${name//-/_}" &>/dev/null 2>&1; then
        success "[$name] already installed"
    else
        pip install -q "$pkg" 2>/dev/null && tick "$name" || cross "$name"
    fi
}

apt_install() {
    local pkg="$1"
    local check="${2:-$1}"
    if command -v "$check" &>/dev/null; then
        success "[$check] already installed"
        INSTALLED=$((INSTALLED+1))
    else
        install_pkg "$pkg"
        command -v "$check" &>/dev/null && tick "$check" || cross "$check"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
header "System Dependencies"
# ─────────────────────────────────────────────────────────────────────────────
info "Updating package lists..."
sudo apt-get update -qq 2>/dev/null || true

SYSTEM_PKGS=(
    curl git wget unzip python3 python3-pip python3-venv
    nmap masscan nikto dnsrecon dnsenum fierce
    whois net-tools netcat-openbsd
    chromium-driver chromium
    libssl-dev libffi-dev python3-dev
    ruby ruby-dev build-essential
    libpcap-dev libnetfilter-queue-dev
    jq ncat sqlmap
)
for p in "${SYSTEM_PKGS[@]}"; do
    apt_install "$p"
done

# ─────────────────────────────────────────────────────────────────────────────
header "Go Installation"
# ─────────────────────────────────────────────────────────────────────────────
if ! command -v go &>/dev/null; then
    GO_VER="1.22.3"
    OS_NAME=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
    GO_TAR="go${GO_VER}.${OS_NAME}-${ARCH}.tar.gz"
    info "Downloading Go $GO_VER..."
    wget -q "https://go.dev/dl/${GO_TAR}" -O /tmp/${GO_TAR}
    sudo tar -C /usr/local -xzf /tmp/${GO_TAR}
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
    success "Go $GO_VER installed"
fi
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin
success "Go: $(go version)"

# ─────────────────────────────────────────────────────────────────────────────
header "Go Tools (Phase 01-04: Recon & Discovery)"
# ─────────────────────────────────────────────────────────────────────────────

# ── Subdomain enumeration ─────────────────────────────────────────────────────
go_install "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"    subfinder
go_install "github.com/owasp-amass/amass/v4/...@latest"                       amass
go_install "github.com/tomnomnom/assetfinder@latest"                          assetfinder
go_install "github.com/findomain/findomain@latest"                             findomain       || \
    (curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux-i386.zip \
     && unzip -o findomain-linux-i386.zip -d ~/.local/bin 2>/dev/null; rm -f *.zip)
go_install "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"        chaos
go_install "github.com/d3mondev/puredns/v2@latest"                            puredns
go_install "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"     shuffledns
go_install "github.com/themightyglider/gotator@latest"                         gotator
go_install "github.com/infosec-au/altdns@latest"                              altdns           || \
    pip install -q altdns 2>/dev/null
go_install "github.com/gwen001/github-subdomains@latest"                       github-subdomains

# ── DNS ───────────────────────────────────────────────────────────────────────
go_install "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"                 dnsx
go_install "github.com/blechschmidt/massdns@latest"                           massdns          || \
    (git clone --depth 1 https://github.com/blechschmidt/massdns /tmp/massdns \
     && make -C /tmp/massdns 2>/dev/null && sudo cp /tmp/massdns/bin/massdns /usr/local/bin/)

# ── HTTP probing ──────────────────────────────────────────────────────────────
go_install "github.com/projectdiscovery/httpx/cmd/httpx@latest"               httpx
go_install "github.com/tomnomnom/httprobe@latest"                              httprobe
go_install "github.com/michenriksen/aquatone@latest"                           aquatone

# ── Technology detection ───────────────────────────────────────────────────────
go_install "github.com/sensepost/gowitness@latest"                             gowitness

# ─────────────────────────────────────────────────────────────────────────────
header "Go Tools (Phase 05: Port Scanning)"
# ─────────────────────────────────────────────────────────────────────────────
go_install "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"            naabu

# RustScan (fastest scanner)
if ! command -v rustscan &>/dev/null; then
    info "Installing rustscan..."
    if command -v cargo &>/dev/null; then
        cargo install rustscan 2>/dev/null && tick rustscan || cross rustscan
    else
        curl -LO https://github.com/RustScan/RustScan/releases/latest/download/rustscan_2.3.0_amd64.deb 2>/dev/null \
            && sudo dpkg -i rustscan_*.deb 2>/dev/null && rm -f rustscan_*.deb \
            && tick rustscan || cross rustscan
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
header "Go Tools (Phase 06: Crawling & URL Discovery)"
# ─────────────────────────────────────────────────────────────────────────────
go_install "github.com/projectdiscovery/katana/cmd/katana@latest"             katana
go_install "github.com/jaeles-project/gospider@latest"                        gospider
go_install "github.com/hakluke/hakrawler@latest"                              hakrawler
go_install "github.com/lc/gau/v2/cmd/gau@latest"                             gau
go_install "github.com/tomnomnom/waybackurls@latest"                          waybackurls
go_install "github.com/bp0lr/gauplus@latest"                                  gauplus
go_install "github.com/tomnomnom/meg@latest"                                  meg
go_install "github.com/tomnomnom/gf@latest"                                   gf

# GF patterns
if [ ! -d ~/.gf ]; then
    git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns ~/.gf 2>/dev/null
    success "gf patterns installed"
fi

# ─────────────────────────────────────────────────────────────────────────────
header "Go Tools (Phase 07: Secret Detection)"
# ─────────────────────────────────────────────────────────────────────────────
go_install "github.com/trufflesecurity/trufflehog/v3@latest"                  trufflehog
go_install "github.com/gitleaks/gitleaks/v8@latest"                           gitleaks
go_install "github.com/nikitastupin/clairvoyance@latest"                       clairvoyance      || true
go_install "github.com/zricethezav/gitleaks/v8@latest"                        gitleaks          || true

# ─────────────────────────────────────────────────────────────────────────────
header "Go Tools (Phase 08: Vulnerability Scanning)"
# ─────────────────────────────────────────────────────────────────────────────
go_install "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"          nuclei
go_install "github.com/hahwul/dalfox/v2@latest"                              dalfox
go_install "github.com/dwisiswant0/crlfuzz@latest"                            crlfuzz
go_install "github.com/iangcarroll/cookiemonster/cmd/cookiemonster@latest"     cookiemonster     || true
go_install "github.com/ffuf/ffuf/v2@latest"                                   ffuf
go_install "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest" interactsh-client

# ─────────────────────────────────────────────────────────────────────────────
header "Go Tools (Phase 09: Content Discovery)"
# ─────────────────────────────────────────────────────────────────────────────
go_install "github.com/OJ/gobuster/v3@latest"                                 gobuster
go_install "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"                 tlsx

# ─────────────────────────────────────────────────────────────────────────────
header "Go Tools (Phase 10: Cloud)"
# ─────────────────────────────────────────────────────────────────────────────
go_install "github.com/projectdiscovery/cloudbrute/cmd/cloudbrute@latest"     cloudbrute

# ─────────────────────────────────────────────────────────────────────────────
header "Python Tools"
# ─────────────────────────────────────────────────────────────────────────────
info "Setting up Python virtual environment..."
python3 -m venv .venv
source .venv/bin/activate
pip install -q --upgrade pip

# Core dependencies
pip install -q -r requirements.txt

# Additional Python tools installed in venv
info "Installing Python security tools..."

pip_install "theHarvester"       theHarvester
pip_install "dirsearch"          dirsearch
pip_install "knockpy"            knockpy
pip_install "sublist3r"          sublist3r
pip_install "paramspider"        paramspider
pip_install "arjun"              arjun
pip_install "xsstrike"           xsstrike
pip_install "wfuzz"              wfuzz
pip_install "wafw00f"            wafw00f
pip_install "whatweb"            whatweb          || apt_install whatweb whatweb
pip_install "jwt_tool"           jwt_tool         || pip install -q jwt_tool 2>/dev/null
pip_install "graphw00f"          graphw00f
pip_install "corsy"              corsy
pip_install "s3scanner"          s3scanner
pip_install "cloudhunter"        cloudhunter       || pip install -q cloud_enum 2>/dev/null
pip_install "autopoisoner"       autopoisoner      || true
pip_install "cariddi"            cariddi           || true
pip_install "photon"             photon
pip_install "socialscan"         socialscan        || true
pip_install "holehe"             holehe            || true
pip_install "pyWhat"             pywhat            || true
pip_install "h8mail"             h8mail            || true

# LinkFinder + SecretFinder
if [ ! -f /usr/local/bin/linkfinder ]; then
    info "Installing LinkFinder..."
    git clone --depth 1 https://github.com/GerbenJavado/LinkFinder /opt/linkfinder 2>/dev/null
    pip install -q -r /opt/linkfinder/requirements.txt 2>/dev/null
    ln -sf /opt/linkfinder/linkfinder.py /usr/local/bin/linkfinder
    chmod +x /opt/linkfinder/linkfinder.py
    tick linkfinder
fi

if [ ! -f /usr/local/bin/secretfinder ]; then
    info "Installing SecretFinder..."
    git clone --depth 1 https://github.com/m4ll0k/SecretFinder /opt/secretfinder 2>/dev/null
    pip install -q -r /opt/secretfinder/requirements.txt 2>/dev/null
    ln -sf /opt/secretfinder/SecretFinder.py /usr/local/bin/secretfinder
    chmod +x /opt/secretfinder/SecretFinder.py
    tick secretfinder
fi

if ! command -v smuggler &>/dev/null; then
    info "Installing Smuggler (HTTP request smuggling)..."
    git clone --depth 1 https://github.com/defparam/smuggler /opt/smuggler 2>/dev/null
    ln -sf /opt/smuggler/smuggler.py /usr/local/bin/smuggler
    chmod +x /opt/smuggler/smuggler.py
    tick smuggler
fi

if ! command -v nomore403 &>/dev/null; then
    info "Installing nomore403 (403 bypass)..."
    go install github.com/devploit/nomore403@latest 2>/dev/null && tick nomore403 || cross nomore403
fi

if ! command -v git-dumper &>/dev/null; then
    info "Installing git-dumper..."
    pip install -q git-dumper 2>/dev/null && tick git-dumper || cross git-dumper
fi

if ! command -v ssrfmap &>/dev/null; then
    info "Installing SSRFmap..."
    git clone --depth 1 https://github.com/swisskyrepo/SSRFmap /opt/ssrfmap 2>/dev/null
    pip install -q -r /opt/ssrfmap/requirements.txt 2>/dev/null
    ln -sf /opt/ssrfmap/ssrfmap.py /usr/local/bin/ssrfmap
    chmod +x /opt/ssrfmap/ssrfmap.py
    tick ssrfmap
fi

if ! command -v graphw00f &>/dev/null; then
    info "Installing graphw00f (GraphQL fingerprinting)..."
    pip install -q graphw00f 2>/dev/null && tick graphw00f || cross graphw00f
fi

if ! command -v jwt_tool &>/dev/null; then
    info "Installing jwt_tool..."
    git clone --depth 1 https://github.com/ticarpi/jwt_tool /opt/jwt_tool 2>/dev/null
    pip install -q -r /opt/jwt_tool/requirements.txt 2>/dev/null
    ln -sf /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool
    chmod +x /opt/jwt_tool/jwt_tool.py
    tick jwt_tool
fi

# feroxbuster
if ! command -v feroxbuster &>/dev/null; then
    info "Installing feroxbuster..."
    curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | \
        bash -s -- -b ~/.local/bin 2>/dev/null && tick feroxbuster || cross feroxbuster
fi

# EyeWitness
if ! command -v eyewitness &>/dev/null; then
    info "Installing EyeWitness..."
    git clone --depth 1 https://github.com/RedSiege/EyeWitness /opt/eyewitness 2>/dev/null
    python3 /opt/eyewitness/setup/setup.py 2>/dev/null || true
    ln -sf /opt/eyewitness/EyeWitness.py /usr/local/bin/eyewitness
    chmod +x /opt/eyewitness/EyeWitness.py
    tick eyewitness
fi

# ParamSpider
if ! command -v paramspider &>/dev/null; then
    pip install paramspider 2>/dev/null && tick paramspider || \
    (git clone --depth 1 https://github.com/devanshbatham/ParamSpider /opt/paramspider 2>/dev/null \
     && pip install -q -r /opt/paramspider/requirements.txt 2>/dev/null \
     && ln -sf /opt/paramspider/paramspider.py /usr/local/bin/paramspider \
     && tick paramspider)
fi

# cloud_enum
if ! command -v cloud_enum &>/dev/null; then
    info "Installing cloud_enum..."
    git clone --depth 1 https://github.com/initstring/cloud_enum /opt/cloud_enum 2>/dev/null
    pip install -q -r /opt/cloud_enum/requirements.txt 2>/dev/null
    ln -sf /opt/cloud_enum/cloud_enum.py /usr/local/bin/cloud_enum
    chmod +x /opt/cloud_enum/cloud_enum.py
    tick cloud_enum
fi

# s3scanner
if ! command -v s3scanner &>/dev/null; then
    pip install -q s3scanner 2>/dev/null && tick s3scanner || cross s3scanner
fi

# XSStrike
if ! command -v xsstrike &>/dev/null; then
    git clone --depth 1 https://github.com/s0md3v/XSStrike /opt/xsstrike 2>/dev/null
    pip install -q -r /opt/xsstrike/requirements.txt 2>/dev/null
    ln -sf /opt/xsstrike/xsstrike.py /usr/local/bin/xsstrike
    chmod +x /opt/xsstrike/xsstrike.py
    tick xsstrike
fi

# commix (command injection)
if ! command -v commix &>/dev/null; then
    apt_install commix commix || \
    (git clone --depth 1 https://github.com/commixproject/commix /opt/commix 2>/dev/null \
     && ln -sf /opt/commix/commix.py /usr/local/bin/commix \
     && tick commix)
fi

# ─────────────────────────────────────────────────────────────────────────────
header "Ruby Tools"
# ─────────────────────────────────────────────────────────────────────────────
if command -v gem &>/dev/null; then
    gem install wpscan 2>/dev/null && tick wpscan || cross wpscan
fi

# ─────────────────────────────────────────────────────────────────────────────
header "Nuclei Templates Update"
# ─────────────────────────────────────────────────────────────────────────────
info "Updating nuclei templates (all community templates)..."
nuclei -update-templates 2>/dev/null && success "Nuclei templates updated" || warn "Template update failed"

# Install nuclei-templates extra repos
nuclei_extra_dir="$HOME/nuclei-templates-extra"
if [ ! -d "$nuclei_extra_dir" ]; then
    mkdir -p "$nuclei_extra_dir"
    # Fuzzing templates
    git clone --depth 1 https://github.com/projectdiscovery/fuzzing-templates \
        "$nuclei_extra_dir/fuzzing-templates" 2>/dev/null && success "Fuzzing templates cloned"
    # CNVD templates (Chinese vuln DB)
    git clone --depth 1 https://github.com/ExpLangcn/NucleiTP \
        "$nuclei_extra_dir/NucleiTP" 2>/dev/null && success "NucleiTP templates cloned"
    # More community templates
    git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates \
        "$nuclei_extra_dir/nuclei-templates"     2>/dev/null && success "nuclei-templates cloned"
fi

# ─────────────────────────────────────────────────────────────────────────────
header "GF Patterns (for filtering interesting params/paths)"
# ─────────────────────────────────────────────────────────────────────────────
GF_DIR="$HOME/.gf"
mkdir -p "$GF_DIR"
if [ "$(ls -A $GF_DIR 2>/dev/null | wc -l)" -lt 5 ]; then
    git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns /tmp/gf-patterns 2>/dev/null
    cp /tmp/gf-patterns/*.json "$GF_DIR/" 2>/dev/null && success "GF patterns installed" || true
fi

# ─────────────────────────────────────────────────────────────────────────────
header "Wordlists (Large, Production-Grade)"
# ─────────────────────────────────────────────────────────────────────────────
mkdir -p wordlists

info "Cloning SecLists (the gold standard)..."
if [ ! -d /usr/share/seclists ] && [ ! -d /opt/SecLists ]; then
    git clone --depth 1 https://github.com/danielmiessler/SecLists /opt/SecLists 2>/dev/null \
        && success "SecLists cloned to /opt/SecLists" || warn "SecLists clone failed — downloading individually"
    SECLISTS="/opt/SecLists"
elif [ -d /usr/share/seclists ]; then
    SECLISTS="/usr/share/seclists"
    success "SecLists found at /usr/share/seclists"
else
    SECLISTS="/opt/SecLists"
    success "SecLists found at /opt/SecLists"
fi

# ── Subdomain wordlists ────────────────────────────────────────────────────────
info "Building mega subdomain wordlist..."
SUBS_WL="wordlists/subdomains.txt"
> "$SUBS_WL"

# SecLists subdomains (multiple lists merged)
for wl in \
    "$SECLISTS/Discovery/DNS/subdomains-top1million-110000.txt" \
    "$SECLISTS/Discovery/DNS/fierce-hostlist.txt" \
    "$SECLISTS/Discovery/DNS/deepmagic.com-prefixes-top500.txt" \
    "$SECLISTS/Discovery/DNS/deepmagic.com-prefixes-top50000.txt" \
    "$SECLISTS/Discovery/DNS/bitquark-subdomains-top100000.txt" \
    "$SECLISTS/Discovery/DNS/combined_subdomains.txt" \
    "$SECLISTS/Discovery/DNS/dns-Jhaddix.txt"
do
    [ -f "$wl" ] && cat "$wl" >> "$SUBS_WL" && info "  Added: $(basename $wl)"
done

# Download assetnote subdomains (massive, well-known)
if [ "$(wc -l < "$SUBS_WL" 2>/dev/null)" -lt 100000 ]; then
    info "Downloading assetnote subdomains wordlist..."
    wget -q "https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt" \
         -O /tmp/assetnote_dns.txt 2>/dev/null \
    && cat /tmp/assetnote_dns.txt >> "$SUBS_WL" \
    && success "Assetnote DNS wordlist added" || warn "Assetnote DNS download failed"
fi

# n0kovo subdomains (huge list)
wget -q "https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_small.txt" \
     -O /tmp/n0kovo.txt 2>/dev/null \
&& cat /tmp/n0kovo.txt >> "$SUBS_WL" \
&& success "n0kovo subdomains added" || true

# Deduplicate and sort
sort -u "$SUBS_WL" -o "$SUBS_WL"
SUBS_COUNT=$(wc -l < "$SUBS_WL")
success "Final subdomain wordlist: ${SUBS_COUNT} entries → wordlists/subdomains.txt"

# ── Directory wordlists ────────────────────────────────────────────────────────
info "Building mega directory wordlist..."
DIRS_WL="wordlists/directories.txt"
> "$DIRS_WL"

for wl in \
    "$SECLISTS/Discovery/Web-Content/raft-large-directories.txt" \
    "$SECLISTS/Discovery/Web-Content/raft-large-files.txt" \
    "$SECLISTS/Discovery/Web-Content/raft-medium-directories.txt" \
    "$SECLISTS/Discovery/Web-Content/common.txt" \
    "$SECLISTS/Discovery/Web-Content/directory-list-2.3-medium.txt" \
    "$SECLISTS/Discovery/Web-Content/directory-list-2.3-big.txt" \
    "$SECLISTS/Discovery/Web-Content/quickhits.txt" \
    "$SECLISTS/Discovery/Web-Content/Apache.fuzz.txt" \
    "$SECLISTS/Discovery/Web-Content/nginx.conf.bak.txt" \
    "$SECLISTS/Discovery/Web-Content/CGIs.txt"
do
    [ -f "$wl" ] && cat "$wl" >> "$DIRS_WL" && info "  Added: $(basename $wl)"
done

# Assetnote best wordlist (best for modern apps)
info "Downloading assetnote best-wordlist..."
wget -q "https://wordlists-cdn.assetnote.io/data/manually-curated/best-word-list-short.txt" \
     -O /tmp/assetnote_web.txt 2>/dev/null \
&& cat /tmp/assetnote_web.txt >> "$DIRS_WL" \
&& success "Assetnote web wordlist added" || true

wget -q "https://wordlists-cdn.assetnote.io/data/automated/httparchive_apiroutes_2024.01.28.txt" \
     -O /tmp/assetnote_api.txt 2>/dev/null \
&& cat /tmp/assetnote_api.txt >> "$DIRS_WL" \
&& success "Assetnote API routes wordlist added" || true

sort -u "$DIRS_WL" -o "$DIRS_WL"
DIRS_COUNT=$(wc -l < "$DIRS_WL")
success "Final directory wordlist: ${DIRS_COUNT} entries → wordlists/directories.txt"

# ── API-specific wordlist ──────────────────────────────────────────────────────
info "Building API-focused wordlist..."
API_WL="wordlists/api_paths.txt"
> "$API_WL"
for wl in \
    "$SECLISTS/Discovery/Web-Content/api/api-endpoints.txt" \
    "$SECLISTS/Discovery/Web-Content/api/objects.txt" \
    "$SECLISTS/Discovery/Web-Content/api/api-seen-in-wild.txt"
do
    [ -f "$wl" ] && cat "$wl" >> "$API_WL" && info "  Added: $(basename $wl)"
done
wget -q "https://wordlists-cdn.assetnote.io/data/automated/httparchive_apiroutes_2024.01.28.txt" \
     -O /tmp/api_assetnote.txt 2>/dev/null \
&& cat /tmp/api_assetnote.txt >> "$API_WL" || true
sort -u "$API_WL" -o "$API_WL"
success "API wordlist: $(wc -l < "$API_WL") entries"

# ── Parameter wordlist ─────────────────────────────────────────────────────────
info "Building parameter wordlist..."
PARAMS_WL="wordlists/parameters.txt"
> "$PARAMS_WL"
for wl in \
    "$SECLISTS/Discovery/Web-Content/burp-parameter-names.txt" \
    "$SECLISTS/Discovery/Web-Content/raft-large-words.txt"
do
    [ -f "$wl" ] && cat "$wl" >> "$PARAMS_WL" && info "  Added: $(basename $wl)"
done
wget -q "https://wordlists-cdn.assetnote.io/data/automated/httparchive_parameters_2024.01.28.txt" \
     -O /tmp/params_assetnote.txt 2>/dev/null \
&& cat /tmp/params_assetnote.txt >> "$PARAMS_WL" || true
sort -u "$PARAMS_WL" -o "$PARAMS_WL"
success "Parameter wordlist: $(wc -l < "$PARAMS_WL") entries"

# ── Backup/sensitive files ─────────────────────────────────────────────────────
info "Downloading backup/sensitive files wordlist..."
BACKUP_WL="wordlists/backup_files.txt"
for wl in \
    "$SECLISTS/Discovery/Web-Content/raft-large-files.txt" \
    "$SECLISTS/Fuzzing/LFI/LFI-Jhaddix.txt"
do
    [ -f "$wl" ] && cat "$wl" >> "$BACKUP_WL" && info "  Added: $(basename $wl)"
done
sort -u "$BACKUP_WL" -o "$BACKUP_WL" 2>/dev/null
success "Backup files wordlist created"

# ── LFI payloads ──────────────────────────────────────────────────────────────
LFI_WL="wordlists/lfi_payloads.txt"
for wl in \
    "$SECLISTS/Fuzzing/LFI/LFI-Jhaddix.txt" \
    "$SECLISTS/Fuzzing/LFI/LFI-LFISuite-pathtotest.txt" \
    "$SECLISTS/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt" \
    "$SECLISTS/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt"
do
    [ -f "$wl" ] && cat "$wl" >> "$LFI_WL"
done
sort -u "$LFI_WL" -o "$LFI_WL" 2>/dev/null
success "LFI payloads: $(wc -l < "$LFI_WL" 2>/dev/null) entries"

# ── XSS payloads ──────────────────────────────────────────────────────────────
XSS_WL="wordlists/xss_payloads.txt"
for wl in \
    "$SECLISTS/Fuzzing/XSS/XSS-Jhaddix.txt" \
    "$SECLISTS/Fuzzing/XSS/XSS-BruteLogic.txt" \
    "$SECLISTS/Fuzzing/XSS/XSS-somdev.txt"
do
    [ -f "$wl" ] && cat "$wl" >> "$XSS_WL"
done
sort -u "$XSS_WL" -o "$XSS_WL" 2>/dev/null
success "XSS payloads: $(wc -l < "$XSS_WL" 2>/dev/null) entries"

# ── SQLi payloads ─────────────────────────────────────────────────────────────
SQLI_WL="wordlists/sqli_payloads.txt"
for wl in \
    "$SECLISTS/Fuzzing/SQLi/Generic-SQLi.txt" \
    "$SECLISTS/Fuzzing/SQLi/quick-SQLi.txt" \
    "$SECLISTS/Fuzzing/SQLi/Generic-BlindSQLi.fuzzdb.txt"
do
    [ -f "$wl" ] && cat "$wl" >> "$SQLI_WL"
done
sort -u "$SQLI_WL" -o "$SQLI_WL" 2>/dev/null
success "SQLi payloads: $(wc -l < "$SQLI_WL" 2>/dev/null) entries"

# ── User/pass wordlists ────────────────────────────────────────────────────────
CREDS_WL="wordlists/usernames.txt"
PASS_WL="wordlists/passwords.txt"
for wl in "$SECLISTS/Usernames/top-usernames-shortlist.txt" \
           "$SECLISTS/Usernames/Names/names.txt"; do
    [ -f "$wl" ] && cat "$wl" >> "$CREDS_WL"
done
for wl in "$SECLISTS/Passwords/xato-net-10-million-passwords-100000.txt" \
           "$SECLISTS/Passwords/Common-Credentials/10k-most-common.txt"; do
    [ -f "$wl" ] && cat "$wl" >> "$PASS_WL"
done
sort -u "$CREDS_WL" -o "$CREDS_WL" 2>/dev/null || true
sort -u "$PASS_WL" -o "$PASS_WL" 2>/dev/null || true
success "Creds wordlists created"

# ── DNS resolvers ─────────────────────────────────────────────────────────────
RESOLVERS="wordlists/resolvers.txt"
wget -q "https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt" \
     -O "$RESOLVERS" 2>/dev/null \
&& success "DNS resolvers: $(wc -l < "$RESOLVERS") entries" \
|| warn "Resolver list failed — using defaults"

# ─────────────────────────────────────────────────────────────────────────────
header "MassDNS Resolvers & Wordlists"
# ─────────────────────────────────────────────────────────────────────────────
wget -q "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" \
     -O wordlists/resolvers_trickest.txt 2>/dev/null && success "Trickest resolvers downloaded" || true

# ─────────────────────────────────────────────────────────────────────────────
header "PATH Configuration"
# ─────────────────────────────────────────────────────────────────────────────
GOBIN_EXPORT='export PATH=$PATH:$HOME/go/bin:/usr/local/go/bin:$HOME/.local/bin'
for rc in ~/.bashrc ~/.zshrc; do
    if ! grep -q "go/bin" "$rc" 2>/dev/null; then
        echo "$GOBIN_EXPORT" >> "$rc" 2>/dev/null || true
    fi
done

# ─────────────────────────────────────────────────────────────────────────────
header "Final Verification"
# ─────────────────────────────────────────────────────────────────────────────
echo ""
info "Checking all tools:"
ALL_TOOLS=(
    "subfinder" "amass" "assetfinder" "findomain" "chaos"
    "puredns" "shuffledns" "dnsx" "massdns" "dnsrecon"
    "httpx" "httprobe" "gowitness" "aquatone"
    "nmap" "masscan" "naabu" "rustscan"
    "katana" "gospider" "hakrawler" "gau" "waybackurls" "meg" "gf"
    "trufflehog" "gitleaks"
    "nuclei" "dalfox" "crlfuzz" "ffuf" "gobuster" "feroxbuster"
    "commix" "sqlmap" "nikto" "wafw00f"
    "nomore403" "git-dumper" "smuggler" "ssrfmap"
    "jwt_tool" "graphw00f" "xsstrike" "wfuzz"
    "interactsh-client" "tlsx" "cloudbrute"
    "dirsearch" "paramspider" "arjun" "linkfinder" "secretfinder"
    "wpscan" "eyewitness" "photon"
)

TOTAL_FOUND=0
TOTAL_MISSING=0
for tool in "${ALL_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} $tool"
        TOTAL_FOUND=$((TOTAL_FOUND+1))
    else
        echo -e "  ${RED}✗${NC} $tool"
        TOTAL_MISSING=$((TOTAL_MISSING+1))
    fi
done

echo ""
echo -e "  ${CYAN}Wordlists:${NC}"
for wl in wordlists/subdomains.txt wordlists/directories.txt wordlists/parameters.txt \
           wordlists/api_paths.txt wordlists/lfi_payloads.txt wordlists/xss_payloads.txt \
           wordlists/sqli_payloads.txt wordlists/resolvers.txt; do
    if [ -f "$wl" ]; then
        echo -e "  ${GREEN}✓${NC} $wl ($(wc -l < "$wl" | tr -d ' ') lines)"
    else
        echo -e "  ${YELLOW}?${NC} $wl — not found"
    fi
done

echo ""
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo -e "${GREEN}  Tools found:   $TOTAL_FOUND / ${#ALL_TOOLS[@]}${NC}"
echo -e "${YELLOW}  Tools missing: $TOTAL_MISSING${NC}"
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo ""
success "DOMINION installation complete!"
echo ""
echo -e "  ${CYAN}Next steps:${NC}"
echo -e "  1. source .venv/bin/activate"
echo -e "  2. cp config.example.yml config.yml && nano config.yml  (add API keys)"
echo -e "  3. python dominion.py -d example.com"
echo ""
