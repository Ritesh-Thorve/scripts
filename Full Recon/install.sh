#!/usr/bin/env bash
# =============================================================================
#  install.sh — Automated tool installer for recon.sh
#  Supports: Kali Linux, Ubuntu 20.04+, Debian 11+
#  Usage   : sudo ./install.sh
# =============================================================================

set -euo pipefail

# ──────────────────────────────────────────────────────────────────────────────
#  COLOURS
# ──────────────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; WHITE='\033[1;37m'; DIM='\033[2m'; NC='\033[0m'
BOLD='\033[1m'

# ──────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ──────────────────────────────────────────────────────────────────────────────
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[-]${NC} $*"; }
section() { echo -e "\n${CYAN}══ $* ══${NC}"; }
ok()      { echo -e "${GREEN}[✓]${NC} $*"; }
skip()    { echo -e "${DIM}[~] Already installed: $*${NC}"; }

tool_exists() { command -v "$1" &>/dev/null; }

# ──────────────────────────────────────────────────────────────────────────────
#  CHECKS
# ──────────────────────────────────────────────────────────────────────────────
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Please run as root: sudo ./install.sh"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        OS_NAME="${ID:-unknown}"
        OS_VERSION="${VERSION_ID:-0}"
        info "Detected OS: ${PRETTY_NAME:-$OS_NAME $OS_VERSION}"
    else
        warn "Cannot detect OS — assuming Debian/Ubuntu compatible"
        OS_NAME="ubuntu"
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
#  SYSTEM PACKAGES
# ──────────────────────────────────────────────────────────────────────────────
install_apt_packages() {
    section "System Packages"
    info "Updating package list..."
    apt-get update -qq

    local packages=(
        git curl wget unzip tar
        python3 python3-pip python3-venv
        build-essential libpcap-dev
        nmap masscan dnsutils whois
        chromium-browser    # for gowitness
        jq
        ruby ruby-dev       # for whatweb
        libssl-dev
        net-tools
    )

    for pkg in "${packages[@]}"; do
        if dpkg -s "$pkg" &>/dev/null 2>&1; then
            skip "$pkg"
        else
            info "Installing $pkg..."
            apt-get install -y -qq "$pkg" 2>/dev/null || \
                warn "Failed to install $pkg — skipping"
        fi
    done
    ok "System packages done"
}

# ──────────────────────────────────────────────────────────────────────────────
#  GO LANGUAGE
# ──────────────────────────────────────────────────────────────────────────────
install_go() {
    section "Go Language"
    if tool_exists go; then
        local ver; ver="$(go version | awk '{print $3}')"
        skip "Go already installed ($ver)"
        return
    fi

    local GO_VERSION="1.22.3"
    local GO_ARCH="linux-amd64"
    local GO_TAR="go${GO_VERSION}.${GO_ARCH}.tar.gz"

    info "Installing Go ${GO_VERSION}..."
    wget -q "https://go.dev/dl/${GO_TAR}" -O "/tmp/${GO_TAR}"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "/tmp/${GO_TAR}"
    rm "/tmp/${GO_TAR}"

    # Add to PATH for root and all future shells
    if ! grep -q "/usr/local/go/bin" /etc/profile.d/go.sh 2>/dev/null; then
        cat >> /etc/profile.d/go.sh << 'EOF'
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
EOF
    fi
    export PATH="$PATH:/usr/local/go/bin"
    export GOPATH="$HOME/go"
    export PATH="$PATH:$GOPATH/bin"

    ok "Go installed: $(go version)"
}

# ──────────────────────────────────────────────────────────────────────────────
#  GO TOOLS INSTALLER
# ──────────────────────────────────────────────────────────────────────────────
install_go_tool() {
    local name="$1"
    local pkg="$2"
    if tool_exists "$name"; then
        skip "$name"
        return
    fi
    info "Installing $name..."
    # Ensure GOPATH/bin is in PATH
    export GOPATH="${GOPATH:-$HOME/go}"
    export PATH="$PATH:/usr/local/go/bin:$GOPATH/bin"

    GOFLAGS="-mod=mod" go install "$pkg" 2>/dev/null && \
        ok "$name installed" || \
        warn "Failed to install $name — check your internet connection"
}

install_go_tools() {
    section "Go-based Recon Tools"
    export GOPATH="${HOME}/go"
    export PATH="$PATH:/usr/local/go/bin:${GOPATH}/bin"
    mkdir -p "$GOPATH"

    install_go_tool "subfinder"    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    install_go_tool "dnsx"         "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    install_go_tool "httpx"        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    install_go_tool "nuclei"       "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    install_go_tool "katana"       "github.com/projectdiscovery/katana/cmd/katana@latest"
    install_go_tool "naabu"        "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    install_go_tool "chaos"        "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
    install_go_tool "notify"       "github.com/projectdiscovery/notify/cmd/notify@latest"
    install_go_tool "anew"         "github.com/tomnomnom/anew@latest"
    install_go_tool "assetfinder"  "github.com/tomnomnom/assetfinder@latest"
    install_go_tool "waybackurls"  "github.com/tomnomnom/waybackurls@latest"
    install_go_tool "gau"          "github.com/lc/gau/v2/cmd/gau@latest"
    install_go_tool "hakrawler"    "github.com/hakluke/hakrawler@latest"
    install_go_tool "gowitness"    "github.com/sensepost/gowitness@latest"
    install_go_tool "amass"        "github.com/owasp-amass/amass/v4/...@master"
    install_go_tool "ffuf"         "github.com/ffuf/ffuf/v2@latest"
    install_go_tool "dnsgen"       "github.com/svrs/dnsgen@latest"

    # Copy binaries to /usr/local/bin for system-wide access
    cp "${GOPATH}/bin/"* /usr/local/bin/ 2>/dev/null || true
    ok "Go tools installed"
}

# ──────────────────────────────────────────────────────────────────────────────
#  FINDOMAIN (binary release)
# ──────────────────────────────────────────────────────────────────────────────
install_findomain() {
    section "findomain"
    if tool_exists findomain; then skip "findomain"; return; fi

    info "Installing findomain..."
    wget -q "https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux" \
        -O /usr/local/bin/findomain 2>/dev/null && \
        chmod +x /usr/local/bin/findomain && \
        ok "findomain installed" || \
        warn "findomain install failed"
}

# ──────────────────────────────────────────────────────────────────────────────
#  PYTHON TOOLS
# ──────────────────────────────────────────────────────────────────────────────
install_python_tools() {
    section "Python Tools"

    # paramspider
    if ! tool_exists paramspider; then
        info "Installing paramspider..."
        pip3 install paramspider 2>/dev/null && ok "paramspider" || \
            warn "paramspider install failed"
    else skip "paramspider"; fi

    # arjun
    if ! tool_exists arjun; then
        info "Installing arjun..."
        pip3 install arjun 2>/dev/null && ok "arjun" || warn "arjun install failed"
    else skip "arjun"; fi

    # wafw00f
    if ! tool_exists wafw00f; then
        info "Installing wafw00f..."
        pip3 install wafw00f 2>/dev/null && ok "wafw00f" || warn "wafw00f install failed"
    else skip "wafw00f"; fi

    # theHarvester
    if ! tool_exists theHarvester 2>/dev/null; then
        info "Installing theHarvester..."
        pip3 install theHarvester 2>/dev/null && ok "theHarvester" || \
            warn "theHarvester install failed"
    else skip "theHarvester"; fi
}

# ──────────────────────────────────────────────────────────────────────────────
#  WHATWEB (Ruby gem)
# ──────────────────────────────────────────────────────────────────────────────
install_whatweb() {
    section "WhatWeb"
    if tool_exists whatweb; then skip "whatweb"; return; fi

    if tool_exists gem; then
        info "Installing WhatWeb..."
        gem install whatweb 2>/dev/null && ok "whatweb" || warn "whatweb install failed"
    else
        warn "Ruby gem not found — skipping WhatWeb"
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
#  NUCLEI TEMPLATES
# ──────────────────────────────────────────────────────────────────────────────
install_nuclei_templates() {
    section "Nuclei Templates"
    if tool_exists nuclei; then
        info "Downloading/updating nuclei templates..."
        nuclei -update-templates -silent 2>/dev/null && ok "Nuclei templates updated" || \
            warn "Could not update templates — run manually: nuclei -update-templates"
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
#  WORDLISTS
# ──────────────────────────────────────────────────────────────────────────────
install_wordlists() {
    section "Wordlists"

    # dirb wordlists
    if [[ ! -f /usr/share/wordlists/dirb/common.txt ]]; then
        apt-get install -y -qq wordlists 2>/dev/null || \
        apt-get install -y -qq dirb 2>/dev/null || \
        info "Could not install dirb wordlists via apt — trying manual download..."

        mkdir -p /usr/share/wordlists/dirb
        wget -q "https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt" \
            -O /usr/share/wordlists/dirb/common.txt 2>/dev/null || \
            warn "Could not download common.txt"
    else
        skip "dirb wordlists already present"
    fi

    # SecLists (subset — only if not already present)
    if [[ ! -d /usr/share/seclists ]]; then
        if [[ -f /usr/bin/apt ]]; then
            apt-get install -y -qq seclists 2>/dev/null && \
                ok "SecLists installed" || warn "SecLists not available via apt"
        fi
    else
        skip "SecLists"
    fi

    ok "Wordlists ready"
}

# ──────────────────────────────────────────────────────────────────────────────
#  RESOLVER LIST FOR DNSX
# ──────────────────────────────────────────────────────────────────────────────
install_resolvers() {
    section "DNS Resolvers"
    local SCRIPT_DIR; SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local resolvers_file="${SCRIPT_DIR}/resolvers.txt"

    if [[ -s "$resolvers_file" ]]; then
        skip "resolvers.txt already exists"
        return
    fi

    info "Downloading public resolver list..."
    wget -q "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" \
        -O "$resolvers_file" 2>/dev/null && \
        ok "$(wc -l < "$resolvers_file") resolvers downloaded" || {
        # Fallback minimal list
        cat > "$resolvers_file" << 'EOF'
1.1.1.1
8.8.8.8
8.8.4.4
9.9.9.9
1.0.0.1
208.67.222.222
208.67.220.220
94.140.14.14
94.140.15.15
EOF
        warn "Using fallback resolver list (8 resolvers)"
    }
}

# ──────────────────────────────────────────────────────────────────────────────
#  CREATE DEFAULT CONFIG FILE
# ──────────────────────────────────────────────────────────────────────────────
create_config() {
    section "Configuration"
    local SCRIPT_DIR; SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local conf="${SCRIPT_DIR}/recon.conf"

    if [[ -f "$conf" ]]; then
        skip "recon.conf already exists"
        return
    fi

    cat > "$conf" << 'EOF'
# =============================================================================
# recon.conf — Configuration file for recon.sh
# Set values here instead of passing flags every run.
# =============================================================================

# ── API Keys ──────────────────────────────────────────────────────────────────
# Get your Chaos key at: https://cloud.projectdiscovery.io
# CHAOS_KEY=""

# Shodan API key (https://account.shodan.io)
# SHODAN_KEY=""

# Censys API (https://search.censys.io/account/api)
# CENSYS_ID=""
# CENSYS_SECRET=""

# SecurityTrails API (https://securitytrails.com/app/account/credentials)
# ST_API_KEY=""

# ── Default Settings ──────────────────────────────────────────────────────────
THREADS=10
RATE_LIMIT=150
TIMEOUT=10
MODE="normal"

# Proxy (uncomment to route through Burp Suite)
# PROXY="http://127.0.0.1:8080"

# Wordlist for content discovery
WORDLIST="/usr/share/wordlists/dirb/common.txt"

# DNS bruteforce wordlist
DNS_WORDLIST="/usr/share/wordlists/dnsmap.txt"

# Nuclei severity filter: info,low,medium,high,critical
NUCLEI_SEVERITY="medium,high,critical"

# Enable port scanning by default (true/false)
PORT_SCAN=false

# Send notifications via notify (true/false)
NOTIFY_ENABLED=false
EOF
    ok "Created recon.conf — edit it to add your API keys"
}

# ──────────────────────────────────────────────────────────────────────────────
#  PATH SETUP
# ──────────────────────────────────────────────────────────────────────────────
setup_path() {
    local gopath_line='export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin'
    local bashrc="$HOME/.bashrc"
    local zshrc="$HOME/.zshrc"

    for rc in "$bashrc" "$zshrc"; do
        [[ -f "$rc" ]] && grep -q "go/bin" "$rc" 2>/dev/null || \
            echo "$gopath_line" >> "$rc"
    done

    export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"
}

# ──────────────────────────────────────────────────────────────────────────────
#  CHMOD recon.sh
# ──────────────────────────────────────────────────────────────────────────────
make_executable() {
    local SCRIPT_DIR; SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    chmod +x "${SCRIPT_DIR}/recon.sh" 2>/dev/null || true
    ok "recon.sh marked executable"
}

# ──────────────────────────────────────────────────────────────────────────────
#  FINAL SUMMARY
# ──────────────────────────────────────────────────────────────────────────────
print_summary() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}      ${BOLD}INSTALLATION SUMMARY${NC}                          ${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"

    local tools=(
        subfinder dnsx httpx nuclei katana naabu chaos notify
        anew assetfinder waybackurls gau hakrawler gowitness
        amass ffuf findomain whatweb wafw00f arjun paramspider
    )

    for t in "${tools[@]}"; do
        if tool_exists "$t"; then
            echo -e "${CYAN}║${NC}  ${GREEN}✓${NC}  $t"
        else
            echo -e "${CYAN}║${NC}  ${RED}✗${NC}  $t ${DIM}(not installed)${NC}"
        fi
    done

    echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}Next steps:${NC}"
    echo -e "${CYAN}║${NC}  1. Edit ${BOLD}recon.conf${NC} and add your API keys"
    echo -e "${CYAN}║${NC}  2. Run: ${BOLD}source ~/.bashrc${NC}"
    echo -e "${CYAN}║${NC}  3. Run: ${BOLD}./recon.sh target.com${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ──────────────────────────────────────────────────────────────────────────────
#  MAIN
# ──────────────────────────────────────────────────────────────────────────────
main() {
    echo -e "${CYAN}"
    echo "  ╦╔╗╔╔═╗╔╦╗╔═╗╦  ╦  ╔═╗╦═╗"
    echo "  ║║║║╚═╗ ║ ╠═╣║  ║  ║╣ ╠╦╝"
    echo "  ╩╝╚╝╚═╝ ╩ ╩ ╩╩═╝╩═╝╚═╝╩╚═"
    echo -e "${NC}  Recon Toolkit Installer\n"

    check_root
    detect_os
    install_apt_packages
    install_go
    setup_path
    install_go_tools
    install_findomain
    install_python_tools
    install_whatweb
    install_nuclei_templates
    install_wordlists
    install_resolvers
    create_config
    make_executable
    print_summary
}

main "$@"