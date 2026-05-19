#!/usr/bin/env bash
# =============================================================================
#  recon.sh — Automated Bug Bounty Reconnaissance Toolkit
#  Author  : recon-toolkit
#  Version : 2.0.0
#  Usage   : ./recon.sh [options] <target.com>
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# ──────────────────────────────────────────────────────────────────────────────
#  CONSTANTS & DEFAULTS
# ──────────────────────────────────────────────────────────────────────────────
VERSION="2.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/recon.conf"

# Colour codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m' # No Colour

# ──────────────────────────────────────────────────────────────────────────────
#  DEFAULT CONFIG (overridden by recon.conf or CLI flags)
# ──────────────────────────────────────────────────────────────────────────────
TARGET=""
MODE="normal"          # fast | normal | deep
THREADS=10
RATE_LIMIT=150         # requests per second for httpx/nuclei
TIMEOUT=10             # seconds per request
PROXY=""               # e.g. http://127.0.0.1:8080
PORT_SCAN=false
NOTIFY_ENABLED=false
RESUME=false
WORDLIST="/usr/share/wordlists/dirb/common.txt"
DNS_WORDLIST="/usr/share/wordlists/dnsmap.txt"
RESOLVERS_FILE="${SCRIPT_DIR}/resolvers.txt"
OUTPUT_BASE=""         # set after target is known
SKIP_NUCLEI=false
NUCLEI_SEVERITY="medium,high,critical"

# API keys (set in recon.conf or environment)
CHAOS_KEY="${CHAOS_KEY:-}"
SHODAN_KEY="${SHODAN_KEY:-}"
CENSYS_ID="${CENSYS_ID:-}"
CENSYS_SECRET="${CENSYS_SECRET:-}"
ST_API_KEY="${ST_API_KEY:-}"       # SecurityTrails

# ──────────────────────────────────────────────────────────────────────────────
#  LOAD CONFIG FILE (if present)
# ──────────────────────────────────────────────────────────────────────────────
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$CONFIG_FILE"
        log_debug "Loaded config from $CONFIG_FILE"
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
#  LOGGING HELPERS
# ──────────────────────────────────────────────────────────────────────────────
LOG_FILE=""  # set after OUTPUT_BASE is known

log_raw()   { echo -e "$*"; }
log_info()  { echo -e "${GREEN}[INFO]${NC}  $*" | tee -a "$LOG_FILE" 2>/dev/null || echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*" | tee -a "$LOG_FILE" 2>/dev/null || echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" | tee -a "$LOG_FILE" 2>/dev/null || echo -e "${RED}[ERROR]${NC} $*"; }
log_step()  { echo -e "${CYAN}[STEP]${NC}  ${BOLD}$*${NC}" | tee -a "$LOG_FILE" 2>/dev/null || echo -e "${CYAN}[STEP]${NC}  ${BOLD}$*${NC}"; }
log_debug() { [[ "${DEBUG:-false}" == "true" ]] && echo -e "${DIM}[DEBUG] $*${NC}"; }
log_ok()    { echo -e "${GREEN}[✓]${NC}    $*" | tee -a "$LOG_FILE" 2>/dev/null || echo -e "${GREEN}[✓]${NC}    $*"; }
log_skip()  { echo -e "${DIM}[SKIP]  $*${NC}"; }

# Print the big banner
banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗   ███████╗██╗  ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║   ██╔════╝██║  ██║
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║   ███████╗███████║
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║   ╚════██║██╔══██║
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╗███████║██║  ██║
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚══════╝╚═╝  ╚═╝
EOF
    echo -e "${NC}${WHITE}  Bug Bounty & Pentest Reconnaissance Toolkit  v${VERSION}${NC}"
    echo -e "${DIM}  ─────────────────────────────────────────────────────${NC}"
    echo ""
}

# ──────────────────────────────────────────────────────────────────────────────
#  USAGE
# ──────────────────────────────────────────────────────────────────────────────
usage() {
    cat << EOF
${BOLD}USAGE${NC}
  ./recon.sh [OPTIONS] <target.com>

${BOLD}MODES${NC}
  --fast          Quick scan (passive subs + live probing + basic nuclei)
  --deep          Full scan (all phases, bruteforcing, port scan, deep crawl)
  (default)       Normal scan (most phases, no bruteforcing or port scan)

${BOLD}OPTIONS${NC}
  -t, --threads   N       Parallel threads           (default: 10)
  -r, --rate      N       Requests per second        (default: 150)
  -T, --timeout   N       Seconds per request        (default: 10)
  -p, --proxy     URL     HTTP/SOCKS proxy           (e.g. http://127.0.0.1:8080)
  -w, --wordlist  FILE    Content discovery wordlist
  --ports                 Enable port scanning       (requires naabu/nmap)
  --no-nuclei             Skip nuclei scanning
  --severity      S       Nuclei severity filter     (default: medium,high,critical)
  --resume                Resume previous scan
  --notify                Send findings via notify
  --config        FILE    Config file path
  -h, --help              Show this help

${BOLD}EXAMPLES${NC}
  ./recon.sh example.com
  ./recon.sh --fast example.com
  ./recon.sh --deep --ports --proxy http://127.0.0.1:8080 example.com
  ./recon.sh --resume example.com

${BOLD}API KEYS${NC}
  Set in recon.conf or as environment variables:
  CHAOS_KEY, SHODAN_KEY, CENSYS_ID, CENSYS_SECRET, ST_API_KEY
EOF
}

# ──────────────────────────────────────────────────────────────────────────────
#  ARGUMENT PARSING
# ──────────────────────────────────────────────────────────────────────────────
parse_args() {
    [[ $# -eq 0 ]] && { usage; exit 1; }

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --fast)           MODE="fast"           ;;
            --deep)           MODE="deep"           ;;
            -t|--threads)     THREADS="$2";   shift ;;
            -r|--rate)        RATE_LIMIT="$2"; shift;;
            -T|--timeout)     TIMEOUT="$2";   shift ;;
            -p|--proxy)       PROXY="$2";     shift ;;
            -w|--wordlist)    WORDLIST="$2";  shift ;;
            --ports)          PORT_SCAN=true         ;;
            --no-nuclei)      SKIP_NUCLEI=true       ;;
            --severity)       NUCLEI_SEVERITY="$2"; shift ;;
            --resume)         RESUME=true            ;;
            --notify)         NOTIFY_ENABLED=true    ;;
            --config)         CONFIG_FILE="$2"; shift;;
            -h|--help)        usage; exit 0          ;;
            -*)               log_error "Unknown flag: $1"; usage; exit 1 ;;
            *)                TARGET="$1"            ;;
        esac
        shift
    done

    [[ -z "$TARGET" ]] && { log_error "No target specified."; usage; exit 1; }

    # Sanitise target (strip http/https/trailing slash)
    TARGET="${TARGET#http://}"
    TARGET="${TARGET#https://}"
    TARGET="${TARGET%%/*}"
}

# ──────────────────────────────────────────────────────────────────────────────
#  DIRECTORY SETUP
# ──────────────────────────────────────────────────────────────────────────────
setup_dirs() {
    OUTPUT_BASE="${SCRIPT_DIR}/recon/${TARGET}"
    LOG_FILE="${OUTPUT_BASE}/logs/recon_$(date +%Y%m%d_%H%M%S).log"

    local dirs=(
        "${OUTPUT_BASE}/subs"
        "${OUTPUT_BASE}/dns"
        "${OUTPUT_BASE}/live"
        "${OUTPUT_BASE}/urls"
        "${OUTPUT_BASE}/js"
        "${OUTPUT_BASE}/params"
        "${OUTPUT_BASE}/scans"
        "${OUTPUT_BASE}/screenshots"
        "${OUTPUT_BASE}/secrets"
        "${OUTPUT_BASE}/logs"
        "${OUTPUT_BASE}/reports"
    )

    for d in "${dirs[@]}"; do
        mkdir -p "$d"
    done

    log_debug "Output directory: $OUTPUT_BASE"
}

# ──────────────────────────────────────────────────────────────────────────────
#  TOOL EXISTENCE CHECK
# ──────────────────────────────────────────────────────────────────────────────
# Returns 0 if tool exists, 1 if not
tool_exists() {
    command -v "$1" &>/dev/null
}

# Print a summary of available vs missing tools
check_tools() {
    log_step "Checking installed tools..."

    local required=(curl jq sort uniq)
    local optional=(
        subfinder amass assetfinder findomain chaos
        dnsx httpx
        katana gau waybackurls hakrawler
        ffuf nuclei
        gowitness naabu
        anew notify whatweb wafw00f
    )

    local missing_required=()
    local missing_optional=()

    for t in "${required[@]}"; do
        tool_exists "$t" || missing_required+=("$t")
    done

    if [[ ${#missing_required[@]} -gt 0 ]]; then
        log_error "Required tools missing: ${missing_required[*]}"
        log_error "Run: ./install.sh"
        exit 1
    fi

    for t in "${optional[@]}"; do
        if tool_exists "$t"; then
            log_ok "  $t"
        else
            log_warn "  $t (not found — phase will be skipped)"
            missing_optional+=("$t")
        fi
    done

    [[ ${#missing_optional[@]} -gt 0 ]] && \
        log_warn "Install missing tools: ./install.sh"

    echo ""
}

# ──────────────────────────────────────────────────────────────────────────────
#  RESUME CHECK
# ──────────────────────────────────────────────────────────────────────────────
# Reads/writes a checkpoint file so phases are not re-run on resume
CHECKPOINT_FILE=""
mark_done()   { echo "$1" >> "$CHECKPOINT_FILE"; }
is_done()     { grep -qx "$1" "$CHECKPOINT_FILE" 2>/dev/null; }
should_run()  {
    local phase="$1"
    if $RESUME && is_done "$phase"; then
        log_skip "Phase already done: $phase (use --resume to skip)"
        return 1
    fi
    return 0
}

setup_checkpoint() {
    CHECKPOINT_FILE="${OUTPUT_BASE}/logs/.checkpoint"
    if ! $RESUME; then
        > "$CHECKPOINT_FILE"   # reset on fresh run
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
#  PROXY / USER-AGENT HELPERS
# ──────────────────────────────────────────────────────────────────────────────
# Build common httpx/curl proxy flag
proxy_flag_httpx() { [[ -n "$PROXY" ]] && echo "-http-proxy $PROXY" || echo ""; }
proxy_flag_curl()  { [[ -n "$PROXY" ]] && echo "-x $PROXY"          || echo ""; }

# Pick a random user-agent string
random_ua() {
    local agents=(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15"
        "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0"
    )
    echo "${agents[$((RANDOM % ${#agents[@]}))]}"
}

# ──────────────────────────────────────────────────────────────────────────────
#  PHASE 1 — PASSIVE SUBDOMAIN ENUMERATION
# ──────────────────────────────────────────────────────────────────────────────
phase_passive_subs() {
    should_run "passive_subs" || return 0
    log_step "Phase 1 — Passive Subdomain Enumeration"

    local subs_dir="${OUTPUT_BASE}/subs"
    local ua; ua="$(random_ua)"

    # ── subfinder ──────────────────────────────────────────────────────────
    if tool_exists subfinder; then
        log_info "Running subfinder..."
        local key_flag=""
        [[ -n "$CHAOS_KEY" ]] && key_flag="-provider-config ${SCRIPT_DIR}/provider-config.yaml"
        subfinder -d "$TARGET" -all -silent $key_flag \
            -o "${subs_dir}/subfinder.txt" 2>/dev/null || true
        log_ok "subfinder done: $(wc -l < "${subs_dir}/subfinder.txt" 2>/dev/null || echo 0) results"
    fi

    # ── amass passive ──────────────────────────────────────────────────────
    if tool_exists amass && [[ "$MODE" != "fast" ]]; then
        log_info "Running amass passive (this can take a while)..."
        amass enum -passive -d "$TARGET" \
            -o "${subs_dir}/amass.txt" 2>/dev/null || true
        log_ok "amass done: $(wc -l < "${subs_dir}/amass.txt" 2>/dev/null || echo 0) results"
    fi

    # ── assetfinder ───────────────────────────────────────────────────────
    if tool_exists assetfinder; then
        log_info "Running assetfinder..."
        assetfinder --subs-only "$TARGET" \
            > "${subs_dir}/assetfinder.txt" 2>/dev/null || true
        log_ok "assetfinder done: $(wc -l < "${subs_dir}/assetfinder.txt" 2>/dev/null || echo 0) results"
    fi

    # ── findomain ─────────────────────────────────────────────────────────
    if tool_exists findomain; then
        log_info "Running findomain..."
        findomain -t "$TARGET" -u "${subs_dir}/findomain.txt" 2>/dev/null || true
        log_ok "findomain done: $(wc -l < "${subs_dir}/findomain.txt" 2>/dev/null || echo 0) results"
    fi

    # ── chaos ─────────────────────────────────────────────────────────────
    if tool_exists chaos && [[ -n "$CHAOS_KEY" ]]; then
        log_info "Running chaos..."
        PDCP_API_KEY="$CHAOS_KEY" chaos -d "$TARGET" -silent \
            -o "${subs_dir}/chaos.txt" 2>/dev/null || true
        log_ok "chaos done: $(wc -l < "${subs_dir}/chaos.txt" 2>/dev/null || echo 0) results"
    fi

    # ── crt.sh (CT logs via API — no tool required) ───────────────────────
    log_info "Querying crt.sh..."
    curl -s $(proxy_flag_curl) \
        -A "$ua" \
        "https://crt.sh/?q=%25.${TARGET}&output=json" \
        --max-time 30 2>/dev/null \
        | jq -r '.[].name_value' 2>/dev/null \
        | sed 's/\*\.//g' \
        | grep -E "\.${TARGET//./\\.}$" \
        | sort -u > "${subs_dir}/crtsh.txt" || true
    log_ok "crt.sh done: $(wc -l < "${subs_dir}/crtsh.txt" 2>/dev/null || echo 0) results"

    # ── SecurityTrails API ────────────────────────────────────────────────
    if [[ -n "$ST_API_KEY" ]]; then
        log_info "Querying SecurityTrails..."
        curl -s $(proxy_flag_curl) \
            -H "APIKEY: ${ST_API_KEY}" \
            "https://api.securitytrails.com/v1/domain/${TARGET}/subdomains" \
            --max-time 30 2>/dev/null \
            | jq -r '.subdomains[]' 2>/dev/null \
            | sed "s/$/.${TARGET}/" \
            > "${subs_dir}/securitytrails.txt" || true
        log_ok "SecurityTrails done: $(wc -l < "${subs_dir}/securitytrails.txt" 2>/dev/null || echo 0) results"
    fi

    # ── Merge & deduplicate ───────────────────────────────────────────────
    log_info "Merging and deduplicating subdomains..."
    cat "${subs_dir}"/*.txt 2>/dev/null \
        | grep -E "\.${TARGET//./\\.}$" \
        | grep -v "^[[:space:]]*$" \
        | sort -u \
        > "${subs_dir}/all_subs.txt"

    local count; count="$(wc -l < "${subs_dir}/all_subs.txt")"
    log_ok "Total unique subdomains: ${BOLD}${count}${NC}"
    mark_done "passive_subs"
}

# ──────────────────────────────────────────────────────────────────────────────
#  PHASE 2 — ACTIVE DNS RESOLUTION
# ──────────────────────────────────────────────────────────────────────────────
phase_dns_resolution() {
    should_run "dns_resolution" || return 0
    log_step "Phase 2 — Active DNS Resolution"

    local subs_file="${OUTPUT_BASE}/subs/all_subs.txt"
    local dns_dir="${OUTPUT_BASE}/dns"

    if [[ ! -s "$subs_file" ]]; then
        log_warn "No subdomains found; skipping DNS resolution."
        return
    fi

    # ── dnsx — resolve and grab records ───────────────────────────────────
    if tool_exists dnsx; then
        log_info "Resolving with dnsx..."
        dnsx -l "$subs_file" \
            -a -aaaa -cname -mx -ns -txt \
            -resp -silent \
            -t "$THREADS" \
            -rl "$RATE_LIMIT" \
            -o "${dns_dir}/dns_records.txt" 2>/dev/null || true

        # Resolved hostnames only (for next phases)
        cat "${dns_dir}/dns_records.txt" 2>/dev/null \
            | awk '{print $1}' | sort -u \
            > "${dns_dir}/resolved.txt"

        log_ok "Resolved: $(wc -l < "${dns_dir}/resolved.txt" 2>/dev/null || echo 0) hosts"

        # Dangling CNAME check (subdomain takeover candidates)
        log_info "Checking for dangling CNAMEs..."
        dnsx -l "$subs_file" -cname -resp -silent 2>/dev/null \
            | grep -iv "$TARGET" \
            > "${dns_dir}/dangling_cnames.txt" || true

        local dcount; dcount="$(wc -l < "${dns_dir}/dangling_cnames.txt")"
        [[ "$dcount" -gt 0 ]] && \
            log_warn "Possible subdomain takeover candidates: ${dcount} (check ${dns_dir}/dangling_cnames.txt)"
    else
        log_warn "dnsx not found — using basic host resolution..."
        while IFS= read -r sub; do
            host "$sub" &>/dev/null && echo "$sub"
        done < "$subs_file" \
            | sort -u > "${dns_dir}/resolved.txt"
    fi

    # ── Deep mode: subdomain permutation ──────────────────────────────────
    if [[ "$MODE" == "deep" ]] && tool_exists dnsgen && tool_exists dnsx; then
        log_info "Generating subdomain permutations (deep mode)..."
        cat "${OUTPUT_BASE}/subs/all_subs.txt" \
            | dnsgen - 2>/dev/null \
            | dnsx -silent -t "$THREADS" \
            >> "${dns_dir}/resolved.txt" || true
        sort -u "${dns_dir}/resolved.txt" -o "${dns_dir}/resolved.txt"
        log_ok "After permutations: $(wc -l < "${dns_dir}/resolved.txt") resolved"
    fi

    mark_done "dns_resolution"
}

# ──────────────────────────────────────────────────────────────────────────────
#  PHASE 3 — LIVE HOST PROBING
# ──────────────────────────────────────────────────────────────────────────────
phase_live_hosts() {
    should_run "live_hosts" || return 0
    log_step "Phase 3 — Live Host Probing"

    local resolved="${OUTPUT_BASE}/dns/resolved.txt"
    local live_dir="${OUTPUT_BASE}/live"
    local ua; ua="$(random_ua)"

    # Fallback: use raw subs if DNS phase was skipped
    [[ ! -s "$resolved" ]] && resolved="${OUTPUT_BASE}/subs/all_subs.txt"

    if [[ ! -s "$resolved" ]]; then
        log_warn "No resolved hosts; skipping live probing."
        return
    fi

    if tool_exists httpx; then
        log_info "Probing live hosts with httpx..."
        local proxy_f; proxy_f="$(proxy_flag_httpx)"

        # Full JSON for later processing
        httpx -l "$resolved" \
            -silent \
            -status-code -title \
            -tech-detect \
            -follow-redirects \
            -content-length \
            -web-server \
            -cdn \
            -asn \
            -ip \
            -cname \
            -threads "$THREADS" \
            -rate-limit "$RATE_LIMIT" \
            -timeout "$TIMEOUT" \
            -H "User-Agent: $ua" \
            $proxy_f \
            -json \
            -o "${live_dir}/httpx_full.json" 2>/dev/null || true

        # Plain URL list for downstream tools
        jq -r '.url' "${live_dir}/httpx_full.json" 2>/dev/null \
            | sort -u > "${live_dir}/live_hosts.txt"

        # Separate by status code
        for code in 200 301 302 401 403 500; do
            jq -r "select(.status_code==${code}) | .url" \
                "${live_dir}/httpx_full.json" 2>/dev/null \
                | sort -u > "${live_dir}/status_${code}.txt"
        done

        local lcount; lcount="$(wc -l < "${live_dir}/live_hosts.txt")"
        log_ok "Live hosts found: ${BOLD}${lcount}${NC}"

        # Tech summary
        if [[ -s "${live_dir}/httpx_full.json" ]]; then
            log_info "Tech stack summary:"
            jq -r '.tech_detect[]?' "${live_dir}/httpx_full.json" 2>/dev/null \
                | sort | uniq -c | sort -rn | head -20 \
                >> "${OUTPUT_BASE}/logs/tech_summary.txt" || true
        fi
    else
        log_warn "httpx not found — falling back to curl-based probing (slow)..."
        while IFS= read -r host; do
            for scheme in https http; do
                local url="${scheme}://${host}"
                if curl -s -o /dev/null -w "%{http_code}" \
                    --max-time "$TIMEOUT" \
                    $(proxy_flag_curl) \
                    "$url" 2>/dev/null | grep -qE "^[23]"; then
                    echo "$url" >> "${live_dir}/live_hosts.txt"
                    break
                fi
            done
        done < "$resolved"
    fi

    mark_done "live_hosts"
}

# ──────────────────────────────────────────────────────────────────────────────
#  PHASE 4 — URL COLLECTION (Web Crawling)
# ──────────────────────────────────────────────────────────────────────────────
phase_url_collection() {
    should_run "url_collection" || return 0
    log_step "Phase 4 — URL Collection (Active Crawling)"

    local live_file="${OUTPUT_BASE}/live/live_hosts.txt"
    local urls_dir="${OUTPUT_BASE}/urls"
    local ua; ua="$(random_ua)"

    [[ ! -s "$live_file" ]] && { log_warn "No live hosts; skipping URL collection."; return; }

    # ── katana ────────────────────────────────────────────────────────────
    if tool_exists katana; then
        log_info "Crawling with katana..."
        local depth=3
        [[ "$MODE" == "fast" ]] && depth=2
        [[ "$MODE" == "deep" ]] && depth=5

        local proxy_flag=""
        [[ -n "$PROXY" ]] && proxy_flag="-proxy $PROXY"

        katana -list "$live_file" \
            -silent \
            -depth "$depth" \
            -concurrency "$THREADS" \
            -timeout "$TIMEOUT" \
            -H "User-Agent: $ua" \
            $proxy_flag \
            -o "${urls_dir}/katana.txt" 2>/dev/null || true
        log_ok "katana: $(wc -l < "${urls_dir}/katana.txt" 2>/dev/null || echo 0) URLs"
    fi

    # ── hakrawler ─────────────────────────────────────────────────────────
    if tool_exists hakrawler && [[ "$MODE" != "fast" ]]; then
        log_info "Crawling with hakrawler..."
        cat "$live_file" \
            | hakrawler \
                -t "$THREADS" \
                -timeout "$TIMEOUT" \
                -h "User-Agent: $ua" \
                2>/dev/null \
            > "${urls_dir}/hakrawler.txt" || true
        log_ok "hakrawler: $(wc -l < "${urls_dir}/hakrawler.txt" 2>/dev/null || echo 0) URLs"
    fi

    # ── Merge all active crawl results ────────────────────────────────────
    cat "${urls_dir}"/*.txt 2>/dev/null \
        | grep -E "^https?://" \
        | sort -u > "${urls_dir}/all_urls.txt"
    log_ok "Total unique crawled URLs: $(wc -l < "${urls_dir}/all_urls.txt" 2>/dev/null || echo 0)"

    mark_done "url_collection"
}

# ──────────────────────────────────────────────────────────────────────────────
#  PHASE 5 — HISTORICAL URL GATHERING
# ──────────────────────────────────────────────────────────────────────────────
phase_historical_urls() {
    should_run "historical_urls" || return 0
    log_step "Phase 5 — Historical URL Gathering (Wayback / GAU)"

    local urls_dir="${OUTPUT_BASE}/urls"

    # ── waybackurls ───────────────────────────────────────────────────────
    if tool_exists waybackurls; then
        log_info "Fetching from Wayback Machine..."
        echo "$TARGET" \
            | waybackurls 2>/dev/null \
            | sort -u > "${urls_dir}/wayback.txt" || true
        log_ok "waybackurls: $(wc -l < "${urls_dir}/wayback.txt" 2>/dev/null || echo 0) URLs"
    fi

    # ── gau (GetAllURLs) ──────────────────────────────────────────────────
    if tool_exists gau; then
        log_info "Fetching from GAU sources..."
        local gau_flags="--threads ${THREADS}"
        [[ -n "$PROXY" ]] && gau_flags+=" --proxy ${PROXY}"

        echo "$TARGET" \
            | gau $gau_flags 2>/dev/null \
            | sort -u > "${urls_dir}/gau.txt" || true
        log_ok "gau: $(wc -l < "${urls_dir}/gau.txt" 2>/dev/null || echo 0) URLs"
    fi

    # ── Combine historical + active ───────────────────────────────────────
    cat "${urls_dir}/wayback.txt" "${urls_dir}/gau.txt" \
        "${urls_dir}/all_urls.txt" 2>/dev/null \
        | grep -E "^https?://" \
        | sort -u > "${urls_dir}/all_urls_combined.txt"
    log_ok "Combined unique URLs: $(wc -l < "${urls_dir}/all_urls_combined.txt" 2>/dev/null || echo 0)"

    mark_done "historical_urls"
}

# ──────────────────────────────────────────────────────────────────────────────
#  PHASE 6 — JAVASCRIPT FILE EXTRACTION
# ──────────────────────────────────────────────────────────────────────────────
phase_js_extraction() {
    should_run "js_extraction" || return 0
    log_step "Phase 6 — JavaScript File Extraction"

    local urls_file="${OUTPUT_BASE}/urls/all_urls_combined.txt"
    local js_dir="${OUTPUT_BASE}/js"
    local ua; ua="$(random_ua)"

    [[ ! -s "$urls_file" ]] && { log_warn "No URLs; skipping JS extraction."; return; }

    # ── Extract JS URLs ───────────────────────────────────────────────────
    grep -iE "\.js(\?|$)" "$urls_file" \
        | sort -u > "${js_dir}/js_urls.txt"
    log_info "Found $(wc -l < "${js_dir}/js_urls.txt") JS URLs"

    # ── Download and analyse each JS file ────────────────────────────────
    local downloaded=0
    while IFS= read -r jsurl; do
        local fname; fname="${js_dir}/$(echo "$jsurl" | md5sum | cut -d' ' -f1).js"
        curl -s -L \
            --max-time "$TIMEOUT" \
            $(proxy_flag_curl) \
            -A "$ua" \
            "$jsurl" \
            -o "$fname" 2>/dev/null && ((downloaded++)) || true
    done < "${js_dir}/js_urls.txt"
    log_ok "Downloaded ${downloaded} JS files"

    # ── Secret patterns search in JS ──────────────────────────────────────
    log_info "Searching for secrets in JS files..."
    grep -rihE \
        "(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|client[_-]?secret|aws[_-]?access|aws[_-]?secret|private[_-]?key|bearer\s+[a-z0-9._\-]{10,}|['\"][a-z0-9]{32,}['\"])" \
        "${js_dir}"/*.js 2>/dev/null \
        | grep -v "//.*\(redacted\|example\|placeholder\)" \
        | sort -u > "${OUTPUT_BASE}/secrets/js_secrets.txt" || true

    # ── Endpoint extraction from JS ───────────────────────────────────────
    grep -rihEo "(https?://[^\"' <>]+|/[a-zA-Z0-9_/.-]{3,})" \
        "${js_dir}"/*.js 2>/dev/null \
        | grep -v "^//" \
        | sort -u > "${js_dir}/js_endpoints.txt" || true

    log_ok "Potential secrets in JS: $(wc -l < "${OUTPUT_BASE}/secrets/js_secrets.txt" 2>/dev/null || echo 0)"
    log_ok "JS endpoints extracted: $(wc -l < "${js_dir}/js_endpoints.txt" 2>/dev/null || echo 0)"

    mark_done "js_extraction"
}

# ──────────────────────────────────────────────────────────────────────────────
#  PHASE 7 — PARAMETER DISCOVERY
# ──────────────────────────────────────────────────────────────────────────────
phase_param_discovery() {
    should_run "param_discovery" || return 0
    log_step "Phase 7 — Parameter Discovery"

    local urls_file="${OUTPUT_BASE}/urls/all_urls_combined.txt"
    local params_dir="${OUTPUT_BASE}/params"

    [[ ! -s "$urls_file" ]] && { log_warn "No URLs; skipping param discovery."; return; }

    # ── Extract param names from historical URLs ───────────────────────────
    log_info "Extracting parameter names from historical URLs..."
    grep "?" "$urls_file" 2>/dev/null \
        | sed 's/#.*//' \
        | grep -oE "[?&][a-zA-Z0-9_%-]+(=|&|$)" \
        | tr -d '?&=' \
        | sort -u > "${params_dir}/param_names.txt"
    log_ok "Unique parameter names: $(wc -l < "${params_dir}/param_names.txt" 2>/dev/null || echo 0)"

    # ── Separate URLs with params ─────────────────────────────────────────
    grep "?" "$urls_file" 2>/dev/null \
        | sort -u > "${params_dir}/urls_with_params.txt"
    log_ok "URLs with parameters: $(wc -l < "${params_dir}/urls_with_params.txt" 2>/dev/null || echo 0)"

    # ── Deep mode: arjun parameter bruteforcing ───────────────────────────
    if [[ "$MODE" == "deep" ]] && tool_exists arjun; then
        log_info "Running arjun on live hosts (deep mode — this is slow)..."
        local live_file="${OUTPUT_BASE}/live/live_hosts.txt"
        [[ -s "$live_file" ]] && \
            arjun -i "$live_file" \
                -t "$THREADS" \
                --stable \
                -oJ "${params_dir}/arjun_results.json" 2>/dev/null || true
    fi

    mark_done "param_discovery"
}

# ──────────────────────────────────────────────────────────────────────────────
#  PHASE 8 — CONTENT DISCOVERY (Directory Bruteforce)
# ──────────────────────────────────────────────────────────────────────────────
phase_content_discovery() {
    should_run "content_discovery" || return 0
    log_step "Phase 8 — Content Discovery"

    local live_file="${OUTPUT_BASE}/live/live_hosts.txt"
    local scans_dir="${OUTPUT_BASE}/scans"
    local ua; ua="$(random_ua)"

    [[ ! -s "$live_file" ]] && { log_warn "No live hosts; skipping content discovery."; return; }

    if [[ ! -f "$WORDLIST" ]]; then
        log_warn "Wordlist not found: $WORDLIST — trying fallback..."
        for wl in \
            /usr/share/wordlists/dirb/common.txt \
            /usr/share/dirb/wordlists/common.txt \
            /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt; do
            [[ -f "$wl" ]] && { WORDLIST="$wl"; break; }
        done
    fi

    if [[ ! -f "$WORDLIST" ]]; then
        log_warn "No wordlist found; skipping content discovery."
        return
    fi

    # In fast mode only scan the main domain, otherwise scan all live hosts
    local targets=()
    if [[ "$MODE" == "fast" ]]; then
        targets=("https://${TARGET}")
    else
        mapfile -t targets < "$live_file"
    fi

    local ffuf_threads=50
    [[ "$MODE" == "fast" ]] && ffuf_threads=25

    if tool_exists ffuf; then
        for target_url in "${targets[@]}"; do
            [[ -z "$target_url" ]] && continue
            local safe_name; safe_name="$(echo "$target_url" | sed 's|https\?://||;s|/|_|g')"
            log_info "ffuf → ${target_url}"

            local proxy_flag=""
            [[ -n "$PROXY" ]] && proxy_flag="-x $PROXY"

            ffuf -u "${target_url}/FUZZ" \
                -w "$WORDLIST" \
                -mc "200,204,301,302,307,401,403,405" \
                -t "$ffuf_threads" \
                -timeout "$TIMEOUT" \
                -H "User-Agent: $ua" \
                $proxy_flag \
                -o "${scans_dir}/ffuf_${safe_name}.json" \
                -of json \
                -silent 2>/dev/null || true
        done
        log_ok "Content discovery complete"

        # Admin panel detection from ffuf results
        log_info "Checking for admin panels..."
        grep -rihE \
            "(admin|administrator|manage|manager|login|signin|dashboard|panel|control|backend|wp-admin|phpmyadmin|cpanel|webmail)" \
            "${scans_dir}"/ffuf_*.json 2>/dev/null \
            | jq -r '.results[]? | .url' 2>/dev/null \
            | sort -u > "${scans_dir}/admin_panels.txt" || \
        grep -rihE \
            "\"url\".*/(admin|login|dashboard|panel|manage)" \
            "${scans_dir}"/ffuf_*.json 2>/dev/null \
            | grep -oE '"url":"[^"]+"' | sed 's/"url":"//;s/"//' \
            | sort -u > "${scans_dir}/admin_panels.txt" || true
    else
        log_warn "ffuf not found — skipping directory bruteforce"
    fi

    mark_done "content_discovery"
}

# ──────────────────────────────────────────────────────────────────────────────
#  PHASE 9 — TECH FINGERPRINTING
# ──────────────────────────────────────────────────────────────────────────────
phase_tech_fingerprint() {
    should_run "tech_fingerprint" || return 0
    log_step "Phase 9 — Technology Fingerprinting"

    local live_file="${OUTPUT_BASE}/live/live_hosts.txt"
    local scans_dir="${OUTPUT_BASE}/scans"

    [[ ! -s "$live_file" ]] && { log_warn "No live hosts; skipping tech fingerprinting."; return; }

    # ── whatweb ───────────────────────────────────────────────────────────
    if tool_exists whatweb; then
        log_info "Running WhatWeb..."
        whatweb \
            -i "$live_file" \
            -a 3 \
            --log-json="${scans_dir}/whatweb.json" \
            --quiet 2>/dev/null || true
        log_ok "WhatWeb done"
    fi

    # ── wafw00f (WAF detection) ───────────────────────────────────────────
    if tool_exists wafw00f && [[ "$MODE" != "fast" ]]; then
        log_info "Detecting WAFs with wafw00f..."
        while IFS= read -r url; do
            wafw00f "$url" -o "${scans_dir}/wafw00f_$(echo "$url" | md5sum | cut -d' ' -f1).txt" \
                2>/dev/null || true
        done < "$live_file"
        log_ok "WAF detection done"
    fi

    # ── API endpoint detection ────────────────────────────────────────────
    log_info "Searching for exposed APIs and Swagger endpoints..."
    cat "${OUTPUT_BASE}/urls/all_urls_combined.txt" 2>/dev/null \
        | grep -iE "(swagger|api-docs|openapi|graphql|v1|v2|v3|rest|api)" \
        | sort -u > "${scans_dir}/api_endpoints.txt" || true
    log_ok "Possible API endpoints: $(wc -l < "${scans_dir}/api_endpoints.txt" 2>/dev/null || echo 0)"

    mark_done "tech_fingerprint"
}

# ──────────────────────────────────────────────────────────────────────────────
#  PHASE 10 — NUCLEI SCANNING
# ──────────────────────────────────────────────────────────────────────────────
phase_nuclei() {
    $SKIP_NUCLEI && { log_skip "Nuclei scanning skipped (--no-nuclei)"; return; }
    should_run "nuclei" || return 0
    log_step "Phase 10 — Nuclei Vulnerability Scanning"

    local live_file="${OUTPUT_BASE}/live/live_hosts.txt"
    local scans_dir="${OUTPUT_BASE}/scans"
    local ua; ua="$(random_ua)"

    [[ ! -s "$live_file" ]] && { log_warn "No live hosts; skipping nuclei."; return; }

    if ! tool_exists nuclei; then
        log_warn "nuclei not found; skipping."
        return
    fi

    # ── Update templates (skip in fast mode to save time) ─────────────────
    if [[ "$MODE" != "fast" ]]; then
        log_info "Updating nuclei templates..."
        nuclei -update-templates -silent 2>/dev/null || true
    fi

    local proxy_flag=""
    [[ -n "$PROXY" ]] && proxy_flag="-proxy $PROXY"

    # ── Template set selection ────────────────────────────────────────────
    local templates="-t cves/ -t exposures/ -t misconfiguration/ -t vulnerabilities/"
    [[ "$MODE" == "fast" ]] && templates="-t cves/ -t exposures/"
    [[ "$MODE" == "deep" ]] && templates="-t cves/ -t exposures/ -t misconfiguration/ -t vulnerabilities/ -t technologies/ -t default-logins/"

    log_info "Running nuclei (severity: ${NUCLEI_SEVERITY}, mode: ${MODE})..."
    nuclei -l "$live_file" \
        $templates \
        -severity "$NUCLEI_SEVERITY" \
        -c "$THREADS" \
        -rl "$RATE_LIMIT" \
        -timeout "$TIMEOUT" \
        -H "User-Agent: $ua" \
        $proxy_flag \
        -silent \
        -json \
        -o "${scans_dir}/nuclei_results.json" 2>/dev/null || true

    # Human-readable summary
    jq -r '[.info.severity, .info.name, .host] | join(" | ")' \
        "${scans_dir}/nuclei_results.json" 2>/dev/null \
        | sort -u > "${scans_dir}/nuclei_summary.txt" || true

    local ncount; ncount="$(wc -l < "${scans_dir}/nuclei_summary.txt" 2>/dev/null || echo 0)"
    log_ok "Nuclei findings: ${BOLD}${ncount}${NC}"

    # Notify critical/highs
    if $NOTIFY_ENABLED && tool_exists notify && [[ "$ncount" -gt 0 ]]; then
        jq -r 'select(.info.severity == "critical" or .info.severity == "high") | .info.name + " on " + .host' \
            "${scans_dir}/nuclei_results.json" 2>/dev/null \
            | notify -silent 2>/dev/null || true
    fi

    mark_done "nuclei"
}

# ──────────────────────────────────────────────────────────────────────────────
#  PHASE 11 — SCREENSHOT COLLECTION
# ──────────────────────────────────────────────────────────────────────────────
phase_screenshots() {
    should_run "screenshots" || return 0
    log_step "Phase 11 — Screenshot Collection"

    local live_file="${OUTPUT_BASE}/live/live_hosts.txt"
    local shots_dir="${OUTPUT_BASE}/screenshots"

    [[ ! -s "$live_file" ]] && { log_warn "No live hosts; skipping screenshots."; return; }

    if tool_exists gowitness; then
        log_info "Taking screenshots with gowitness..."
        gowitness file \
            -f "$live_file" \
            -P "$shots_dir" \
            --timeout "$TIMEOUT" \
            --threads "$THREADS" \
            --disable-logging \
            2>/dev/null || true

        local scount; scount="$(find "$shots_dir" -name "*.png" 2>/dev/null | wc -l)"
        log_ok "Screenshots taken: ${scount}"
    else
        log_warn "gowitness not found — skipping screenshots"
    fi

    mark_done "screenshots"
}

# ──────────────────────────────────────────────────────────────────────────────
#  PHASE 12 — ASN & CDN DETECTION
# ──────────────────────────────────────────────────────────────────────────────
phase_asn_cdn() {
    should_run "asn_cdn" || return 0
    log_step "Phase 12 — ASN & CDN Detection"

    local dns_dir="${OUTPUT_BASE}/dns"
    local scans_dir="${OUTPUT_BASE}/scans"

    # ── Extract IPs from httpx JSON ───────────────────────────────────────
    jq -r '.host // empty' "${OUTPUT_BASE}/live/httpx_full.json" 2>/dev/null \
        | sort -u > "${dns_dir}/ips.txt" || true

    # ── ASN info via ipinfo.io (free, no key needed) ───────────────────────
    log_info "Fetching ASN info for discovered IPs..."
    > "${scans_dir}/asn_info.txt"
    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        curl -s "https://ipinfo.io/${ip}/json" \
            --max-time 5 2>/dev/null \
            | jq -r '"IP: \(.ip) | ASN: \(.org) | Country: \(.country)"' \
            >> "${scans_dir}/asn_info.txt" 2>/dev/null || true
    done < <(head -20 "${dns_dir}/ips.txt" 2>/dev/null)   # limit to 20 IPs to stay polite

    log_ok "ASN info collected"

    # ── CDN detection via httpx CDN field ─────────────────────────────────
    jq -r 'select(.cdn != null and .cdn != false) | "\(.url) -> CDN: \(.cdn)"' \
        "${OUTPUT_BASE}/live/httpx_full.json" 2>/dev/null \
        | sort -u > "${scans_dir}/cdn_detected.txt" || true
    log_ok "CDN-fronted hosts: $(wc -l < "${scans_dir}/cdn_detected.txt" 2>/dev/null || echo 0)"

    mark_done "asn_cdn"
}

# ──────────────────────────────────────────────────────────────────────────────
#  PHASE 13 — OPTIONAL PORT SCANNING
# ──────────────────────────────────────────────────────────────────────────────
phase_port_scan() {
    $PORT_SCAN || return 0
    should_run "port_scan" || return 0
    log_step "Phase 13 — Port Scanning (optional)"

    local resolved="${OUTPUT_BASE}/dns/resolved.txt"
    local scans_dir="${OUTPUT_BASE}/scans"

    [[ ! -s "$resolved" ]] && { log_warn "No resolved hosts; skipping port scan."; return; }

    # ── naabu (fast port scanner) ──────────────────────────────────────────
    if tool_exists naabu; then
        log_info "Running naabu port scan..."
        local ports="80,443,8080,8443,8000,8888,9000,9090,3000,4000,5000,6060"
        [[ "$MODE" == "deep" ]] && ports="top-100"

        naabu -l "$resolved" \
            -p "$ports" \
            -c "$THREADS" \
            -rate "$RATE_LIMIT" \
            -silent \
            -o "${scans_dir}/open_ports.txt" 2>/dev/null || true
        log_ok "Open ports: $(wc -l < "${scans_dir}/open_ports.txt" 2>/dev/null || echo 0)"
    elif tool_exists nmap; then
        log_info "Running nmap (top 100 ports)..."
        nmap -iL "$resolved" \
            --top-ports 100 \
            -T4 \
            --open \
            -oN "${scans_dir}/nmap_results.txt" \
            2>/dev/null || true
        log_ok "nmap scan complete"
    else
        log_warn "Neither naabu nor nmap found; skipping port scan"
    fi

    mark_done "port_scan"
}

# ──────────────────────────────────────────────────────────────────────────────
#  PHASE 14 — SECRET & INTERESTING ENDPOINT DETECTION
# ──────────────────────────────────────────────────────────────────────────────
phase_secrets() {
    should_run "secrets" || return 0
    log_step "Phase 14 — Secret & Interesting Endpoint Detection"

    local urls_file="${OUTPUT_BASE}/urls/all_urls_combined.txt"
    local secrets_dir="${OUTPUT_BASE}/secrets"

    [[ ! -s "$urls_file" ]] && { log_warn "No URLs; skipping secrets phase."; return; }

    # ── Interesting URL patterns ──────────────────────────────────────────
    local patterns=(
        # Keys & tokens
        "api[_-]?key|apikey|access[_-]?key|secret[_-]?key|client[_-]?secret|bearer"
        # Credentials
        "password|passwd|pwd|credential|auth[_-]?token"
        # Cloud
        "aws|s3[.:]|gcp|azure|firebase|bucket"
        # Admin & management
        "admin|administrator|manage|manager|dashboard|panel|control|backend"
        # Dev/debug
        "debug|test|dev|staging|qa|uat|internal|backup|config|setup|install|phpinfo"
        # Databases
        "phpmyadmin|adminer|db|database|mysql|postgres|mongo|redis|elastic"
        # Git/source
        "\.git|\.env|\.htaccess|\.htpasswd|web\.config|\.DS_Store"
        # API docs
        "swagger|api-docs|openapi|graphql|introspect|wsdl"
        # Files
        "\.(bak|backup|old|orig|tmp|sql|log|dump|tar|zip|7z|gz)"
    )

    > "${secrets_dir}/interesting_urls.txt"
    for pattern in "${patterns[@]}"; do
        grep -iE "$pattern" "$urls_file" 2>/dev/null \
            >> "${secrets_dir}/interesting_urls.txt" || true
    done
    sort -u "${secrets_dir}/interesting_urls.txt" -o "${secrets_dir}/interesting_urls.txt"

    log_ok "Interesting URLs found: $(wc -l < "${secrets_dir}/interesting_urls.txt" 2>/dev/null || echo 0)"

    # ── Combine all secrets ───────────────────────────────────────────────
    cat "${secrets_dir}"/js_secrets.txt 2>/dev/null | sort -u \
        > "${secrets_dir}/all_secrets.txt"

    mark_done "secrets"
}

# ──────────────────────────────────────────────────────────────────────────────
#  FINAL REPORT GENERATION
# ──────────────────────────────────────────────────────────────────────────────
generate_report() {
    log_step "Generating Final Summary Report"

    local report_file="${OUTPUT_BASE}/reports/summary_$(date +%Y%m%d_%H%M%S).txt"
    local html_report="${OUTPUT_BASE}/reports/report.html"

    # Collect counts
    local subs_count;     subs_count="$(wc -l < "${OUTPUT_BASE}/subs/all_subs.txt" 2>/dev/null || echo 0)"
    local resolved_count; resolved_count="$(wc -l < "${OUTPUT_BASE}/dns/resolved.txt" 2>/dev/null || echo 0)"
    local live_count;     live_count="$(wc -l < "${OUTPUT_BASE}/live/live_hosts.txt" 2>/dev/null || echo 0)"
    local urls_count;     urls_count="$(wc -l < "${OUTPUT_BASE}/urls/all_urls_combined.txt" 2>/dev/null || echo 0)"
    local js_count;       js_count="$(wc -l < "${OUTPUT_BASE}/js/js_urls.txt" 2>/dev/null || echo 0)"
    local params_count;   params_count="$(wc -l < "${OUTPUT_BASE}/params/param_names.txt" 2>/dev/null || echo 0)"
    local nuclei_count;   nuclei_count="$(wc -l < "${OUTPUT_BASE}/scans/nuclei_summary.txt" 2>/dev/null || echo 0)"
    local secrets_count;  secrets_count="$(wc -l < "${OUTPUT_BASE}/secrets/interesting_urls.txt" 2>/dev/null || echo 0)"

    cat > "$report_file" << EOF
╔══════════════════════════════════════════════════════════════╗
║            RECON SUMMARY REPORT — ${TARGET}
║            Date: $(date +"%Y-%m-%d %H:%M:%S")
║            Mode: ${MODE}
╚══════════════════════════════════════════════════════════════╝

DISCOVERY SUMMARY
─────────────────────────────────────────────────────────────
  Total Subdomains       : ${subs_count}
  Resolved Domains       : ${resolved_count}
  Live Hosts             : ${live_count}
  URLs Collected         : ${urls_count}
  JS Files Found         : ${js_count}
  Parameters Found       : ${params_count}
  Nuclei Findings        : ${nuclei_count}
  Interesting URLs       : ${secrets_count}

OUTPUT DIRECTORY
─────────────────────────────────────────────────────────────
  ${OUTPUT_BASE}

KEY FILES
─────────────────────────────────────────────────────────────
  All subdomains         : subs/all_subs.txt
  Resolved hosts         : dns/resolved.txt
  Live hosts             : live/live_hosts.txt
  Combined URLs          : urls/all_urls_combined.txt
  JS endpoints           : js/js_endpoints.txt
  Interesting URLs       : secrets/interesting_urls.txt
  Nuclei findings        : scans/nuclei_summary.txt
  Admin panels           : scans/admin_panels.txt
  API endpoints          : scans/api_endpoints.txt
  Dangling CNAMEs        : dns/dangling_cnames.txt  (check for takeovers)

EOF

    # Append nuclei findings if any
    if [[ -s "${OUTPUT_BASE}/scans/nuclei_summary.txt" ]]; then
        echo "" >> "$report_file"
        echo "NUCLEI FINDINGS" >> "$report_file"
        echo "─────────────────────────────────────────────────────────────" >> "$report_file"
        cat "${OUTPUT_BASE}/scans/nuclei_summary.txt" >> "$report_file"
    fi

    # ── Print to terminal ─────────────────────────────────────────────────
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}${WHITE}RECON COMPLETE — ${TARGET}${NC}  ${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}Total Subdomains   :${NC} ${BOLD}${subs_count}${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}Resolved Domains   :${NC} ${BOLD}${resolved_count}${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}Live Hosts         :${NC} ${BOLD}${live_count}${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}URLs Collected     :${NC} ${BOLD}${urls_count}${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}JS Files Found     :${NC} ${BOLD}${js_count}${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}Parameters Found   :${NC} ${BOLD}${params_count}${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}Nuclei Findings    :${NC} ${BOLD}${nuclei_count}${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}Interesting URLs   :${NC} ${BOLD}${secrets_count}${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${DIM}Report: ${report_file}${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ──────────────────────────────────────────────────────────────────────────────
#  PRINT SCAN CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────
print_config() {
    echo -e "${WHITE}Target   :${NC} ${BOLD}${TARGET}${NC}"
    echo -e "${WHITE}Mode     :${NC} ${BOLD}${MODE}${NC}"
    echo -e "${WHITE}Threads  :${NC} ${THREADS}"
    echo -e "${WHITE}Rate     :${NC} ${RATE_LIMIT} req/s"
    echo -e "${WHITE}Timeout  :${NC} ${TIMEOUT}s"
    [[ -n "$PROXY" ]]  && echo -e "${WHITE}Proxy    :${NC} ${PROXY}"
    $PORT_SCAN         && echo -e "${WHITE}Ports    :${NC} enabled"
    $RESUME            && echo -e "${WHITE}Resume   :${NC} enabled"
    [[ -n "$CHAOS_KEY" ]]  && echo -e "${WHITE}Chaos    :${NC} ${GREEN}API key set${NC}"
    [[ -n "$ST_API_KEY" ]] && echo -e "${WHITE}SecTrails:${NC} ${GREEN}API key set${NC}"
    echo -e "${WHITE}Output   :${NC} ${OUTPUT_BASE}"
    echo ""
}

# ──────────────────────────────────────────────────────────────────────────────
#  MAIN ENTRYPOINT
# ──────────────────────────────────────────────────────────────────────────────
main() {
    banner
    load_config
    parse_args "$@"
    setup_dirs
    setup_checkpoint

    log_info "Starting recon against: ${BOLD}${TARGET}${NC}  [$(date)]"
    print_config
    check_tools

    # Run all phases in order
    phase_passive_subs
    phase_dns_resolution
    phase_live_hosts
    phase_url_collection
    phase_historical_urls
    phase_js_extraction
    phase_param_discovery
    phase_content_discovery
    phase_tech_fingerprint
    phase_nuclei
    phase_screenshots
    phase_asn_cdn
    phase_port_scan
    phase_secrets

    generate_report
    log_info "All done. Output: ${OUTPUT_BASE}"
}

main "$@"