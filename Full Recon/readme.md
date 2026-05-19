# recon.sh — Automated Bug Bounty Reconnaissance Toolkit

A production-quality, modular bash reconnaissance toolkit for bug bounty hunters and penetration testers. Automates the full recon pipeline from passive subdomain discovery through to vulnerability scanning.

---

## Table of Contents

- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage Examples](#-usage-examples)
- [Scan Modes](#-scan-modes)
- [Output Structure](#-output-structure)
- [API Keys Setup](#-api-keys-setup)
- [Proxy Usage](#-proxy-usage)
- [Notification Setup](#-notification-setup)
- [Resuming Scans](#-resuming-scans)
- [Config File Reference](#-config-file-reference)
- [Recon Phases Explained](#-recon-phases-explained)
- [Troubleshooting](#-troubleshooting)

---

## Features

| Feature | Details |
|---------|---------|
| **14 Recon Phases** | Passive subs → DNS → Live probing → Crawling → History → JS → Params → Content → Tech → Nuclei → Screenshots → ASN → Ports → Secrets |
| **3 Scan Modes** | Fast (5–15 min), Normal (30–60 min), Deep (1–3 hours) |
| **Resume Support** | Pick up exactly where you left off |
| **Rate Limiting** | Configurable requests/sec to stay polite |
| **Proxy Support** | Route traffic through Burp Suite or any HTTP proxy |
| **Random User-Agents** | Rotate UA strings automatically |
| **API Key Support** | Chaos, SecurityTrails, Shodan, Censys |
| **Deduplication** | All outputs sorted and deduplicated automatically |
| **Colourful Output** | Clear status indicators, progress tracking |
| **Final Report** | Counts, findings summary, key file locations |
| **Notifications** | Send critical findings to Slack/Discord/Telegram |

---

## Requirements

- **OS**: Kali Linux (recommended), Ubuntu 20.04+, or Debian 11+
- **Privileges**: Root or sudo for installation; non-root for scanning
- **Internet**: Required (tools download data from external sources)
- **Disk space**: ~2 GB (Go tools + wordlists + nuclei templates)

---

## Installation

### Step 1 — Clone or download the toolkit

```bash
# Option A: if you have git
git clone https://github.com/yourname/recon-toolkit.git
cd recon-toolkit

# Option B: manually place recon.sh, install.sh, README.md in a folder
mkdir ~/recon-toolkit && cd ~/recon-toolkit
```

### Step 2 — Run the installer

```bash
sudo ./install.sh
```

The installer will:
- Install system packages (`nmap`, `jq`, `curl`, `chromium`, etc.)
- Install Go language runtime
- Install all Go-based recon tools (`subfinder`, `httpx`, `nuclei`, etc.)
- Install Python tools (`arjun`, `wafw00f`, `paramspider`)
- Download nuclei templates
- Download DNS resolver list
- Create a default `recon.conf` config file

### Step 3 — Reload your shell

```bash
source ~/.bashrc
# or
source ~/.zshrc
```

### Step 4 — Verify installation

```bash
./recon.sh --help
```

---

## Quick Start

```bash
# Basic scan (normal mode)
./recon.sh target.com

# That's it! Results go to ./recon/target.com/
```

---

## Usage Examples

### Basic normal scan

```bash
./recon.sh example.com
```

### Fast scan (quick results in ~10 minutes)

```bash
./recon.sh --fast example.com
```

### Deep scan (thorough, takes 1–3 hours)

```bash
./recon.sh --deep example.com
```

### Deep scan with port scanning enabled

```bash
./recon.sh --deep --ports example.com
```

### Scan through Burp Suite proxy

```bash
./recon.sh --proxy http://127.0.0.1:8080 example.com
```

### Custom threads and rate limit

```bash
./recon.sh --threads 20 --rate 300 example.com
```

### Skip nuclei scanning (faster)

```bash
./recon.sh --no-nuclei example.com
```

### Only report high and critical nuclei findings

```bash
./recon.sh --severity high,critical example.com
```

### Resume a previous scan

```bash
./recon.sh --resume example.com
```

### Enable Slack/Discord notifications

```bash
./recon.sh --notify example.com
```

### Use a custom wordlist for content discovery

```bash
./recon.sh --wordlist /usr/share/seclists/Discovery/Web-Content/big.txt example.com
```

### Full deep scan with all options

```bash
./recon.sh \
  --deep \
  --ports \
  --threads 20 \
  --rate 200 \
  --proxy http://127.0.0.1:8080 \
  --notify \
  --severity medium,high,critical \
  example.com
```

---

## Scan Modes

### `--fast` mode
Best for: Quick wins, initial recon, time-limited engagements

- Passive subdomain enumeration (subfinder + crt.sh only)
- DNS resolution
- Live host probing
- Active crawling (shallow depth)
- Historical URLs
- JS extraction
- Nuclei scan (CVEs + exposures templates only)
- **Skips**: amass, content discovery, deep crawl, permutations

Typical time: **5–15 minutes**

---

### Normal mode (default)
Best for: Most bug bounty programs, standard engagements

- All passive subdomain tools
- Full DNS resolution
- Live host probing with tech detection
- Active + historical crawling
- JS file download and secret extraction
- Parameter extraction
- Content discovery (main domain)
- Tech fingerprinting
- Full nuclei scan (CVEs + exposures + misconfigs + vulns)
- Screenshots
- ASN/CDN detection

Typical time: **30–60 minutes**

---

### `--deep` mode
Best for: Critical targets, full coverage, red team engagements

All normal mode phases, plus:
- amass passive enumeration
- Subdomain permutation with dnsgen
- Deep crawl (depth 5)
- Content discovery on all live hosts
- Arjun parameter bruteforcing
- Nuclei with tech + default-logins templates

Typical time: **1–3 hours** (depends on target size)

---

## Output Structure

```
recon/
└── example.com/
    ├── subs/
    │   ├── subfinder.txt       # subdomains from subfinder
    │   ├── assetfinder.txt     # subdomains from assetfinder
    │   ├── amass.txt           # subdomains from amass
    │   ├── crtsh.txt           # subdomains from CT logs
    │   └── all_subs.txt        # ★ merged + deduplicated
    ├── dns/
    │   ├── dns_records.txt     # full DNS records (A, CNAME, MX...)
    │   ├── resolved.txt        # ★ hosts that actually resolve
    │   └── dangling_cnames.txt # potential subdomain takeovers
    ├── live/
    │   ├── httpx_full.json     # full httpx output (JSON)
    │   ├── live_hosts.txt      # ★ live HTTP(S) hosts
    │   ├── status_200.txt      # hosts returning 200
    │   ├── status_403.txt      # hosts returning 403
    │   └── status_401.txt      # hosts returning 401 (often juicy)
    ├── urls/
    │   ├── katana.txt          # URLs from katana crawler
    │   ├── wayback.txt         # Wayback Machine URLs
    │   ├── gau.txt             # GAU URLs
    │   └── all_urls_combined.txt  # ★ all URLs merged
    ├── js/
    │   ├── js_urls.txt         # discovered JS file URLs
    │   ├── js_endpoints.txt    # endpoints extracted from JS
    │   └── *.js                # downloaded JS files
    ├── params/
    │   ├── param_names.txt     # unique parameter names
    │   └── urls_with_params.txt
    ├── scans/
    │   ├── nuclei_results.json # full nuclei output
    │   ├── nuclei_summary.txt  # ★ human-readable findings
    │   ├── admin_panels.txt    # discovered admin panels
    │   ├── api_endpoints.txt   # API/Swagger/GraphQL URLs
    │   ├── asn_info.txt        # ASN data for IPs
    │   └── cdn_detected.txt    # CDN-fronted hosts
    ├── screenshots/
    │   └── *.png               # screenshots of live hosts
    ├── secrets/
    │   ├── js_secrets.txt      # potential secrets in JS
    │   └── interesting_urls.txt # admin/login/config/backup URLs
    ├── logs/
    │   ├── recon_YYYYMMDD.log  # full run log
    │   ├── tech_summary.txt    # technology frequency summary
    │   └── .checkpoint         # resume state
    └── reports/
        └── summary_YYYYMMDD.txt  # ★ final summary report
```

**★ = Start here when reviewing results**

---

## API Keys Setup

API keys dramatically expand your subdomain and intelligence coverage. They are **optional** but strongly recommended.

### Edit `recon.conf`

```bash
nano recon.conf
```

Uncomment and fill in the keys you have:

```bash
# Chaos — ProjectDiscovery dataset (huge subdomain database)
# Get key: https://cloud.projectdiscovery.io
CHAOS_KEY="your-key-here"

# SecurityTrails — DNS history, WHOIS history, reverse-IP
# Get key: https://securitytrails.com/app/account/credentials
ST_API_KEY="your-key-here"

# Shodan — exposed service intelligence
# Get key: https://account.shodan.io
SHODAN_KEY="your-key-here"

# Censys — certificate + host intelligence
# Get keys: https://search.censys.io/account/api
CENSYS_ID="your-id-here"
CENSYS_SECRET="your-secret-here"
```

### Alternative: Environment Variables

```bash
export CHAOS_KEY="your-key-here"
export ST_API_KEY="your-key-here"
./recon.sh target.com
```

---

## Proxy Usage

Route all HTTP traffic through Burp Suite or any proxy:

```bash
# Burp Suite (default port)
./recon.sh --proxy http://127.0.0.1:8080 example.com

# SOCKS5 proxy (e.g. Tor)
./recon.sh --proxy socks5://127.0.0.1:9050 example.com

# Or set in recon.conf permanently:
# PROXY="http://127.0.0.1:8080"
```

> **Burp tip**: Add `example.com` to Burp's target scope first so you can capture interesting requests as they happen.

---

## Notification Setup

Get findings sent directly to Slack, Discord, or Telegram.

### Step 1 — Install notify

```bash
go install github.com/projectdiscovery/notify/cmd/notify@latest
```

### Step 2 — Configure provider

```bash
mkdir -p ~/.config/notify
nano ~/.config/notify/provider-config.yaml
```

#### Slack example:

```yaml
slack:
  - id: "recon-alerts"
    slack_webhook_url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    slack_username: "ReconBot"
    slack_channel: "#bug-bounty"
```

#### Discord example:

```yaml
discord:
  - id: "recon-discord"
    discord_webhook_url: "https://discord.com/api/webhooks/YOUR_WEBHOOK"
    discord_username: "ReconBot"
```

#### Telegram example:

```yaml
telegram:
  - id: "recon-telegram"
    telegram_api_key: "your-bot-token"
    telegram_chat_id: "your-chat-id"
```

### Step 3 — Run with notifications

```bash
./recon.sh --notify example.com
```

Only **critical** and **high** nuclei findings are sent by default.

---

## Resuming Scans

If a scan is interrupted (network drop, power cut, you Ctrl+C'd):

```bash
# Resume exactly where you stopped
./recon.sh --resume example.com
```

The checkpoint file is at:
```
recon/example.com/logs/.checkpoint
```

Each completed phase is written there. Remove a phase name from that file to force it to re-run.

To start completely fresh:
```bash
# Remove checkpoint to start over
rm recon/example.com/logs/.checkpoint
./recon.sh example.com
```

---

## Config File Reference

`recon.conf` sits in the same folder as `recon.sh`. All settings have defaults so you only need to set what you want to change.

```bash
# ── API Keys ────────────────────────────────────────────
CHAOS_KEY=""
SHODAN_KEY=""
CENSYS_ID=""
CENSYS_SECRET=""
ST_API_KEY=""

# ── Tuning ──────────────────────────────────────────────
THREADS=10           # parallel threads (10–50 recommended)
RATE_LIMIT=150       # HTTP requests per second
TIMEOUT=10           # seconds before a request times out
MODE="normal"        # fast | normal | deep

# ── Routing ─────────────────────────────────────────────
PROXY=""             # http://127.0.0.1:8080

# ── Content Discovery ────────────────────────────────────
WORDLIST="/usr/share/wordlists/dirb/common.txt"
DNS_WORDLIST="/usr/share/wordlists/dnsmap.txt"

# ── Nuclei ──────────────────────────────────────────────
NUCLEI_SEVERITY="medium,high,critical"

# ── Features ────────────────────────────────────────────
PORT_SCAN=false
NOTIFY_ENABLED=false
```

---

## Recon Phases Explained

| Phase | What it does | Key tools |
|-------|-------------|-----------|
| 1 — Passive Subs | Collects subdomains without touching the target | subfinder, assetfinder, crt.sh, chaos |
| 2 — DNS Resolution | Resolves which subdomains actually have DNS records | dnsx |
| 3 — Live Hosts | Finds hosts serving HTTP/HTTPS | httpx |
| 4 — URL Collection | Crawls live hosts for URLs | katana, hakrawler |
| 5 — Historical URLs | Retrieves archived URLs | waybackurls, gau |
| 6 — JS Extraction | Downloads JS files, extracts secrets + endpoints | grep, curl |
| 7 — Param Discovery | Finds GET/POST parameter names | URL analysis, arjun |
| 8 — Content Discovery | Bruteforces directories and files | ffuf |
| 9 — Tech Fingerprint | Identifies tech stack, WAFs | whatweb, wafw00f |
| 10 — Nuclei | Scans for known CVEs and misconfigurations | nuclei |
| 11 — Screenshots | Visual snapshot of each live host | gowitness |
| 12 — ASN/CDN | Maps IPs to ASNs, detects CDN-fronted hosts | ipinfo.io, httpx |
| 13 — Port Scan | Scans for open ports (optional) | naabu, nmap |
| 14 — Secrets | Flags interesting URLs (admin, config, backup) | grep patterns |

---

## Troubleshooting

### "Permission denied" running recon.sh

```bash
chmod +x recon.sh
```

### Tools installed but not found after install.sh

```bash
source ~/.bashrc
# or add manually:
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
```

### nuclei: "could not find templates"

```bash
nuclei -update-templates
```

### httpx / subfinder: "connection refused" or no results

- Check your internet connection
- Try `--rate 50` to reduce the request rate
- Try `--proxy` if you're behind a corporate firewall

### crt.sh returns empty results

crt.sh can be slow or rate-limit you. Wait a few minutes and retry:
```bash
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | head
```

### gowitness errors about Chrome

```bash
# Install Chromium (required by gowitness)
sudo apt-get install -y chromium-browser

# Or on Kali:
sudo apt-get install -y chromium
```

### amass is extremely slow

amass is thorough but slow. In `--fast` or `--normal` mode it is skipped. Only runs in `--deep` mode. You can also disable it by removing it from your PATH temporarily.

### ffuf content discovery finds nothing

Your wordlist path may be wrong. Check:
```bash
ls /usr/share/wordlists/dirb/
```
Then set in `recon.conf`:
```bash
WORDLIST="/correct/path/to/wordlist.txt"
```

### Out of memory during deep scan

Reduce threads and rate:
```bash
./recon.sh --deep --threads 5 --rate 50 example.com
```

### Resume doesn't work as expected

Check the checkpoint file:
```bash
cat recon/target.com/logs/.checkpoint
```
Remove a line to force that phase to re-run.

---

## Legal Notice

This toolkit is intended for **authorised security testing only**. Always obtain written permission before scanning any target. The authors are not responsible for misuse.

Recommended practice:
- Only scan targets you own or have a signed scope agreement for
- Respect rate limits and `robots.txt`
- Do not use `--deep` or `--ports` without explicit permission
- Read the bug bounty program scope carefully before running

---

## Contributing

PRs welcome! Common improvements:
- Adding new tool integrations
- Improving secret detection patterns
- Better report formatting
- New wordlists

---

*Happy hunting!* 🐛