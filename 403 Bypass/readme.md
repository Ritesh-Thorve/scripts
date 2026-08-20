# bypass_403.py

Fuzzes a 403'd URL with path mutations, spoofed-IP headers, override
headers, and method swaps to find bypasses.

## What it does

For each target URL, it first grabs a baseline (the plain 403) then
fires ~90-110 variations at it across four categories:

- **Path mutations** — trailing dot/slash, `..`, `..;/`, double
  slashes, `%2e`/`%2f`/`%00` encoding tricks, `?`/`#` suffixes, case
  swaps, param pollution (`;foo=bar`), and re-requesting just the
  last path segment.
- **Spoofed-IP headers** — `X-Forwarded-For`, `X-Real-IP`,
  `CF-Connecting-IP`, `True-Client-IP`, etc., set to `127.0.0.1` and
  a few private ranges.
- **Override headers** — `X-Original-URL`, `X-Rewrite-URL`,
  `X-HTTP-Method-Override`, `X-Forwarded-Proto/Scheme/Port`, and
  similar headers some proxies/WAFs trust over the real request.
- **Method + user-agent swaps** — GET/POST/HEAD/OPTIONS/PUT/TRACE/
  PATCH/DELETE/CONNECT, plus a couple of common user-agent strings
  (including a bot UA some WAFs allowlist).

Every response is compared against the baseline and classified into
three tiers so you're not sifting noise:

- **Likely bypass** — a 2xx that isn't the baseline.
- **Worth checking** — a redirect or other non-4xx status.
- **Probably noise** — informational statuses (e.g. 405 on a method
  that was never implemented in the first place).

For anything in the top two tiers it prints a ready-to-run `curl`
command so you can manually reproduce and verify the hit.

## Setup

```bash
pip install requests --break-system-packages
```

## Usage

```bash
# Single endpoint
python3 bypass403.py -u https://api.example.com/images

# Batch — one URL per line
python3 bypass403.py -l 403_hits.txt -o results.json

# With a session cookie / auth header
python3 bypass403.py -u https://api.example.com/images -H "Cookie: session=xxx"

# Throttle for rate-limited targets
python3 bypass403.py -u https://api.example.com/images --delay 0.5 -t 5
```

## Flags

| Flag | Description |
|---|---|
| `-u` | Single target URL |
| `-l` | File with one URL per line |
| `-H` | Extra header, repeatable (`-H "Cookie: x" -H "X-Api-Key: y"`) |
| `-o` | Write full JSON results to file |
| `-t` | Concurrent requests per target (default 10) |
| `--timeout` | Per-request timeout in seconds (default 8) |
| `--delay` | Delay between requests, for rate-limited targets |

## Output

Prints the baseline 403 status/length, then any response that came
back non-403/401/404 **and** differs from the baseline. Anything
flagged is a **lead, not a finding** — confirm real data/functionality
exposure before reporting.

## Note

Only run against targets you're authorized to test.
