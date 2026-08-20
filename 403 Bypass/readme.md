# bypass403.py

Fuzzes a 403'd URL with path mutations, spoofed-IP headers, override
headers, and method swaps to find bypasses.

## Setup

```bash
pip install requests --break-system-packages
```

## Usage

```bash
# Single endpoint
python3 bypass_403.py -u https://api.example.com/images

# Batch — one URL per line
python3 bypass_403.py -l 403_hits.txt -o results.json

# With a session cookie / auth header
python3 bypass_403.py -u https://api.example.com/images -H "Cookie: session=xxx"

# Throttle for rate-limited targets
python3 bypass_403.py -u https://api.example.com/images --delay 0.5 -t 5
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
