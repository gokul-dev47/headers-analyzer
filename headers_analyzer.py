#!/usr/bin/env python3
"""
headers_analyzer.py — HTTP Security Headers Analyzer
-----------------------------------------------------
Scans any website and analyzes its HTTP security headers.
Checks for missing, misconfigured, or insecure header values,
calculates a security score, and generates a detailed report.

Author: (your name)
Version: 1.0
Tested on: Python 3.8+

USAGE:
    python3 headers_analyzer.py -u https://example.com
    python3 headers_analyzer.py -u https://example.com --output report.txt
    python3 headers_analyzer.py -u https://example.com --verbose
    python3 headers_analyzer.py --batch sites.txt --output batch_report.txt

DISCLAIMER:
    Only scan websites you own or have explicit permission to test.
    This tool only sends a single HTTP GET request — it does not
    crawl, brute-force, or stress-test the target.
"""

import argparse
import json
import sys
import urllib.parse
from datetime import datetime

try:
    import requests
    from requests.exceptions import SSLError, ConnectionError, Timeout, RequestException
except ImportError:
    print("[!] Missing dependency: requests")
    print("    Fix: pip install requests")
    sys.exit(1)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    RED    = Fore.RED
    GREEN  = Fore.GREEN
    YELLOW = Fore.YELLOW
    CYAN   = Fore.CYAN
    BLUE   = Fore.BLUE
    BOLD   = Style.BRIGHT
    DIM    = Style.DIM
    RESET  = Style.RESET_ALL
except ImportError:
    RED = GREEN = YELLOW = CYAN = BLUE = BOLD = DIM = RESET = ""


# ─────────────────────────────────────────────────────────────────────────────
# Security header definitions
# Each entry defines: description, weight (score impact), severity if missing,
# and optional checks for misconfigured values.
# ─────────────────────────────────────────────────────────────────────────────
SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "Strict-Transport-Security (HSTS)",
        "description": "Forces browsers to use HTTPS. Prevents protocol downgrade attacks.",
        "weight": 15,
        "severity": "HIGH",
        "good_patterns": ["max-age"],
        "bad_patterns": [],
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "content-security-policy": {
        "name": "Content-Security-Policy (CSP)",
        "description": "Restricts sources of scripts, styles, images. Mitigates XSS attacks.",
        "weight": 20,
        "severity": "HIGH",
        "good_patterns": [],
        "bad_patterns": ["unsafe-inline", "unsafe-eval", "*"],
        "recommendation": "Add a CSP that restricts script/style sources. Start with: Content-Security-Policy: default-src 'self'",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "description": "Prevents the page from being embedded in iframes. Stops clickjacking.",
        "weight": 10,
        "severity": "MEDIUM",
        "good_patterns": ["deny", "sameorigin"],
        "bad_patterns": ["allow-from"],
        "recommendation": "Add: X-Frame-Options: DENY  (or SAMEORIGIN if you need iframe embedding on same origin)",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "description": "Prevents MIME-type sniffing. Stops browsers from interpreting files differently.",
        "weight": 10,
        "severity": "MEDIUM",
        "good_patterns": ["nosniff"],
        "bad_patterns": [],
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "description": "Controls how much referrer info is sent with requests. Protects user privacy.",
        "weight": 5,
        "severity": "LOW",
        "good_patterns": [
            "no-referrer",
            "strict-origin",
            "strict-origin-when-cross-origin",
            "no-referrer-when-downgrade",
        ],
        "bad_patterns": ["unsafe-url"],
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "description": "Controls browser features (camera, mic, geolocation). Limits attack surface.",
        "weight": 10,
        "severity": "MEDIUM",
        "good_patterns": [],
        "bad_patterns": [],
        "recommendation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
    },
    "x-xss-protection": {
        "name": "X-XSS-Protection",
        "description": "Legacy XSS filter for older browsers. Mostly superseded by CSP.",
        "weight": 5,
        "severity": "LOW",
        "good_patterns": ["1; mode=block"],
        "bad_patterns": ["0"],
        "recommendation": "Add: X-XSS-Protection: 1; mode=block  (low priority — focus on CSP instead)",
    },
    "cache-control": {
        "name": "Cache-Control",
        "description": "Controls caching behavior. Prevents sensitive data from being cached.",
        "weight": 5,
        "severity": "LOW",
        "good_patterns": ["no-store", "no-cache", "private"],
        "bad_patterns": ["public"],
        "recommendation": "For sensitive pages, add: Cache-Control: no-store, no-cache, must-revalidate",
    },
    "cross-origin-opener-policy": {
        "name": "Cross-Origin-Opener-Policy (COOP)",
        "description": "Isolates browsing context from cross-origin documents. Prevents XS-Leaks.",
        "weight": 5,
        "severity": "LOW",
        "good_patterns": ["same-origin", "same-origin-allow-popups"],
        "bad_patterns": [],
        "recommendation": "Add: Cross-Origin-Opener-Policy: same-origin",
    },
    "cross-origin-resource-policy": {
        "name": "Cross-Origin-Resource-Policy (CORP)",
        "description": "Prevents other origins from loading your resources.",
        "weight": 5,
        "severity": "LOW",
        "good_patterns": ["same-origin", "same-site"],
        "bad_patterns": ["cross-origin"],
        "recommendation": "Add: Cross-Origin-Resource-Policy: same-origin",
    },
    "cross-origin-embedder-policy": {
        "name": "Cross-Origin-Embedder-Policy (COEP)",
        "description": "Required for advanced browser isolation features (SharedArrayBuffer etc).",
        "weight": 5,
        "severity": "LOW",
        "good_patterns": ["require-corp"],
        "bad_patterns": [],
        "recommendation": "Add: Cross-Origin-Embedder-Policy: require-corp",
    },
    "server": {
        "name": "Server (Information Disclosure)",
        "description": "Reveals server software and version. Should be removed or obfuscated.",
        "weight": 3,
        "severity": "INFO",
        "good_patterns": [],
        "bad_patterns": ["apache", "nginx", "iis", "php", "asp", "express", "tomcat"],
        "recommendation": "Remove or blank the Server header to avoid revealing server fingerprint.",
        "is_disclosure": True,
    },
    "x-powered-by": {
        "name": "X-Powered-By (Information Disclosure)",
        "description": "Reveals backend technology (PHP, ASP.NET etc). Should be removed.",
        "weight": 2,
        "severity": "INFO",
        "good_patterns": [],
        "bad_patterns": ["php", "asp", "express", "rails", "django"],
        "recommendation": "Remove X-Powered-By header entirely.",
        "is_disclosure": True,
    },
}

# Bonus headers — extra credit if present
BONUS_HEADERS = {
    "expect-ct": "Certificate Transparency enforcement",
    "nel":       "Network Error Logging",
    "report-to": "Reporting API endpoint",
}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def banner():
    print(f"""
{CYAN}{BOLD}╔══════════════════════════════════════════════════════╗
║   HTTP Security Headers Analyzer  v1.0              ║
║   Authorized testing only                           ║
╚══════════════════════════════════════════════════════╝{RESET}
""")


def log_info(msg):   print(f"{GREEN}[+]{RESET} {msg}")
def log_warn(msg):   print(f"{YELLOW}[!]{RESET} {msg}")
def log_error(msg):  print(f"{RED}[✗]{RESET} {msg}")
def log_step(msg):   print(f"{CYAN}[→]{RESET} {msg}")


def normalize_url(url: str) -> str:
    """Ensure URL has a scheme."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def get_grade(score: int) -> tuple:
    """Return letter grade and colour based on score."""
    if score >= 90:
        return "A+", GREEN
    elif score >= 80:
        return "A",  GREEN
    elif score >= 70:
        return "B",  CYAN
    elif score >= 60:
        return "C",  YELLOW
    elif score >= 40:
        return "D",  YELLOW
    else:
        return "F",  RED


def fetch_headers(url: str, timeout: int) -> tuple:
    """
    Fetch HTTP headers from target URL.
    Returns (headers_dict, status_code, final_url, error_msg)
    """
    session = requests.Session()
    session.headers["User-Agent"] = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/123.0 Safari/537.36"
    )

    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True)
        return dict(resp.headers), resp.status_code, resp.url, None

    except SSLError:
        # Retry without SSL verification (note it in output)
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            resp = session.get(url, timeout=timeout, allow_redirects=True, verify=False)
            return dict(resp.headers), resp.status_code, resp.url, "SSL_WARN"
        except Exception as e:
            return {}, 0, url, f"SSL error: {e}"

    except Timeout:
        return {}, 0, url, "Request timed out"
    except ConnectionError:
        return {}, 0, url, "Could not connect to host"
    except RequestException as e:
        return {}, 0, url, str(e)


# ─────────────────────────────────────────────────────────────────────────────
# Core analysis
# ─────────────────────────────────────────────────────────────────────────────

def analyze_headers(raw_headers: dict) -> dict:
    """
    Analyze response headers against the security header definitions.
    Returns a structured results dict.
    """
    # Normalize header names to lowercase for comparison
    headers_lower = {k.lower(): v for k, v in raw_headers.items()}

    results = {
        "present":      [],   # Header present and correctly configured
        "misconfigured":[],   # Header present but with bad values
        "missing":      [],   # Header absent entirely
        "disclosure":   [],   # Information-disclosure headers found
        "bonus":        [],   # Bonus headers present
        "score":        0,
        "max_score":    0,
    }

    for header_key, meta in SECURITY_HEADERS.items():
        is_disclosure = meta.get("is_disclosure", False)
        weight        = meta["weight"]
        value         = headers_lower.get(header_key, "")
        value_lower   = value.lower()

        if is_disclosure:
            # For disclosure headers: bad if present with identifying info
            if value:
                has_bad = any(bad in value_lower for bad in meta["bad_patterns"])
                if has_bad or not meta["bad_patterns"]:
                    results["disclosure"].append({
                        "header":         meta["name"],
                        "value":          value,
                        "severity":       meta["severity"],
                        "recommendation": meta["recommendation"],
                    })
                    # Penalise score for disclosure
                    results["score"] = max(0, results["score"] - weight)
            continue

        results["max_score"] += weight

        if not value:
            # Header is missing
            results["missing"].append({
                "header":         meta["name"],
                "key":            header_key,
                "severity":       meta["severity"],
                "description":    meta["description"],
                "recommendation": meta["recommendation"],
                "weight":         weight,
            })
        else:
            # Header is present — check for bad patterns
            has_bad  = any(bad  in value_lower for bad  in meta["bad_patterns"])
            has_good = any(good in value_lower for good in meta["good_patterns"]) if meta["good_patterns"] else True

            if has_bad:
                results["misconfigured"].append({
                    "header":         meta["name"],
                    "key":            header_key,
                    "value":          value,
                    "severity":       meta["severity"],
                    "issue":          f"Contains potentially unsafe directive",
                    "recommendation": meta["recommendation"],
                    "weight":         weight // 2,  # Partial credit
                })
                results["score"] += weight // 2
            elif not has_good and meta["good_patterns"]:
                results["misconfigured"].append({
                    "header":         meta["name"],
                    "key":            header_key,
                    "value":          value,
                    "severity":       meta["severity"],
                    "issue":          "Present but missing recommended directives",
                    "recommendation": meta["recommendation"],
                    "weight":         weight // 2,
                })
                results["score"] += weight // 2
            else:
                results["present"].append({
                    "header": meta["name"],
                    "key":    header_key,
                    "value":  value,
                    "weight": weight,
                })
                results["score"] += weight

    # Check bonus headers
    for bkey, bdesc in BONUS_HEADERS.items():
        if bkey in headers_lower:
            results["bonus"].append({
                "header": bkey,
                "value":  headers_lower[bkey],
                "desc":   bdesc,
            })

    # Clamp score to 0-100
    if results["max_score"] > 0:
        results["score"] = min(100, int((results["score"] / results["max_score"]) * 100))
    else:
        results["score"] = 0

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Display
# ─────────────────────────────────────────────────────────────────────────────

def print_results(url: str, results: dict, status_code: int, verbose: bool):
    score          = results["score"]
    grade, g_color = get_grade(score)

    print(f"\n{'─' * 56}")
    print(f"  Target : {url}")
    print(f"  Status : HTTP {status_code}")
    print(f"  Score  : {g_color}{BOLD}{score}/100  (Grade: {grade}){RESET}")
    print(f"{'─' * 56}\n")

    # ── Present headers ───────────────────────────────────────────────────────
    if results["present"]:
        print(f"{GREEN}{BOLD}✅ Secure Headers Present ({len(results['present'])}){RESET}")
        for h in results["present"]:
            print(f"  {GREEN}✓{RESET} {h['header']}")
            if verbose:
                print(f"      Value: {DIM}{h['value'][:120]}{RESET}")
        print()

    # ── Misconfigured headers ─────────────────────────────────────────────────
    if results["misconfigured"]:
        print(f"{YELLOW}{BOLD}⚠️  Misconfigured Headers ({len(results['misconfigured'])}){RESET}")
        for h in results["misconfigured"]:
            sev_color = RED if h["severity"] == "HIGH" else YELLOW
            print(f"  {YELLOW}⚠{RESET} {h['header']}  {sev_color}[{h['severity']}]{RESET}")
            print(f"      Current : {DIM}{h['value'][:100]}{RESET}")
            print(f"      Issue   : {h['issue']}")
            if verbose:
                print(f"      Fix     : {h['recommendation']}")
        print()

    # ── Missing headers ───────────────────────────────────────────────────────
    if results["missing"]:
        print(f"{RED}{BOLD}❌ Missing Headers ({len(results['missing'])}){RESET}")
        for h in results["missing"]:
            sev_color = RED if h["severity"] == "HIGH" else (YELLOW if h["severity"] == "MEDIUM" else CYAN)
            print(f"  {RED}✗{RESET} {h['header']}  {sev_color}[{h['severity']}]{RESET}")
            if verbose:
                print(f"      {DIM}{h['description']}{RESET}")
                print(f"      Fix: {h['recommendation']}")
        print()

    # ── Information disclosure ────────────────────────────────────────────────
    if results["disclosure"]:
        print(f"{YELLOW}{BOLD}🔍 Information Disclosure ({len(results['disclosure'])}){RESET}")
        for h in results["disclosure"]:
            print(f"  {YELLOW}ℹ{RESET} {h['header']}: {DIM}{h['value']}{RESET}")
            if verbose:
                print(f"      Fix: {h['recommendation']}")
        print()

    # ── Bonus headers ─────────────────────────────────────────────────────────
    if results["bonus"]:
        print(f"{CYAN}{BOLD}⭐ Bonus Headers Present ({len(results['bonus'])}){RESET}")
        for h in results["bonus"]:
            print(f"  {CYAN}★{RESET} {h['header']}: {h['desc']}")
        print()

    # ── Priority fixes ────────────────────────────────────────────────────────
    high_missing = [h for h in results["missing"] if h["severity"] == "HIGH"]
    if high_missing:
        print(f"{RED}{BOLD}🚨 Top Priority Fixes:{RESET}")
        for h in high_missing:
            print(f"  → {h['recommendation']}")
        print()


# ─────────────────────────────────────────────────────────────────────────────
# Report writer
# ─────────────────────────────────────────────────────────────────────────────

def write_report(url: str, results: dict, status_code: int, output_path: str):
    score         = results["score"]
    grade, _      = get_grade(score)
    timestamp     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(output_path, "w") as f:
        f.write("=" * 62 + "\n")
        f.write("  HTTP Security Headers Analyzer — Report\n")
        f.write("=" * 62 + "\n")
        f.write(f"  Target    : {url}\n")
        f.write(f"  Date      : {timestamp}\n")
        f.write(f"  HTTP Code : {status_code}\n")
        f.write(f"  Score     : {score}/100  (Grade: {grade})\n")
        f.write("=" * 62 + "\n\n")

        f.write(f"SUMMARY\n{'─'*40}\n")
        f.write(f"  Secure headers    : {len(results['present'])}\n")
        f.write(f"  Misconfigured     : {len(results['misconfigured'])}\n")
        f.write(f"  Missing headers   : {len(results['missing'])}\n")
        f.write(f"  Info disclosure   : {len(results['disclosure'])}\n\n")

        if results["present"]:
            f.write(f"SECURE HEADERS\n{'─'*40}\n")
            for h in results["present"]:
                f.write(f"  [OK] {h['header']}\n")
                f.write(f"       {h['value'][:120]}\n\n")

        if results["misconfigured"]:
            f.write(f"MISCONFIGURED HEADERS\n{'─'*40}\n")
            for h in results["misconfigured"]:
                f.write(f"  [WARN] {h['header']}  [{h['severity']}]\n")
                f.write(f"         Current: {h['value'][:100]}\n")
                f.write(f"         Issue  : {h['issue']}\n")
                f.write(f"         Fix    : {h['recommendation']}\n\n")

        if results["missing"]:
            f.write(f"MISSING HEADERS\n{'─'*40}\n")
            for h in results["missing"]:
                f.write(f"  [MISS] {h['header']}  [{h['severity']}]\n")
                f.write(f"         {h['description']}\n")
                f.write(f"         Fix: {h['recommendation']}\n\n")

        if results["disclosure"]:
            f.write(f"INFORMATION DISCLOSURE\n{'─'*40}\n")
            for h in results["disclosure"]:
                f.write(f"  [INFO] {h['header']}: {h['value']}\n")
                f.write(f"         Fix: {h['recommendation']}\n\n")

    log_info(f"Report saved → {output_path}")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    banner()

    parser = argparse.ArgumentParser(
        description="HTTP Security Headers Analyzer — authorized testing only",
        epilog="Example: python3 headers_analyzer.py -u https://example.com"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url",
        help="Single target URL (e.g. https://example.com)")
    group.add_argument("--batch",
        help="Text file with one URL per line for bulk scanning")

    parser.add_argument("--output",
        default=None,
        help="Save report to file (auto-named if findings exist)")
    parser.add_argument("--timeout",
        type=int, default=10,
        help="Request timeout in seconds (default: 10)")
    parser.add_argument("--verbose", "-v",
        action="store_true",
        help="Show header values, descriptions, and fix recommendations")
    parser.add_argument("--json",
        default=None,
        help="Save raw results as JSON file")

    args = parser.parse_args()

    # ── Single URL mode ───────────────────────────────────────────────────────
    if args.url:
        url = normalize_url(args.url)
        log_info(f"Target  : {url}")
        log_step("Fetching headers...")

        headers, status, final_url, error = fetch_headers(url, args.timeout)

        if error:
            if error == "SSL_WARN":
                log_warn("SSL certificate issue — scanned with verification disabled.")
            else:
                log_error(f"Could not fetch headers: {error}")
                sys.exit(1)

        if not headers:
            log_error("No headers returned from target.")
            sys.exit(1)

        log_info(f"Got {len(headers)} headers — analyzing...\n")
        results = analyze_headers(headers)
        print_results(final_url, results, status, args.verbose)

        # Save report
        if args.output:
            write_report(final_url, results, status, args.output)
        elif results["missing"] or results["misconfigured"]:
            auto = f"headers_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            write_report(final_url, results, status, auto)

        if args.json:
            with open(args.json, "w") as jf:
                json.dump({"url": final_url, "status": status, "results": results}, jf, indent=2)
            log_info(f"JSON saved → {args.json}")

    # ── Batch mode ────────────────────────────────────────────────────────────
    elif args.batch:
        try:
            with open(args.batch) as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            log_error(f"Batch file not found: {args.batch}")
            sys.exit(1)

        if not urls:
            log_error("Batch file is empty.")
            sys.exit(1)

        log_info(f"Batch scan: {len(urls)} targets\n")
        all_results = []

        for url in urls:
            url = normalize_url(url)
            print(f"\n{'═'*56}")
            log_step(f"Scanning: {url}")
            headers, status, final_url, error = fetch_headers(url, args.timeout)

            if error and error != "SSL_WARN":
                log_error(f"Skipping — {error}")
                continue

            results = analyze_headers(headers)
            print_results(final_url, results, status, args.verbose)
            all_results.append({"url": final_url, "score": results["score"], "results": results})

        # Batch summary
        if all_results:
            print(f"\n{'═'*56}")
            print(f"{BOLD}BATCH SUMMARY{RESET}")
            print(f"{'─'*56}")
            for r in sorted(all_results, key=lambda x: x["score"]):
                grade, g_color = get_grade(r["score"])
                print(f"  {g_color}{grade}{RESET}  {r['score']:3d}/100  {r['url']}")

            avg = sum(r["score"] for r in all_results) // len(all_results)
            print(f"\n  Average score: {avg}/100")

        if args.output and all_results:
            with open(args.output, "w") as f:
                f.write("Batch Scan Report\n")
                f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                for r in all_results:
                    grade, _ = get_grade(r["score"])
                    f.write(f"[{grade}] {r['score']}/100  {r['url']}\n")
            log_info(f"Batch report saved → {args.output}")


if __name__ == "__main__":
    main()
