# 🛡️ HTTP Security Headers Analyzer

A command-line tool that analyzes the HTTP security headers of any website and produces a detailed security assessment with a score, grade, and prioritized remediation steps.

Built for web application penetration testing, security audits, bug bounty recon, and learning about defensive web security.

---

## ⚠️ Legal Disclaimer

> Use this tool **only** on websites you own or have explicit written permission to test.  
> This tool sends a **single HTTP GET request** — it does not crawl, brute-force, or stress-test targets.

---

## What It Checks

| Header | Severity | What It Protects Against |
|--------|----------|--------------------------|
| Content-Security-Policy (CSP) | 🔴 HIGH | XSS, data injection attacks |
| Strict-Transport-Security (HSTS) | 🔴 HIGH | Protocol downgrade, MITM attacks |
| X-Frame-Options | 🟡 MEDIUM | Clickjacking attacks |
| X-Content-Type-Options | 🟡 MEDIUM | MIME-type sniffing attacks |
| Permissions-Policy | 🟡 MEDIUM | Feature abuse (camera, mic, GPS) |
| Referrer-Policy | 🟢 LOW | Referrer information leakage |
| Cache-Control | 🟢 LOW | Sensitive data cached in browser |
| X-XSS-Protection | 🟢 LOW | Legacy XSS filter (older browsers) |
| Cross-Origin-Opener-Policy | 🟢 LOW | XS-Leaks, cross-origin attacks |
| Cross-Origin-Resource-Policy | 🟢 LOW | Unauthorized resource loading |
| Cross-Origin-Embedder-Policy | 🟢 LOW | Browser isolation bypass |
| Server (disclosure) | ℹ️ INFO | Server fingerprinting |
| X-Powered-By (disclosure) | ℹ️ INFO | Technology fingerprinting |

---

## Features

- **Security score out of 100** with A+ to F grading
- **Three finding categories:** Present ✅ / Misconfigured ⚠️ / Missing ❌
- **Information disclosure detection** — flags Server and X-Powered-By leakage
- **Priority fix recommendations** — highlights HIGH severity issues first
- **Batch scanning** — scan multiple sites from a text file
- **Report export** — save findings as `.txt` or `.json`
- **Verbose mode** — shows header values, descriptions, and exact fix commands
- **SSL fallback** — handles SSL certificate errors gracefully

---

## Installation

```bash
git clone https://github.com/yourusername/cybersecurity-portfolio.git
cd cybersecurity-portfolio/headers-analyzer
pip install -r requirements.txt
```

**Requirements:** Python 3.8+

---

## Usage

### Scan a single site
```bash
python3 headers_analyzer.py -u https://example.com
```

### Verbose mode (show values + fix recommendations)
```bash
python3 headers_analyzer.py -u https://example.com --verbose
```

### Save report to file
```bash
python3 headers_analyzer.py -u https://example.com --output report.txt
```

### Batch scan multiple sites
```bash
python3 headers_analyzer.py --batch sites.txt --output batch_report.txt
```

### Export raw results as JSON
```bash
python3 headers_analyzer.py -u https://example.com --json results.json
```

### sites.txt format (for batch scanning)
```
https://site1.com
https://site2.com
https://site3.com
```

---

## Example Output

```
╔══════════════════════════════════════════════════════╗
║   HTTP Security Headers Analyzer  v1.0              ║
╚══════════════════════════════════════════════════════╝

[+] Target  : https://example.com
[→] Fetching headers...
[+] Got 18 headers — analyzing...

────────────────────────────────────────────────────────
  Target : https://example.com
  Status : HTTP 200
  Score  : 65/100  (Grade: C)
────────────────────────────────────────────────────────

✅ Secure Headers Present (5)
  ✓ Strict-Transport-Security (HSTS)
  ✓ X-Frame-Options
  ✓ X-Content-Type-Options
  ✓ Referrer-Policy
  ✓ Cache-Control

⚠️  Misconfigured Headers (1)
  ⚠ Content-Security-Policy (CSP)  [HIGH]
      Current : default-src 'none'; script-src 'unsafe-inline'
      Issue   : Contains potentially unsafe directive

❌ Missing Headers (4)
  ✗ Permissions-Policy  [MEDIUM]
  ✗ Cross-Origin-Opener-Policy  [LOW]
  ✗ Cross-Origin-Resource-Policy  [LOW]
  ✗ Cross-Origin-Embedder-Policy  [LOW]

🔍 Information Disclosure (1)
  ℹ Server: nginx/1.18.0

🚨 Top Priority Fixes:
  → Tighten CSP — remove 'unsafe-inline' from script-src
```

---

## Scoring System

| Score | Grade | Meaning |
|-------|-------|---------|
| 90-100 | A+ | Excellent security posture |
| 80-89 | A | Strong configuration |
| 70-79 | B | Good, minor gaps |
| 60-69 | C | Average, several improvements needed |
| 40-59 | D | Weak, significant gaps |
| 0-39 | F | Poor — major headers missing |

---

## Real-World Results (examples)

| Site | Score | Notable |
|------|-------|---------|
| github.com | 60/100 C | Missing COOP, CORP, COEP |
| Well-configured app | 85/100 A | Good HSTS + CSP |
| Typical small business site | 10/100 F | Most headers missing |

---

## Use Cases

- **Bug bounty recon** — quickly check if a target has weak headers before deeper testing
- **Web app pentesting** — include header analysis in engagement reports
- **Developer audit** — check your own app's security posture before deployment
- **Learning** — understand what each security header does and why it matters

---

## References

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)
- [PortSwigger: Clickjacking](https://portswigger.net/web-security/clickjacking)
- [MDN: HTTP Security Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#security)
- [securityheaders.com](https://securityheaders.com) — online reference

---

## License

MIT License — see [LICENSE](../LICENSE) for details.
