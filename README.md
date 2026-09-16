# SecScan — Website Security Header & TLS Checker

A command-line tool that audits a website's security posture by checking:
1. **HTTP security headers** (CSP, HSTS, X-Frame-Options, etc.)
2. **TLS/SSL configuration** (protocol version, certificate validity & expiry)

It then produces a simple A–F grade and a readable report (or JSON, for
scripting/automation).

Built as a personal project to apply concepts from network security and
DevSecOps coursework in a small, practical tool.

---

## Why these checks?

A missing header doesn't mean a site is "hacked" — it means one layer of
defense-in-depth is absent. This tool is intentionally framed around
*why* each check matters, not just whether it passes:

| Header | What it defends against |
|---|---|
| `Strict-Transport-Security` | SSL-stripping / protocol downgrade attacks on untrusted networks |
| `Content-Security-Policy` | Cross-Site Scripting (XSS) — restricts what scripts/resources the browser will run |
| `X-Frame-Options` | Clickjacking — stops the page being embedded in a malicious iframe |
| `X-Content-Type-Options` | MIME-sniffing attacks (browser misinterpreting file types) |
| `Referrer-Policy` | Leakage of sensitive URL data to third-party sites via the `Referer` header |
| `Permissions-Policy` | Limits blast radius (camera/mic/geolocation access) if the page is ever compromised |

TLS checks cover:
- **Protocol version** — flags deprecated TLS 1.0/1.1/SSLv2/SSLv3 (still enabled on some legacy systems, known to have exploitable weaknesses)
- **Certificate expiry** — flags certs that have expired or are expiring within 14 days
- **Certificate details** — subject and issuer, for a sanity check on trust chain

---

## Installation

```bash
git clone <your-repo-url>
cd secscan
pip install -r requirements.txt
```

Requires Python 3.9+.

## Usage

```bash
# Human-readable report
python3 -m secscan.cli https://example.com

# JSON output (for scripting / CI pipelines)
python3 -m secscan.cli https://example.com --json

# Save report to a file
python3 -m secscan.cli https://example.com --json --out report.json
```

You can omit `https://` — the tool will add it automatically.

## Example output

```
============================================================
  Security Scan Report — https://github.com
  Grade: A  (score: 90/100)
============================================================

HTTP Security Headers  (5 present / 6 checked)
  [PASS] Strict-Transport-Security: max-age=31536000; includeSubdomains; preload
  [PASS] Content-Security-Policy: default-src 'none'; base-uri 'self'; ...
  [PASS] X-Frame-Options: deny
  [PASS] X-Content-Type-Options: nosniff
  [PASS] Referrer-Policy: origin-when-cross-origin, strict-origin-when-cross-origin
  [FAIL] Permissions-Policy — missing
         why it matters: Lets a site explicitly disable browser features it
         doesn't need (camera, microphone, geolocation)...

TLS / Certificate
  [PASS] Protocol: TLSv1.3
  [PASS] Certificate valid, expires in 27 days
         subject: github.com, issuer: DigiCert Inc
```

More examples, including a lower-scoring site for contrast, are in
[`sample-reports/`](./sample-reports).

> **Note:** the sample reports in this repo were generated in a sandboxed
> dev environment that intercepts TLS traffic, so the certificate issuer
> shows as a placeholder rather than a real Certificate Authority. Reports
> generated on a normal machine will show the actual issuer (e.g. DigiCert,
> Let's Encrypt).

## Grading methodology

Starting from 100 points:
- **−10** per missing security header (6 checked → up to −60)
- **−20** if the negotiated TLS protocol is deprecated (TLS 1.0/1.1)
- **−30** if the TLS handshake / certificate verification fails outright
- **−40** if the certificate has expired
- **−10** if the certificate expires within 14 days

This is a simple, transparent scoring model — not an attempt to replicate
any commercial tool's proprietary algorithm. The goal is a quick, explainable
signal, not a definitive security rating.

## Code quality

This project's own code has been scanned with [Bandit](https://bandit.readthedocs.io/)
(a static analysis tool for common Python security issues). Result:

```
Test results:
    No issues identified.

Run metrics:
    Total issues (by severity):
        Undefined: 0
        Low: 0
        Medium: 0
        High: 0
```

Full output: [`bandit_report.txt`](./bandit_report.txt)

## Project structure

```
secscan/
├── secscan/
│   ├── __init__.py
│   ├── headers.py      # HTTP security header checks
│   ├── tls.py           # TLS/certificate checks
│   └── cli.py            # entry point, grading, report formatting
├── sample-reports/       # example scans (see note above)
├── requirements.txt
├── bandit_report.txt
└── README.md
```

## Limitations & possible extensions

This is a first pass, not a production security scanner. Known gaps and
ideas for future work:
- No DNS-based checks (SPF/DMARC/DKIM records)
- No check for weak cipher suites within a "good" protocol version
- No batch scanning (multiple URLs from a file)
- No HTML report output, only text/JSON
- Grading model is simple/linear rather than weighted by real-world risk

## Disclaimer

This tool only performs passive, read-only checks (HTTP header inspection
and a standard TLS handshake) — the same information your browser
already reads on every page load. It does not send exploit payloads
or attempt to bypass any security control. Still, only scan sites you
own or have permission to test.
