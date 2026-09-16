"""
cli.py — the entry point. Ties headers.py and tls.py together,
computes a simple grade, and prints a readable report (or JSON).

Usage:
    python3 -m secscan.cli https://example.com
    python3 -m secscan.cli https://example.com --json
    python3 -m secscan.cli https://example.com --json --out report.json
"""

import argparse
import json
import sys
from datetime import datetime, timezone

from secscan.headers import check_headers, SECURITY_HEADERS
from secscan.tls import check_tls


def compute_grade(header_result: dict, tls_result: dict) -> str:
    """
    Simple scoring, loosely inspired by securityheaders.com's approach:
    Start at 100, deduct points for each problem found.

    This is intentionally simple and transparent — for your README, it's
    worth explaining you chose clarity over trying to exactly match a
    commercial tool's proprietary scoring.
    """
    score = 100

    # -10 per missing header (6 possible headers -> up to -60)
    score -= 10 * len(header_result["missing"])

    if tls_result.get("error"):
        score -= 30
    else:
        if tls_result.get("protocol_is_weak"):
            score -= 20
        if tls_result.get("expired"):
            score -= 40
        elif tls_result.get("days_until_expiry", 999) < 14:
            score -= 10  # expiring soon

    score = max(score, 0)

    if score >= 90:
        return "A", score
    elif score >= 75:
        return "B", score
    elif score >= 60:
        return "C", score
    elif score >= 40:
        return "D", score
    else:
        return "F", score


def run_scan(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url  # be forgiving if user forgets the scheme

    header_result = check_headers(url)
    tls_result = check_tls(url)
    grade, score = compute_grade(header_result, tls_result)

    return {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "target": url,
        "grade": grade,
        "score": score,
        "headers": header_result,
        "tls": tls_result,
    }


def print_human_report(result: dict):
    print(f"\n{'=' * 60}")
    print(f"  Security Scan Report — {result['target']}")
    print(f"  Grade: {result['grade']}  (score: {result['score']}/100)")
    print(f"{'=' * 60}\n")

    h = result["headers"]
    print(f"HTTP Security Headers  ({len(h['present'])} present / "
          f"{len(h['present']) + len(h['missing'])} checked)")
    for name, value in h["present"].items():
        display = value if len(value) < 70 else value[:67] + "..."
        print(f"  [PASS] {name}: {display}")
    for name, why in h["missing"].items():
        print(f"  [FAIL] {name} — missing")
        print(f"         why it matters: {why}")
    print()

    t = result["tls"]
    print("TLS / Certificate")
    if t["error"]:
        print(f"  [FAIL] {t['error']}")
    else:
        proto_flag = "[FAIL]" if t["protocol_is_weak"] else "[PASS]"
        print(f"  {proto_flag} Protocol: {t['protocol']}")

        if t["expired"]:
            print(f"  [FAIL] Certificate EXPIRED on {t['cert_expires']}")
        elif t["days_until_expiry"] < 14:
            print(f"  [WARN] Certificate expires soon: {t['days_until_expiry']} days left")
        else:
            print(f"  [PASS] Certificate valid, expires in {t['days_until_expiry']} days")

        print(f"         subject: {t['cert_subject']}, issuer: {t['cert_issuer']}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Check a website's HTTP security headers and TLS/SSL configuration."
    )
    parser.add_argument("url", help="Target URL, e.g. https://example.com")
    parser.add_argument("--json", action="store_true", help="Output as JSON instead of a human-readable report")
    parser.add_argument("--out", metavar="FILE", help="Write the report to a file instead of stdout")

    args = parser.parse_args()

    try:
        result = run_scan(args.url)
    except Exception as e:
        print(f"Error scanning {args.url}: {e}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        output = json.dumps(result, indent=2, default=str)
        if args.out:
            with open(args.out, "w") as f:
                f.write(output)
            print(f"Report written to {args.out}")
        else:
            print(output)
    else:
        if args.out:
            import io
            import contextlib
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                print_human_report(result)
            with open(args.out, "w") as f:
                f.write(buf.getvalue())
            print(f"Report written to {args.out}")
        else:
            print_human_report(result)


if __name__ == "__main__":
    main()
