"""
headers.py — checks a site's HTTP response headers against a set of
well-known security headers.

Why this matters (for your README / your own understanding):
Each of these headers tells the browser how to behave defensively.
A missing header doesn't mean a site is "hacked" — it means one layer
of defense-in-depth is absent. That's the framing security analysts use.
"""

import requests


# Each entry: header name -> (why it matters, what a "good" value looks like)
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "why": "Forces browsers to only use HTTPS for this site, even if a user "
               "types http:// or clicks an http link. Without it, an attacker on "
               "the same network (e.g. public wifi) can downgrade the connection "
               "to plain HTTP and intercept traffic (SSL stripping).",
        "good_example": "max-age=31536000; includeSubDomains",
    },
    "Content-Security-Policy": {
        "why": "Restricts which sources of scripts, styles, images, etc. the "
               "browser is allowed to load. This is the single biggest defense "
               "against Cross-Site Scripting (XSS) — even if an attacker injects "
               "a <script> tag, CSP can stop the browser from running it.",
        "good_example": "default-src 'self'",
    },
    "X-Frame-Options": {
        "why": "Prevents the page from being loaded inside an <iframe> on another "
               "site. Without this, an attacker can overlay invisible buttons on "
               "top of your real site (clickjacking) and trick users into clicking "
               "things like 'Transfer money' without realizing it.",
        "good_example": "DENY or SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "why": "Stops the browser from trying to 'guess' a file's type (MIME "
               "sniffing). Without it, a browser might execute a file uploaded as "
               "an image as if it were JavaScript.",
        "good_example": "nosniff",
    },
    "Referrer-Policy": {
        "why": "Controls how much of the current page's URL gets leaked to other "
               "sites when a user clicks a link. Without it, sensitive info in "
               "URLs (session tokens, search queries) can leak to third parties.",
        "good_example": "strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "why": "Lets a site explicitly disable browser features it doesn't need "
               "(camera, microphone, geolocation). Without it, if the page is "
               "ever compromised by injected code, that code has access to "
               "whatever the browser allows by default.",
        "good_example": "geolocation=(), camera=(), microphone=()",
    },
}


def fetch_headers(url: str, timeout: int = 8):
    """
    Makes a GET request and returns the response headers.
    Raises requests exceptions on network failure — caller handles those.
    """
    response = requests.get(url, timeout=timeout, allow_redirects=True)
    return response.headers, response.url  # response.url = final URL after redirects


def check_headers(url: str) -> dict:
    """
    Returns a dict report:
    {
        "url": final url after redirects,
        "present": {header: value, ...},
        "missing": {header: why_it_matters, ...},
    }
    """
    headers, final_url = fetch_headers(url)

    present = {}
    missing = {}

    for header_name, info in SECURITY_HEADERS.items():
        if header_name in headers:
            present[header_name] = headers[header_name]
        else:
            missing[header_name] = info["why"]

    return {
        "url": final_url,
        "present": present,
        "missing": missing,
    }


if __name__ == "__main__":
    # Quick manual test — run: python3 headers.py
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    result = check_headers(target)
    print(f"\nChecked: {result['url']}\n")
    print(f"Present ({len(result['present'])}):")
    for h, v in result["present"].items():
        print(f"  [OK] {h}: {v}")
    print(f"\nMissing ({len(result['missing'])}):")
    for h, why in result["missing"].items():
        print(f"  [MISSING] {h}")
