"""
tls.py — checks a site's TLS/SSL configuration: certificate validity,
expiry, and protocol version.

How this works, conceptually:
We open a raw socket to the host on port 443, wrap it in an SSL context,
and complete a TLS handshake. If the handshake succeeds, we can read the
negotiated protocol version and pull the certificate details from it.
This is the same first step your browser does before showing the padlock icon.
"""

import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse


# TLS 1.0 and 1.1 are deprecated (known weaknesses, disabled by major browsers
# since ~2020). A "good" site should only be negotiating 1.2 or 1.3.
WEAK_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}


def get_hostname(url: str) -> str:
    """Extracts just the hostname from a full URL, e.g. https://x.com/a -> x.com"""
    parsed = urlparse(url)
    return parsed.hostname or url


def check_tls(url: str, port: int = 443, timeout: int = 8) -> dict:
    """
    Returns a dict report:
    {
        "hostname": ...,
        "connected": bool,
        "protocol": "TLSv1.3" etc,
        "protocol_is_weak": bool,
        "cert_subject": ...,
        "cert_issuer": ...,
        "cert_expires": datetime,
        "days_until_expiry": int,
        "expired": bool,
        "error": str or None,
    }
    """
    hostname = get_hostname(url)
    report = {
        "hostname": hostname,
        "connected": False,
        "protocol": None,
        "protocol_is_weak": None,
        "cert_subject": None,
        "cert_issuer": None,
        "cert_expires": None,
        "days_until_expiry": None,
        "expired": None,
        "error": None,
    }

    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                report["connected"] = True
                report["protocol"] = ssock.version()
                report["protocol_is_weak"] = ssock.version() in WEAK_PROTOCOLS

                cert = ssock.getpeercert()

                # Subject/issuer come back as nested tuples, e.g.
                # (((‘commonName’, ‘github.com’),),) — flatten for readability
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                report["cert_subject"] = subject.get("commonName", "unknown")
                report["cert_issuer"] = issuer.get("organizationName", "unknown")

                expires_str = cert["notAfter"]  # e.g. 'Jun  4 12:00:00 2027 GMT'
                expires = datetime.strptime(expires_str, "%b %d %H:%M:%S %Y %Z")
                expires = expires.replace(tzinfo=timezone.utc)
                report["cert_expires"] = expires

                days_left = (expires - datetime.now(timezone.utc)).days
                report["days_until_expiry"] = days_left
                report["expired"] = days_left < 0

    except ssl.SSLCertVerificationError as e:
        report["error"] = f"Certificate verification failed: {e.reason}"
    except socket.timeout:
        report["error"] = "Connection timed out"
    except socket.gaierror:
        report["error"] = "Could not resolve hostname"
    except ConnectionRefusedError:
        report["error"] = "Connection refused (port 443 may be closed)"
    except Exception as e:
        report["error"] = f"Unexpected error: {e}"

    return report


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    result = check_tls(target)
    print(f"\nTLS check for: {result['hostname']}\n")
    if result["error"]:
        print(f"  ERROR: {result['error']}")
    else:
        weak_flag = " (WEAK — deprecated protocol)" if result["protocol_is_weak"] else ""
        print(f"  Protocol: {result['protocol']}{weak_flag}")
        print(f"  Cert subject: {result['cert_subject']}")
        print(f"  Cert issuer: {result['cert_issuer']}")
        print(f"  Expires: {result['cert_expires']} ({result['days_until_expiry']} days left)")
        if result["expired"]:
            print("  ⚠ CERTIFICATE HAS EXPIRED")
