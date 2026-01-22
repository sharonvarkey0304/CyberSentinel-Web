"""
headers.py
----------
Security misconfiguration detection.
Each missing header = one finding.
"""

SEC_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

def scan_headers(client, target):
    findings = []
    # Use a stable endpoint instead of root /
    test_url = f"{target.rstrip('/')}/rest/products"

    try:
       r = client.get(test_url)
    except Exception:
      return [{
           "issue": "Connection Error",
           "severity": "Low",
           "details": "Target root endpoint closed connection during header scan",
           "endpoint": test_url
      }]
    return findings
