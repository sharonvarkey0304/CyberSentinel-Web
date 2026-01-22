"""
api_exposure.py
---------------
Detects exposed API endpoints.
Each accessible API = separate finding.
"""

def scan_api_exposure(client, endpoints):
    findings = []

    for ep in endpoints:
        try:
            r = client.get(ep["url"])
            if r.status_code == 200 and "application/json" in r.headers.get("Content-Type", ""):
                findings.append({
                    "issue": "Exposed API Endpoint",
                    "severity": "Low",
                    "endpoint": ep["url"]
                })
        except:
            continue

    return findings
