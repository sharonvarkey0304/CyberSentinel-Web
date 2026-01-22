"""
csrf.py
-------
Detects missing CSRF tokens in POST forms.
"""

def scan_csrf(endpoints):
    findings = []

    for ep in endpoints:
        if ep["method"] == "POST":
            if not any("csrf" in p.lower() for p in ep["params"]):
                findings.append({
                    "issue": "Missing CSRF Protection",
                    "severity": "Medium",
                    "endpoint": ep["url"],
                    "parameters": ep["params"]
                })

    return findings
