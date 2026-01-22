"""
methods.py
----------
Checks allowed HTTP methods.
Each risky method = finding.
"""

def scan_methods(client, target):
    findings = []

    try:
        r = client.get(target)
        allow = r.headers.get("Allow", "")
        for m in ["PUT", "DELETE", "TRACE", "OPTIONS"]:
            if m in allow:
                findings.append({
                    "issue": "Dangerous HTTP Method Enabled",
                    "severity": "Medium",
                    "method": m
                })
    except:
        pass

    return findings
