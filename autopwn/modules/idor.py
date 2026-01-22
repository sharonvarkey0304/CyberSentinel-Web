"""
idor.py
-------
Heuristic IDOR detection.
Each ID-like parameter = finding.
"""

ID_PARAMS = ["id", "user", "userId", "accountId", "basketId"]

def scan_idor(endpoints):
    findings = []

    for ep in endpoints:
        for p in ep.get("params", []):
            if p.lower() in ID_PARAMS:
                findings.append({
                    "issue": "Potential IDOR",
                    "severity": "Medium",
                    "endpoint": ep["url"],
                    "parameter": p
                })

    return findings
