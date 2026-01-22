"""
sqli.py
-------
Error-based SQL Injection detection.
Each parameter tested independently.
"""

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "'"
]

ERROR_SIGNS = [
    "sql syntax",
    "mysql",
    "sqlite",
    "postgres",
    "syntax error"
]

def scan_sqli(client, endpoints):
    findings = []

    for ep in endpoints:
        if ep["method"] != "GET":
            continue

        for param in ep["params"]:
            for payload in SQLI_PAYLOADS:
                try:
                    r = client.get(ep["url"], params={param: payload})

                    if any(e in r.text.lower() for e in ERROR_SIGNS):
                        findings.append({
                            "issue": "SQL Injection",
                            "severity": "Critical",
                            "endpoint": ep["url"],
                            "parameter": param,
                            "payload": payload
                        })
                except Exception:
                    continue

    return findings
