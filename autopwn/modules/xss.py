"""
xss.py
------
Reflected XSS detection using multiple payloads.
Each reflected payload = separate finding.
"""

XSS_PAYLOADS = [
    "XSS_PAYLOAD_SVG_<svg/onload=alert(1)>",
    "XSS_PAYLOAD_IMG_<img src=x onerror=alert(1)>",
    "XSS_PAYLOAD_SCRIPT_\"><script>alert(1)</script>"
]

def scan_xss(client, endpoints):
    findings = []

    for ep in endpoints:
        if not ep["params"]:
            continue

        for param in ep["params"]:
            for payload in XSS_PAYLOADS:
                data = {p: "test" for p in ep["params"]}
                data[param] = payload

                try:
                    if ep["method"] == "GET":
                        r = client.get(ep["url"], params=data)
                    else:
                        r = client.post(ep["url"], data=data)

                    if payload in r.text or param in r.text:
                        findings.append({
                            "issue": "Reflected XSS",
                            "severity": "High",
                            "endpoint": ep["url"],
                            "parameter": param,
                            "payload": payload
                        })
                except Exception:
                    continue

    return findings
