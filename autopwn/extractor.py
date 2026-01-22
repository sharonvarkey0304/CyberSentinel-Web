"""
extractor.py
-------------
Extracts endpoints, parameters, and forms.

Why:
- Modern apps use forms & POST requests
- Without this, Juice Shop will show no findings
"""

from urllib.parse import urlparse, parse_qs

def extract_endpoints(pages):
    endpoints = []

    for url, soup in pages:
        # URL query parameters
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if qs:
            endpoints.append({
                "url": parsed.scheme + "://" + parsed.netloc + parsed.path,
                "method": "GET",
                "params": list(qs.keys())
            })

        # HTML forms
        for form in soup.select("form"):
            action = form.get("action") or url
            method = form.get("method", "get").upper()
            params = []

            for inp in form.select("input[name]"):
                params.append(inp["name"])

            endpoints.append({
                "url": action,
                "method": method,
                "params": params
            })

    return endpoints
