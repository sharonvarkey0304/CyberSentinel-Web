"""
http_client.py
--------------
Robust HTTP client wrapper for AutoPwn-Web.
Handles SPA targets (e.g. OWASP Juice Shop),
redirects, timeouts, and authentication safely.
"""

import requests
from requests.exceptions import RequestException


class HttpClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "AutoPwn-Web/1.0 (+Educational Pentest Tool)"
        })

    def get(self, url, params=None):
        """
        Safe GET request with redirect handling.
        Never crashes the scanner.
        """
        try:
            return self.session.get(
                url,
                params=params,
                timeout=10,
                allow_redirects=True
            )
        except RequestException as e:
            # Return dummy response-like object
            class Dummy:
                status_code = 0
                headers = {}
                text = ""
            return Dummy()

    def post(self, url, data=None, json=None):
        """
        Safe POST request.
        """
        try:
            return self.session.post(
                url,
                data=data,
                json=json,
                timeout=10,
                allow_redirects=True
            )
        except RequestException as e:
            raise ConnectionError(f"POST failed for {url}: {e}")

    def safe_probe(self, base_url: str):
        """
        Probe a stable endpoint instead of SPA root (/).
        Used to avoid Juice Shop root connection drops.
        """
        test_endpoints = [
            "/rest/products",
            "/api/Users",
            "/rest/user/login",
        ]

        for ep in test_endpoints:
            try:
                r = self.get(f"{base_url.rstrip('/')}{ep}")
                if r.status_code < 500:
                    return r
            except Exception:
                continue

        raise ConnectionError("No stable endpoint reachable on target")

    def login_juiceshop(self, base_url: str, email: str, password: str) -> bool:
        """
        Authenticate to OWASP Juice Shop.
        Tries JSON first, then form-encoded.
        """
        login_url = f"{base_url.rstrip('/')}/rest/user/login"

        # Attempt JSON login (preferred)
        try:
            r = self.post(login_url, json={
                "email": email,
                "password": password
            })
            if r.status_code in (200, 201) and r.text:
                return True
        except Exception:
            pass

        # Fallback to form login
        try:
            r = self.post(login_url, data={
                "email": email,
                "password": password
            })
            return r.status_code in (200, 201)
        except Exception:
            return False
