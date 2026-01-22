"""
Simple session-based authentication.
Educational, not production auth.
"""

from fastapi import Request
from fastapi.responses import RedirectResponse

# Hardcoded creds (acceptable for coursework)
DASHBOARD_USER = "admin"
DASHBOARD_PASS = "admin123"


def is_authenticated(request: Request) -> bool:
    return request.session.get("logged_in", False)


def require_auth(request: Request):
    if not is_authenticated(request):
        return RedirectResponse("/login", status_code=302)
