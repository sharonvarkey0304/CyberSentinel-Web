from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from autopwn.storage import list_scans, get_findings
from dashboard.auth import require_auth

router = APIRouter()
templates = Jinja2Templates(directory="dashboard/templates")


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@router.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    if username == "admin" and password == "admin123":
        request.session["logged_in"] = True
        return RedirectResponse("/dashboard", status_code=302)
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": "Invalid credentials"}
    )


@router.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=302)


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    auth = require_auth(request)
    if auth:
        return auth

    scans = list_scans(limit=50)
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "scans": scans}
    )


@router.get("/dashboard/scan/{scan_id}", response_class=HTMLResponse)
def scan_detail(request: Request, scan_id: int):
    auth = require_auth(request)
    if auth:
        return auth

    findings = get_findings(scan_id)
    return templates.TemplateResponse(
        "scan.html",
        {"request": request, "findings": findings, "scan_id": scan_id}
    )
