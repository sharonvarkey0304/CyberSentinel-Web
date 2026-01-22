from datetime import datetime

from autopwn.http_client import HttpClient
from autopwn.crawler import crawl
from autopwn.extractor import extract_endpoints

from autopwn.modules.xss import scan_xss
from autopwn.modules.sqli import scan_sqli
from autopwn.modules.csrf import scan_csrf
from autopwn.modules.headers import scan_headers
from autopwn.modules.idor import scan_idor
from autopwn.modules.api_exposure import scan_api_exposure
from autopwn.modules.methods import scan_methods

from autopwn.scoring import dedupe_and_enrich
from autopwn.storage import insert_scan, insert_findings

from reports.report_builder import build_report


def run_scan(
    target: str,
    auth_email: str | None = None,
    auth_password: str | None = None
):
    started = datetime.now()
    print(f"[+] Target: {target}")
    client = HttpClient()

    # Optional auth
    authed = False
    if auth_email and auth_password:
        authed = client.login_juiceshop(target, auth_email, auth_password)
        print(f"[+] Auth enabled: {authed}")

    # Crawl (SPA pages may be limited)
    pages = crawl(client, target)
    print(f"[+] Pages crawled: {len(pages)}")

    endpoints = extract_endpoints(pages)

    # Seeded endpoints for Juice Shop SPA
    seeded = [
        {"url": f"{target}/rest/products/search", "method": "GET", "params": ["q"]},
        {"url": f"{target}/rest/products", "method": "GET", "params": ["limit"]},
        {"url": f"{target}/api/Users", "method": "GET", "params": ["email"]},
        {"url": f"{target}/rest/user/login", "method": "POST", "params": ["email", "password"]},
        {"url": f"{target}/rest/user/whoami", "method": "GET", "params": ["token"]},
        {"url": f"{target}/rest/basket", "method": "GET", "params": ["id"]},
        {"url": f"{target}/api/Feedbacks", "method": "GET", "params": ["comment"]},
        {"url": f"{target}/rest/orders", "method": "GET", "params": ["orderId"]},
    ]

    # Auth-only (best-effort — some versions vary)
    if authed:
        seeded += [
            {"url": f"{target}/rest/basket", "method": "GET", "params": ["id"]},
            {"url": f"{target}/rest/basket/items", "method": "GET", "params": ["basketId"]},
            {"url": f"{target}/rest/wallet/balance", "method": "GET", "params": ["userId"]},
        ]

    endpoints.extend(seeded)
    print(f"[+] Endpoints found (including seeded): {len(endpoints)}")

    # Run modules
    findings = []
    findings += scan_headers(client, target)
    findings += scan_methods(client, target)
    findings += scan_idor(endpoints)
    findings += scan_api_exposure(client, endpoints)
    findings += scan_methods(client, target)
    findings += scan_csrf(endpoints)
    findings += scan_sqli(client, endpoints)
    findings += scan_xss(client, endpoints)

    total_count, unique_findings = dedupe_and_enrich(findings)

    # Report from UNIQUE findings (cleaner)
    report_file = build_report(target, endpoints, unique_findings)

    # Severity summary for DB
    sev_crit = sum(1 for f in unique_findings if f.get("severity") == "Critical")
    sev_high = sum(1 for f in unique_findings if f.get("severity") == "High")
    sev_med = sum(1 for f in unique_findings if f.get("severity") == "Medium")
    sev_low = sum(1 for f in unique_findings if f.get("severity") == "Low")

    finished = datetime.now()

    print(f"[+] Total findings: {total_count}")
    print(f"[+] Unique findings: {len(unique_findings)}")
    print(f"[+] Report saved: {report_file}")

    # Save to SQLite
    scan_id = insert_scan({
        "target": target,
        "started_at": started.isoformat(timespec="seconds"),
        "finished_at": finished.isoformat(timespec="seconds"),
        "endpoints_count": len(endpoints),
        "findings_total": total_count,
        "findings_unique": len(unique_findings),
        "severity_critical": sev_crit,
        "severity_high": sev_high,
        "severity_medium": sev_med,
        "severity_low": sev_low,
        "report_path": report_file
    })
    insert_findings(scan_id, unique_findings)

    print(f"[+] Saved scan to DB: autopwn.db (scan_id={scan_id})")
