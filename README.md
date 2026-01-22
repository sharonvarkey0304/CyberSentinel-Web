# AutoPwn-Web (Master-Level Automated Web Pentest Tool)

AutoPwn-Web is an educational automated penetration testing framework designed for **authorized targets only** (e.g., OWASP Juice Shop).  
It demonstrates end-to-end automation: reconnaissance, modular vulnerability checks, reporting, persistence, scheduling, and an API for dashboards.

## Legal & Ethical Notice
Use this tool **only** on systems you own or have explicit permission to test.  
This project is designed for coursework/lab environments.

---

## Key Features
- **SPA-aware scanning** using seeded endpoint discovery for modern apps (Juice Shop)
- Modular checks:
  - Reflected XSS (multi-payload, per-parameter)
  - SQL Injection (error-based heuristics)
  - Missing CSRF protection
  - Missing security headers
  - Potential IDOR (heuristic indicators)
  - Exposed API endpoints
  - HTTP method misconfiguration (best-effort)
- **Deduplication + scoring** (simple CVSS-like scoring)
- **HTML report** per scan:
  - Timestamped filename (no overwrites)
  - Safe HTML escaping (payloads never execute)
  - Charts: severity distribution + issue distribution
- **SQLite persistence** (`autopwn.db`):
  - Scan history and findings evidence
- **FastAPI API** for reporting/dashboard integration
- **Daily scheduling** via cron script

---

## Project Structure
