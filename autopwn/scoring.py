"""
scoring.py
----------
Deduplication and a simple CVSS-like scoring model.

Goal:
- Reduce noisy duplicates
- Produce 'Unique findings' count
- Give a numeric score for dashboards/reporting

Note: This is intentionally simplified for coursework.
"""

import hashlib


SEVERITY_BASE = {
    "Critical": 9.5,
    "High": 7.5,
    "Medium": 5.0,
    "Low": 2.5,
    "Info": 1.0
}


def fingerprint(f: dict) -> str:
    """
    Create a stable fingerprint to deduplicate findings.

    Dedup key includes:
      issue + endpoint + parameter + payload (if present)
    """
    issue = (f.get("issue") or "").strip().lower()
    endpoint = (f.get("endpoint") or "").strip().lower()
    parameter = (f.get("parameter") or "").strip().lower()
    payload = (f.get("payload") or "").strip().lower()

    raw = f"{issue}|{endpoint}|{parameter}|{payload}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def score_finding(f: dict) -> float:
    """
    Simple scoring:
    - base by severity
    - small boosts for exploitation hints (payload/parameter)
    """
    sev = f.get("severity", "Low")
    base = SEVERITY_BASE.get(sev, 2.5)

    boost = 0.0
    if f.get("payload"):
        boost += 0.3
    if f.get("parameter"):
        boost += 0.2
    if f.get("issue", "").lower().find("sql") != -1:
        boost += 0.5

    s = base + boost
    return round(min(s, 10.0), 1)


def dedupe_and_enrich(findings: list[dict]):
    """
    Returns:
      total_count, unique_findings (list)
    """
    seen = set()
    unique = []

    for f in findings:
        f["fingerprint"] = fingerprint(f)
        f["score"] = score_finding(f)

        if f["fingerprint"] in seen:
            continue
        seen.add(f["fingerprint"])
        unique.append(f)

    return len(findings), unique
