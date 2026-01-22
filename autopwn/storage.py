"""
storage.py
----------
SQLite persistence for scan history + findings.

Why:
- Evidence for coursework
- Trend analysis over time
- Enables dashboard/API
"""

import sqlite3
from pathlib import Path
from datetime import datetime


DB_PATH = Path("autopwn.db")


def _connect():
    return sqlite3.connect(DB_PATH)


def init_db():
    with _connect() as con:
        cur = con.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT NOT NULL,
            endpoints_count INTEGER NOT NULL,
            findings_total INTEGER NOT NULL,
            findings_unique INTEGER NOT NULL,
            severity_critical INTEGER NOT NULL,
            severity_high INTEGER NOT NULL,
            severity_medium INTEGER NOT NULL,
            severity_low INTEGER NOT NULL,
            report_path TEXT NOT NULL
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            issue TEXT NOT NULL,
            severity TEXT NOT NULL,
            score REAL NOT NULL,
            endpoint TEXT,
            parameter TEXT,
            payload TEXT,
            details TEXT,
            fingerprint TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
        """)

        con.commit()


def insert_scan(summary: dict) -> int:
    """
    summary keys:
      target, started_at, finished_at, endpoints_count,
      findings_total, findings_unique,
      severity_critical, severity_high, severity_medium, severity_low,
      report_path
    """
    init_db()
    with _connect() as con:
        cur = con.cursor()
        cur.execute("""
        INSERT INTO scans (
            target, started_at, finished_at, endpoints_count,
            findings_total, findings_unique,
            severity_critical, severity_high, severity_medium, severity_low,
            report_path
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (
            summary["target"], summary["started_at"], summary["finished_at"],
            summary["endpoints_count"],
            summary["findings_total"], summary["findings_unique"],
            summary["severity_critical"], summary["severity_high"],
            summary["severity_medium"], summary["severity_low"],
            summary["report_path"]
        ))
        con.commit()
        return int(cur.lastrowid)


def insert_findings(scan_id: int, findings: list[dict]):
    init_db()
    now = datetime.now().isoformat(timespec="seconds")
    with _connect() as con:
        cur = con.cursor()
        for f in findings:
            cur.execute("""
            INSERT INTO findings (
                scan_id, issue, severity, score,
                endpoint, parameter, payload, details,
                fingerprint, created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?)
            """, (
                scan_id,
                f.get("issue", ""),
                f.get("severity", "Low"),
                float(f.get("score", 0.0)),
                f.get("endpoint"),
                f.get("parameter"),
                f.get("payload"),
                f.get("details"),
                f.get("fingerprint", ""),
                now
            ))
        con.commit()


def list_scans(limit: int = 50):
    init_db()
    with _connect() as con:
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(r) for r in cur.fetchall()]


def get_scan(scan_id: int):
    init_db()
    with _connect() as con:
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = cur.fetchone()
        return dict(row) if row else None


def get_findings(scan_id: int):
    init_db()
    with _connect() as con:
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY score DESC", (scan_id,))
        return [dict(r) for r in cur.fetchall()]
