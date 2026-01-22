from fastapi import APIRouter
from api.database import SessionLocal
from api.models import Scan, Finding

router = APIRouter()

@router.get("/scans")
def list_scans():
    db = SessionLocal()
    scans = db.query(Scan).all()
    return {
        "items": [
            {
                "id": s.id,
                "target": s.target,
                "findings_total": s.findings_total
            }
            for s in scans
        ]
    }

@router.get("/scans/{scan_id}/findings")
def scan_findings(scan_id: int):
    db = SessionLocal()
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    return {
        "items": [
            {
                "issue": f.issue,
                "severity": f.severity,
                "endpoint": f.endpoint,
                "details": f.details,
                "score": f.score
            }
            for f in findings
        ]
    }
