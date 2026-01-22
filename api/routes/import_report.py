import json
from fastapi import APIRouter
from api.database import SessionLocal
from api.models import Scan, Finding

router = APIRouter()

@router.post("/import_report")
def import_report(path: str):
    db = SessionLocal()

    with open(path, "r") as f:
        report = json.load(f)

    scan = Scan(
        target=report["target"],
        findings_total=len(report["findings"])
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    for f in report["findings"]:
        finding = Finding(
            scan_id=scan.id,
            issue=f["issue"],
            severity=f["severity"],
            endpoint=f.get("endpoint", ""),
            details=f.get("details", ""),
            score=f.get("score", 0.0),
        )
        db.add(finding)

    db.commit()
    db.close()

    return {"imported": 1, "scan_id": scan.id}
