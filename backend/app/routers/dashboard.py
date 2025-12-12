from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from ..db import get_db
from .. import models

router = APIRouter(
    prefix="/dashboard",
    tags=["dashboard"],
)


@router.get("/summary")
def get_dashboard_summary(db: Session = Depends(get_db)):
    """
    High-level JSON dashboard for the TTI Automation backend.

    Returns total objects and open match counts grouped by severity.
    """

    # Basic totals
    total_clients = db.query(func.count(models.Client.id)).scalar() or 0
    total_assets = db.query(func.count(models.Asset.id)).scalar() or 0
    total_software = db.query(func.count(models.Software.id)).scalar() or 0
    total_vulns = db.query(func.count(models.Vulnerability.id)).scalar() or 0
    total_matches = db.query(func.count(models.ClientVulnerability.id)).scalar() or 0

    # Open matches by severity (join client_vulnerabilities + vulnerabilities)
    severity_col = func.coalesce(models.Vulnerability.severity, "UNKNOWN")
    rows = (
        db.query(
            severity_col,
            func.count(models.ClientVulnerability.id),
        )
        .join(
            models.Vulnerability,
            models.ClientVulnerability.vulnerability_id == models.Vulnerability.id,
        )
        .filter(models.ClientVulnerability.status == "open")
        .group_by(severity_col)
        .all()
    )

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for severity_value, count in rows:
        key = (severity_value or "UNKNOWN").upper()
        if key not in severity_counts:
            key = "UNKNOWN"
        severity_counts[key] = count

    return {
        "totals": {
            "clients": total_clients,
            "assets": total_assets,
            "software": total_software,
            "vulnerabilities": total_vulns,
            "matches": total_matches,
        },
        "open_matches_by_severity": severity_counts,
    }
