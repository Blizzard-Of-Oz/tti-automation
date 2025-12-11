from typing import Dict

from sqlalchemy.orm import Session

from . import models


def match_client_vulnerabilities(db: Session, client_id: int) -> Dict[str, int]:
    """
    For a given client:
    - Look at all assets and their software
    - For each software, find VulnerabilityAffect rows with matching vendor/product
    - Create ClientVulnerability entries if they do not already exist
    Returns a dict with some stats.
    """
    client = db.query(models.Client).filter(models.Client.id == client_id).first()
    if not client:
        raise ValueError("Client not found")

    assets = (
        db.query(models.Asset)
        .filter(models.Asset.client_id == client_id)
        .all()
    )

    assets_seen = len(assets)
    software_seen = 0
    created = 0
    skipped_existing = 0

    for asset in assets:
        for sw in asset.software:
            software_seen += 1

            # Basic normalized vendor/product
            vendor = (sw.vendor or "").lower()
            product = (sw.product or "").lower()
            if not vendor or not product:
                continue

            # Find all affects with same vendor and product
            affects = (
                db.query(models.VulnerabilityAffect)
                .filter(
                    models.VulnerabilityAffect.vendor.ilike(vendor),
                    models.VulnerabilityAffect.product.ilike(product),
                )
                .all()
            )

            for affect in affects:
                vuln = affect.vulnerability

                # Check if we already have a match for this combo
                existing = (
                    db.query(models.ClientVulnerability)
                    .filter(
                        models.ClientVulnerability.client_id == client_id,
                        models.ClientVulnerability.vulnerability_id == vuln.id,
                        models.ClientVulnerability.asset_id == asset.id,
                        models.ClientVulnerability.software_id == sw.id,
                    )
                    .first()
                )
                if existing:
                    skipped_existing += 1
                    continue

                cv = models.ClientVulnerability(
                    client_id=client_id,
                    vulnerability_id=vuln.id,
                    asset_id=asset.id,
                    software_id=sw.id,
                    status="open",
                )
                db.add(cv)
                created += 1

    db.commit()

    return {
        "assets_seen": assets_seen,
        "software_seen": software_seen,
        "matches_created": created,
        "matches_skipped_existing": skipped_existing,
    }
