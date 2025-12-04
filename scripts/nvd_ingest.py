import os
from datetime import datetime, timedelta
from typing import List, Tuple, Optional

import requests
from dotenv import load_dotenv

from backend.app.db import SessionLocal
from backend.app.models import (
    SourceDocument,
    Vulnerability,
    VulnerabilityAffect,
)


# --- Helpers for parsing NVD data ---


def get_nvd_api_key() -> Optional[str]:
    load_dotenv()
    return os.getenv("NVD_API_KEY") or None


def build_nvd_url(days_back: int = 1) -> str:
    """
    Build NVD API URL for CVEs published in the last `days_back` days.
    Uses the 2.0 CVE API.
    """
    end = datetime.utcnow()
    start = end - timedelta(days=days_back)

    # NVD expects ISO 8601 with milliseconds and Z
    pub_start = start.strftime("%Y-%m-%dT00:00:00.000Z")
    pub_end = end.strftime("%Y-%m-%dT23:59:59.000Z")

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    return f"{base_url}?pubStartDate={pub_start}&pubEndDate={pub_end}&startIndex=0"


def fetch_nvd_data(days_back: int = 1) -> dict:
    url = build_nvd_url(days_back)
    headers = {}
    api_key = get_nvd_api_key()
    if api_key:
        headers["apiKey"] = api_key

    print(f"[NVD] Fetching CVEs from URL: {url}")
    resp = requests.get(url, headers=headers, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    print(f"[NVD] Received {len(data.get('vulnerabilities', []))} items")
    return data


def parse_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        # NVD uses ISO 8601 with fractional seconds, e.g. "2024-05-10T16:34:53.457"
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def extract_description(cve: dict) -> Tuple[str, str]:
    """
    Returns (title, description) from NVD CVE JSON.
    We take the English description as both title (short) and full description.
    """
    desc_list = cve.get("descriptions", [])
    en_desc = None
    for d in desc_list:
        if d.get("lang") == "en":
            en_desc = d.get("value")
            break
    if not en_desc and desc_list:
        en_desc = desc_list[0].get("value", "")

    title = en_desc.split(".")[0][:250] if en_desc else "No description"
    return title, en_desc or "No description provided."


def extract_metrics(vuln: dict) -> Tuple[Optional[str], Optional[float], Optional[str]]:
    """
    Extract severity, score, and vector from cvssMetricV31 / V30 / V2.
    """
    metrics = vuln.get("metrics", {})

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key)
        if metric_list:
            m = metric_list[0]
            severity = m.get("baseSeverity")
            cvss_data = m.get("cvssData", {})
            score = cvss_data.get("baseScore") or m.get("baseScore")
            vector = cvss_data.get("vectorString") or m.get("vectorString")
            return severity, score, vector

    return None, None, None


def extract_cwe_id(vuln: dict) -> Optional[str]:
    weaknesses = vuln.get("weaknesses", [])
    if not weaknesses:
        return None
    # Take first weakness, first description
    for w in weaknesses:
        desc_list = w.get("description") or []
        for d in desc_list:
            val = d.get("value")
            if val and val.startswith("CWE-"):
                return val
    return None


def extract_cpe_matches(vuln: dict) -> List[dict]:
    """
    Extract CPE matches from the configurations section.
    Returns a list of dicts with vendor, product, version info and cpe_uri.
    """
    results: List[dict] = []
    configs = vuln.get("configurations", [])
    for cfg in configs:
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria") or ""
                if not cpe:
                    continue
                parts = cpe.split(":")
                vendor = parts[3] if len(parts) > 3 else ""
                product = parts[4] if len(parts) > 4 else ""
                version = parts[5] if len(parts) > 5 else ""

                results.append(
                    {
                        "vendor": vendor,
                        "product": product,
                        "version": version,
                        "cpe_uri": cpe,
                        "version_start": match.get("versionStartIncluding")
                        or match.get("versionStartExcluding"),
                        "version_end": match.get("versionEndIncluding")
                        or match.get("versionEndExcluding"),
                    }
                )
    return results


# --- Main ingestion logic ---


def ingest_recent_nvd_cves(days_back: int = 1) -> None:
    """
    Fetch recent CVEs from NVD and store them into the database.
    Skips CVEs that already exist (based on cve_id).
    """
    data = fetch_nvd_data(days_back)

    vulns = data.get("vulnerabilities", [])

    db = SessionLocal()
    try:
        # Store raw source document
        source_doc = SourceDocument(
            source_name="NVD",
            external_id=f"nvd_recent_{days_back}d_{datetime.utcnow().isoformat()}",
            fetched_at=datetime.utcnow(),
            raw_data=data,
        )
        db.add(source_doc)
        db.flush()  # get source_doc.id

        new_count = 0
        skipped = 0

        for item in vulns:
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue

            # Skip if already exists
            existing = (
                db.query(Vulnerability)
                .filter(Vulnerability.cve_id == cve_id)
                .first()
            )
            if existing:
                skipped += 1
                continue

            title, description = extract_description(cve)
            severity, score, vector = extract_metrics(item)
            cwe_id = extract_cwe_id(item)
            published = parse_datetime(item.get("published"))
            last_modified = parse_datetime(item.get("lastModified"))

            vuln_row = Vulnerability(
                cve_id=cve_id,
                title=title,
                description=description,
                severity=severity,
                cvss_score=score,
                cvss_vector=vector,
                cwe_id=cwe_id,
                published_date=published,
                last_modified_date=last_modified,
                is_zero_day=False,
                source_document_id=source_doc.id,
            )
            db.add(vuln_row)
            db.flush()  # get vuln_row.id

            # Affects
            for cpe in extract_cpe_matches(item):
                affect = VulnerabilityAffect(
                    vulnerability_id=vuln_row.id,
                    vendor=cpe["vendor"],
                    product=cpe["product"],
                    version_start=cpe["version_start"],
                    version_end=cpe["version_end"],
                    version_type=None,
                    cpe_uri=cpe["cpe_uri"],
                )
                db.add(affect)

            new_count += 1

        db.commit()
        print(f"[NVD] Ingestion complete. New CVEs: {new_count}, skipped (existing): {skipped}")

    except Exception as exc:
        db.rollback()
        print(f"[NVD] ERROR during ingestion: {exc}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    # Default: fetch last 1 day of CVEs
    ingest_recent_nvd_cves(days_back=1)
