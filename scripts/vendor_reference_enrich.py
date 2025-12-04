import re
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional

from backend.app.db import SessionLocal
from backend.app.models import Vulnerability, SourceDocument


VENDOR_DOMAINS = {
    "microsoft": ["microsoft.com", "msrc.microsoft.com"],
    "cisco": ["cisco.com"],
    "fortinet": ["fortinet.com"],
    "vmware": ["vmware.com"],
    "oracle": ["oracle.com"],
    "redhat": ["redhat.com"],
}


def classify_reference(url: str, tags: Optional[list]) -> Dict[str, Any]:
    """
    Classify a reference URL into vendor/advisory/etc. based on domain and tags.
    """
    tags = tags or []
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    hostname = hostname.lower()

    vendor_name: Optional[str] = None
    for vendor, domains in VENDOR_DOMAINS.items():
        if any(d in hostname for d in domains):
            vendor_name = vendor
            break

    ref_type = "other"
    # Simple heuristics on tags
    tag_str = ",".join(tags).lower()
    if "vendor advisory" in tag_str or "patch" in tag_str or "mitigation" in tag_str:
        ref_type = "advisory"
    elif "exploit" in tag_str:
        ref_type = "exploit"
    elif "third party advisory" in tag_str:
        ref_type = "third_party"

    # Fallbacks based on URL patterns if no tags
    if ref_type == "other":
        if any(x in url.lower() for x in ["advisory", "security-update", "kb/"]):
            ref_type = "advisory"

    source = "external"
    if vendor_name:
        source = "vendor"

    return {
        "url": url,
        "tags": tags,
        "type": ref_type,
        "source": source,
        "vendor": vendor_name,
    }


def get_nvd_item_for_vuln(vuln: Vulnerability, source_doc: SourceDocument) -> Optional[dict]:
    """
    Given a Vulnerability and its NVD SourceDocument, find the matching CVE entry
    inside source_doc.raw_data['vulnerabilities'].
    """
    if not vuln.cve_id or not source_doc.raw_data:
        return None

    data = source_doc.raw_data
    items = data.get("vulnerabilities", [])
    for item in items:
        cve = item.get("cve", {})
        if cve.get("id") == vuln.cve_id:
            return item
    return None


def extract_references_from_nvd_item(item: dict) -> List[Dict[str, Any]]:
    """
    Extract list of reference dicts from an NVD 'vulnerabilities' item.
    """
    cve = item.get("cve", {})
    refs = cve.get("references", [])
    results: List[Dict[str, Any]] = []

    for ref in refs:
        url = ref.get("url")
        if not url:
            continue
        tags = ref.get("tags") or []
        classified = classify_reference(url, tags)
        results.append(classified)

    return results


def enrich_vulnerabilities_with_references(limit: int = 200) -> None:
    """
    For vulnerabilities that don't yet have 'references' in their llm_summary,
    extract references from NVD raw JSON and store them.
    """
    db = SessionLocal()
    try:
        # Select a batch of vulnerabilities to enrich
        vulns = (
            db.query(Vulnerability)
            .order_by(Vulnerability.id)
            .limit(limit)
            .all()
        )

        updated = 0

        for vuln in vulns:
            # Get existing summary JSON
            summary = vuln.llm_summary or {}
            existing_refs = summary.get("references")

            # If we already have references, skip
            if existing_refs:
                continue

            # Get the NVD raw item for this vulnerability
            source_doc = vuln.source_document
            if not source_doc:
                continue

            nvd_item = get_nvd_item_for_vuln(vuln, source_doc)
            if not nvd_item:
                continue

            refs = extract_references_from_nvd_item(nvd_item)
            if not refs:
                continue

            summary["references"] = refs
            vuln.llm_summary = summary
            updated += 1

        db.commit()
        print(f"[REF] Enrichment complete. Vulnerabilities updated: {updated}")

    except Exception as exc:
        db.rollback()
        print(f"[REF] ERROR during enrichment: {exc}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    # Enrich up to 200 vulnerabilities in one run
    enrich_vulnerabilities_with_references(limit=200)
