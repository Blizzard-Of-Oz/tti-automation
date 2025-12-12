from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional

from jinja2 import Template
from sqlalchemy.orm import Session, joinedload

from . import models


HTML_TEMPLATE = Template("""
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Security Advisory - {{ client_name }}</title>
    <style>
      body { font-family: Arial, sans-serif; font-size: 14px; color: #222; }
      h1 { font-size: 20px; }
      h2 { font-size: 16px; margin-top: 24px; }
      table { border-collapse: collapse; width: 100%; margin-top: 12px; }
      th, td { border: 1px solid #ddd; padding: 6px 8px; vertical-align: top; }
      th { background-color: #f2f2f2; text-align: left; }
      .sev-CRITICAL { color: #b71c1c; font-weight: bold; }
      .sev-HIGH { color: #e65100; font-weight: bold; }
      .sev-MEDIUM { color: #f9a825; }
      .sev-LOW { color: #2e7d32; }
      .meta { font-size: 12px; color: #666; }
    </style>
  </head>
  <body>
    <h1>Security Advisory for {{ client_name }}</h1>
    <p class="meta">
      Generated on {{ generated_at }} – Open vulnerabilities impacting this client.
    </p>

    {% if items %}
      <h2>Summary</h2>
      <ul>
        <li>Total vulnerabilities: {{ stats.total }}</li>
        <li>Critical: {{ stats.critical }}, High: {{ stats.high }}, Medium: {{ stats.medium }}, Low: {{ stats.low }}</li>
      </ul>

      <h2>Detailed Impact</h2>
      <table>
        <thead>
          <tr>
            <th>CVE</th>
            <th>Severity</th>
            <th>CVSS</th>
            <th>Asset / Software</th>
            <th>Summary</th>
            <th>Key Reference</th>
          </tr>
        </thead>
        <tbody>
          {% for item in items %}
          <tr>
            <td><a href="https://nvd.nist.gov/vuln/detail/{{ item.cve_id }}">{{ item.cve_id }}</a></td>
            <td class="sev-{{ item.severity|upper }}">{{ item.severity or "UNKNOWN" }}</td>
            <td>{{ item.cvss_score if item.cvss_score is not none else "-" }}</td>
            <td>
              <strong>{{ item.asset_hostname or "N/A" }}</strong><br>
              {{ item.software_vendor }} {{ item.software_product }} {{ item.software_version or "" }}
            </td>
            <td>{{ item.summary_text }}</td>
            <td>
              {% if item.reference_url %}
                <a href="{{ item.reference_url }}">{{ item.reference_label }}</a>
              {% else %}
                -
              {% endif %}
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>

      <p class="meta">
        This advisory is intended for internal security and IT teams to prioritise patching and mitigation.
      </p>
    {% else %}
      <p>
        No open vulnerabilities have been matched to this client's registered assets and software at this time.
        This advisory is generated as a test and confirmation of the monitoring pipeline.
      </p>
    {% endif %}
  </body>
</html>
""")


def _summarise_severity(items: List[Dict[str, Any]]) -> Dict[str, int]:
    stats = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    for item in items:
        stats["total"] += 1
        sev = (item.get("severity") or "").upper()
        if sev == "CRITICAL":
            stats["critical"] += 1
        elif sev == "HIGH":
            stats["high"] += 1
        elif sev == "MEDIUM":
            stats["medium"] += 1
        elif sev == "LOW":
            stats["low"] += 1
    return stats


def _pick_reference_url(vuln: models.Vulnerability) -> Tuple[Optional[str], Optional[str]]:
    meta = vuln.llm_summary or {}
    refs = meta.get("references") or []
    if not isinstance(refs, list):
        return None, None

    # Prefer vendor advisory
    for ref in refs:
        if ref.get("source") == "vendor":
            return ref.get("url"), "Vendor advisory"

    # Fallback: any advisory / third-party
    for ref in refs:
        if ref.get("type") in {"advisory", "third_party"}:
            return ref.get("url"), "Advisory"

    # Fallback: first URL
    if refs:
        return refs[0].get("url"), "Reference"

    return None, None

def build_client_advisory_email(db: Session, client_id: int) -> Dict[str, Any]:
    # Load client
    client = db.query(models.Client).filter(models.Client.id == client_id).first()
    if not client:
        raise ValueError("Client not found")

    # All open matches for this client
    matches = (
        db.query(models.ClientVulnerability)
        .filter(models.ClientVulnerability.client_id == client_id)
        .filter(models.ClientVulnerability.status == "open")
        .all()
    )

    # Sort by severity + CVSS (descending)
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

    def sort_key(cv: models.ClientVulnerability):
        v = cv.vulnerability
        if not v:
            return (0, 0.0)
        sev = (v.severity or "").upper()
        score = v.cvss_score or 0.0
        return (severity_order.get(sev, 0), score)

    matches.sort(key=sort_key, reverse=True)

    # Build items for the template
    items: List[Dict[str, Any]] = []
    for cv in matches:
        vuln = cv.vulnerability
        if not vuln:
            continue

        # Safely load asset / software using IDs (no ORM relationship needed)
        asset = None
        software = None

        asset_id = getattr(cv, "asset_id", None)
        if asset_id is not None:
            asset = db.get(models.Asset, asset_id)

        software_id = getattr(cv, "software_id", None)
        if software_id is not None:
            software = db.get(models.Software, software_id)

        meta = vuln.llm_summary or {}
        if not isinstance(meta, dict):
            meta = {}

        summary_text = meta.get("summary_text") or (vuln.description or "").strip()
        if len(summary_text) > 600:
            summary_text = summary_text[:600] + "..."

        ref_url, ref_label = _pick_reference_url(vuln)

        items.append(
            {
                "cve_id": vuln.cve_id,
                "severity": vuln.severity,
                "cvss_score": vuln.cvss_score,
                "asset_hostname": asset.hostname if asset else None,
                "software_vendor": software.vendor if software else "",
                "software_product": software.product if software else "",
                "software_version": software.version if software else "",
                "summary_text": summary_text,
                "reference_url": ref_url,
                "reference_label": ref_label,
            }
        )


    # Compute stats for the header
    stats = _summarise_severity(items)
    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    # HTML body
    html_body = HTML_TEMPLATE.render(
        client_name=client.name,
        generated_at=generated_at,
        items=items,
        stats=stats,
    )

    # Plain-text body
    lines = [
        f"Security Advisory for {client.name}",
        f"Generated at {generated_at}",
        "",
    ]
    if items:
        lines.append(
            f"Total vulns: {stats['total']} "
            f"(Critical {stats['critical']}, High {stats['high']}, "
            f"Medium {stats['medium']}, Low {stats['low']})"
        )
        lines.append("")
        for item in items[:15]:
            lines.append(
                f"- {item['cve_id']} [{item['severity'] or 'UNKNOWN'}] "
                f"on {item['asset_hostname'] or 'N/A'} "
                f"({item['software_vendor']} {item['software_product']} {item['software_version']})"
            )
    else:
        lines.append(
            "No open vulnerabilities matched to this client's inventory at this time."
        )
    text_body = "\n".join(lines)

    subject = f"Security Advisory – {client.name} – {stats['total']} open vulnerability(ies)"

    # Return everything needed to build the API response
    return {
        "client_id": client_id,
        "subject": subject,
        "body_html": html_body,
        "body_text": text_body,
        "stats": stats,
        "items_count": len(items),
    }
