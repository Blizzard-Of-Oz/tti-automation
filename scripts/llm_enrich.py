import json

from backend.app.db import SessionLocal
from backend.app import models
from backend.app.db import SessionLocal
from backend.app import models
from backend.app.llm_summarizer import generate_llm_summary


def main() -> None:
    db = SessionLocal()
    try:
        vulns = db.query(models.Vulnerability).order_by(models.Vulnerability.id).all()
        updated = 0

        for vuln in vulns:
            meta = vuln.llm_summary or {}
            if not isinstance(meta, dict):
                meta = {}

            # Skip if we already have a summary
            if meta.get("summary_text"):
                continue

            summary_text = generate_llm_summary(vuln)

            # IMPORTANT: create a NEW dict so SQLAlchemy sees the change
            new_meta = dict(meta)
            new_meta["summary_text"] = summary_text

            vuln.llm_summary = new_meta
            updated += 1

        db.commit()
        print(f"[LLM] Completed. Vulnerabilities updated with summaries: {updated}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
