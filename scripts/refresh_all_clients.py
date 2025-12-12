"""
Run a full refresh for all clients:
- Re-run the matching engine per client
- If there are new matches, build an advisory email draft

You can run this manually or from cron, e.g. once per day.
"""

from datetime import datetime

from backend.app.db import SessionLocal
from backend.app import models, matching, email_builder


def refresh_all_clients() -> None:
    db = SessionLocal()
    try:
        clients = db.query(models.Client).order_by(models.Client.id).all()
        if not clients:
            print("[refresh] No clients found in the database.")
            return

        print(f"[refresh] Starting refresh at {datetime.utcnow()} UTC")
        total_new_matches = 0

        for client in clients:
            print(f"\n[refresh] Client #{client.id}: {client.name}")

            # 1) Run matching engine
            stats = matching.match_client_vulnerabilities(db, client.id)
            print(
                f"   Matching stats: assets_seen={stats.get('assets_seen', 0)}, "
                f"software_seen={stats.get('software_seen', 0)}, "
                f"matches_created={stats.get('matches_created', 0)}, "
                f"matches_skipped_existing={stats.get('matches_skipped_existing', 0)}"
            )

            new_matches = stats.get("matches_created", 0) or 0
            total_new_matches += new_matches

            # 2) If there are new matches, build an advisory draft
            if new_matches > 0:
                log, meta = email_builder.build_client_advisory_email(db, client.id)
                subject = meta.get("subject")
                to_addr = meta.get("to_addresses")
                print(f"   Advisory prepared: '{subject}'")
                print(f"   To: {to_addr}")
                # We are not sending the email here; this is a draft step.

        print(f"\n[refresh] Finished at {datetime.utcnow()} UTC")
        print(f"[refresh] Total new matches created across all clients: {total_new_matches}")

    finally:
        db.close()


if __name__ == "__main__":
    refresh_all_clients()
