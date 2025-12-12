from sqlalchemy import text
from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session

from .db import get_db
from .routers import clients as clients_router
from .routers import dashboard as dashboard_router

app = FastAPI(
    title="TTI Automation API",
    description="Backend API for CVE ingestion, enrichment, and client notifications.",
    version="0.1.0",
)

# Routers
app.include_router(clients_router.router)
app.include_router(dashboard_router.router)


@app.get("/health")
def health_check(db: Session = Depends(get_db)):
    """
    Simple health endpoint.

    It will try to open a DB session; if something is wrong with
    the PostgreSQL connection, this endpoint will fail.
    """
    db.execute(text("SELECT 1"))
    return {"status": "ok"}
