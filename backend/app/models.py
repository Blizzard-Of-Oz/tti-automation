from datetime import datetime
from typing import Optional

from sqlalchemy import (
    String,
    Integer,
    DateTime,
    Text,
    ForeignKey,
    Float,
    Boolean,
    JSON,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


class SourceDocument(Base):
    __tablename__ = "source_documents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    source_name: Mapped[str] = mapped_column(String(100), index=True)
    external_id: Mapped[Optional[str]] = mapped_column(String(255), index=True)  # e.g. NVD feed id, advisory id
    fetched_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    raw_data: Mapped[dict] = mapped_column(JSON)

    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        back_populates="source_document"
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    cve_id: Mapped[Optional[str]] = mapped_column(String(50), index=True, unique=True)  # null for zero-days
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[Optional[str]] = mapped_column(String(20), index=True)  # e.g. LOW/MEDIUM/HIGH/CRITICAL
    cvss_score: Mapped[Optional[float]] = mapped_column(Float)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(255))
    cwe_id: Mapped[Optional[str]] = mapped_column(String(50))
    published_date: Mapped[Optional[datetime]] = mapped_column(DateTime)
    last_modified_date: Mapped[Optional[datetime]] = mapped_column(DateTime)
    is_zero_day: Mapped[bool] = mapped_column(Boolean, default=False)

    # LLM summary fields (optional)
    llm_summary: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    source_document_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("source_documents.id"), nullable=False
    )
    source_document: Mapped["SourceDocument"] = relationship(
        back_populates="vulnerabilities"
    )

    affects: Mapped[list["VulnerabilityAffect"]] = relationship(
        back_populates="vulnerability",
        cascade="all, delete-orphan",
    )
    client_vulnerabilities: Mapped[list["ClientVulnerability"]] = relationship(
        back_populates="vulnerability"
    )


class VulnerabilityAffect(Base):
    __tablename__ = "vulnerability_affects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    vulnerability_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("vulnerabilities.id"), nullable=False, index=True
    )
    vendor: Mapped[str] = mapped_column(String(200), index=True)
    product: Mapped[str] = mapped_column(String(200), index=True)
    version_start: Mapped[Optional[str]] = mapped_column(String(50))
    version_end: Mapped[Optional[str]] = mapped_column(String(50))
    version_type: Mapped[Optional[str]] = mapped_column(String(5))  # e.g. "<", "<=", ">=", "="
    cpe_uri: Mapped[Optional[str]] = mapped_column(String(500))

    vulnerability: Mapped["Vulnerability"] = relationship(back_populates="affects")


class Client(Base):
    __tablename__ = "clients"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    code: Mapped[Optional[str]] = mapped_column(String(50), unique=True, index=True)  # short code like BBAC, XYZ
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    assets: Mapped[list["Asset"]] = relationship(
        back_populates="client", cascade="all, delete-orphan"
    )
    contacts: Mapped[list["ClientContact"]] = relationship(
        back_populates="client", cascade="all, delete-orphan"
    )
    client_vulnerabilities: Mapped[list["ClientVulnerability"]] = relationship(
        back_populates="client"
    )


class ClientContact(Base):
    __tablename__ = "client_contacts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    client_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("clients.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255))
    email: Mapped[str] = mapped_column(String(255), index=True)
    role: Mapped[Optional[str]] = mapped_column(String(100))  # e.g. CISO, SOC manager
    is_primary: Mapped[bool] = mapped_column(Boolean, default=True)

    client: Mapped["Client"] = relationship(back_populates="contacts")


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    client_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("clients.id"), nullable=False, index=True
    )
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(50), index=True)
    asset_type: Mapped[Optional[str]] = mapped_column(String(100))  # server, firewall, workstation, etc.
    criticality: Mapped[Optional[str]] = mapped_column(String(20))  # LOW/MEDIUM/HIGH
    owner: Mapped[Optional[str]] = mapped_column(String(255))

    client: Mapped["Client"] = relationship(back_populates="assets")
    software: Mapped[list["Software"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )


class Software(Base):
    __tablename__ = "software"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    asset_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("assets.id"), nullable=False, index=True
    )
    vendor: Mapped[str] = mapped_column(String(200), index=True)
    product: Mapped[str] = mapped_column(String(200), index=True)
    version: Mapped[Optional[str]] = mapped_column(String(100))
    cpe_uri: Mapped[Optional[str]] = mapped_column(String(500))

    asset: Mapped["Asset"] = relationship(back_populates="software")


class ClientVulnerability(Base):
    __tablename__ = "client_vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    client_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("clients.id"), nullable=False, index=True
    )
    vulnerability_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("vulnerabilities.id"), nullable=False, index=True
    )
    impact_level: Mapped[Optional[str]] = mapped_column(String(20))  # LOW/MEDIUM/HIGH/CRITICAL
    status: Mapped[str] = mapped_column(String(20), default="new")  # new, notified, remediated, ignored
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    client: Mapped["Client"] = relationship(back_populates="client_vulnerabilities")
    vulnerability: Mapped["Vulnerability"] = relationship(
        back_populates="client_vulnerabilities"
    )
    email_logs: Mapped[list["EmailLog"]] = relationship(
        back_populates="client_vulnerability"
    )


class EmailLog(Base):
    __tablename__ = "email_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    client_vulnerability_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("client_vulnerabilities.id"),
        nullable=False,
        index=True,
    )
    sent_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    to_addresses: Mapped[str] = mapped_column(Text)  # comma-separated list
    cc_addresses: Mapped[Optional[str]] = mapped_column(Text)
    subject: Mapped[str] = mapped_column(String(500))
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text)

    client_vulnerability: Mapped["ClientVulnerability"] = relationship(
        back_populates="email_logs"
    )
