from datetime import UTC, datetime
from typing import Any, Optional

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base

# Cross-database variant types for SQLite (Pytest) and PostgreSQL (Production)
BIGINT_PK = Integer().with_variant(BigInteger, "postgresql")
JSON_TYPE = JSONB().with_variant(JSON, "sqlite")
ARRAY_STRING = ARRAY(String).with_variant(JSON, "sqlite")
ARRAY_BIGINT = ARRAY(BigInteger).with_variant(JSON, "sqlite")


class Machine(Base):
    __tablename__ = "machines"

    id: Mapped[int] = mapped_column(BIGINT_PK, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    criticality: Mapped[str] = mapped_column(String(32), default="MEDIUM", nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    events: Mapped[list["Event"]] = relationship("Event", back_populates="machine")
    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="machine")
    incidents: Mapped[list["Incident"]] = relationship("Incident", back_populates="machine")


class MessageTemplate(Base):
    __tablename__ = "message_templates"

    id: Mapped[int] = mapped_column(BIGINT_PK, primary_key=True, autoincrement=True)
    template_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    template_text: Mapped[str] = mapped_column(Text, nullable=False)
    param_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    events: Mapped[list["Event"]] = relationship("Event", back_populates="template")


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(BIGINT_PK, primary_key=True, autoincrement=True)
    machine_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("machines.id"), nullable=False)
    source: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str | None] = mapped_column(String(128), nullable=True)
    entry_type: Mapped[str] = mapped_column(String(64), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    template_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("message_templates.id"), nullable=True)

    ts_utc: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    hour_of_day: Mapped[int] = mapped_column(Integer, nullable=False)
    day_of_week: Mapped[int] = mapped_column(Integer, nullable=False)
    is_business_hours: Mapped[bool] = mapped_column(Boolean, nullable=False)

    country: Mapped[str | None] = mapped_column(String(128), nullable=True)
    region_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    city: Mapped[str | None] = mapped_column(String(128), nullable=True)

    extracted_entities: Mapped[dict[str, Any]] = mapped_column(JSON_TYPE, default=dict, nullable=False)
    dedup_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)

    machine: Mapped["Machine"] = relationship("Machine", back_populates="events")
    template: Mapped[Optional["MessageTemplate"]] = relationship("MessageTemplate", back_populates="events")

    __table_args__ = (
        Index("ix_events_machine_ts", "machine_id", ts_utc.desc()),
        Index("ix_events_source_entry_type", "source", "entry_type"),
        Index("ix_events_ts_utc_desc", ts_utc.desc()),
        Index("ix_events_template_id", "template_id"),
    )


class Rule(Base):
    __tablename__ = "rules"

    code: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    params: Mapped[dict[str, Any]] = mapped_column(JSON_TYPE, default=dict, nullable=False)
    weight: Mapped[int] = mapped_column(Integer, default=10, nullable=False)
    mitre_techniques: Mapped[list[str]] = mapped_column(ARRAY_STRING, default=list, nullable=False)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="rule")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(BIGINT_PK, primary_key=True, autoincrement=True)
    rule_code: Mapped[str] = mapped_column(String(32), ForeignKey("rules.code"), nullable=False)
    machine_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("machines.id"), nullable=False)
    ts_utc: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    reasons: Mapped[list[dict[str, Any]]] = mapped_column(JSON_TYPE, default=list, nullable=False)
    evidence_event_ids: Mapped[list[int]] = mapped_column(ARRAY_BIGINT, default=list, nullable=False)
    incident_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("incidents.id"), nullable=True)

    machine: Mapped["Machine"] = relationship("Machine", back_populates="findings")
    rule: Mapped["Rule"] = relationship("Rule", back_populates="findings")
    incident: Mapped[Optional["Incident"]] = relationship("Incident", back_populates="findings")

    __table_args__ = (
        Index("ix_findings_machine_ts", "machine_id", ts_utc.desc()),
    )


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(BIGINT_PK, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="OPEN", nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    machine_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("machines.id"), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finding_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    mitre_techniques: Mapped[list[str]] = mapped_column(ARRAY_STRING, default=list, nullable=False)
    assignee: Mapped[str | None] = mapped_column(String(128), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC), nullable=False)

    machine: Mapped["Machine"] = relationship("Machine", back_populates="incidents")
    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="incident")
    audit_notes: Mapped[list["IncidentNote"]] = relationship("IncidentNote", back_populates="incident", cascade="all, delete-orphan", order_by="IncidentNote.created_at.desc()")

    __table_args__ = (
        Index("ix_incidents_status_severity_first_seen", "status", "severity", first_seen.desc()),
    )


class IncidentNote(Base):
    __tablename__ = "incident_notes"

    id: Mapped[int] = mapped_column(BIGINT_PK, primary_key=True, autoincrement=True)
    incident_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("incidents.id"), nullable=False, index=True)
    author_username: Mapped[str] = mapped_column(String(64), nullable=False)
    action_type: Mapped[str] = mapped_column(String(32), default="NOTE", nullable=False)  # NOTE, STATUS_CHANGE, CONTAINMENT, REMEDIATION
    note_text: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="audit_notes")


class Baseline(Base):
    __tablename__ = "baselines"

    machine_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("machines.id"), primary_key=True)
    source: Mapped[str] = mapped_column(String(255), primary_key=True)
    metric: Mapped[str] = mapped_column(String(64), primary_key=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    mean: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    stddev: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    sample_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(BIGINT_PK, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="ANALYST", nullable=False)  # ADMIN, ANALYST, VIEWER
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)


