from __future__ import annotations

import enum
from datetime import datetime
import uuid

from sqlalchemy import String, DateTime, ForeignKey, Text, Enum, Integer, BigInteger
from sqlalchemy.orm import Mapped, mapped_column, relationship

from eviforge.core.db import Base, utcnow


class JobStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), nullable=False, index=True)
    path: Mapped[str] = mapped_column(String(4096), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    md5: Mapped[str] = mapped_column(String(32), nullable=True)
    sha256: Mapped[str] = mapped_column(String(64), nullable=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    
    # Relationships
    case = relationship("Case", backref="evidence_items")


class ChainOfCustody(Base):
    __tablename__ = "chain_of_custody"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), nullable=False, index=True)
    user: Mapped[str] = mapped_column(String(200), nullable=False)
    action: Mapped[str] = mapped_column(String(200), nullable=False)
    details: Mapped[str] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    
    # Hash chain for anti-tamper
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=True)  # SHA256
    curr_hash: Mapped[str] = mapped_column(String(64), nullable=True)  # SHA256 of (id+case+user+action+details+timestamp+prev_hash)

    # Relationships
    case = relationship("Case", backref="custody_chain")


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), nullable=False, index=True)
    tool_name: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[JobStatus] = mapped_column(Enum(JobStatus), default=JobStatus.PENDING, nullable=False)
    result_json: Mapped[str] = mapped_column(Text, nullable=True)
    error_message: Mapped[str] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    case = relationship("Case", backref="jobs")
