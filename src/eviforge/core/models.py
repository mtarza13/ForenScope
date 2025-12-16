from __future__ import annotations

import enum
from datetime import datetime
import uuid

from sqlalchemy import String, DateTime, ForeignKey, Text, Enum, Integer, BigInteger, JSON, Float
from sqlalchemy.orm import Mapped, mapped_column, relationship

from eviforge.core.db import Base, utcnow


class JobStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class User(Base):
    __tablename__ = "users"
    
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(200), nullable=False)
    role: Mapped[str] = mapped_column(String(20), default="analyst") # admin, analyst, viewer
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class FindingSeverity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class FindingStatus(str, enum.Enum):
    OPEN = "open"
    TRIAGED = "triaged"
    CLOSED = "closed"

class Case(Base):
    __tablename__ = "cases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


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
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidence.id"), nullable=True, index=True)
    tool_name: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[JobStatus] = mapped_column(Enum(JobStatus), default=JobStatus.PENDING, nullable=False)

    # Inputs
    params_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Outputs
    result_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_preview_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    output_files_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    stdout_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    stderr_text: Mapped[str | None] = mapped_column(Text, nullable=True)

    error_message: Mapped[str] = mapped_column(Text, nullable=True)

    queued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    # Queue metadata
    rq_job_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    # Relationships
    case = relationship("Case", backref="jobs")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    actor_role: Mapped[str | None] = mapped_column(String(50), nullable=True)

    action: Mapped[str] = mapped_column(String(200), nullable=False)

    case_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    evidence_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    job_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)

    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)

    details_json: Mapped[str | None] = mapped_column(Text, nullable=True)


# --- STEP 4 MODELS ---

class Entity(Base):
    __tablename__ = "entities"
    
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), nullable=False, index=True)
    type: Mapped[str] = mapped_column(String(50), nullable=False) # ip, domain, email, etc.
    value: Mapped[str] = mapped_column(String(1024), nullable=False, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    source_module: Mapped[str] = mapped_column(String(100), nullable=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence.id"), nullable=True)
    
class IOC(Base):
    __tablename__ = "iocs"
    
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), nullable=False, index=True)
    type: Mapped[str] = mapped_column(String(50), nullable=False) # hash, ip, domain
    value: Mapped[str] = mapped_column(String(1024), nullable=False)
    confidence: Mapped[str] = mapped_column(String(50), default="high") # high, med, low
    tags: Mapped[str] = mapped_column(Text, nullable=True) # JSON list or comma sep
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class IOCMatch(Base):
    __tablename__ = "matches"
    
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), nullable=False, index=True)
    ioc_id: Mapped[str] = mapped_column(ForeignKey("iocs.id"), nullable=False)
    entity_id: Mapped[str] = mapped_column(ForeignKey("entities.id"), nullable=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence.id"), nullable=True)
    module: Mapped[str] = mapped_column(String(100), nullable=True)
    context_json: Mapped[str] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class Finding(Base):
    __tablename__ = "findings"
    
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[FindingSeverity] = mapped_column(Enum(FindingSeverity), default=FindingSeverity.MEDIUM)
    status: Mapped[FindingStatus] = mapped_column(Enum(FindingStatus), default=FindingStatus.OPEN)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    related_entities: Mapped[str] = mapped_column(Text, nullable=True) # JSON list IDs
    related_evidence: Mapped[str] = mapped_column(Text, nullable=True) # JSON list IDs
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

class Note(Base):
    __tablename__ = "notes"
    
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), nullable=False)
    target_type: Mapped[str] = mapped_column(String(50), nullable=False) # finding, entity, case
    target_id: Mapped[str] = mapped_column(String(36), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class OSINTActionStatus(str, enum.Enum):
    DRAFT = "draft"
    SUBMITTED = "submitted"
    IN_REVIEW = "in_review"
    COMPLETED = "completed"
    FAILED = "failed"

class OSINTAction(Base):
    __tablename__ = "osint_actions"
    
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(100), nullable=False) # e.g. facecheck
    action_type: Mapped[str] = mapped_column(String(100), nullable=False) # e.g. remove_my_photos
    target_label: Mapped[str] = mapped_column(String(200), nullable=True) # e.g. "Selfie opt-out"
    status: Mapped[OSINTActionStatus] = mapped_column(Enum(OSINTActionStatus), default=OSINTActionStatus.DRAFT)
    tracking_url: Mapped[str] = mapped_column(Text, nullable=True)
    notes: Mapped[str] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    # Relationships
    case = relationship("Case", backref="osint_actions")

# Internal revision 1

# Internal revision 2

# Internal revision 4

# Internal revision 6

# Internal revision 11

# Internal revision 12

# Internal revision 21

# Internal revision 22

# Internal revision 26

# Internal revision 27

# Internal revision 28

# Internal revision 29

# Internal revision 30

# Internal revision 32

# Internal revision 35

# Internal revision 36

# Internal revision 39

# Internal revision 40

# Internal revision 52

# Internal revision 58

# Internal revision 62

# Internal revision 63

# Internal revision 66

# Internal revision 70

# Internal revision 75

# Internal revision 79

# Internal revision 81

# Internal revision 87

# Rev 12

# Rev 15

# Rev 19

# Rev 32

# Rev 33

# Rev 44

# Rev 67

# Rev 74

# Rev 76

# Rev 85
