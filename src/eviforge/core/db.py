from __future__ import annotations

from datetime import datetime, timezone
import json
import uuid

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(200), primary_key=True)
    value_json: Mapped[str] = mapped_column(Text(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(400), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


def create_session_factory(database_url: str):
    connect_args = {}
    if database_url.startswith("sqlite:"):
        connect_args = {"check_same_thread": False}

    engine = create_engine(database_url, future=True, connect_args=connect_args)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, class_=Session, expire_on_commit=False)


def get_setting(session: Session, key: str):
    row = session.get(Setting, key)
    if not row:
        return None
    return json.loads(row.value_json)


def set_setting(session: Session, key: str, value) -> None:
    row = Setting(key=key, value_json=json.dumps(value, sort_keys=True))
    session.merge(row)
    session.commit()
