from __future__ import annotations

import enum
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from sqlalchemy import JSON, Boolean, DateTime, Enum, ForeignKey, Integer, Numeric, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .saas_db import Base


class UserRole(str, enum.Enum):
    USER = "user"
    ADMIN = "admin"


class SubscriptionStatus(str, enum.Enum):
    ACTIVE = "active"
    CANCELED = "canceled"
    PAUSED = "paused"


class TestRunStatus(str, enum.Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), default=UserRole.USER)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    subscriptions: Mapped[list[UserSubscription]] = relationship("UserSubscription", back_populates="user")
    usage_events: Mapped[list[UsageEvent]] = relationship("UsageEvent", back_populates="user")
    test_runs: Mapped[list[TestRun]] = relationship("TestRun", back_populates="user")
    security_logs: Mapped[list[SecurityLog]] = relationship("SecurityLog", back_populates="user")


class SubscriptionPlan(Base, TimestampMixin):
    __tablename__ = "subscription_plans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(Text, default="")
    monthly_test_quota: Mapped[int | None] = mapped_column(Integer, nullable=True)
    price_per_test: Mapped[Decimal] = mapped_column(Numeric(10, 4), default=Decimal("0.0500"))
    monthly_fee: Mapped[Decimal] = mapped_column(Numeric(10, 2), default=Decimal("0.00"))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    subscriptions: Mapped[list[UserSubscription]] = relationship("UserSubscription", back_populates="plan")


class UserSubscription(Base, TimestampMixin):
    __tablename__ = "user_subscriptions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    plan_id: Mapped[int] = mapped_column(ForeignKey("subscription_plans.id"))
    status: Mapped[SubscriptionStatus] = mapped_column(Enum(SubscriptionStatus), default=SubscriptionStatus.ACTIVE)
    cycle_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    cycle_end: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc) + timedelta(days=30),
    )

    user: Mapped[User] = relationship("User", back_populates="subscriptions")
    plan: Mapped[SubscriptionPlan] = relationship("SubscriptionPlan", back_populates="subscriptions")


class TestRun(Base, TimestampMixin):
    __tablename__ = "test_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)

    target: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer, default=80)
    protocol: Mapped[str] = mapped_column(String(16), default="tcp")
    attack_vector: Mapped[str] = mapped_column(String(64), default="basic")

    requested_count: Mapped[int] = mapped_column(Integer, default=1000)
    requested_duration: Mapped[int] = mapped_column(Integer, default=60)
    requested_rps: Mapped[float] = mapped_column(Numeric(12, 2), default=0)
    workers: Mapped[int] = mapped_column(Integer, default=1)
    backend: Mapped[str] = mapped_column(String(16), default="cpu")

    status: Mapped[TestRunStatus] = mapped_column(Enum(TestRunStatus), default=TestRunStatus.RUNNING)
    process_pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    user: Mapped[User] = relationship("User", back_populates="test_runs")
    usage_events: Mapped[list[UsageEvent]] = relationship("UsageEvent", back_populates="test_run")


class UsageEvent(Base, TimestampMixin):
    __tablename__ = "usage_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    test_run_id: Mapped[int | None] = mapped_column(ForeignKey("test_runs.id"), nullable=True)

    event_type: Mapped[str] = mapped_column(String(64), default="test_start")
    units: Mapped[int] = mapped_column(Integer, default=1)
    unit_price: Mapped[Decimal] = mapped_column(Numeric(10, 4), default=Decimal("0.0000"))
    total_cost: Mapped[Decimal] = mapped_column(Numeric(12, 4), default=Decimal("0.0000"))
    currency: Mapped[str] = mapped_column(String(8), default="USD")
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)

    user: Mapped[User] = relationship("User", back_populates="usage_events")
    test_run: Mapped[TestRun | None] = relationship("TestRun", back_populates="usage_events")


class SecurityLog(Base):
    __tablename__ = "security_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True, nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(32), default="ok")
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    details_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)

    user: Mapped[User | None] = relationship("User", back_populates="security_logs")
