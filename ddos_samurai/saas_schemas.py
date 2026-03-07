from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, EmailStr, Field

try:
    import email_validator  # type: ignore  # noqa: F401
    _EmailType = EmailStr
except Exception:
    # Keep schemas importable in minimal environments without optional
    # pydantic[email] extra.
    _EmailType = str


class UserCreate(BaseModel):
    email: _EmailType
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=128)


class UserOut(BaseModel):
    id: int
    email: _EmailType
    username: str
    role: str
    is_active: bool


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class PlanCreate(BaseModel):
    code: str = Field(min_length=2, max_length=32)
    name: str = Field(min_length=2, max_length=128)
    description: str = ""
    monthly_test_quota: int | None = None
    price_per_test: Decimal = Decimal("0.0500")
    monthly_fee: Decimal = Decimal("0.00")
    is_active: bool = True


class PlanOut(BaseModel):
    id: int
    code: str
    name: str
    description: str
    monthly_test_quota: int | None
    price_per_test: Decimal
    monthly_fee: Decimal
    is_active: bool


class SubscriptionOut(BaseModel):
    plan: PlanOut
    status: str
    cycle_start: datetime
    cycle_end: datetime


class SubscriptionChangeRequest(BaseModel):
    plan_code: str = Field(min_length=2, max_length=32)


class BillingSummaryOut(BaseModel):
    currency: str
    cycle_start: datetime
    cycle_end: datetime
    total_usage_units: int
    payg_total: Decimal
    monthly_fee: Decimal
    total_due: Decimal
    monthly_test_quota: int | None
    remaining_quota: int | None


class TestStartRequest(BaseModel):
    target: str
    port: int = 80
    protocol: str = "tcp"
    attack_vector: str = "basic"
    count: int = 1000
    duration: int = 60
    workers: int = 2
    rps: float = 0
    backend: str = "cpu"

    tcp_flags: str = "S"
    source_port: int = 0
    ttl: int | None = 64
    tos: int | None = 0
    window: int | None = 65535

    spoof: bool = False
    spoof_mode: str = "realistic"
    spoof_ip: str | None = None
    spoof_subnet: str | None = None

    http_method: str = "GET"
    http_path: str = "/"
    http_concurrency: int = 50
    user_agent: str = "chrome_120"
    ja3_profile: str = "none"
    h2_profile: str = "none"
    l7_quic_require_native: bool = False
    quic_expect_header_name: str = ""
    quic_expect_header_value_contains: str = ""
    quic_expect_body_substring: str = ""
    ninja_mode: bool = False

    anomaly_types: list[int] = []
    reflector_file: str | None = None

    allow_public_target: bool = False


class LegacyAttackConfig(TestStartRequest):
    attackvector: str = "basic"


class TestRunOut(BaseModel):
    id: int
    status: str
    target: str
    port: int
    protocol: str
    attack_vector: str
    requested_count: int
    requested_duration: int
    requested_rps: Decimal
    workers: int
    backend: str
    process_pid: int | None
    started_at: datetime
    finished_at: datetime | None


class SecurityLogOut(BaseModel):
    id: int
    event_type: str
    status: str
    ip_address: str | None
    created_at: datetime
    details_json: dict
