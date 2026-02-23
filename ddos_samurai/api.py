from __future__ import annotations

import os
import re
import signal
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm

from ddos_samurai.cli import is_admin

from .saas_schemas import (
    BillingSummaryOut,
    LegacyAttackConfig,
    PlanCreate,
    PlanOut,
    SecurityLogOut,
    SubscriptionChangeRequest,
    SubscriptionOut,
    TestRunOut,
    TestStartRequest,
    TokenOut,
    UserCreate,
    UserOut,
)

_SAAS_IMPORT_ERROR: Exception | None = None
SAAS_BACKEND_AVAILABLE = True


def _missing_saas_dependency(*args, **kwargs):
    detail = "SaaS backend dependencies are unavailable."
    if _SAAS_IMPORT_ERROR is not None:
        detail = f"{detail} Missing dependency: {_SAAS_IMPORT_ERROR}"
    raise ModuleNotFoundError(detail)


try:
    from sqlalchemy import Select, func, or_, select
    from sqlalchemy.orm import Session

    from .saas_auth import create_access_token, get_current_user, hash_password, require_admin, verify_password
    from .saas_db import SessionLocal, get_db, init_db
    from .saas_models import (
        SecurityLog,
        SubscriptionPlan,
        SubscriptionStatus,
        TestRun,
        TestRunStatus,
        UsageEvent,
        User,
        UserRole,
        UserSubscription,
    )
except Exception as exc:
    _SAAS_IMPORT_ERROR = exc
    SAAS_BACKEND_AVAILABLE = False
    Select = Any  # type: ignore[assignment]
    Session = Any  # type: ignore[assignment]

    class _FuncProxy:
        def __getattr__(self, _name: str):
            return _missing_saas_dependency

    func = _FuncProxy()  # type: ignore[assignment]

    def select(*args, **kwargs):
        return _missing_saas_dependency(*args, **kwargs)

    def or_(*args, **kwargs):
        return _missing_saas_dependency(*args, **kwargs)

    create_access_token = _missing_saas_dependency  # type: ignore[assignment]
    get_current_user = _missing_saas_dependency  # type: ignore[assignment]
    hash_password = _missing_saas_dependency  # type: ignore[assignment]
    require_admin = _missing_saas_dependency  # type: ignore[assignment]
    verify_password = _missing_saas_dependency  # type: ignore[assignment]
    SessionLocal = _missing_saas_dependency  # type: ignore[assignment]
    get_db = _missing_saas_dependency  # type: ignore[assignment]
    init_db = _missing_saas_dependency  # type: ignore[assignment]

    class _MissingModel:
        pass

    SecurityLog = _MissingModel  # type: ignore[assignment]
    SubscriptionPlan = _MissingModel  # type: ignore[assignment]
    SubscriptionStatus = _MissingModel  # type: ignore[assignment]
    TestRun = _MissingModel  # type: ignore[assignment]
    TestRunStatus = _MissingModel  # type: ignore[assignment]
    UsageEvent = _MissingModel  # type: ignore[assignment]
    User = _MissingModel  # type: ignore[assignment]
    UserRole = _MissingModel  # type: ignore[assignment]
    UserSubscription = _MissingModel  # type: ignore[assignment]

try:
    import psutil  # type: ignore
except Exception:
    psutil = None

try:
    from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
except Exception:
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"

    class _NoopMetric:
        def labels(self, *args, **kwargs):
            return self

        def inc(self, *args, **kwargs):
            return None

        def observe(self, *args, **kwargs):
            return None

    def Counter(*args, **kwargs):  # type: ignore
        return _NoopMetric()

    def Histogram(*args, **kwargs):  # type: ignore
        return _NoopMetric()

    def generate_latest() -> bytes:  # type: ignore
        return b""

try:
    import python_multipart as _python_multipart  # type: ignore  # noqa: F401
    _FORMDATA_AVAILABLE = True
except Exception:
    try:
        import multipart as _multipart  # type: ignore  # noqa: F401
        _FORMDATA_AVAILABLE = True
    except Exception:
        _FORMDATA_AVAILABLE = False


app = FastAPI(title="DDoSamurai SaaS API", version="3.0.0")

CORS_ORIGINS = [o.strip() for o in os.getenv("SAMURAI_CORS_ORIGINS", "*").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS if CORS_ORIGINS else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


HTTP_REQUESTS = Counter(
    "samurai_api_http_requests_total",
    "Total HTTP requests handled by SaaS API",
    ["method", "path", "status"],
)
HTTP_LATENCY = Histogram(
    "samurai_api_http_request_seconds",
    "HTTP request latency in seconds",
    ["method", "path"],
)
AUTH_FAILURES = Counter("samurai_api_auth_failures_total", "Failed login attempts")
TEST_STARTS = Counter("samurai_api_test_starts_total", "Started test runs")
TEST_STOPS = Counter("samurai_api_test_stops_total", "Stopped test runs")


_RUN_LOGS: dict[int, deque[dict]] = defaultdict(lambda: deque(maxlen=400))
_RUN_PROCESSES: dict[int, subprocess.Popen] = {}
_RUN_LOCK = threading.Lock()


@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    started = time.perf_counter()
    response = await call_next(request)
    elapsed = time.perf_counter() - started

    path = request.url.path
    HTTP_REQUESTS.labels(request.method, path, str(response.status_code)).inc()
    HTTP_LATENCY.labels(request.method, path).observe(elapsed)
    return response


@app.on_event("startup")
def startup_event() -> None:
    if not SAAS_BACKEND_AVAILABLE:
        return
    init_db()
    with SessionLocal() as db:
        _ensure_default_plans(db)


def _ensure_default_plans(db: Session) -> None:
    existing_rows = db.scalars(select(SubscriptionPlan)).all()
    existing_by_code = {p.code: p for p in existing_rows}

    defaults = {
        "free": {
            "name": "Free",
            "description": "Starter tier with limited monthly tests",
            "monthly_test_quota": 10000,
            "price_per_test": Decimal("0.0000"),
            "monthly_fee": Decimal("0.00"),
            "is_active": True,
        },
        "payg": {
            "name": "Pay As You Go",
            "description": "No monthly fee, pay per API test usage",
            "monthly_test_quota": None,
            "price_per_test": Decimal("0.0015"),
            "monthly_fee": Decimal("0.00"),
            "is_active": True,
        },
        "premium": {
            "name": "Premium",
            "description": "Monthly subscription with high quota and discounted overage",
            "monthly_test_quota": 200000,
            "price_per_test": Decimal("0.0004"),
            "monthly_fee": Decimal("99.00"),
            "is_active": True,
        },
    }

    dirty = False
    for code, spec in defaults.items():
        row = existing_by_code.get(code)
        if row is None:
            row = SubscriptionPlan(code=code, **spec)
            db.add(row)
            dirty = True
            continue
        if (
            row.name != spec["name"]
            or row.description != spec["description"]
            or row.monthly_test_quota != spec["monthly_test_quota"]
            or Decimal(row.price_per_test) != spec["price_per_test"]
            or Decimal(row.monthly_fee) != spec["monthly_fee"]
            or row.is_active != spec["is_active"]
        ):
            row.name = spec["name"]
            row.description = spec["description"]
            row.monthly_test_quota = spec["monthly_test_quota"]
            row.price_per_test = spec["price_per_test"]
            row.monthly_fee = spec["monthly_fee"]
            row.is_active = spec["is_active"]
            dirty = True

    legacy_pro = existing_by_code.get("pro")
    if legacy_pro is not None and legacy_pro.is_active:
        legacy_pro.is_active = False
        dirty = True

    if dirty:
        db.commit()


def _ensure_user_subscription(db: Session, user: User) -> UserSubscription:
    active = _get_active_subscription(db, user.id)
    if active is not None:
        return active

    free_plan = db.scalar(select(SubscriptionPlan).where(SubscriptionPlan.code == "free"))
    if free_plan is None:
        raise RuntimeError("Default free plan is missing")

    now = datetime.now(timezone.utc)
    sub = UserSubscription(
        user_id=user.id,
        plan_id=free_plan.id,
        status=SubscriptionStatus.ACTIVE,
        cycle_start=now,
        cycle_end=now + timedelta(days=30),
    )
    db.add(sub)
    db.commit()
    db.refresh(sub)
    return sub


def _get_active_subscription(db: Session, user_id: int) -> UserSubscription | None:
    now = datetime.now(timezone.utc)
    q: Select[tuple[UserSubscription]] = (
        select(UserSubscription)
        .where(
            UserSubscription.user_id == user_id,
            UserSubscription.status == SubscriptionStatus.ACTIVE,
            UserSubscription.cycle_end >= now,
        )
        .order_by(UserSubscription.cycle_end.desc())
    )
    return db.scalar(q)


def _extract_client_meta(request: Request) -> tuple[str | None, str | None]:
    forwarded = request.headers.get("x-forwarded-for")
    ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else None)
    ua = request.headers.get("user-agent")
    return ip, ua


def _security_log(
    db: Session,
    event_type: str,
    status_text: str,
    request: Request,
    user_id: int | None = None,
    details: dict | None = None,
) -> None:
    ip, ua = _extract_client_meta(request)
    row = SecurityLog(
        user_id=user_id,
        event_type=event_type,
        status=status_text,
        ip_address=ip,
        user_agent=ua,
        details_json=details or {},
    )
    db.add(row)
    db.commit()


def _estimate_usage_units(payload: TestStartRequest) -> int:
    if payload.count > 0:
        return max(1, int(payload.count))
    if payload.rps > 0 and payload.duration > 0:
        return max(1, int(payload.rps * payload.duration))
    return max(1, int(payload.duration))


def _build_test_command(payload: TestStartRequest) -> list[str]:
    cmd = [sys.executable, "-m", "ddos_samurai.cli"]
    cmd.extend(["--target", payload.target, "--port", str(payload.port)])
    cmd.extend(["--protocol", payload.protocol, "--attack-vector", payload.attack_vector])
    cmd.extend(["--count", str(payload.count)])
    cmd.extend(["--tcp-flags", payload.tcp_flags])
    cmd.extend(["--source-port", str(payload.source_port)])
    cmd.extend(["--workers", str(payload.workers), "--rps", str(payload.rps)])
    cmd.extend(["--compute-backend", payload.backend])

    if payload.window is not None:
        cmd.extend(["--window", str(payload.window)])
    if payload.ttl is not None:
        cmd.extend(["--ttl", str(payload.ttl)])
    if payload.tos is not None:
        cmd.extend(["--tos", str(payload.tos)])

    if payload.spoof:
        cmd.append("--spoof")
        cmd.extend(["--spoof-mode", payload.spoof_mode])
        if payload.spoof_ip:
            cmd.extend(["--spoof-ip", payload.spoof_ip])
        if payload.spoof_subnet:
            cmd.extend(["--spoof-subnet", payload.spoof_subnet])

    cmd.extend(["--http-method", payload.http_method])
    if payload.http_path:
        cmd.extend(["--http-path", payload.http_path])
    cmd.extend(["--http-concurrency", str(payload.http_concurrency)])

    # TLS / JA3 profile: use dedicated field, fall back to user_agent for backwards compat
    tls_profile = payload.ja3_profile if payload.ja3_profile and payload.ja3_profile != "none" else payload.user_agent
    cmd.extend(["--tls-profile", tls_profile])
    if payload.attack_vector == "http2":
        h2_profile = payload.h2_profile if payload.h2_profile and payload.h2_profile != "none" else payload.user_agent
        cmd.extend(["--h2-profile", h2_profile])

    if payload.ninja_mode:
        cmd.append("--ninja-mode")
    if payload.attack_vector == "anomaly" and payload.anomaly_types:
        cmd.append("--anomaly-types")
        cmd.extend([str(x) for x in payload.anomaly_types])
    if payload.reflector_file:
        cmd.extend(["--reflector-file", payload.reflector_file])

    cmd.append("--confirm")
    if payload.allow_public_target:
        cmd.append("--allow-public-target")
    return cmd


def _monitor_run_output(run_id: int, process: subprocess.Popen) -> None:
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

    for raw_line in iter(process.stdout.readline, ""):
        if not raw_line:
            break
        clean = ansi_escape.sub("", raw_line).strip()
        if not clean:
            continue
        with _RUN_LOCK:
            _RUN_LOGS[run_id].append({
                "time": time.strftime("%H:%M:%S"),
                "msg": clean,
            })

    return_code = process.wait()
    finished_status = TestRunStatus.COMPLETED if return_code == 0 else TestRunStatus.FAILED

    with SessionLocal() as db:
        run = db.scalar(select(TestRun).where(TestRun.id == run_id))
        if run is not None and run.status == TestRunStatus.RUNNING:
            run.status = finished_status
            run.finished_at = datetime.now(timezone.utc)
            if return_code != 0:
                run.error_message = f"Process exited with code {return_code}"
            db.commit()

    with _RUN_LOCK:
        _RUN_PROCESSES.pop(run_id, None)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "samurai-saas-api"}


@app.get("/metrics")
def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/auth/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, request: Request, db: Annotated[Session, Depends(get_db)]):
    existing = db.scalar(
        select(User).where(or_(User.email == payload.email.lower(), User.username == payload.username.lower()))
    )
    if existing:
        _security_log(db, "register", "error", request, details={"reason": "duplicate_user"})
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email or username already exists")

    first_user = db.scalar(select(func.count(User.id))) == 0
    user = User(
        email=payload.email.lower(),
        username=payload.username.lower(),
        password_hash=hash_password(payload.password),
        role=UserRole.ADMIN if first_user else UserRole.USER,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    _ensure_user_subscription(db, user)
    _security_log(db, "register", "ok", request, user_id=user.id)

    return UserOut(
        id=user.id,
        email=user.email,
        username=user.username,
        role=user.role.value,
        is_active=user.is_active,
    )


if _FORMDATA_AVAILABLE:
    @app.post("/auth/token", response_model=TokenOut)
    def login(
        request: Request,
        form: Annotated[OAuth2PasswordRequestForm, Depends()],
        db: Annotated[Session, Depends(get_db)],
    ):
        user = db.scalar(
            select(User).where(or_(User.username == form.username.lower(), User.email == form.username.lower()))
        )
        if user is None or not verify_password(form.password, user.password_hash):
            AUTH_FAILURES.inc()
            _security_log(db, "login", "error", request, details={"username": form.username})
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

        token, expires_in = create_access_token(user.id, user.role)
        _ensure_user_subscription(db, user)
        _security_log(db, "login", "ok", request, user_id=user.id)
        return TokenOut(access_token=token, expires_in=expires_in)
else:
    @app.post("/auth/token", response_model=TokenOut)
    def login(_request: Request):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="python-multipart is required for /auth/token endpoint",
        )


@app.get("/auth/me", response_model=UserOut)
def me(current_user: Annotated[User, Depends(get_current_user)]):
    return UserOut(
        id=current_user.id,
        email=current_user.email,
        username=current_user.username,
        role=current_user.role.value,
        is_active=current_user.is_active,
    )


@app.get("/plans", response_model=list[PlanOut])
def list_plans(db: Annotated[Session, Depends(get_db)]):
    plans = db.scalars(select(SubscriptionPlan).where(SubscriptionPlan.is_active.is_(True))).all()
    return [
        PlanOut(
            id=plan.id,
            code=plan.code,
            name=plan.name,
            description=plan.description,
            monthly_test_quota=plan.monthly_test_quota,
            price_per_test=plan.price_per_test,
            monthly_fee=plan.monthly_fee,
            is_active=plan.is_active,
        )
        for plan in plans
    ]


@app.post("/admin/plans", response_model=PlanOut)
def create_plan(
    payload: PlanCreate,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_admin)],
):
    existing = db.scalar(select(SubscriptionPlan).where(SubscriptionPlan.code == payload.code.lower()))
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Plan code already exists")

    plan = SubscriptionPlan(
        code=payload.code.lower(),
        name=payload.name,
        description=payload.description,
        monthly_test_quota=payload.monthly_test_quota,
        price_per_test=payload.price_per_test,
        monthly_fee=payload.monthly_fee,
        is_active=payload.is_active,
    )
    db.add(plan)
    db.commit()
    db.refresh(plan)
    return PlanOut(
        id=plan.id,
        code=plan.code,
        name=plan.name,
        description=plan.description,
        monthly_test_quota=plan.monthly_test_quota,
        price_per_test=plan.price_per_test,
        monthly_fee=plan.monthly_fee,
        is_active=plan.is_active,
    )


@app.get("/subscription/me", response_model=SubscriptionOut)
def my_subscription(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    sub = _ensure_user_subscription(db, current_user)
    plan = db.scalar(select(SubscriptionPlan).where(SubscriptionPlan.id == sub.plan_id))
    if plan is None:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Subscription plan missing")

    return SubscriptionOut(
        plan=PlanOut(
            id=plan.id,
            code=plan.code,
            name=plan.name,
            description=plan.description,
            monthly_test_quota=plan.monthly_test_quota,
            price_per_test=plan.price_per_test,
            monthly_fee=plan.monthly_fee,
            is_active=plan.is_active,
        ),
        status=sub.status.value,
        cycle_start=sub.cycle_start,
        cycle_end=sub.cycle_end,
    )


@app.post("/subscription/change", response_model=SubscriptionOut)
def change_subscription(
    payload: SubscriptionChangeRequest,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    target_code = payload.plan_code.lower().strip()
    plan = db.scalar(
        select(SubscriptionPlan).where(
            SubscriptionPlan.code == target_code,
            SubscriptionPlan.is_active.is_(True),
        )
    )
    if plan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Plan not found")

    active = _ensure_user_subscription(db, current_user)
    current_plan = db.scalar(select(SubscriptionPlan).where(SubscriptionPlan.id == active.plan_id))
    if current_plan is not None and current_plan.code == plan.code:
        return SubscriptionOut(
            plan=PlanOut(
                id=plan.id,
                code=plan.code,
                name=plan.name,
                description=plan.description,
                monthly_test_quota=plan.monthly_test_quota,
                price_per_test=plan.price_per_test,
                monthly_fee=plan.monthly_fee,
                is_active=plan.is_active,
            ),
            status=active.status.value,
            cycle_start=active.cycle_start,
            cycle_end=active.cycle_end,
        )

    active.status = SubscriptionStatus.CANCELED
    now = datetime.now(timezone.utc)
    new_sub = UserSubscription(
        user_id=current_user.id,
        plan_id=plan.id,
        status=SubscriptionStatus.ACTIVE,
        cycle_start=now,
        cycle_end=now + timedelta(days=30),
    )
    db.add(new_sub)
    db.commit()
    db.refresh(new_sub)

    _security_log(
        db,
        event_type="subscription_change",
        status_text="ok",
        request=request,
        user_id=current_user.id,
        details={"from": (current_plan.code if current_plan else "unknown"), "to": plan.code},
    )

    return SubscriptionOut(
        plan=PlanOut(
            id=plan.id,
            code=plan.code,
            name=plan.name,
            description=plan.description,
            monthly_test_quota=plan.monthly_test_quota,
            price_per_test=plan.price_per_test,
            monthly_fee=plan.monthly_fee,
            is_active=plan.is_active,
        ),
        status=new_sub.status.value,
        cycle_start=new_sub.cycle_start,
        cycle_end=new_sub.cycle_end,
    )


@app.get("/billing/summary", response_model=BillingSummaryOut)
def billing_summary(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    sub = _ensure_user_subscription(db, current_user)
    plan = db.scalar(select(SubscriptionPlan).where(SubscriptionPlan.id == sub.plan_id))
    if plan is None:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Subscription plan missing")

    usage = db.scalar(
        select(func.coalesce(func.sum(UsageEvent.units), 0)).where(
            UsageEvent.user_id == current_user.id,
            UsageEvent.created_at >= sub.cycle_start,
            UsageEvent.created_at <= sub.cycle_end,
        )
    )
    payg_total = db.scalar(
        select(func.coalesce(func.sum(UsageEvent.total_cost), Decimal("0.0000"))).where(
            UsageEvent.user_id == current_user.id,
            UsageEvent.created_at >= sub.cycle_start,
            UsageEvent.created_at <= sub.cycle_end,
        )
    )
    usage_units = int(usage or 0)
    payg = Decimal(payg_total or Decimal("0.0000"))
    monthly_fee = Decimal(plan.monthly_fee or Decimal("0.00"))

    remaining_quota = None
    if plan.monthly_test_quota is not None:
        remaining_quota = max(0, int(plan.monthly_test_quota) - usage_units)

    return BillingSummaryOut(
        currency="USD",
        cycle_start=sub.cycle_start,
        cycle_end=sub.cycle_end,
        total_usage_units=usage_units,
        payg_total=payg,
        monthly_fee=monthly_fee,
        total_due=(payg + monthly_fee),
        monthly_test_quota=plan.monthly_test_quota,
        remaining_quota=remaining_quota,
    )


def _start_test_internal(
    payload: TestStartRequest,
    request: Request,
    current_user: User,
    db: Session,
) -> TestRunOut:
    if payload.protocol in {"icmp", "tcp", "udp"} and not is_admin():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Raw socket tests require root privileges on the API host",
        )

    sub = _ensure_user_subscription(db, current_user)
    plan = db.scalar(select(SubscriptionPlan).where(SubscriptionPlan.id == sub.plan_id))
    if plan is None:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Subscription plan missing")

    units = _estimate_usage_units(payload)
    used_units = int(
        db.scalar(
            select(func.coalesce(func.sum(UsageEvent.units), 0)).where(
                UsageEvent.user_id == current_user.id,
                UsageEvent.created_at >= sub.cycle_start,
                UsageEvent.created_at <= sub.cycle_end,
            )
        )
        or 0
    )
    if plan.monthly_test_quota is not None and used_units + units > int(plan.monthly_test_quota):
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="Monthly quota exceeded for this subscription",
        )

    run = TestRun(
        user_id=current_user.id,
        target=payload.target,
        port=payload.port,
        protocol=payload.protocol,
        attack_vector=payload.attack_vector,
        requested_count=payload.count,
        requested_duration=payload.duration,
        requested_rps=payload.rps,
        workers=payload.workers,
        backend=payload.backend,
        status=TestRunStatus.RUNNING,
        started_at=datetime.now(timezone.utc),
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    unit_price = Decimal(plan.price_per_test or Decimal("0.0000"))
    total_cost = unit_price * Decimal(units)
    usage_event = UsageEvent(
        user_id=current_user.id,
        test_run_id=run.id,
        event_type="test_start",
        units=units,
        unit_price=unit_price,
        total_cost=total_cost,
        currency="USD",
        metadata_json={
            "target": payload.target,
            "attack_vector": payload.attack_vector,
            "protocol": payload.protocol,
            "count": payload.count,
            "duration": payload.duration,
            "rps": payload.rps,
        },
    )
    db.add(usage_event)
    db.commit()

    cmd = _build_test_command(payload)
    cwd = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=cwd,
            text=True,
            bufsize=1,
            universal_newlines=True,
        )
    except Exception as exc:
        run.status = TestRunStatus.FAILED
        run.error_message = str(exc)
        run.finished_at = datetime.now(timezone.utc)
        db.commit()
        _security_log(
            db,
            event_type="test_start",
            status_text="error",
            request=request,
            user_id=current_user.id,
            details={"run_id": run.id, "error": str(exc)},
        )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to start test: {exc}") from exc

    run.process_pid = process.pid
    db.commit()

    with _RUN_LOCK:
        _RUN_PROCESSES[run.id] = process

    monitor = threading.Thread(target=_monitor_run_output, args=(run.id, process), daemon=True)
    monitor.start()

    TEST_STARTS.inc()
    _security_log(
        db,
        event_type="test_start",
        status_text="ok",
        request=request,
        user_id=current_user.id,
        details={"run_id": run.id, "pid": process.pid, "units": units, "cost": str(total_cost)},
    )

    return TestRunOut(
        id=run.id,
        status=run.status.value,
        target=run.target,
        port=run.port,
        protocol=run.protocol,
        attack_vector=run.attack_vector,
        requested_count=run.requested_count,
        requested_duration=run.requested_duration,
        requested_rps=run.requested_rps,
        workers=run.workers,
        backend=run.backend,
        process_pid=run.process_pid,
        started_at=run.started_at,
        finished_at=run.finished_at,
    )


@app.post("/tests/start", response_model=TestRunOut)
def start_test(
    payload: TestStartRequest,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    return _start_test_internal(payload, request, current_user, db)


@app.post("/attack/start", response_model=TestRunOut)
def start_attack_compat(
    payload: LegacyAttackConfig,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    # Backwards-compatible field mapping
    if payload.attackvector:
        payload.attack_vector = payload.attackvector
    return _start_test_internal(payload, request, current_user, db)


def _stop_run_process(run: TestRun) -> None:
    if run.process_pid is None:
        return

    with _RUN_LOCK:
        process = _RUN_PROCESSES.get(run.id)

    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
    else:
        try:
            if psutil is None:
                os.kill(run.process_pid, signal.SIGTERM)
                time.sleep(0.2)
                try:
                    os.kill(run.process_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                parent = psutil.Process(run.process_pid)
                for child in parent.children(recursive=True):
                    child.kill()
                parent.kill()
        except ProcessLookupError:
            pass
        except Exception:
            pass

    with _RUN_LOCK:
        _RUN_PROCESSES.pop(run.id, None)


@app.post("/tests/{run_id}/stop", response_model=TestRunOut)
def stop_test(
    run_id: int,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    run = db.scalar(select(TestRun).where(TestRun.id == run_id))
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")

    if current_user.role != UserRole.ADMIN and run.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to stop this run")

    _stop_run_process(run)
    run.status = TestRunStatus.STOPPED
    run.finished_at = datetime.now(timezone.utc)
    db.commit()

    TEST_STOPS.inc()
    _security_log(
        db,
        event_type="test_stop",
        status_text="ok",
        request=request,
        user_id=current_user.id,
        details={"run_id": run.id, "pid": run.process_pid},
    )

    return TestRunOut(
        id=run.id,
        status=run.status.value,
        target=run.target,
        port=run.port,
        protocol=run.protocol,
        attack_vector=run.attack_vector,
        requested_count=run.requested_count,
        requested_duration=run.requested_duration,
        requested_rps=run.requested_rps,
        workers=run.workers,
        backend=run.backend,
        process_pid=run.process_pid,
        started_at=run.started_at,
        finished_at=run.finished_at,
    )


@app.post("/attack/stop")
def stop_attack_compat(
    run_id: int,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    return stop_test(run_id=run_id, request=request, current_user=current_user, db=db)


@app.get("/tests/runs", response_model=list[TestRunOut])
def list_runs(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    limit: int = 50,
):
    q = select(TestRun).order_by(TestRun.started_at.desc()).limit(max(1, min(limit, 200)))
    if current_user.role != UserRole.ADMIN:
        q = q.where(TestRun.user_id == current_user.id)

    runs = db.scalars(q).all()
    return [
        TestRunOut(
            id=run.id,
            status=run.status.value,
            target=run.target,
            port=run.port,
            protocol=run.protocol,
            attack_vector=run.attack_vector,
            requested_count=run.requested_count,
            requested_duration=run.requested_duration,
            requested_rps=run.requested_rps,
            workers=run.workers,
            backend=run.backend,
            process_pid=run.process_pid,
            started_at=run.started_at,
            finished_at=run.finished_at,
        )
        for run in runs
    ]


@app.get("/tests/{run_id}/logs")
def run_logs(
    run_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    run = db.scalar(select(TestRun).where(TestRun.id == run_id))
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")

    if current_user.role != UserRole.ADMIN and run.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")

    with _RUN_LOCK:
        items = list(_RUN_LOGS.get(run_id, []))
    return {"run_id": run_id, "logs": items}


@app.get("/security/logs", response_model=list[SecurityLogOut])
def security_logs(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    limit: int = 100,
):
    q = select(SecurityLog).order_by(SecurityLog.created_at.desc()).limit(max(1, min(limit, 500)))
    if current_user.role != UserRole.ADMIN:
        q = q.where(SecurityLog.user_id == current_user.id)

    rows = db.scalars(q).all()
    return [
        SecurityLogOut(
            id=row.id,
            event_type=row.event_type,
            status=row.status,
            ip_address=row.ip_address,
            created_at=row.created_at,
            details_json=row.details_json,
        )
        for row in rows
    ]


@app.get("/stats")
def stats(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    q = select(TestRun)
    if current_user.role != UserRole.ADMIN:
        q = q.where(TestRun.user_id == current_user.id)

    runs = db.scalars(q).all()
    running = sum(1 for r in runs if r.status == TestRunStatus.RUNNING)
    completed = sum(1 for r in runs if r.status == TestRunStatus.COMPLETED)
    failed = sum(1 for r in runs if r.status == TestRunStatus.FAILED)
    stopped = sum(1 for r in runs if r.status == TestRunStatus.STOPPED)

    with _RUN_LOCK:
        logs_count = sum(len(v) for v in _RUN_LOGS.values())

    return {
        "is_running": running > 0,
        "running_count": running,
        "completed_count": completed,
        "failed_count": failed,
        "stopped_count": stopped,
        "total_runs": len(runs),
        "buffered_logs": logs_count,
    }
