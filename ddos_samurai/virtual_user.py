"""
VirtualUser (VU) Engine — Per-User Isolated L7 Session State | Samurai v2.0
Each VirtualUser maintains its own:
  - Cookie jar (httpx.Cookies)
  - Header state (dynamic headers like CSRF tokens)
  - Redirect history
  - Token cache (auth_token, csrf_token, session_id, etc.)
  - Connection affinity (own httpx.AsyncClient)

Supports workflow execution: login → redirect → token parse → action chain
with response-based branching and retry/backoff.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

try:
    import httpx
    _HTTPX = True
except ImportError:
    _HTTPX = False

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
#  Data Models
# ---------------------------------------------------------------------------

class StepAction(str, Enum):
    """What to do after a workflow step completes."""
    CONTINUE = "continue"
    BRANCH = "branch"
    STOP = "stop"
    RETRY = "retry"


@dataclass
class ExtractRule:
    """Rule for extracting data from an HTTP response."""
    field_name: str                         # key stored in VU tokens
    source: str = "header"                  # "header", "body_regex", "cookie"
    header_name: str | None = None          # e.g. "X-CSRF-Token"
    regex_pattern: str | None = None        # used when source == "body_regex"
    cookie_name: str | None = None          # used when source == "cookie"


@dataclass
class WorkflowStep:
    """A single step in an L7 workflow."""
    name: str
    method: str = "GET"
    path: str = "/"
    body: str | bytes | None = None
    expected_status: tuple[int, int] = (200, 399)   # inclusive range
    follow_redirects: bool = True
    extract: list[ExtractRule] = field(default_factory=list)
    inject_tokens: list[str] = field(default_factory=list)   # "token_key" or "Header-Name:token_key"
    branch_on: dict[int, int] | None = None     # status_code → step_index
    timeout_s: float = 10.0
    max_retries: int = 0


@dataclass
class WorkflowResult:
    """Result of a complete VU workflow execution."""
    user_id: int
    steps_total: int = 0
    steps_ok: int = 0
    steps_failed: int = 0
    redirects_followed: int = 0
    cookies_captured: int = 0
    tokens_extracted: int = 0
    retries_used: int = 0
    total_time_s: float = 0.0
    first_step_latency_ms: float = 0.0
    error: str | None = None


# ---------------------------------------------------------------------------
#  L7 Accuracy Metrics Collector
# ---------------------------------------------------------------------------

@dataclass
class L7Metrics:
    """Aggregated L7 stateful accuracy metrics across all VUs."""
    total_vus: int = 0
    workflows_completed: int = 0
    workflows_failed: int = 0
    total_steps: int = 0
    steps_ok: int = 0
    steps_failed: int = 0
    redirects_followed: int = 0
    cookies_captured: int = 0
    cookies_applied: int = 0        # times a captured cookie was reused
    tokens_extracted: int = 0
    tokens_injected: int = 0        # times an extracted token was reused
    retry_attempts: int = 0
    retry_successes: int = 0
    session_runs_total: int = 0
    active_sessions: int = 0
    active_sessions_peak: int = 0

    @property
    def session_success_rate(self) -> float:
        return self.workflows_completed / max(1, self.total_vus)

    @property
    def cookie_set_apply_rate(self) -> float:
        return self.cookies_applied / max(1, self.cookies_captured)

    @property
    def redirect_follow_ratio(self) -> float:
        return self.redirects_followed / max(1, self.total_steps)

    @property
    def retry_success_rate(self) -> float:
        return self.retry_successes / max(1, self.retry_attempts)

    def as_dict(self) -> dict[str, Any]:
        return {
            "total_vus": self.total_vus,
            "session_success_rate": round(self.session_success_rate, 4),
            "cookie_set_apply_rate": round(self.cookie_set_apply_rate, 4),
            "redirect_follow_ratio": round(self.redirect_follow_ratio, 4),
            "retry_success_rate": round(self.retry_success_rate, 4),
            "workflows_completed": self.workflows_completed,
            "workflows_failed": self.workflows_failed,
            "steps_ok": self.steps_ok,
            "steps_failed": self.steps_failed,
            "redirects_followed": self.redirects_followed,
            "cookies_captured": self.cookies_captured,
            "cookies_applied": self.cookies_applied,
            "tokens_extracted": self.tokens_extracted,
            "tokens_injected": self.tokens_injected,
            "retry_attempts": self.retry_attempts,
            "retry_successes": self.retry_successes,
            "session_runs_total": self.session_runs_total,
            "active_sessions_peak": self.active_sessions_peak,
        }


# ---------------------------------------------------------------------------
#  VirtualUser
# ---------------------------------------------------------------------------

class VirtualUser:
    """Per-user isolated L7 session with its own cookie jar and state."""

    __slots__ = (
        "user_id", "base_url", "cookie_jar", "headers",
        "redirect_history", "tokens", "_client",
        "_verify", "_timeout_s", "_metrics",
    )

    def __init__(
        self,
        user_id: int,
        base_url: str,
        verify: bool = False,
        timeout_s: float = 10.0,
        user_agent: str | None = None,
        metrics: L7Metrics | None = None,
    ):
        self.user_id = user_id
        self.base_url = base_url
        self.cookie_jar = httpx.Cookies() if _HTTPX else {}
        self.headers: dict[str, str] = {}
        if user_agent:
            self.headers["User-Agent"] = user_agent
        else:
            self.headers["User-Agent"] = f"DDoSamurai-VU/{user_id}"
        self.redirect_history: list[str] = []
        self.tokens: dict[str, str] = {}
        self._client: Optional[httpx.AsyncClient] = None
        self._verify = verify
        self._timeout_s = timeout_s
        self._metrics = metrics

    # -- lifecycle ----------------------------------------------------------

    async def _ensure_client(self):
        if self._client is None:
            if not _HTTPX:
                raise RuntimeError("httpx is required for VirtualUser")
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                cookies=self.cookie_jar,
                headers=self.headers,
                verify=self._verify,
                timeout=self._timeout_s,
                follow_redirects=False,  # we track redirects manually
            )
        return self._client

    async def close(self):
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # -- extraction ---------------------------------------------------------

    def _extract_from_response(self, resp, rules: list[ExtractRule]):
        """Extract tokens/data from HTTP response per configured rules."""
        for rule in rules:
            value = None
            if rule.source == "header" and rule.header_name:
                value = resp.headers.get(rule.header_name)
            elif rule.source == "cookie" and rule.cookie_name:
                value = resp.cookies.get(rule.cookie_name)
                if value and self._metrics:
                    self._metrics.cookies_captured += 1
            elif rule.source == "body_regex" and rule.regex_pattern:
                match = re.search(rule.regex_pattern, resp.text or "")
                if match:
                    value = match.group(1) if match.lastindex else match.group(0)

            if value:
                self.tokens[rule.field_name] = value
                if self._metrics:
                    self._metrics.tokens_extracted += 1
                log.debug("VU-%d extracted %s=%s", self.user_id, rule.field_name, value[:32])

    # -- step execution -----------------------------------------------------

    async def _execute_step(self, step: WorkflowStep) -> tuple[bool, int, int]:
        """Execute a single workflow step. Returns (success, status_code, retries_used)."""
        client = await self._ensure_client()

        # Inject tokens as headers
        request_headers = {}
        for token_spec in step.inject_tokens:
            header_name = str(token_spec).strip()
            token_key = header_name
            if ":" in header_name:
                header_name, token_key = [s.strip() for s in header_name.split(":", 1)]
            if token_key in self.tokens and header_name:
                request_headers[header_name] = self.tokens[token_key]
                if self._metrics:
                    self._metrics.tokens_injected += 1

        # Apply any captured cookies from previous steps
        if self.cookie_jar and self._metrics:
            self._metrics.cookies_applied += len(self.cookie_jar)

        last_exc = None
        rendered_body = step.body
        if isinstance(rendered_body, str) and self.tokens:
            for t_key, t_val in self.tokens.items():
                rendered_body = rendered_body.replace(f"{{{{{t_key}}}}}", str(t_val))

        for attempt in range(1 + step.max_retries):
            try:
                resp = await client.request(
                    step.method, step.path,
                    content=rendered_body,
                    headers=request_headers,
                    timeout=step.timeout_s,
                )

                # Capture Set-Cookie on initial response
                if resp.cookies:
                    self.cookie_jar.update(resp.cookies)
                    if self._metrics:
                        self._metrics.cookies_captured += len(resp.cookies)

                # Handle redirects manually to track them
                if step.follow_redirects:
                    redirect_hops = 0
                    while 300 <= resp.status_code < 400 and redirect_hops < 10:
                        location = str(resp.headers.get("location", "") or "").strip()
                        if not location:
                            break
                        self.redirect_history.append(location)
                        if self._metrics:
                            self._metrics.redirects_followed += 1
                        resp = await client.request("GET", location, timeout=step.timeout_s)
                        if resp.cookies:
                            self.cookie_jar.update(resp.cookies)
                            if self._metrics:
                                self._metrics.cookies_captured += len(resp.cookies)
                        redirect_hops += 1

                # Extract tokens
                if step.extract:
                    self._extract_from_response(resp, step.extract)

                # Check status
                status_ok = step.expected_status[0] <= resp.status_code <= step.expected_status[1]

                if attempt > 0 and self._metrics:
                    self._metrics.retry_successes += 1

                return (status_ok, resp.status_code, int(attempt))

            except Exception as exc:
                last_exc = exc
                if attempt < step.max_retries:
                    if self._metrics:
                        self._metrics.retry_attempts += 1
                    backoff = min(0.5 * (2 ** attempt), 5.0)
                    await asyncio.sleep(backoff)

        log.warning("VU-%d step '%s' failed after %d attempts: %s",
                     self.user_id, step.name, 1 + step.max_retries, last_exc)
        return (False, 0, int(step.max_retries))

    # -- workflow execution -------------------------------------------------

    async def execute_workflow(self, steps: list[WorkflowStep]) -> WorkflowResult:
        """
        Execute a sequence of WorkflowSteps.
        Supports branching: if step.branch_on maps a status_code → step_index,
        execution jumps to that step instead of the next one.
        """
        result = WorkflowResult(user_id=self.user_id, steps_total=len(steps))
        t0 = time.monotonic()

        step_idx = 0
        try:
            while 0 <= step_idx < len(steps):
                step = steps[step_idx]
                step_started = time.monotonic()
                ok, status, retries_used = await self._execute_step(step)
                if result.first_step_latency_ms <= 0.0:
                    result.first_step_latency_ms = max(0.0, (time.monotonic() - step_started) * 1000.0)
                result.retries_used += int(max(0, retries_used))

                if self._metrics:
                    self._metrics.total_steps += 1

                if ok:
                    result.steps_ok += 1
                    if self._metrics:
                        self._metrics.steps_ok += 1
                else:
                    result.steps_failed += 1
                    if self._metrics:
                        self._metrics.steps_failed += 1
                    # If step failed and no branch, stop
                    if not step.branch_on or status not in step.branch_on:
                        break

                # Branching
                if step.branch_on and status in step.branch_on:
                    step_idx = step.branch_on[status]
                else:
                    step_idx += 1

        except Exception as exc:
            result.error = str(exc)
        finally:
            result.total_time_s = time.monotonic() - t0
            result.redirects_followed = len(self.redirect_history)
            result.cookies_captured = len(self.cookie_jar) if hasattr(self.cookie_jar, '__len__') else 0
            result.tokens_extracted = len(self.tokens)

        return result


# ---------------------------------------------------------------------------
#  VU Pool — Run multiple VUs concurrently
# ---------------------------------------------------------------------------

async def run_vu_pool(
    vu_count: int,
    base_url: str,
    steps: list[WorkflowStep],
    concurrency: int = 10,
    verify: bool = False,
    timeout_s: float = 10.0,
    user_agent: str | None = None,
    session_repeats: int = 1,
    max_active_sessions: int | None = None,
    session_keepalive: bool = True,
) -> tuple[list[WorkflowResult], L7Metrics]:
    """
    Create `vu_count` VirtualUsers, each executing the same workflow,
    with at most `concurrency` running in parallel.
    Returns (results, aggregated_metrics).
    """
    vu_count = max(0, int(vu_count))
    session_repeats = max(1, int(session_repeats))
    total_sessions = int(vu_count * session_repeats)
    concurrency = max(1, int(concurrency))
    if max_active_sessions is not None:
        try:
            concurrency = min(concurrency, max(1, int(max_active_sessions)))
        except Exception:
            pass
    metrics = L7Metrics(total_vus=vu_count, session_runs_total=total_sessions)
    if total_sessions <= 0:
        return [], metrics

    results: list[WorkflowResult] = []
    result_lock = asyncio.Lock()
    id_queue: asyncio.Queue[tuple[int, int] | None] = asyncio.Queue()
    for uid in range(vu_count):
        for rep_idx in range(session_repeats):
            id_queue.put_nowait((uid, rep_idx))

    worker_count = min(total_sessions, concurrency)
    for _ in range(worker_count):
        id_queue.put_nowait(None)

    async def _worker_loop() -> None:
        vu_cache: dict[int, VirtualUser] = {}
        while True:
            item = await id_queue.get()
            if item is None:
                break
            uid, _rep_idx = item
            vu: VirtualUser | None = None
            if session_keepalive:
                vu = vu_cache.get(int(uid))
            if vu is None:
                vu = VirtualUser(
                    user_id=int(uid),
                    base_url=base_url,
                    verify=verify,
                    timeout_s=timeout_s,
                    user_agent=user_agent,
                    metrics=metrics,
                )
                if session_keepalive:
                    vu_cache[int(uid)] = vu
            metrics.active_sessions += 1
            if metrics.active_sessions > metrics.active_sessions_peak:
                metrics.active_sessions_peak = metrics.active_sessions
            try:
                result = await vu.execute_workflow(steps)
                if result.error is None and result.steps_failed == 0:
                    metrics.workflows_completed += 1
                else:
                    metrics.workflows_failed += 1
            except Exception as exc:
                metrics.workflows_failed += 1
                result = WorkflowResult(user_id=int(uid), error=str(exc))
            finally:
                metrics.active_sessions = max(0, int(metrics.active_sessions) - 1)
                if not session_keepalive:
                    await vu.close()
            async with result_lock:
                results.append(result)
        for vu in list(vu_cache.values()):
            try:
                await vu.close()
            except Exception:
                pass

    workers = [asyncio.create_task(_worker_loop()) for _ in range(worker_count)]
    await asyncio.gather(*workers, return_exceptions=False)
    return results, metrics
