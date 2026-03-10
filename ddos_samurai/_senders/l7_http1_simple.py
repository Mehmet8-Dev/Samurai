import asyncio
import random


async def http_app_sender(
    target_ip,
    target_port,
    count,
    concurrency,
    http_method,
    http_path,
    payloads,
    verbose,
    scheme="http",
    verify=True,
    timeout_s=5.0,
    retries=0,
    ssl_context=None,
    cookies=None,
    user_agent=None,
    live_sent=None,
    live_errors=None,
    live_progress=None,
    *,
    HTTPX_AVAILABLE: bool,
    httpx_module,
    stats_fn,
    update_live_fn,
    log_info,
    log_error,
    utils_mod,
):
    """
    Send standard HTTP/1.1 requests using httpx.
    """
    del verbose
    if not HTTPX_AVAILABLE:
        log_error("HTTP sender için 'httpx' kütüphanesi yüklü değil.")
        return stats_fn(attempted=count, sent=0, errors=count)

    base_url = f"{scheme}://{target_ip}:{target_port}"
    log_info(f"HTTP sender initialized. Target: {base_url}, Count: {count}")

    headers = {}
    if user_agent:
        headers["User-Agent"] = user_agent
    else:
        headers["User-Agent"] = (
            random.choice(utils_mod.USER_AGENTS) if hasattr(utils_mod, "USER_AGENTS") else "Samurai/2.0"
        )

    ok = 0
    err = 0
    responses = 0
    status_2xx = 0
    status_4xx = 0
    status_5xx = 0

    async def _flush(tasks):
        nonlocal ok, err, responses, status_2xx, status_4xx, status_5xx
        if not tasks:
            return
        res = await asyncio.gather(*tasks, return_exceptions=True)
        tasks.clear()

        batch_sent = 0
        batch_err = 0
        for r in res:
            if isinstance(r, Exception):
                err += 1
                batch_err += 1
                continue
            ok += 1
            batch_sent += 1
            responses += 1
            code = int(getattr(r, "status_code", 0) or 0)
            if 200 <= code < 300:
                status_2xx += 1
            elif 400 <= code < 500:
                status_4xx += 1
            elif code >= 500:
                status_5xx += 1

        update_live_fn(live_sent, batch_sent)
        update_live_fn(live_errors, batch_err)

    retry_attempt_total = 0
    retry_success_count = 0
    max_retries = max(0, int(retries))

    async def _request_with_retry(client, method, path, data):
        nonlocal retry_attempt_total, retry_success_count
        last_exc = None
        for attempt in range(1 + max_retries):
            try:
                resp = await client.request(method, path, content=data)
                if attempt > 0:
                    retry_success_count += 1
                return resp
            except (
                httpx_module.ConnectError,
                httpx_module.ReadTimeout,
                httpx_module.WriteTimeout,
                httpx_module.ConnectTimeout,
                httpx_module.PoolTimeout,
            ) as exc:
                last_exc = exc
                if attempt < max_retries:
                    retry_attempt_total += 1
                    backoff = min(0.5 * (2**attempt), 5.0)
                    await asyncio.sleep(backoff)
        raise last_exc

    try:
        limits = httpx_module.Limits(max_keepalive_connections=concurrency, max_connections=concurrency)
        async with httpx_module.AsyncClient(
            verify=ssl_context if ssl_context else verify,
            base_url=base_url,
            limits=limits,
            cookies=cookies,
            headers=headers,
            timeout=timeout_s,
        ) as client:
            tasks = []
            for _i in range(count):
                update_live_fn(live_progress, 1)
                path = random.choice(http_path) if isinstance(http_path, list) else http_path
                data = random.choice(payloads) if payloads else None

                tasks.append(asyncio.create_task(_request_with_retry(client, http_method, path, data)))

                if len(tasks) >= concurrency:
                    await _flush(tasks)

            if tasks:
                await _flush(tasks)

    except Exception as e:
        log_error(f"HTTP sender failed: {e}")
        err += max(0, count - ok)
    finally:
        log_info(
            f"HTTP sender finished sending {count} requests. "
            f"retries_total={retry_attempt_total} retry_recovered={retry_success_count}"
        )
    return stats_fn(
        attempted=count,
        sent=ok,
        errors=max(err, count - ok),
        responses_total=responses,
        status_2xx=status_2xx,
        status_4xx=status_4xx,
        status_5xx=status_5xx,
        retry_attempt_total=retry_attempt_total,
        retry_success_count=retry_success_count,
    )

