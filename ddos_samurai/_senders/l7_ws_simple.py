import asyncio


async def websocket_sender(
    target_ip,
    target_port,
    count,
    concurrency,
    ws_path,
    ws_message,
    verbose,
    ssl_context=None,
    live_sent=None,
    live_errors=None,
    live_progress=None,
    *,
    WEBSOCKETS_AVAILABLE: bool,
    websockets_module,
    stats_fn,
    update_live_fn,
    log_info,
    log_error,
):
    """
    Send WebSocket messages/pings with fair count distribution.
    """
    if not WEBSOCKETS_AVAILABLE:
        log_error("WebSocket desteği için 'websockets' kütüphanesi yüklü değil.")
        return stats_fn(attempted=count, sent=0, errors=count)

    scheme = "wss" if target_port == 443 else "ws"
    uri = f"{scheme}://{target_ip}:{target_port}{ws_path}"
    log_info(f"WebSocket sender initialized. URI: {uri}, Count: {count}")

    sent_msgs = 0
    errors = 0
    effective_concurrency = min(max(1, concurrency), count) if count > 0 else 1
    per_worker_base = count // effective_concurrency
    remainder = count % effective_concurrency

    def _worker_count(worker_id):
        return per_worker_base + (1 if worker_id < remainder else 0)

    async def _ws_worker(worker_id):
        nonlocal sent_msgs, errors
        my_count = _worker_count(worker_id)
        try:
            async with websockets_module.connect(uri, ssl=ssl_context) as websocket:
                for _ in range(my_count):
                    update_live_fn(live_progress, 1)
                    await websocket.send(ws_message)
                    sent_msgs += 1
                    update_live_fn(live_sent, 1)
                    if verbose:
                        log_info(f"WS message sent: {ws_message}")
                    await asyncio.sleep(0.01)
        except Exception as e:
            errors += 1
            update_live_fn(live_errors, 1)
            if verbose:
                log_error(f"WS connection failed: {e}")

    tasks = [asyncio.create_task(_ws_worker(i)) for i in range(effective_concurrency)]
    await asyncio.gather(*tasks)
    log_info("WebSocket sender finished.")
    return stats_fn(attempted=count, sent=sent_msgs, errors=max(errors, count - sent_msgs))

