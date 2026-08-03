#pragma once

// Native network helpers — the C++ replacement for the L2/L3 resolution
// utilities in the former ddos_samurai/utils.py (get_local_ip,
// get_gateway_mac, mac_to_int). Used by the L2-capable senders (AF_XDP/DPDK)
// and the orchestrator when a source address or next-hop MAC is needed.
//
// All resolution is done natively via /proc and getsockname() — no subprocess
// calls to `ip`/`arp`.

#include <cstdint>
#include <string>

namespace samurai::core {

// Best-effort local IPv4 address for outbound traffic. Mirrors
// utils.get_local_ip(): a UDP "connect" (no packets sent) lets the OS pick a
// source address, read back via getsockname(); falls back to the host's
// resolved address, then "127.0.0.1".
std::string GetLocalIp();

// Resolve the next-hop MAC toward `target_ip` (or the default gateway when
// empty), using the kernel routing table (/proc/net/route) and the ARP cache
// (/proc/net/arp). Returns "ff:ff:ff:ff:ff:ff" when the MAC cannot be
// resolved — mirrors utils.get_gateway_mac()'s broadcast fallback.
std::string GetGatewayMac(const std::string& target_ip = "");

// "aa:bb:cc:dd:ee:ff" -> 0x0000AABBCCDDEEFF. Returns 0 for malformed input.
// Mirrors utils.mac_to_int().
std::uint64_t MacToInt(const std::string& mac);

}  // namespace samurai::core
