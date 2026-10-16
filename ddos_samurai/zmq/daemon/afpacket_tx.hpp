#pragma once

// Shared af_packet transmission helper.
//
// Several workers (afpacket, cpu, scenario) can put their generated packet pool
// on the wire through the native af_packet kernel-socket backend instead of only
// simulating. This header centralizes that path so every such worker behaves
// identically and the backend selection flows through the distributed control
// plane by environment (the supervisor exec inherits the slave's env):
//
//   SAMURAI_AFPACKET_TX=1          enable real transmission (cpu/scenario opt-in)
//   SAMURAI_AFPACKET_IFACE=<if>    interface for stateful RX / TX_RING
//   SAMURAI_AFPACKET_STATEFUL=1    run the RX handshake handler + state table
//
// Only workers that link af_packet_static include this header.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>

#include <strings.h>

extern "C" {
#include "af_packet.h"
}

#include "engine.hpp"  // ddos_samurai::cpu_native::PacketConfig

namespace samurai::daemon {

inline bool AfPacketEnvFlag(const char* name) {
  const char* v = std::getenv(name);
  return v && v[0] &&
         (std::strcmp(v, "1") == 0 || ::strcasecmp(v, "true") == 0 ||
          ::strcasecmp(v, "yes") == 0 || ::strcasecmp(v, "on") == 0);
}

inline bool AfPacketEnvExplicitlyDisabled(const char* name) {
  const char* v = std::getenv(name);
  return v && v[0] &&
         (std::strcmp(v, "0") == 0 || ::strcasecmp(v, "false") == 0 ||
          ::strcasecmp(v, "no") == 0 || ::strcasecmp(v, "off") == 0);
}

// True by default so jobs transmit for real over af_packet unless explicitly
// disabled via SAMURAI_AFPACKET_TX=0/false/no/off.
inline bool AfPacketTxEnabled() {
  return !AfPacketEnvExplicitlyDisabled("SAMURAI_AFPACKET_TX");
}

struct AfPacketTxStats {
  std::uint64_t packets_sent = 0;
  std::uint64_t packets_errors = 0;
  std::uint64_t bytes_sent = 0;
  int rc = 0;
  std::string error_msg;
  std::string note = "afpacket:l3";
};

// Transmit `count` packets from `pool` (packet_size stride) over the af_packet
// backend. L3 raw sendmmsg by default; SO_TXTIME kernel pacing when ipg_ns>0.
// Stateful RX handshake when SAMURAI_AFPACKET_STATEFUL=1 and an interface is set.
// Accepts optional `stop_flag` (C volatile int*) for sub-5ms abort propagation.
inline AfPacketTxStats AfPacketSendPool(
    const ddos_samurai::cpu_native::PacketConfig& cfg,
    const std::uint8_t* pool, std::size_t pool_len,
    int packet_size, int count, long long ipg_ns,
    const volatile int* stop_flag = nullptr) {
  AfPacketTxStats out;
  const char* iface_env = std::getenv("SAMURAI_AFPACKET_IFACE");
  const std::string iface = iface_env ? iface_env : "";
  const bool stateful = AfPacketEnvFlag("SAMURAI_AFPACKET_STATEFUL") && !iface.empty();

  if (stateful) {
    (void)afpkt_configure_state_engine(65536u, 256u, 60u);
    const std::uint16_t window =
        cfg.window.has_value() ? static_cast<std::uint16_t>(*cfg.window) : static_cast<std::uint16_t>(64240);
    const std::uint8_t ttl =
        cfg.ttl.has_value() ? static_cast<std::uint8_t>(*cfg.ttl) : static_cast<std::uint8_t>(64);
    afpkt_set_mimicry_settings(window, static_cast<std::uint16_t>(1460), ttl);
    (void)afpkt_start_rx_handler(iface.c_str());
  }

  char err[128] = {0};
  afpkt_tx_metrics_t m{};
  const int rc = afpkt_send_l3_ex(cfg.target_ip.c_str(), cfg.target_port,
                                  pool, pool_len, packet_size, count, ipg_ns,
                                  stop_flag, &m, err, sizeof(err));
  out.rc = rc;
  if (err[0]) {
    out.error_msg = err;
  }

  afpkt_state_stats_t st{};
  if (stateful) {
    if (!(stop_flag && *stop_flag)) {
      (void)afpkt_ingest_tx_packets(pool, pool_len, packet_size, count);
      std::this_thread::sleep_for(std::chrono::milliseconds(200));
      afpkt_get_state_engine_stats(&st);
    }
    afpkt_stop_rx_handler();
  }

  out.packets_sent = static_cast<std::uint64_t>(std::max(0, m.sent));
  out.packets_errors = static_cast<std::uint64_t>(std::max(0, m.errors));
  out.bytes_sent = out.packets_sent * static_cast<std::uint64_t>(packet_size);
  if (stop_flag && *stop_flag) {
    out.note = "aborted";
  } else {
    out.note = stateful ? "afpacket:stateful" : "afpacket:l3";
  }
  if (rc != 0 && err[0]) {
    out.note += " tx_error=";
    out.note += err;
  }
  if (stateful && !(stop_flag && *stop_flag)) {
    out.note += " state_active=" + std::to_string(st.active_entries) +
                " state_evictions=" + std::to_string(st.timeout_evictions);
  }
  return out;
}

}  // namespace samurai::daemon
