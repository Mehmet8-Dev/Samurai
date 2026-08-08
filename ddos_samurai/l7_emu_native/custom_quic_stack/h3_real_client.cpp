#include "h3_real_client.hpp"

#include "h3_ngtcp2_client.hpp"

namespace ddos_samurai::l7_emu_native::custom_quic_stack {

bool run_h3_real_client(
    const Profile& profile,
    const RuntimeConfig& cfg,
    UdpProbeCounters* out) {
  // Compatibility shim: legacy entrypoint now delegates to native in-process
  // ngtcp2/nghttp3 runtime (no shell curl path).
  return run_h3_ngtcp2_client(profile, cfg, out);
}

}  // namespace ddos_samurai::l7_emu_native::custom_quic_stack
