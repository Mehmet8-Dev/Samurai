#include "h3_real_client.hpp"

#include "h3_ngtcp2_client.hpp"

namespace ddos_samurai::l7_emu_native::custom_quic_stack {

bool run_h3_real_client(
    const Profile& profile,
    const RuntimeConfig& cfg,
    UdpProbeCounters* out) {
  // Compatibility shim (kept intentionally thin): the legacy "real client"
  // entrypoint delegates to the in-process ngtcp2/nghttp3 runtime. A separate
  // curl/shell path was removed; do not reintroduce an alternate H3 stack here.
  return run_h3_ngtcp2_client(profile, cfg, out);
}

}  // namespace ddos_samurai::l7_emu_native::custom_quic_stack
