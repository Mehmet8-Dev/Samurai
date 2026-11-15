#include "crypto_backend.hpp"

namespace samurai::l7_emu_native::custom_quic_stack {

bool quic_crypto_ready(const RuntimeCapabilities& caps) {
  return caps.openssl && caps.ngtcp2 && caps.nghttp3;
}

}  // namespace samurai::l7_emu_native::custom_quic_stack
