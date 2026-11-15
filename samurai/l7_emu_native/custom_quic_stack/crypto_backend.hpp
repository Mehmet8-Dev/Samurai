#pragma once

#include "../engine.hpp"

namespace samurai::l7_emu_native::custom_quic_stack {

bool quic_crypto_ready(const RuntimeCapabilities& caps);

}  // namespace samurai::l7_emu_native::custom_quic_stack
