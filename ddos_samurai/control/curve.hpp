#pragma once

// CURVE transport-encryption helpers for the ZMQ control plane. Encryption is
// opt-in: when no keys are configured the transport stays plaintext and behaves
// exactly as before. Keys are Z85 strings (40 chars) as produced by
// zmq_curve_keypair, so they pass cleanly as CLI arguments / env vars.
//
// Only compiled with libzmq (SAMURAI_CONTROL_HAVE_ZMQ).

#include <string>

namespace samurai::control {

struct CurveKeypair {
  std::string public_key;   // Z85, 40 chars
  std::string secret_key;   // Z85, 40 chars
  bool ok = false;
};

// Generate a fresh CURVE keypair (libsodium-backed). ok=false if libzmq was
// built without CURVE support.
CurveKeypair GenerateCurveKeypair();

// Client-side CURVE credentials: the server's public key plus this client's own
// (typically ephemeral) keypair. Encrypts + authenticates the server to the
// client; combined with the app-layer cluster-secret this protects the channel.
struct CurveClientCreds {
  std::string server_public;
  std::string client_public;
  std::string client_secret;
  bool ok() const {
    return !server_public.empty() && !client_public.empty() && !client_secret.empty();
  }
};

}  // namespace samurai::control
