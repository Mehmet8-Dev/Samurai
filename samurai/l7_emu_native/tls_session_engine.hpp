#pragma once

#include <cstddef>
#include <cstdint>
#include <atomic>
#include <mutex>
#include <string>
#include <vector>

namespace samurai::l7_emu_native {

struct Profile;

// AES-NI-friendly cipher preferences shared by every client SSL_CTX in the
// engine. Offering AES-128-GCM ahead of AES-256-GCM and ChaCha20-Poly1305 keeps
// the symmetric-encryption CPU cost minimal on hardware with AES acceleration,
// which is what saturates first under high-throughput HTTP/2 + TLS load.
inline constexpr const char* kDefaultTls12CipherList =
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305";
inline constexpr const char* kDefaultTls13Ciphersuites =
    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";

// TLS session cache entry for session ticket/ID reuse.
struct TlsSessionCacheEntry {
  std::vector<uint8_t> ticket_data{};
  std::string target_host{};
  uint16_t target_port{0};
  uint64_t created_ns{0};
  uint64_t lifetime_hint_s{0};
  bool valid{false};
};

// SNI rotation pool configuration.
struct SniPoolConfig {
  std::vector<std::string> hostnames{};
  std::string rotation_mode{"round_robin"};  // round_robin, random, sequential
  uint32_t seed{0};
};

// Cipher suite manipulation configuration.
struct CipherSuiteConfig {
  std::string cipher_list{};    // OpenSSL cipher string (TLS 1.2)
  std::string ciphersuites{};   // OpenSSL ciphersuites string (TLS 1.3)
  bool randomize_order{false};
  uint32_t seed{0};
};

// Per-thread TLS context avoiding cross-thread lock contention.
struct ThreadLocalTlsContext {
  void* ssl_ctx{nullptr};  // SSL_CTX* (opaque to avoid header dep)
  std::vector<TlsSessionCacheEntry> session_cache{};
  std::size_t cache_capacity{256};
  std::atomic<uint64_t> cache_hits{0};
  std::atomic<uint64_t> cache_misses{0};
  std::atomic<uint64_t> handshakes_full{0};
  std::atomic<uint64_t> handshakes_resumed{0};
  std::atomic<uint64_t> handshakes_failed{0};
  uint32_t sni_cursor{0};
  bool initialized{false};
};

// Aggregate TLS telemetry counters.
struct TlsSessionStats {
  uint64_t handshakes_completed{0};
  uint64_t handshakes_failed{0};
  uint64_t session_reuse_hits{0};
  uint64_t session_reuse_misses{0};
  uint64_t full_handshakes{0};
  uint64_t resumed_handshakes{0};
  uint64_t sni_rotations{0};
};

// Main TLS Session Engine — manages per-thread SSL_CTX pools with session
// ticket caching, SNI rotation, and cipher suite manipulation.
class TlsSessionEngine {
 public:
  TlsSessionEngine();
  ~TlsSessionEngine();

  // Initialize with profile-level TLS configuration.
  bool configure(const SniPoolConfig& sni_config,
                 const CipherSuiteConfig& cipher_config,
                 int verify_mode,
                 std::size_t session_cache_capacity);

  // Get or create a thread-local SSL_CTX.
  ThreadLocalTlsContext* get_thread_context();

  // Create a new SSL* from the thread-local context.
  // When use_mem_bio is true, creates with memory BIOs for custom TCP.
  // When ktls_socket_fd >= 0 the SSL is bound to that real socket fd
  // (SSL_set_fd) instead of a BIO, so the kernel-TLS ULP can engage after the
  // handshake (SSL_OP_ENABLE_KTLS is set on the shared CTX); use_mem_bio is
  // ignored in that case.
  void* create_ssl(ThreadLocalTlsContext* tctx,
                   const std::string& target_host,
                   uint16_t target_port,
                   bool use_mem_bio,
                   int ktls_socket_fd = -1);

  // Attempt to resume a previous TLS session using cached ticket.
  bool try_resume_session(ThreadLocalTlsContext* tctx, void* ssl,
                          const std::string& target_host, uint16_t target_port);

  // Store a completed TLS session for future reuse.
  void cache_session(ThreadLocalTlsContext* tctx, void* ssl,
                     const std::string& target_host, uint16_t target_port);

  // Get the next SNI hostname from the rotation pool.
  std::string next_sni(ThreadLocalTlsContext* tctx) const;

  // Collect aggregate statistics.
  TlsSessionStats snapshot_stats() const;

  // Tear down all thread-local contexts.
  void shutdown();

 private:
  SniPoolConfig sni_config_{};
  CipherSuiteConfig cipher_config_{};
  int verify_mode_{0};
  std::size_t session_cache_capacity_{256};
  bool configured_{false};

  mutable std::mutex registry_mu_{};
  std::vector<ThreadLocalTlsContext*> registered_contexts_{};
};

}  // namespace samurai::l7_emu_native
