#include "tls_session_engine.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <random>

#ifdef SAMURAI_WITH_OPENSSL
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#endif

namespace ddos_samurai::l7_emu_native {

namespace {

uint64_t monotonic_ns_now() {
  return static_cast<uint64_t>(
      std::chrono::steady_clock::now().time_since_epoch().count());
}

#ifdef SAMURAI_WITH_OPENSSL
// New-session callback used by OpenSSL to deliver session tickets.
// The callback is installed on each thread-local SSL_CTX.
int new_session_cb(SSL* ssl, SSL_SESSION* session) {
  auto* tctx = static_cast<ThreadLocalTlsContext*>(
      SSL_CTX_get_ex_data(SSL_get_SSL_CTX(ssl), 0));
  if (tctx == nullptr || session == nullptr) {
    return 0;
  }

  // Serialize the session into DER.
  int der_len = i2d_SSL_SESSION(session, nullptr);
  if (der_len <= 0) {
    return 0;
  }
  std::vector<uint8_t> der_buf(static_cast<std::size_t>(der_len));
  unsigned char* p = der_buf.data();
  if (i2d_SSL_SESSION(session, &p) <= 0) {
    return 0;
  }

  // Extract the servername that was used for this connection.
  const char* sni_name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
  std::string host = sni_name ? sni_name : "";

  // Store in the circular session cache.
  TlsSessionCacheEntry entry{};
  entry.ticket_data = std::move(der_buf);
  entry.target_host = std::move(host);
  entry.target_port = 0;  // Will be set externally if needed.
  entry.created_ns = monotonic_ns_now();
  entry.lifetime_hint_s = SSL_SESSION_get_timeout(session);
  entry.valid = true;

  if (tctx->session_cache.size() < tctx->cache_capacity) {
    tctx->session_cache.push_back(std::move(entry));
  } else if (!tctx->session_cache.empty()) {
    // Circular overwrite of the oldest entry.
    std::size_t oldest_idx = 0;
    uint64_t oldest_ns = tctx->session_cache[0].created_ns;
    for (std::size_t i = 1; i < tctx->session_cache.size(); ++i) {
      if (tctx->session_cache[i].created_ns < oldest_ns) {
        oldest_ns = tctx->session_cache[i].created_ns;
        oldest_idx = i;
      }
    }
    tctx->session_cache[oldest_idx] = std::move(entry);
  }

  return 0;  // 0 = OpenSSL takes ownership of the SSL_SESSION.
}
#endif  // SAMURAI_WITH_OPENSSL

}  // namespace

// ---------------------------------------------------------------------------
// TlsSessionEngine public methods
// ---------------------------------------------------------------------------

TlsSessionEngine::TlsSessionEngine() = default;

TlsSessionEngine::~TlsSessionEngine() { shutdown(); }

bool TlsSessionEngine::configure(const SniPoolConfig& sni_config,
                                  const CipherSuiteConfig& cipher_config,
                                  int verify_mode,
                                  std::size_t session_cache_capacity) {
  sni_config_ = sni_config;
  cipher_config_ = cipher_config;
  verify_mode_ = verify_mode;
  session_cache_capacity_ = session_cache_capacity > 0 ? session_cache_capacity : 256;
  configured_ = true;
  return true;
}

ThreadLocalTlsContext* TlsSessionEngine::get_thread_context() {
  // The context is heap-allocated and owned by the engine (freed in shutdown()),
  // not by thread-local storage. Worker threads that create TLS sessions exit
  // (and are joined) before the engine is destroyed; if the context lived in
  // thread_local storage its destructor would run at thread exit while the
  // engine's registry still held a pointer to it, so shutdown() would touch
  // freed memory. Keeping ownership in the engine keeps those pointers valid.
  thread_local ThreadLocalTlsContext* tctx_ptr = nullptr;
  if (tctx_ptr != nullptr && tctx_ptr->initialized) {
    return tctx_ptr;
  }
  if (tctx_ptr == nullptr) {
    tctx_ptr = new ThreadLocalTlsContext();
  }
  ThreadLocalTlsContext& tctx = *tctx_ptr;

  if (tctx.initialized) {
    return &tctx;
  }

#ifdef SAMURAI_WITH_OPENSSL
  SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
  if (ctx == nullptr) {
    return nullptr;
  }

  // Set minimum protocol to TLS 1.2.
  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

#ifdef SSL_OP_ENABLE_KTLS
  // Enable Linux Kernel TLS (kTLS) crypto offload for high-performance transport.
  SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);
#endif

  // Apply cipher suite configuration. When the caller leaves the preference
  // empty we still pin an AES-NI-friendly ordering: on hardware with AES
  // acceleration, AES-128-GCM costs roughly half the CPU of AES-256-GCM and far
  // less than ChaCha20-Poly1305, so offering it first keeps the symmetric-crypto
  // load off the critical path before the NIC saturates.
  SSL_CTX_set_cipher_list(
      ctx,
      cipher_config_.cipher_list.empty() ? kDefaultTls12CipherList
                                         : cipher_config_.cipher_list.c_str());
#if TLS1_3_VERSION
  SSL_CTX_set_ciphersuites(
      ctx,
      cipher_config_.ciphersuites.empty() ? kDefaultTls13Ciphersuites
                                          : cipher_config_.ciphersuites.c_str());
#endif

  // Configure ALPN to negotiate both h2 and http/1.1.
  static const unsigned char kAlpn[] = "\x02h2\x08http/1.1";
  SSL_CTX_set_alpn_protos(ctx, kAlpn, sizeof(kAlpn) - 1);

  // Peer verification.
  SSL_CTX_set_verify(ctx, verify_mode_ ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, nullptr);

  // Enable built-in session cache for ticket storage.
  SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL);

  // Store a pointer to the thread-local context for the callback.
  SSL_CTX_set_ex_data(ctx, 0, &tctx);

  // Install the new-session callback for ticket capture.
  SSL_CTX_sess_set_new_cb(ctx, new_session_cb);

  tctx.ssl_ctx = ctx;
#else
  tctx.ssl_ctx = nullptr;
#endif

  tctx.cache_capacity = session_cache_capacity_;
  tctx.session_cache.reserve(std::min<std::size_t>(session_cache_capacity_, 1024));
  tctx.initialized = true;

  // Register for aggregate stats collection.
  {
    std::lock_guard<std::mutex> lock(registry_mu_);
    registered_contexts_.push_back(&tctx);
  }

  return &tctx;
}

void* TlsSessionEngine::create_ssl(ThreadLocalTlsContext* tctx,
                                     const std::string& target_host,
                                     uint16_t target_port,
                                     bool use_mem_bio) {
  (void)target_port;
#ifdef SAMURAI_WITH_OPENSSL
  if (tctx == nullptr || tctx->ssl_ctx == nullptr) {
    return nullptr;
  }

  auto* ctx = static_cast<SSL_CTX*>(tctx->ssl_ctx);
  SSL* ssl = SSL_new(ctx);
  if (ssl == nullptr) {
    return nullptr;
  }

  // Apply SNI.
  std::string sni = target_host;
  if (!sni_config_.hostnames.empty()) {
    sni = next_sni(tctx);
    tctx->sni_cursor++;
  }
  if (!sni.empty()) {
    SSL_set_tlsext_host_name(ssl, sni.c_str());
  }

  if (use_mem_bio) {
    // Zero-copy path: memory BIOs for custom TCP dataplane.
    BIO* rbio = BIO_new(BIO_s_mem());
    BIO* wbio = BIO_new(BIO_s_mem());
    if (rbio == nullptr || wbio == nullptr) {
      if (rbio) BIO_free(rbio);
      if (wbio) BIO_free(wbio);
      SSL_free(ssl);
      return nullptr;
    }
    BIO_set_mem_eof_return(rbio, -1);
    BIO_set_mem_eof_return(wbio, -1);
    SSL_set_bio(ssl, rbio, wbio);
  }

  SSL_set_connect_state(ssl);
  return ssl;
#else
  (void)tctx;
  (void)target_host;
  (void)use_mem_bio;
  return nullptr;
#endif
}

bool TlsSessionEngine::try_resume_session(ThreadLocalTlsContext* tctx,
                                            void* ssl_ptr,
                                            const std::string& target_host,
                                            uint16_t target_port) {
#ifdef SAMURAI_WITH_OPENSSL
  if (tctx == nullptr || ssl_ptr == nullptr) {
    return false;
  }
  auto* ssl = static_cast<SSL*>(ssl_ptr);

  for (auto& entry : tctx->session_cache) {
    if (!entry.valid) continue;
    if (entry.target_host != target_host) continue;
    if (entry.target_port != 0 && entry.target_port != target_port) continue;

    // Check expiry.
    const uint64_t now = monotonic_ns_now();
    if (entry.lifetime_hint_s > 0 &&
        (now - entry.created_ns) > entry.lifetime_hint_s * 1'000'000'000ULL) {
      entry.valid = false;
      continue;
    }

    // Deserialize the DER session.
    const unsigned char* p = entry.ticket_data.data();
    SSL_SESSION* session = d2i_SSL_SESSION(nullptr, &p,
                                            static_cast<long>(entry.ticket_data.size()));
    if (session == nullptr) {
      entry.valid = false;
      continue;
    }

    if (SSL_set_session(ssl, session) == 1) {
      SSL_SESSION_free(session);
      tctx->cache_hits.fetch_add(1, std::memory_order_relaxed);
      tctx->handshakes_resumed.fetch_add(1, std::memory_order_relaxed);
      return true;
    }
    SSL_SESSION_free(session);
  }

  tctx->cache_misses.fetch_add(1, std::memory_order_relaxed);
  return false;
#else
  (void)tctx;
  (void)ssl_ptr;
  (void)target_host;
  (void)target_port;
  return false;
#endif
}

void TlsSessionEngine::cache_session(ThreadLocalTlsContext* tctx,
                                      void* ssl_ptr,
                                      const std::string& target_host,
                                      uint16_t target_port) {
#ifdef SAMURAI_WITH_OPENSSL
  if (tctx == nullptr || ssl_ptr == nullptr) {
    return;
  }
  auto* ssl = static_cast<SSL*>(ssl_ptr);
  SSL_SESSION* session = SSL_get1_session(ssl);
  if (session == nullptr) {
    return;
  }

  int der_len = i2d_SSL_SESSION(session, nullptr);
  if (der_len <= 0) {
    SSL_SESSION_free(session);
    return;
  }
  std::vector<uint8_t> der_buf(static_cast<std::size_t>(der_len));
  unsigned char* p = der_buf.data();
  if (i2d_SSL_SESSION(session, &p) <= 0) {
    SSL_SESSION_free(session);
    return;
  }

  TlsSessionCacheEntry entry{};
  entry.ticket_data = std::move(der_buf);
  entry.target_host = target_host;
  entry.target_port = target_port;
  entry.created_ns = monotonic_ns_now();
  entry.lifetime_hint_s = SSL_SESSION_get_timeout(session);
  entry.valid = true;

  SSL_SESSION_free(session);

  if (tctx->session_cache.size() < tctx->cache_capacity) {
    tctx->session_cache.push_back(std::move(entry));
  } else if (!tctx->session_cache.empty()) {
    std::size_t oldest_idx = 0;
    uint64_t oldest_ns = tctx->session_cache[0].created_ns;
    for (std::size_t i = 1; i < tctx->session_cache.size(); ++i) {
      if (tctx->session_cache[i].created_ns < oldest_ns) {
        oldest_ns = tctx->session_cache[i].created_ns;
        oldest_idx = i;
      }
    }
    tctx->session_cache[oldest_idx] = std::move(entry);
  }
#else
  (void)tctx;
  (void)ssl_ptr;
  (void)target_host;
  (void)target_port;
#endif
}

std::string TlsSessionEngine::next_sni(ThreadLocalTlsContext* tctx) const {
  if (sni_config_.hostnames.empty()) {
    return {};
  }
  if (sni_config_.rotation_mode == "random") {
    std::mt19937 rng(sni_config_.seed + (tctx ? tctx->sni_cursor : 0));
    std::uniform_int_distribution<std::size_t> dist(0, sni_config_.hostnames.size() - 1);
    return sni_config_.hostnames[dist(rng)];
  }
  // round_robin / sequential
  const uint32_t cursor = tctx ? tctx->sni_cursor : 0;
  return sni_config_.hostnames[cursor % sni_config_.hostnames.size()];
}

TlsSessionStats TlsSessionEngine::snapshot_stats() const {
  TlsSessionStats stats{};
  std::lock_guard<std::mutex> lock(registry_mu_);
  for (const auto* tctx : registered_contexts_) {
    if (tctx == nullptr) continue;
    const uint64_t full = tctx->handshakes_full.load(std::memory_order_relaxed);
    const uint64_t resumed = tctx->handshakes_resumed.load(std::memory_order_relaxed);
    const uint64_t failed = tctx->handshakes_failed.load(std::memory_order_relaxed);
    stats.full_handshakes += full;
    stats.resumed_handshakes += resumed;
    stats.handshakes_completed += full + resumed;
    stats.handshakes_failed += failed;
    stats.session_reuse_hits += tctx->cache_hits.load(std::memory_order_relaxed);
    stats.session_reuse_misses += tctx->cache_misses.load(std::memory_order_relaxed);
    stats.sni_rotations += tctx->sni_cursor;
  }
  return stats;
}

void TlsSessionEngine::shutdown() {
#ifdef SAMURAI_WITH_OPENSSL
  std::lock_guard<std::mutex> lock(registry_mu_);
  for (auto* tctx : registered_contexts_) {
    if (tctx == nullptr) continue;
    if (tctx->ssl_ctx != nullptr) {
      SSL_CTX_free(static_cast<SSL_CTX*>(tctx->ssl_ctx));
      tctx->ssl_ctx = nullptr;
    }
    tctx->session_cache.clear();
    tctx->initialized = false;
    // The engine owns the heap-allocated per-thread context (see
    // get_thread_context); free it now that its worker thread has exited.
    delete tctx;
  }
  registered_contexts_.clear();
#endif
}

}  // namespace ddos_samurai::l7_emu_native
