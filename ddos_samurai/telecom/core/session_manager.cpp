#include "ddos_samurai/telecom/core/session_manager.hpp"

#include <sys/mman.h>
#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <new>

namespace ddos_samurai::telecom {

namespace {

uint32_t NextPowerOf2(uint32_t v) {
    if (v == 0) return 1;
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    return v + 1;
}

} // namespace

SessionManager::SessionManager(uint32_t max_sessions, int socket_id)
    : max_sessions_(std::max(1u, max_sessions)),
      socket_id_(socket_id) {

    // Havuz boyutunu hesapla (128 bayt * max_sessions)
    pool_alloc_size_ = static_cast<size_t>(max_sessions_) * sizeof(TelcoSessionContext);

    // Hugepages ile tahsis etmeyi dene (2MB / 1GB sayfalar)
    void* addr = ::mmap(nullptr, pool_alloc_size_, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
    if (addr != MAP_FAILED) {
        sessions_pool_ = static_cast<TelcoSessionContext*>(addr);
        using_hugepages_ = true;
    } else {
        // Standart posix_memalign (64 bayt önbellek çizgisi hizalamalı fallback)
        void* mem = nullptr;
        if (::posix_memalign(&mem, 64, pool_alloc_size_) == 0) {
            sessions_pool_ = static_cast<TelcoSessionContext*>(mem);
        } else {
            sessions_pool_ = new TelcoSessionContext[max_sessions_];
        }
        using_hugepages_ = false;
    }

    std::memset(sessions_pool_, 0, pool_alloc_size_);

    // Boş indeks yığınını hazırla
    free_indices_ = std::make_unique<uint32_t[]>(max_sessions_);
    for (uint32_t i = 0; i < max_sessions_; ++i) {
        free_indices_[i] = max_sessions_ - 1 - i;
    }
    free_head_.store(max_sessions_, std::memory_order_relaxed);

    // Hash tablolarının boyutunu belirle (En az 2 katı, 2'nin kuvveti)
    hash_size_ = NextPowerOf2(std::max(65536u, max_sessions_ * 2));
    hash_mask_ = hash_size_ - 1;

    // Hash tabloları için bellek tahsisi
    size_t bucket_bytes = static_cast<size_t>(hash_size_) * sizeof(TelcoSessionContext*);
    hash_buckets_ = static_cast<TelcoSessionContext**>(::calloc(hash_size_, sizeof(TelcoSessionContext*)));
    pppoe_buckets_ = static_cast<TelcoSessionContext**>(::calloc(hash_size_, sizeof(TelcoSessionContext*)));
    gtpu_buckets_ = static_cast<TelcoSessionContext**>(::calloc(hash_size_, sizeof(TelcoSessionContext*)));
}

SessionManager::~SessionManager() {
    if (hash_buckets_) { ::free(hash_buckets_); hash_buckets_ = nullptr; }
    if (pppoe_buckets_) { ::free(pppoe_buckets_); pppoe_buckets_ = nullptr; }
    if (gtpu_buckets_) { ::free(gtpu_buckets_); gtpu_buckets_ = nullptr; }

    if (sessions_pool_) {
        if (using_hugepages_) {
            ::munmap(sessions_pool_, pool_alloc_size_);
        } else {
            ::free(sessions_pool_);
        }
        sessions_pool_ = nullptr;
    }
}

TelcoSessionContext* SessionManager::AcquireSession() noexcept {
    while (true) {
        uint32_t current_head = free_head_.load(std::memory_order_relaxed);
        if (current_head == 0) {
            return nullptr; // Havuz doldu
        }
        if (free_head_.compare_exchange_weak(current_head, current_head - 1,
                                             std::memory_order_acquire,
                                             std::memory_order_relaxed)) {
            uint32_t idx = free_indices_[current_head - 1];
            TelcoSessionContext* session = &sessions_pool_[idx];
            session->Reset();
            active_sessions_.fetch_add(1, std::memory_order_relaxed);
            return session;
        }
    }
}

void SessionManager::ReleaseSession(TelcoSessionContext* ctx) noexcept {
    if (!ctx) return;

    // Aktif hash bağlamalarını temizle
    Unbind5Tuple(ctx);
    UnbindPppoeSession(ctx);
    UnbindGtpuSession(ctx);

    // İndeksi hesapla
    ptrdiff_t diff = ctx - sessions_pool_;
    if (diff < 0 || static_cast<size_t>(diff) >= max_sessions_) {
        return; // Geçersiz işaretçi
    }
    uint32_t idx = static_cast<uint32_t>(diff);

    ctx->Reset();
    ctx->state = SessionState::TEARDOWN;

    while (true) {
        uint32_t current_head = free_head_.load(std::memory_order_relaxed);
        if (current_head >= max_sessions_) {
            break; // Hata durumunda taşmayı engelle
        }
        free_indices_[current_head] = idx;
        if (free_head_.compare_exchange_weak(current_head, current_head + 1,
                                             std::memory_order_release,
                                             std::memory_order_relaxed)) {
            active_sessions_.fetch_sub(1, std::memory_order_relaxed);
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// 5-Tuple Hash Lookup & Management
// ---------------------------------------------------------------------------

TelcoSessionContext* SessionManager::FindSessionBy5Tuple(const Flow5Tuple& tuple) const noexcept {
    uint32_t h = Hash5Tuple(tuple);
    if (h == 0) h = 1;
    uint32_t idx = h & hash_mask_;

    for (uint32_t p = 0; p < MAX_PROBES; ++p) {
        uint32_t slot = (idx + p) & hash_mask_;
        TelcoSessionContext* s = hash_buckets_[slot];
        if (!s) return nullptr;

        if (s->flow_hash == h &&
            s->client_ip == tuple.src_ip &&
            s->peer_ip == tuple.dst_ip &&
            s->client_port == tuple.src_port &&
            s->peer_port == tuple.dst_port &&
            s->ip_proto == tuple.proto) {
            return s;
        }
    }
    return nullptr;
}

TelcoSessionContext* SessionManager::FindSessionBy5Tuple(uint32_t src_ip, uint32_t dst_ip, 
                                                        uint16_t src_port, uint16_t dst_port, 
                                                        uint8_t proto) const noexcept {
    Flow5Tuple tuple{src_ip, dst_ip, src_port, dst_port, proto, {0}};
    return FindSessionBy5Tuple(tuple);
}

bool SessionManager::Bind5Tuple(TelcoSessionContext* ctx, const Flow5Tuple& tuple) noexcept {
    if (!ctx) return false;

    // Önceki eşleşme varsa temizle
    Unbind5Tuple(ctx);

    uint32_t h = Hash5Tuple(tuple);
    if (h == 0) h = 1;
    ctx->client_ip = tuple.src_ip;
    ctx->peer_ip = tuple.dst_ip;
    ctx->client_port = tuple.src_port;
    ctx->peer_port = tuple.dst_port;
    ctx->ip_proto = tuple.proto;
    ctx->flow_hash = h;

    uint32_t idx = h & hash_mask_;
    for (uint32_t p = 0; p < MAX_PROBES; ++p) {
        uint32_t slot = (idx + p) & hash_mask_;
        if (hash_buckets_[slot] == nullptr || hash_buckets_[slot] == ctx) {
            hash_buckets_[slot] = ctx;
            return true;
        }
    }
    return false; // Probe limiti aşıldı
}

bool SessionManager::Bind5Tuple(TelcoSessionContext* ctx, uint32_t src_ip, uint32_t dst_ip,
                                uint16_t src_port, uint16_t dst_port, uint8_t proto) noexcept {
    Flow5Tuple tuple{src_ip, dst_ip, src_port, dst_port, proto, {0}};
    return Bind5Tuple(ctx, tuple);
}

void SessionManager::Unbind5Tuple(TelcoSessionContext* ctx) noexcept {
    if (!ctx || ctx->flow_hash == 0) return;

    uint32_t h = ctx->flow_hash;
    uint32_t idx = h & hash_mask_;

    for (uint32_t p = 0; p < MAX_PROBES; ++p) {
        uint32_t slot = (idx + p) & hash_mask_;
        if (hash_buckets_[slot] == ctx) {
            hash_buckets_[slot] = nullptr;

            // Backward-shift deletion (tombstone gerektirmeyen deterministik temizleme)
            uint32_t next = (slot + 1) & hash_mask_;
            while (hash_buckets_[next] != nullptr) {
                TelcoSessionContext* rehash_ctx = hash_buckets_[next];
                hash_buckets_[next] = nullptr;

                uint32_t r_h = rehash_ctx->flow_hash;
                uint32_t r_idx = r_h & hash_mask_;
                for (uint32_t rp = 0; rp < MAX_PROBES; ++rp) {
                    uint32_t r_slot = (r_idx + rp) & hash_mask_;
                    if (hash_buckets_[r_slot] == nullptr) {
                        hash_buckets_[r_slot] = rehash_ctx;
                        break;
                    }
                }
                next = (next + 1) & hash_mask_;
            }
            break;
        }
        if (hash_buckets_[slot] == nullptr) break;
    }
    ctx->flow_hash = 0;
}

// ---------------------------------------------------------------------------
// PPPoE Session Lookup & Management
// ---------------------------------------------------------------------------

TelcoSessionContext* SessionManager::FindPppoeSession(const uint8_t mac[6], uint16_t session_id) const noexcept {
    uint32_t h = HashPppoe(mac, session_id);
    uint32_t idx = h & hash_mask_;

    for (uint32_t p = 0; p < MAX_PROBES; ++p) {
        uint32_t slot = (idx + p) & hash_mask_;
        TelcoSessionContext* s = pppoe_buckets_[slot];
        if (!s) return nullptr;

        if (s->session_id == session_id && std::memcmp(s->client_mac, mac, 6) == 0) {
            return s;
        }
    }
    return nullptr;
}

bool SessionManager::BindPppoeSession(TelcoSessionContext* ctx, const uint8_t mac[6], uint16_t session_id) noexcept {
    if (!ctx) return false;

    UnbindPppoeSession(ctx);

    std::memcpy(ctx->client_mac, mac, 6);
    ctx->session_id = session_id;

    uint32_t h = HashPppoe(mac, session_id);
    uint32_t idx = h & hash_mask_;

    for (uint32_t p = 0; p < MAX_PROBES; ++p) {
        uint32_t slot = (idx + p) & hash_mask_;
        if (pppoe_buckets_[slot] == nullptr || pppoe_buckets_[slot] == ctx) {
            pppoe_buckets_[slot] = ctx;
            return true;
        }
    }
    return false;
}

void SessionManager::UnbindPppoeSession(TelcoSessionContext* ctx) noexcept {
    if (!ctx || ctx->session_id == 0) return;

    uint32_t h = HashPppoe(ctx->client_mac, static_cast<uint16_t>(ctx->session_id));
    uint32_t idx = h & hash_mask_;

    for (uint32_t p = 0; p < MAX_PROBES; ++p) {
        uint32_t slot = (idx + p) & hash_mask_;
        if (pppoe_buckets_[slot] == ctx) {
            pppoe_buckets_[slot] = nullptr;

            uint32_t next = (slot + 1) & hash_mask_;
            while (pppoe_buckets_[next] != nullptr) {
                TelcoSessionContext* rehash_ctx = pppoe_buckets_[next];
                pppoe_buckets_[next] = nullptr;

                uint32_t r_h = HashPppoe(rehash_ctx->client_mac, static_cast<uint16_t>(rehash_ctx->session_id));
                uint32_t r_idx = r_h & hash_mask_;
                for (uint32_t rp = 0; rp < MAX_PROBES; ++rp) {
                    uint32_t r_slot = (r_idx + rp) & hash_mask_;
                    if (pppoe_buckets_[r_slot] == nullptr) {
                        pppoe_buckets_[r_slot] = rehash_ctx;
                        break;
                    }
                }
                next = (next + 1) & hash_mask_;
            }
            break;
        }
        if (pppoe_buckets_[slot] == nullptr) break;
    }
}

// ---------------------------------------------------------------------------
// GTP-U Session Lookup & Management
// ---------------------------------------------------------------------------

TelcoSessionContext* SessionManager::FindGtpuSession(uint32_t teid) const noexcept {
    if (teid == 0) return nullptr;
    uint32_t h = HashTeid(teid);
    uint32_t idx = h & hash_mask_;

    for (uint32_t p = 0; p < MAX_PROBES; ++p) {
        uint32_t slot = (idx + p) & hash_mask_;
        TelcoSessionContext* s = gtpu_buckets_[slot];
        if (!s) return nullptr;

        if (s->teid_uplink == teid || s->teid_downlink == teid) {
            return s;
        }
    }
    return nullptr;
}

bool SessionManager::BindGtpuSession(TelcoSessionContext* ctx, uint32_t teid) noexcept {
    if (!ctx || teid == 0) return false;

    UnbindGtpuSession(ctx);

    ctx->teid_uplink = teid;
    uint32_t h = HashTeid(teid);
    uint32_t idx = h & hash_mask_;

    for (uint32_t p = 0; p < MAX_PROBES; ++p) {
        uint32_t slot = (idx + p) & hash_mask_;
        if (gtpu_buckets_[slot] == nullptr || gtpu_buckets_[slot] == ctx) {
            gtpu_buckets_[slot] = ctx;
            return true;
        }
    }
    return false;
}

void SessionManager::UnbindGtpuSession(TelcoSessionContext* ctx) noexcept {
    if (!ctx || ctx->teid_uplink == 0) return;

    uint32_t h = HashTeid(ctx->teid_uplink);
    uint32_t idx = h & hash_mask_;

    for (uint32_t p = 0; p < MAX_PROBES; ++p) {
        uint32_t slot = (idx + p) & hash_mask_;
        if (gtpu_buckets_[slot] == ctx) {
            gtpu_buckets_[slot] = nullptr;

            uint32_t next = (slot + 1) & hash_mask_;
            while (gtpu_buckets_[next] != nullptr) {
                TelcoSessionContext* rehash_ctx = gtpu_buckets_[next];
                gtpu_buckets_[next] = nullptr;

                uint32_t r_h = HashTeid(rehash_ctx->teid_uplink);
                uint32_t r_idx = r_h & hash_mask_;
                for (uint32_t rp = 0; rp < MAX_PROBES; ++rp) {
                    uint32_t r_slot = (r_idx + rp) & hash_mask_;
                    if (gtpu_buckets_[r_slot] == nullptr) {
                        gtpu_buckets_[r_slot] = rehash_ctx;
                        break;
                    }
                }
                next = (next + 1) & hash_mask_;
            }
            break;
        }
        if (gtpu_buckets_[slot] == nullptr) break;
    }
}

size_t SessionManager::GetMemoryFootprintBytes() const noexcept {
    size_t total = pool_alloc_size_;
    total += static_cast<size_t>(max_sessions_) * sizeof(uint32_t); // free_indices
    total += 3 * static_cast<size_t>(hash_size_) * sizeof(TelcoSessionContext*); // buckets
    return total;
}

} // namespace ddos_samurai::telecom
