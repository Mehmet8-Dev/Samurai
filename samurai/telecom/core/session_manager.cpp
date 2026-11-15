#include "samurai/telecom/core/session_manager.hpp"

#include <sys/mman.h>
#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <new>

namespace samurai::telecom {

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

    // 1. Hugepages ile tahsis etmeyi dene (2MB / 1GB sayfalar)
    void* addr = ::mmap(nullptr, pool_alloc_size_, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
    if (addr != MAP_FAILED) {
        sessions_pool_ = static_cast<TelcoSessionContext*>(addr);
        alloc_type_ = AllocationType::HugePage;
    } else {
        // 2. Standart posix_memalign (64 bayt önbellek çizgisi hizalamalı fallback)
        void* mem = nullptr;
        if (::posix_memalign(&mem, 64, pool_alloc_size_) == 0 && mem != nullptr) {
            sessions_pool_ = static_cast<TelcoSessionContext*>(mem);
            alloc_type_ = AllocationType::PosixMemalign;
        } else {
            // 3. Güvenli standart new[] fallback
            sessions_pool_ = new (std::nothrow) TelcoSessionContext[max_sessions_];
            alloc_type_ = AllocationType::NewArray;
        }
    }

    if (!sessions_pool_) {
        throw std::bad_alloc();
    }

    std::memset(sessions_pool_, 0, pool_alloc_size_);

    // Boş indeks yığınını hazırla (ABA-korumalı Treiber Stack)
    free_indices_ = std::make_unique<uint32_t[]>(max_sessions_);
    for (uint32_t i = 0; i < max_sessions_; ++i) {
        free_indices_[i] = (i + 1 < max_sessions_) ? (i + 1) : EMPTY_HEAD;
    }
    free_head_.store(PackHead(0, 0), std::memory_order_release);

    // Hash tablolarının boyutunu belirle (En az 2 katı, 2'nin kuvveti)
    hash_size_ = NextPowerOf2(std::max(65536u, max_sessions_ * 2));
    hash_mask_ = hash_size_ - 1;
    shard_size_ = hash_size_ / NUM_LOCK_SHARDS;
    shard_mask_ = shard_size_ - 1;
    shard_locks_ = std::make_unique<ShardRwSpinLock[]>(NUM_LOCK_SHARDS);

    // Hash tabloları için bellek tahsisi
    hash_buckets_ = static_cast<TelcoSessionContext**>(::calloc(hash_size_, sizeof(TelcoSessionContext*)));
    pppoe_buckets_ = static_cast<TelcoSessionContext**>(::calloc(hash_size_, sizeof(TelcoSessionContext*)));
    gtpu_buckets_ = static_cast<TelcoSessionContext**>(::calloc(hash_size_, sizeof(TelcoSessionContext*)));
    dhcp_buckets_ = static_cast<TelcoSessionContext**>(::calloc(hash_size_, sizeof(TelcoSessionContext*)));
    bfd_buckets_ = static_cast<TelcoSessionContext**>(::calloc(hash_size_, sizeof(TelcoSessionContext*)));
    pfcp_buckets_ = static_cast<TelcoSessionContext**>(::calloc(hash_size_, sizeof(TelcoSessionContext*)));

    if (!hash_buckets_ || !pppoe_buckets_ || !gtpu_buckets_ ||
        !dhcp_buckets_ || !bfd_buckets_ || !pfcp_buckets_) {
        if (hash_buckets_) { ::free(hash_buckets_); hash_buckets_ = nullptr; }
        if (pppoe_buckets_) { ::free(pppoe_buckets_); pppoe_buckets_ = nullptr; }
        if (gtpu_buckets_) { ::free(gtpu_buckets_); gtpu_buckets_ = nullptr; }
        if (dhcp_buckets_) { ::free(dhcp_buckets_); dhcp_buckets_ = nullptr; }
        if (bfd_buckets_) { ::free(bfd_buckets_); bfd_buckets_ = nullptr; }
        if (pfcp_buckets_) { ::free(pfcp_buckets_); pfcp_buckets_ = nullptr; }
        if (sessions_pool_) {
            if (alloc_type_ == AllocationType::HugePage) ::munmap(sessions_pool_, pool_alloc_size_);
            else if (alloc_type_ == AllocationType::PosixMemalign) ::free(sessions_pool_);
            else if (alloc_type_ == AllocationType::NewArray) delete[] sessions_pool_;
            sessions_pool_ = nullptr;
        }
        throw std::bad_alloc();
    }
}

SessionManager::~SessionManager() {
    if (hash_buckets_) { ::free(hash_buckets_); hash_buckets_ = nullptr; }
    if (pppoe_buckets_) { ::free(pppoe_buckets_); pppoe_buckets_ = nullptr; }
    if (gtpu_buckets_) { ::free(gtpu_buckets_); gtpu_buckets_ = nullptr; }
    if (dhcp_buckets_) { ::free(dhcp_buckets_); dhcp_buckets_ = nullptr; }
    if (bfd_buckets_) { ::free(bfd_buckets_); bfd_buckets_ = nullptr; }
    if (pfcp_buckets_) { ::free(pfcp_buckets_); pfcp_buckets_ = nullptr; }

    if (sessions_pool_) {
        switch (alloc_type_) {
            case AllocationType::HugePage:
                ::munmap(sessions_pool_, pool_alloc_size_);
                break;
            case AllocationType::PosixMemalign:
                ::free(sessions_pool_);
                break;
            case AllocationType::NewArray:
                delete[] sessions_pool_;
                break;
        }
        sessions_pool_ = nullptr;
    }
}

TelcoSessionContext* SessionManager::AcquireSession() noexcept {
    while (true) {
        uint64_t current = free_head_.load(std::memory_order_acquire);
        uint32_t head_idx = UnpackIdx(current);
        if (head_idx == EMPTY_HEAD || head_idx >= max_sessions_) {
            return nullptr; // Havuz doldu
        }
        uint32_t tag = UnpackTag(current);
        uint32_t next_idx = free_indices_[head_idx];
        uint64_t next_packed = PackHead(next_idx, tag + 1);

        if (free_head_.compare_exchange_weak(current, next_packed,
                                             std::memory_order_acq_rel,
                                             std::memory_order_acquire)) {
            TelcoSessionContext* session = &sessions_pool_[head_idx];
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
    UnbindDhcpSession(ctx);
    UnbindBfdSession(ctx);
    UnbindPfcpSession(ctx);

    // İndeksi hesapla
    ptrdiff_t diff = ctx - sessions_pool_;
    if (diff < 0 || static_cast<size_t>(diff) >= max_sessions_) {
        return; // Geçersiz işaretçi
    }
    uint32_t idx = static_cast<uint32_t>(diff);

    ctx->Reset();
    ctx->state = SessionState::TEARDOWN;

    while (true) {
        uint64_t current = free_head_.load(std::memory_order_acquire);
        uint32_t head_idx = UnpackIdx(current);
        uint32_t tag = UnpackTag(current);
        free_indices_[idx] = head_idx;
        uint64_t next_packed = PackHead(idx, tag + 1);

        if (free_head_.compare_exchange_weak(current, next_packed,
                                             std::memory_order_release,
                                             std::memory_order_acquire)) {
            active_sessions_.fetch_sub(1, std::memory_order_relaxed);
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// 5-Tuple Hash Lookup & Management (Shard-Locked Linear Probing)
// ---------------------------------------------------------------------------

TelcoSessionContext* SessionManager::FindSessionBy5Tuple(const Flow5Tuple& tuple) const noexcept {
    uint32_t h = Hash5Tuple(tuple);
    if (h == 0) h = 1;
    const uint32_t shard_id = ShardIdFromHash(h);
    const uint32_t shard_base = shard_id * shard_size_;
    const uint32_t local_idx = h & shard_mask_;

    ReadLockGuard guard(shard_locks_[shard_id]);
    for (uint32_t p = 0; p < MAX_PROBES; ++p) {
        const uint32_t slot = shard_base + ((local_idx + p) & shard_mask_);
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
    const uint32_t shard_id = ShardIdFromHash(h);
    const uint32_t shard_base = shard_id * shard_size_;
    const uint32_t local_idx = h & shard_mask_;

    WriteLockGuard guard(shard_locks_[shard_id]);
    ctx->client_ip = tuple.src_ip;
    ctx->peer_ip = tuple.dst_ip;
    ctx->client_port = tuple.src_port;
    ctx->peer_port = tuple.dst_port;
    ctx->ip_proto = tuple.proto;
    ctx->flow_hash = h;

    for (uint32_t p = 0; p < MAX_PROBES; ++p) {
        const uint32_t slot = shard_base + ((local_idx + p) & shard_mask_);
        if (hash_buckets_[slot] == nullptr || hash_buckets_[slot] == ctx) {
            hash_buckets_[slot] = ctx;
            return true;
        }
    }
    ctx->flow_hash = 0;
    return false; // Probe limiti aşıldı
}

bool SessionManager::Bind5Tuple(TelcoSessionContext* ctx, uint32_t src_ip, uint32_t dst_ip,
                                uint16_t src_port, uint16_t dst_port, uint8_t proto) noexcept {
    Flow5Tuple tuple{src_ip, dst_ip, src_port, dst_port, proto, {0}};
    return Bind5Tuple(ctx, tuple);
}

void SessionManager::Unbind5Tuple(TelcoSessionContext* ctx) noexcept {
    if (!ctx) return;
    const uint32_t h = ctx->flow_hash;
    if (h == 0) return;

    const uint32_t shard_id = ShardIdFromHash(h);
    const uint32_t shard_base = shard_id * shard_size_;
    const uint32_t local_idx = h & shard_mask_;

    WriteLockGuard guard(shard_locks_[shard_id]);
    if (ctx->flow_hash != h) return;

    for (uint32_t p = 0; p < MAX_PROBES; ++p) {
        const uint32_t local_slot = (local_idx + p) & shard_mask_;
        const uint32_t slot = shard_base + local_slot;
        if (hash_buckets_[slot] == ctx) {
            hash_buckets_[slot] = nullptr;

            // Backward-shift deletion (shard sınırları içinde deterministik temizleme)
            uint32_t next_local = (local_slot + 1) & shard_mask_;
            uint32_t steps = 0;
            while (hash_buckets_[shard_base + next_local] != nullptr && steps < shard_size_) {
                TelcoSessionContext* rehash_ctx = hash_buckets_[shard_base + next_local];
                hash_buckets_[shard_base + next_local] = nullptr;

                const uint32_t r_h = rehash_ctx->flow_hash;
                const uint32_t r_local_idx = r_h & shard_mask_;
                for (uint32_t rp = 0; rp < MAX_PROBES; ++rp) {
                    const uint32_t r_slot = shard_base + ((r_local_idx + rp) & shard_mask_);
                    if (hash_buckets_[r_slot] == nullptr) {
                        hash_buckets_[r_slot] = rehash_ctx;
                        break;
                    }
                }
                next_local = (next_local + 1) & shard_mask_;
                ++steps;
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
    const uint32_t h = HashPppoe(mac, session_id);
    const uint32_t shard_id = ShardIdFromHash(h);
    const uint32_t shard_base = shard_id * shard_size_;
    const uint32_t local_idx = h & shard_mask_;

    ReadLockGuard guard(shard_locks_[shard_id]);
    for (uint32_t p = 0; p < MAX_PROBES; ++p) {
        const uint32_t slot = shard_base + ((local_idx + p) & shard_mask_);
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

    const uint32_t h = HashPppoe(mac, session_id);
    const uint32_t shard_id = ShardIdFromHash(h);
    const uint32_t shard_base = shard_id * shard_size_;
    const uint32_t local_idx = h & shard_mask_;

    WriteLockGuard guard(shard_locks_[shard_id]);
    std::memcpy(ctx->client_mac, mac, 6);
    ctx->session_id = session_id;

    for (uint32_t p = 0; p < MAX_PROBES; ++p) {
        const uint32_t slot = shard_base + ((local_idx + p) & shard_mask_);
        if (pppoe_buckets_[slot] == nullptr || pppoe_buckets_[slot] == ctx) {
            pppoe_buckets_[slot] = ctx;
            return true;
        }
    }
    return false;
}

void SessionManager::UnbindPppoeSession(TelcoSessionContext* ctx) noexcept {
    if (!ctx || ctx->session_id == 0) return;

    const uint32_t h = HashPppoe(ctx->client_mac, static_cast<uint16_t>(ctx->session_id));
    const uint32_t shard_id = ShardIdFromHash(h);
    const uint32_t shard_base = shard_id * shard_size_;
    const uint32_t local_idx = h & shard_mask_;

    WriteLockGuard guard(shard_locks_[shard_id]);
    for (uint32_t p = 0; p < MAX_PROBES; ++p) {
        const uint32_t local_slot = (local_idx + p) & shard_mask_;
        const uint32_t slot = shard_base + local_slot;
        if (pppoe_buckets_[slot] == ctx) {
            pppoe_buckets_[slot] = nullptr;

            uint32_t next_local = (local_slot + 1) & shard_mask_;
            uint32_t steps = 0;
            while (pppoe_buckets_[shard_base + next_local] != nullptr && steps < shard_size_) {
                TelcoSessionContext* rehash_ctx = pppoe_buckets_[shard_base + next_local];
                pppoe_buckets_[shard_base + next_local] = nullptr;

                const uint32_t r_h = HashPppoe(rehash_ctx->client_mac, static_cast<uint16_t>(rehash_ctx->session_id));
                const uint32_t r_local_idx = r_h & shard_mask_;
                for (uint32_t rp = 0; rp < MAX_PROBES; ++rp) {
                    const uint32_t r_slot = shard_base + ((r_local_idx + rp) & shard_mask_);
                    if (pppoe_buckets_[r_slot] == nullptr) {
                        pppoe_buckets_[r_slot] = rehash_ctx;
                        break;
                    }
                }
                next_local = (next_local + 1) & shard_mask_;
                ++steps;
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
    const uint32_t h = HashTeid(teid);
    const uint32_t shard_id = ShardIdFromHash(h);
    const uint32_t shard_base = shard_id * shard_size_;
    const uint32_t local_idx = h & shard_mask_;

    ReadLockGuard guard(shard_locks_[shard_id]);
    for (uint32_t p = 0; p < MAX_PROBES; ++p) {
        const uint32_t slot = shard_base + ((local_idx + p) & shard_mask_);
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

    const uint32_t h = HashTeid(teid);
    const uint32_t shard_id = ShardIdFromHash(h);
    const uint32_t shard_base = shard_id * shard_size_;
    const uint32_t local_idx = h & shard_mask_;

    WriteLockGuard guard(shard_locks_[shard_id]);
    ctx->teid_uplink = teid;

    for (uint32_t p = 0; p < MAX_PROBES; ++p) {
        const uint32_t slot = shard_base + ((local_idx + p) & shard_mask_);
        if (gtpu_buckets_[slot] == nullptr || gtpu_buckets_[slot] == ctx) {
            gtpu_buckets_[slot] = ctx;
            return true;
        }
    }
    return false;
}

void SessionManager::UnbindGtpuSession(TelcoSessionContext* ctx) noexcept {
    if (!ctx || ctx->teid_uplink == 0) return;

    const uint32_t h = HashTeid(ctx->teid_uplink);
    const uint32_t shard_id = ShardIdFromHash(h);
    const uint32_t shard_base = shard_id * shard_size_;
    const uint32_t local_idx = h & shard_mask_;

    WriteLockGuard guard(shard_locks_[shard_id]);
    for (uint32_t p = 0; p < MAX_PROBES; ++p) {
        const uint32_t local_slot = (local_idx + p) & shard_mask_;
        const uint32_t slot = shard_base + local_slot;
        if (gtpu_buckets_[slot] == ctx) {
            gtpu_buckets_[slot] = nullptr;

            uint32_t next_local = (local_slot + 1) & shard_mask_;
            uint32_t steps = 0;
            while (gtpu_buckets_[shard_base + next_local] != nullptr && steps < shard_size_) {
                TelcoSessionContext* rehash_ctx = gtpu_buckets_[shard_base + next_local];
                gtpu_buckets_[shard_base + next_local] = nullptr;

                const uint32_t r_h = HashTeid(rehash_ctx->teid_uplink);
                const uint32_t r_local_idx = r_h & shard_mask_;
                for (uint32_t rp = 0; rp < MAX_PROBES; ++rp) {
                    const uint32_t r_slot = shard_base + ((r_local_idx + rp) & shard_mask_);
                    if (gtpu_buckets_[r_slot] == nullptr) {
                        gtpu_buckets_[r_slot] = rehash_ctx;
                        break;
                    }
                }
                next_local = (next_local + 1) & shard_mask_;
                ++steps;
            }
            break;
        }
        if (gtpu_buckets_[slot] == nullptr) break;
    }
}

// ---------------------------------------------------------------------------
// DHCP Session Lookup & Management
// ---------------------------------------------------------------------------

TelcoSessionContext* SessionManager::FindDhcpSession(uint32_t xid) const noexcept {
    if (xid == 0) return nullptr;
    const uint32_t h = HashDhcp(xid);
    const uint32_t shard_id = ShardIdFromHash(h);
    const uint32_t shard_base = shard_id * shard_size_;
    const uint32_t local_idx = h & shard_mask_;

    ReadLockGuard guard(shard_locks_[shard_id]);
    for (uint32_t p = 0; p < MAX_PROBES; ++p) {
        const uint32_t slot = shard_base + ((local_idx + p) & shard_mask_);
        TelcoSessionContext* s = dhcp_buckets_[slot];
        if (!s) return nullptr;

        if (s->GetDhcpXid() == xid) {
            return s;
        }
    }
    return nullptr;
}

bool SessionManager::BindDhcpSession(TelcoSessionContext* ctx, uint32_t xid) noexcept {
    if (!ctx || xid == 0) return false;

    UnbindDhcpSession(ctx);

    const uint32_t h = HashDhcp(xid);
    const uint32_t shard_id = ShardIdFromHash(h);
    const uint32_t shard_base = shard_id * shard_size_;
    const uint32_t local_idx = h & shard_mask_;

    WriteLockGuard guard(shard_locks_[shard_id]);
    ctx->SetDhcpXid(xid);

    for (uint32_t p = 0; p < MAX_PROBES; ++p) {
        const uint32_t slot = shard_base + ((local_idx + p) & shard_mask_);
        if (dhcp_buckets_[slot] == nullptr || dhcp_buckets_[slot] == ctx) {
            dhcp_buckets_[slot] = ctx;
            return true;
        }
    }
    return false;
}

void SessionManager::UnbindDhcpSession(TelcoSessionContext* ctx) noexcept {
    if (!ctx || ctx->GetDhcpXid() == 0) return;

    const uint32_t h = HashDhcp(ctx->GetDhcpXid());
    const uint32_t shard_id = ShardIdFromHash(h);
    const uint32_t shard_base = shard_id * shard_size_;
    const uint32_t local_idx = h & shard_mask_;

    WriteLockGuard guard(shard_locks_[shard_id]);
    for (uint32_t p = 0; p < MAX_PROBES; ++p) {
        const uint32_t local_slot = (local_idx + p) & shard_mask_;
        const uint32_t slot = shard_base + local_slot;
        if (dhcp_buckets_[slot] == ctx) {
            dhcp_buckets_[slot] = nullptr;

            uint32_t next_local = (local_slot + 1) & shard_mask_;
            uint32_t steps = 0;
            while (dhcp_buckets_[shard_base + next_local] != nullptr && steps < shard_size_) {
                TelcoSessionContext* rehash_ctx = dhcp_buckets_[shard_base + next_local];
                dhcp_buckets_[shard_base + next_local] = nullptr;

                const uint32_t r_h = HashDhcp(rehash_ctx->GetDhcpXid());
                const uint32_t r_local_idx = r_h & shard_mask_;
                for (uint32_t rp = 0; rp < MAX_PROBES; ++rp) {
                    const uint32_t r_slot = shard_base + ((r_local_idx + rp) & shard_mask_);
                    if (dhcp_buckets_[r_slot] == nullptr) {
                        dhcp_buckets_[r_slot] = rehash_ctx;
                        break;
                    }
                }
                next_local = (next_local + 1) & shard_mask_;
                ++steps;
            }
            break;
        }
        if (dhcp_buckets_[slot] == nullptr) break;
    }
}

// ---------------------------------------------------------------------------
// BFD Session Lookup & Management
// ---------------------------------------------------------------------------

TelcoSessionContext* SessionManager::FindBfdSession(uint32_t my_disc) const noexcept {
    if (my_disc == 0) return nullptr;
    const uint32_t h = HashBfd(my_disc);
    const uint32_t shard_id = ShardIdFromHash(h);
    const uint32_t shard_base = shard_id * shard_size_;
    const uint32_t local_idx = h & shard_mask_;

    ReadLockGuard guard(shard_locks_[shard_id]);
    for (uint32_t p = 0; p < MAX_PROBES; ++p) {
        const uint32_t slot = shard_base + ((local_idx + p) & shard_mask_);
        TelcoSessionContext* s = bfd_buckets_[slot];
        if (!s) return nullptr;

        if (s->GetBfdLocalDisc() == my_disc) {
            return s;
        }
    }
    return nullptr;
}

bool SessionManager::BindBfdSession(TelcoSessionContext* ctx, uint32_t my_disc) noexcept {
    if (!ctx || my_disc == 0) return false;

    UnbindBfdSession(ctx);

    const uint32_t h = HashBfd(my_disc);
    const uint32_t shard_id = ShardIdFromHash(h);
    const uint32_t shard_base = shard_id * shard_size_;
    const uint32_t local_idx = h & shard_mask_;

    WriteLockGuard guard(shard_locks_[shard_id]);
    ctx->SetBfdLocalDisc(my_disc);

    for (uint32_t p = 0; p < MAX_PROBES; ++p) {
        const uint32_t slot = shard_base + ((local_idx + p) & shard_mask_);
        if (bfd_buckets_[slot] == nullptr || bfd_buckets_[slot] == ctx) {
            bfd_buckets_[slot] = ctx;
            return true;
        }
    }
    return false;
}

void SessionManager::UnbindBfdSession(TelcoSessionContext* ctx) noexcept {
    if (!ctx || ctx->GetBfdLocalDisc() == 0) return;

    const uint32_t h = HashBfd(ctx->GetBfdLocalDisc());
    const uint32_t shard_id = ShardIdFromHash(h);
    const uint32_t shard_base = shard_id * shard_size_;
    const uint32_t local_idx = h & shard_mask_;

    WriteLockGuard guard(shard_locks_[shard_id]);
    for (uint32_t p = 0; p < MAX_PROBES; ++p) {
        const uint32_t local_slot = (local_idx + p) & shard_mask_;
        const uint32_t slot = shard_base + local_slot;
        if (bfd_buckets_[slot] == ctx) {
            bfd_buckets_[slot] = nullptr;

            uint32_t next_local = (local_slot + 1) & shard_mask_;
            uint32_t steps = 0;
            while (bfd_buckets_[shard_base + next_local] != nullptr && steps < shard_size_) {
                TelcoSessionContext* rehash_ctx = bfd_buckets_[shard_base + next_local];
                bfd_buckets_[shard_base + next_local] = nullptr;

                const uint32_t r_h = HashBfd(rehash_ctx->GetBfdLocalDisc());
                const uint32_t r_local_idx = r_h & shard_mask_;
                for (uint32_t rp = 0; rp < MAX_PROBES; ++rp) {
                    const uint32_t r_slot = shard_base + ((r_local_idx + rp) & shard_mask_);
                    if (bfd_buckets_[r_slot] == nullptr) {
                        bfd_buckets_[r_slot] = rehash_ctx;
                        break;
                    }
                }
                next_local = (next_local + 1) & shard_mask_;
                ++steps;
            }
            break;
        }
        if (bfd_buckets_[slot] == nullptr) break;
    }
}

// ---------------------------------------------------------------------------
// 5G PFCP Session Lookup & Management
// ---------------------------------------------------------------------------

TelcoSessionContext* SessionManager::FindPfcpSession(uint64_t seid) const noexcept {
    if (seid == 0) return nullptr;
    const uint32_t h = HashPfcp(seid);
    const uint32_t shard_id = ShardIdFromHash(h);
    const uint32_t shard_base = shard_id * shard_size_;
    const uint32_t local_idx = h & shard_mask_;

    ReadLockGuard guard(shard_locks_[shard_id]);
    for (uint32_t p = 0; p < MAX_PROBES; ++p) {
        const uint32_t slot = shard_base + ((local_idx + p) & shard_mask_);
        TelcoSessionContext* s = pfcp_buckets_[slot];
        if (!s) return nullptr;

        if (s->GetPfcpSeid() == seid) {
            return s;
        }
    }
    return nullptr;
}

bool SessionManager::BindPfcpSession(TelcoSessionContext* ctx, uint64_t seid) noexcept {
    if (!ctx || seid == 0) return false;

    UnbindPfcpSession(ctx);

    const uint32_t h = HashPfcp(seid);
    const uint32_t shard_id = ShardIdFromHash(h);
    const uint32_t shard_base = shard_id * shard_size_;
    const uint32_t local_idx = h & shard_mask_;

    WriteLockGuard guard(shard_locks_[shard_id]);
    ctx->SetPfcpSeid(seid);

    for (uint32_t p = 0; p < MAX_PROBES; ++p) {
        const uint32_t slot = shard_base + ((local_idx + p) & shard_mask_);
        if (pfcp_buckets_[slot] == nullptr || pfcp_buckets_[slot] == ctx) {
            pfcp_buckets_[slot] = ctx;
            return true;
        }
    }
    return false;
}

void SessionManager::UnbindPfcpSession(TelcoSessionContext* ctx) noexcept {
    if (!ctx || ctx->GetPfcpSeid() == 0) return;

    const uint32_t h = HashPfcp(ctx->GetPfcpSeid());
    const uint32_t shard_id = ShardIdFromHash(h);
    const uint32_t shard_base = shard_id * shard_size_;
    const uint32_t local_idx = h & shard_mask_;

    WriteLockGuard guard(shard_locks_[shard_id]);
    for (uint32_t p = 0; p < MAX_PROBES; ++p) {
        const uint32_t local_slot = (local_idx + p) & shard_mask_;
        const uint32_t slot = shard_base + local_slot;
        if (pfcp_buckets_[slot] == ctx) {
            pfcp_buckets_[slot] = nullptr;

            uint32_t next_local = (local_slot + 1) & shard_mask_;
            uint32_t steps = 0;
            while (pfcp_buckets_[shard_base + next_local] != nullptr && steps < shard_size_) {
                TelcoSessionContext* rehash_ctx = pfcp_buckets_[shard_base + next_local];
                pfcp_buckets_[shard_base + next_local] = nullptr;

                const uint32_t r_h = HashPfcp(rehash_ctx->GetPfcpSeid());
                const uint32_t r_local_idx = r_h & shard_mask_;
                for (uint32_t rp = 0; rp < MAX_PROBES; ++rp) {
                    const uint32_t r_slot = shard_base + ((r_local_idx + rp) & shard_mask_);
                    if (pfcp_buckets_[r_slot] == nullptr) {
                        pfcp_buckets_[r_slot] = rehash_ctx;
                        break;
                    }
                }
                next_local = (next_local + 1) & shard_mask_;
                ++steps;
            }
            break;
        }
        if (pfcp_buckets_[slot] == nullptr) break;
    }
}

size_t SessionManager::GetMemoryFootprintBytes() const noexcept {
    size_t total = pool_alloc_size_;
    total += static_cast<size_t>(max_sessions_) * sizeof(uint32_t); // free_indices
    total += 6 * static_cast<size_t>(hash_size_) * sizeof(TelcoSessionContext*); // 6 bucket tables
    total += static_cast<size_t>(NUM_LOCK_SHARDS) * sizeof(ShardRwSpinLock);
    return total;
}

} // namespace samurai::telecom
