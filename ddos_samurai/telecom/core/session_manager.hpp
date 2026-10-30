#pragma once

#include "ddos_samurai/telecom/core/session_context.hpp"

#include <cstdint>
#include <cstddef>
#include <memory>
#include <atomic>

namespace ddos_samurai::telecom {

class SessionManager {
public:
    explicit SessionManager(uint32_t max_sessions, int socket_id = 0);
    ~SessionManager();

    SessionManager(const SessionManager&) = delete;
    SessionManager& operator=(const SessionManager&) = delete;
    SessionManager(SessionManager&&) = delete;
    SessionManager& operator=(SessionManager&&) = delete;

    // Yeni oturum tahsis et (O(1) Lock-Free ID havuzundan)
    TelcoSessionContext* AcquireSession() noexcept;

    // Oturumu havuza iade et (O(1))
    void ReleaseSession(TelcoSessionContext* ctx) noexcept;

    // Birincil indeksle hızlı doğrudan erişim (O(1))
    inline TelcoSessionContext* GetSessionByIndex(uint32_t index) noexcept {
        if (__builtin_expect(index >= max_sessions_, 0)) return nullptr;
        return &sessions_pool_[index];
    }

    // İşaretçiden havuz indeksini bulma (O(1))
    inline int32_t GetSessionIndex(const TelcoSessionContext* ctx) const noexcept {
        if (!ctx || !sessions_pool_) return -1;
        ptrdiff_t diff = ctx - sessions_pool_;
        return (diff >= 0 && static_cast<size_t>(diff) < max_sessions_) ? static_cast<int32_t>(diff) : -1;
    }

    // Durumlu L4 5-Tuple ile donanım hızlandırmalı O(1) arama
    TelcoSessionContext* FindSessionBy5Tuple(const Flow5Tuple& tuple) const noexcept;
    TelcoSessionContext* FindSessionBy5Tuple(uint32_t src_ip, uint32_t dst_ip, 
                                            uint16_t src_port, uint16_t dst_port, 
                                            uint8_t proto) const noexcept;

    // 5-Tuple kaydı ve silinmesi
    bool Bind5Tuple(TelcoSessionContext* ctx, const Flow5Tuple& tuple) noexcept;
    bool Bind5Tuple(TelcoSessionContext* ctx, uint32_t src_ip, uint32_t dst_ip,
                    uint16_t src_port, uint16_t dst_port, uint8_t proto) noexcept;
    void Unbind5Tuple(TelcoSessionContext* ctx) noexcept;

    // PPPoE için MAC + SessionID ile O(1) arama
    TelcoSessionContext* FindPppoeSession(const uint8_t mac[6], uint16_t session_id) const noexcept;
    bool BindPppoeSession(TelcoSessionContext* ctx, const uint8_t mac[6], uint16_t session_id) noexcept;
    void UnbindPppoeSession(TelcoSessionContext* ctx) noexcept;

    // 4G/5G için TEID ile O(1) arama
    TelcoSessionContext* FindGtpuSession(uint32_t teid) const noexcept;
    bool BindGtpuSession(TelcoSessionContext* ctx, uint32_t teid) noexcept;
    void UnbindGtpuSession(TelcoSessionContext* ctx) noexcept;

    // DHCP için Transaction ID (xid) ile O(1) arama
    TelcoSessionContext* FindDhcpSession(uint32_t xid) const noexcept;
    bool BindDhcpSession(TelcoSessionContext* ctx, uint32_t xid) noexcept;
    void UnbindDhcpSession(TelcoSessionContext* ctx) noexcept;

    // BFD için Local Discriminator ile O(1) arama
    TelcoSessionContext* FindBfdSession(uint32_t my_disc) const noexcept;
    bool BindBfdSession(TelcoSessionContext* ctx, uint32_t my_disc) noexcept;
    void UnbindBfdSession(TelcoSessionContext* ctx) noexcept;

    // 5G PFCP için 64-bit SEID ile O(1) arama
    TelcoSessionContext* FindPfcpSession(uint64_t seid) const noexcept;
    bool BindPfcpSession(TelcoSessionContext* ctx, uint64_t seid) noexcept;
    void UnbindPfcpSession(TelcoSessionContext* ctx) noexcept;

    uint32_t GetActiveSessionCount() const noexcept {
        return active_sessions_.load(std::memory_order_relaxed);
    }

    uint32_t GetCapacity() const noexcept { return max_sessions_; }
    size_t GetMemoryFootprintBytes() const noexcept;

    enum class AllocationType : uint8_t {
        HugePage,
        PosixMemalign,
        NewArray
    };
    AllocationType GetAllocationType() const noexcept { return alloc_type_; }

private:
    uint32_t max_sessions_;
    int socket_id_;
    TelcoSessionContext* sessions_pool_{nullptr};
    AllocationType alloc_type_{AllocationType::PosixMemalign};
    size_t pool_alloc_size_{0};

    std::atomic<uint32_t> active_sessions_{0};

    // Boş oturum indekslerini tutan kilitli olmayan yığın (ABA-korumalı Treiber Stack)
    std::unique_ptr<uint32_t[]> free_indices_;
    std::atomic<uint64_t> free_head_{0};

    static constexpr uint32_t EMPTY_HEAD = 0xFFFFFFFFu;
    static inline uint64_t PackHead(uint32_t idx, uint32_t tag) noexcept {
        return (static_cast<uint64_t>(tag) << 32) | idx;
    }
    static inline uint32_t UnpackIdx(uint64_t packed) noexcept {
        return static_cast<uint32_t>(packed & 0xFFFFFFFFu);
    }
    static inline uint32_t UnpackTag(uint64_t packed) noexcept {
        return static_cast<uint32_t>(packed >> 32);
    }

    // 5-Tuple O(1) arama hash tablosu
    static constexpr uint32_t MAX_PROBES = 32;
    uint32_t hash_size_{0};
    uint32_t hash_mask_{0};
    TelcoSessionContext** hash_buckets_{nullptr};

    // PPPoE (MAC + SessionID) hash tablosu
    TelcoSessionContext** pppoe_buckets_{nullptr};

    // GTP-U (TEID) hash tablosu
    TelcoSessionContext** gtpu_buckets_{nullptr};

    // DHCP (xid) hash tablosu
    TelcoSessionContext** dhcp_buckets_{nullptr};

    // BFD (Discriminator) hash tablosu
    TelcoSessionContext** bfd_buckets_{nullptr};

    // PFCP (SEID) hash tablosu
    TelcoSessionContext** pfcp_buckets_{nullptr};

    static inline uint32_t HashPppoe(const uint8_t mac[6], uint16_t session_id) noexcept {
        uint32_t h = (static_cast<uint32_t>(session_id) * 2654435761u);
        h ^= (static_cast<uint32_t>(mac[4]) << 8) | mac[5];
        h ^= (static_cast<uint32_t>(mac[2]) << 16) | mac[3];
        return h;
    }

    static inline uint32_t HashTeid(uint32_t teid) noexcept {
        return teid * 2654435761u;
    }

    static inline uint32_t HashDhcp(uint32_t xid) noexcept {
        return xid * 2654435761u;
    }

    static inline uint32_t HashBfd(uint32_t disc) noexcept {
        return disc * 2654435761u;
    }

    static inline uint32_t HashPfcp(uint64_t seid) noexcept {
        uint64_t h = seid * 11400714819323198485ULL;
        return static_cast<uint32_t>(h ^ (h >> 32));
    }
};

} // namespace ddos_samurai::telecom
