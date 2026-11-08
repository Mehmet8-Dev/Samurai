#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>

#if defined(__x86_64__) || defined(_M_X64)
#include <x86intrin.h>
#elif defined(__aarch64__)
#if defined(__ARM_FEATURE_CRC32)
#include <arm_acle.h>
#endif
#endif

namespace ddos_samurai::telecom {

enum class SessionState : uint8_t {
    IDLE = 0,
    DISCOVERING,     // PPPoE PADI/PADR / DHCP DISCOVER / PFCP Assoc Req
    AUTHENTICATING,  // PPP PAP/CHAP / 802.1X EAP / IPCP
    ESTABLISHED,     // Aktif tünel / Abone hatta / Veri akışı serbest
    TERMINATING,     // PADT / DHCP RELEASE / PFCP Deletion
    FAILED,          // Timeout veya auth rejection
    TEARDOWN         // Havuza iade ve bellek temizleme
};

struct alignas(16) Flow5Tuple {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
    uint8_t  pad[7];

    bool operator==(const Flow5Tuple& other) const noexcept {
        return src_ip == other.src_ip &&
               dst_ip == other.dst_ip &&
               src_port == other.src_port &&
               dst_port == other.dst_port &&
               proto == other.proto;
    }

    bool operator!=(const Flow5Tuple& other) const noexcept {
        return !(*this == other);
    }
};

#if defined(__SSE4_2__) || defined(__x86_64__)
#if !defined(__SSE4_2__)
__attribute__((target("sse4.2")))
#endif
static inline uint32_t Hash5Tuple(const Flow5Tuple& key) noexcept {
    uint64_t k1 = (static_cast<uint64_t>(key.src_ip) << 32) | key.dst_ip;
    uint64_t k2 = (static_cast<uint64_t>(key.src_port) << 48) |
                  (static_cast<uint64_t>(key.dst_port) << 32) | key.proto;
    uint32_t h = __builtin_ia32_crc32di(0xFFFFFFFFu, k1);
    return __builtin_ia32_crc32di(h, k2);
}
#elif defined(__aarch64__) && defined(__ARM_FEATURE_CRC32)
static inline uint32_t Hash5Tuple(const Flow5Tuple& key) noexcept {
    uint64_t k1 = (static_cast<uint64_t>(key.src_ip) << 32) | key.dst_ip;
    uint64_t k2 = (static_cast<uint64_t>(key.src_port) << 48) |
                  (static_cast<uint64_t>(key.dst_port) << 32) | key.proto;
    uint32_t h = __crc32cd(0xFFFFFFFFu, k1);
    return __crc32cd(h, k2);
}
#else
static inline uint32_t Hash5Tuple(const Flow5Tuple& key) noexcept {
    // FNV-1a 32-bit software fallback
    uint32_t h = 2166136261u;
    h = (h ^ key.src_ip) * 16777619u;
    h = (h ^ key.dst_ip) * 16777619u;
    uint32_t ports = (static_cast<uint32_t>(key.src_port) << 16) | key.dst_port;
    h = (h ^ ports) * 16777619u;
    h = (h ^ key.proto) * 16777619u;
    return h;
}
#endif

// Forward declaration
struct TelcoSessionContext;

struct alignas(64) TelcoSessionContext {
    // =========================================================================
    // --- 1. CACHE LINE (64 Bayt): FASTPATH 5-TUPLE, L2/L3 & TÜNEL TANIMLAYICILARI ---
    // Read-mostly hot path matching data. Tek bir 64 baytlık L1 satırında yaşar.
    // =========================================================================
    uint32_t client_ip;        // Abone IPv4 adresi (4 bayt) - offset 0
    uint32_t peer_ip;          // Ağ geçidi / Hedef Sunucu IPv4 (4 bayt) - offset 4
    uint16_t client_port;      // İstemci kaynak portu (2 bayt) - offset 8
    uint16_t peer_port;        // Sunucu hedef portu (2 bayt) - offset 10
    uint8_t  ip_proto;         // IP Protokol (TCP:6, UDP:17, ICMP:1) (1 bayt) - offset 12
    SessionState state;        // FSM Oturum Durumu (1 bayt) - offset 13
    uint8_t  protocol_id;      // PPPOE, DHCP, GTP, vb. (1 bayt) - offset 14
    uint8_t  pad0;             // 4-bayt hizalama dolgusu (1 bayt) - offset 15

    uint32_t session_id;       // PPPoE Session ID veya Abone İndeksi (4 bayt) - offset 16
    uint32_t teid_uplink;      // 5G/4G GTP-U Uplink TEID (4 bayt) - offset 20
    uint32_t teid_downlink;    // 5G/4G GTP-U Downlink TEID (4 bayt) - offset 24
    uint32_t flow_hash;        // Donanım RSS / SSE4.2 CRC32 5-Tuple Hash (4 bayt) - offset 28

    uint16_t s_vlan;           // Outer Service VLAN (802.1ad QinQ) (2 bayt) - offset 32
    uint16_t c_vlan;           // Inner Customer VLAN (802.1q) (2 bayt) - offset 34
    uint8_t  client_mac[6];    // Abone MAC adresi (6 bayt) - offset 36
    uint8_t  peer_mac[6];      // BRAS / Ağ Geçidi MAC adresi (6 bayt) - offset 42

    uint16_t ppp_lcp_identifier; // PPP transaction identifier (2 bayt) - offset 48
    uint16_t retry_count;        // Yeniden deneme sayacı (2 bayt) - offset 50
    uint32_t ppp_magic_number;   // PPP loop detection magic number (4 bayt) - offset 52

    uint16_t wheel_slot;       // Zamanlayıcı çarkındaki yuva indeksi (2 bayt) - offset 56
    uint8_t  wheel_tier;       // Zamanlayıcı çarkındaki kademe (1 bayt) - offset 58
    uint8_t  in_wheel;         // Çarkta aktif mi (1 bayt) - offset 59
    uint8_t  pad1[4];          // Cache line 1'i tam 64 bayta tamamlama (4 bayt) - offset 60
    // -------------------------------------------------------------------------
    // 1. Cache Line Toplamı: 16 + 16 + 4 + 12 + 8 + 8 = 64 bayt.

    // =========================================================================
    // --- 2. CACHE LINE (64 Bayt): ZAMANLAYICI ÇARKI, FSM VE TELEMETRİ SAYAÇLARI ---
    // Write-mostly slow path / FSM / timing wheel & telemetry state.
    // =========================================================================
    TelcoSessionContext* wheel_prev; // Zamanlayıcı çarkı önceki düğüm (8 bayt) - offset 64
    TelcoSessionContext* wheel_next; // Zamanlayıcı çarkı sonraki düğüm (8 bayt) - offset 72
    uint64_t timer_expire_tsc;       // Süre dolma TSC zamanı (8 bayt) - offset 80
    uint64_t last_activity_tsc;      // Son aktivite TSC zamanı (8 bayt) - offset 88

    uint64_t tx_packets;             // İletilen toplam paket (8 bayt) - offset 96
    uint64_t rx_packets;             // Alınan toplam paket (8 bayt) - offset 104
    uint64_t tx_bytes;               // İletilen toplam bayt (8 bayt) - offset 112
    uint64_t rx_bytes;               // Alınan toplam bayt (8 bayt) - offset 120
    // -------------------------------------------------------------------------
    // 2. Cache Line Toplamı: 32 + 32 = 64 bayt.

    inline void Reset() noexcept {
        std::memset(this, 0, sizeof(TelcoSessionContext));
        state = SessionState::IDLE;
    }

    inline uint32_t GetDhcpXid() const noexcept { return session_id; }
    inline void SetDhcpXid(uint32_t xid) noexcept { session_id = xid; }

    inline uint32_t GetBfdLocalDisc() const noexcept { return session_id; }
    inline void SetBfdLocalDisc(uint32_t disc) noexcept { session_id = disc; }
    inline uint32_t GetBfdRemoteDisc() const noexcept { return ppp_magic_number; }
    inline void SetBfdRemoteDisc(uint32_t disc) noexcept { ppp_magic_number = disc; }

    inline uint64_t GetPfcpSeid() const noexcept {
        uint32_t upper = 0;
        std::memcpy(&upper, pad1, 4);
        return (static_cast<uint64_t>(upper) << 32) | session_id;
    }
    inline void SetPfcpSeid(uint64_t seid) noexcept {
        session_id = static_cast<uint32_t>(seid & 0xFFFFFFFFULL);
        uint32_t upper = static_cast<uint32_t>(seid >> 32);
        std::memcpy(pad1, &upper, 4);
    }

    inline uint64_t GetPfcpRemoteSeid() const noexcept {
        uint32_t upper = (static_cast<uint32_t>(s_vlan) << 16) | c_vlan;
        return (static_cast<uint64_t>(upper) << 32) | ppp_magic_number;
    }
    inline void SetPfcpRemoteSeid(uint64_t seid) noexcept {
        ppp_magic_number = static_cast<uint32_t>(seid & 0xFFFFFFFFULL);
        uint32_t upper = static_cast<uint32_t>(seid >> 32);
        s_vlan = static_cast<uint16_t>(upper >> 16);
        c_vlan = static_cast<uint16_t>(upper & 0xFFFF);
    }

    // SCTP RFC 4960 Yardımcı Fonksiyonları & Multihoming İzleme
    inline uint32_t GetSctpLocalVTag() const noexcept { return session_id; }
    inline void SetSctpLocalVTag(uint32_t vtag) noexcept { session_id = vtag; }
    inline uint32_t GetSctpPeerVTag() const noexcept { return ppp_magic_number; }
    inline void SetSctpPeerVTag(uint32_t vtag) noexcept { ppp_magic_number = vtag; }
    inline uint32_t GetSctpOutboundTsn() const noexcept { return teid_uplink; }
    inline void SetSctpOutboundTsn(uint32_t tsn) noexcept { teid_uplink = tsn; }
    inline uint32_t GetSctpInboundTsn() const noexcept { return teid_downlink; }
    inline void SetSctpInboundTsn(uint32_t tsn) noexcept { teid_downlink = tsn; }

    inline uint8_t GetSctpActivePathIndex() const noexcept { return pad1[0]; }
    inline void SetSctpActivePathIndex(uint8_t idx) noexcept { pad1[0] = idx; }
    inline uint8_t GetSctpPrimaryPathIndex() const noexcept { return pad1[1]; }
    inline void SetSctpPrimaryPathIndex(uint8_t idx) noexcept { pad1[1] = idx; }
    inline uint8_t GetSctpPathCount() const noexcept { return pad1[2]; }
    inline void SetSctpPathCount(uint8_t cnt) noexcept { pad1[2] = cnt; }
};

static_assert(sizeof(TelcoSessionContext) == 128, "TelcoSessionContext tam 2 cache line (128 bayt) olmalidir!");
static_assert(alignof(TelcoSessionContext) == 64, "TelcoSessionContext 64-bayt hizali (cache-aligned) olmalidir!");
static_assert(offsetof(TelcoSessionContext, wheel_prev) == 64, "wheel_prev 2. cache line baslangicinda (offset 64) olmalidir!");

} // namespace ddos_samurai::telecom
