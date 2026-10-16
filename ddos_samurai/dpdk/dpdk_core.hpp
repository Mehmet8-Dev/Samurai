#pragma once
//
// dpdk_core — DDoSamurai'nin TEK native DPDK çekirdeği.
//
// Bu başlık kasıtlı olarak <rte_*.h> veya <Python.h> İÇERMEZ; yalnızca standart
// tipler kullanır. Böylece libdpdk kurulu olmayan ortamlarda da tüketiciler
// (ör. dpdk_worker.cpp) sorunsuz derlenir. Gerçek DPDK mantığı dpdk_core.cpp
// içinde SAMURAI_WITH_DPDK ile koşullanmıştır; destek derlenmediğinde tüm
// fonksiyonlar güvenli biçimde başarısızlık/0 döndürür.
//
#include <cstddef>
#include <cstdint>
#include <string>

namespace samurai::dpdk {

// NIC'in port başına yetenekleri (rte_eth_dev_info'dan türetilir).
struct PortCapabilities {
    uint64_t tx_offload_capa = 0;
    uint64_t rx_offload_capa = 0;
    uint16_t max_tx_queues = 0;
    uint16_t max_rx_queues = 0;
    bool supports_tx_cksum_ipv4 = false;
    bool supports_tx_cksum_udp = false;
    bool supports_rss = false;
};

// Bir portu açarken kullanılan yapılandırma.
struct OpenConfig {
    uint16_t port_id = 0;
    uint16_t num_tx_queues = 1;    // multi-queue TX (Faz 1)
    uint16_t num_rx_queues = 0;    // >0 ise RX etkin (RX yolu kapsamda)
    uint16_t burst_size = 64;
    uint32_t mempool_size = 8192;
    bool enable_rss = false;       // num_rx_queues > 1 ile RSS
    std::string eal_args;
};

// TX işlemi sonucu (batch veya burst).
struct TxResult {
    uint64_t sent = 0;
    uint64_t dropped = 0;
    uint64_t errors = 0;
    uint64_t alloc_failures = 0;
};

// UDP hızlı-yol şablon yapılandırması (network byte order alanlar).
struct UdpFlowConfig {
    uint32_t src_ip_nbo = 0;
    uint32_t dst_ip_nbo = 0;
    uint16_t src_port_nbo = 0;
    uint16_t dst_port_nbo = 0;
    uint8_t src_mac[6] = {0, 0, 0, 0, 0, 0};
    uint8_t dst_mac[6] = {0, 0, 0, 0, 0, 0};
    uint16_t initial_ip_id = 1;
};

// Sayaç + donanım istatistik anlık görüntüsü.
struct Snapshot {
    bool valid = false;
    uint16_t port_id = 0;
    int socket_id = 0;
    int link_up = 0;
    uint16_t burst_size = 0;
    uint64_t tx_packets = 0;
    uint64_t tx_bytes = 0;
    uint64_t tx_errors = 0;
    uint64_t tx_dropped = 0;
    uint64_t rx_packets = 0;
    uint64_t rx_bytes = 0;
    uint64_t rx_dropped = 0;
    uint64_t mbuf_alloc_failures = 0;
    uint64_t mempool_avail = 0;
    // Donanım sayaçları (O6 — rte_eth_stats_get). Destek yoksa 0 kalır.
    bool hw_stats_valid = false;
    uint64_t hw_ipackets = 0;
    uint64_t hw_opackets = 0;
    uint64_t hw_ibytes = 0;
    uint64_t hw_obytes = 0;
    uint64_t hw_ierrors = 0;
    uint64_t hw_oerrors = 0;
    uint64_t hw_imissed = 0;
    uint64_t hw_rx_nombuf = 0;
};

// DPDK desteği derlendi mi?
bool available();

// EAL'i (tek sefer) başlat. Aynı argümanlarla idempotenttir.
bool ensure_eal(const std::string& eal_args, std::string& err);

// Kullanılabilir ethdev port sayısı (DPDK yoksa / port yoksa 0).
uint16_t port_count();

// Port bağlamı aç. Başarıda handle (>0), hatada -1 döner (err doldurulur).
int64_t open_port(const OpenConfig& cfg, std::string& err);

// Açık handle için NIC yeteneklerini sorgula.
bool capabilities(int64_t handle, PortCapabilities& out);

// Portu YAPILANDIRMADAN (open öncesi) yeteneklerini sorgula. EAL başlatılmış
// olmalıdır (ensure_eal). Multi-queue için max_tx_queues öğrenmekte kullanılır.
bool query_capabilities(uint16_t port_id, PortCapabilities& out, std::string& err);

// Açık handle'ın NIC NUMA soketi (bilinmiyorsa -1). NUMA pinning guard için.
int port_socket_id(int64_t handle);

// Çağıran thread'i EAL lcore olarak kaydet/kaydı sil. TX thread'lerinin PMD'ye
// güvenli erişimi ve mempool per-lcore cache'i için kullanılır (multi-queue).
bool register_lcore_thread();
void unregister_lcore_thread();

// Tek burst gönder: `batch` mbuf ayır, `src`'ten (batch*packet_size bayt)
// her paketi kopyala, retry ile tx_burst yap. Bu burst'ün sonucunu döner.
// Multi-queue: her thread kendi queue_id'siyle çağırır (kilitsiz tasarım).
TxResult tx_burst(int64_t handle, uint16_t queue_id, const uint8_t* src,
                  uint16_t packet_size, uint16_t batch);

// `count` paketi (her biri packet_size bayt) `buf`'tan sırayla gönderir;
// burst_size'a göre iç döngüde parçalar. tx_burst üzerine kuruludur.
TxResult send_batch(int64_t handle, uint16_t queue_id, const uint8_t* buf,
                    uint16_t packet_size, uint64_t count);

// TX mempool nesnelerini şablon paketle önceden doldurur. Sonraki tx_burst /
// send_batch çağrılarında yalnızca ilk 64 baytlık L2/L3/L4 başlık mutasyonu
// yapılarak tam paket memcpy yükü ortadan kaldırılır.
bool prepopulate_tx_pool(int64_t handle, const uint8_t* template_pkt, uint16_t packet_size);

// UDP hızlı-yol şablonunu yapılandır.
bool configure_udp_flow(int64_t handle, const UdpFlowConfig& cfg, std::string& err);

// Yapılandırılmış şablonla tek UDP payload gönder. Gönderildiyse 1, aksi 0.
int send_udp_payload(int64_t handle, uint16_t queue_id, const uint8_t* payload,
                     std::size_t payload_len, std::string& err);

// En fazla `budget` ham RX frame'i `out_frames` (budget*stride bayt düz tampon)
// ve `out_lens` (budget adet) içine kopyalar. Alınan frame sayısını döner.
int poll_rx(int64_t handle, uint16_t queue_id, uint16_t budget,
            uint8_t* out_frames, uint16_t stride, uint16_t* out_lens);

// (local_ip, local_port, remote_port) eşleşen UDP payload'larını tamponlara
// ayıklar. Kabul edilen paket sayısını döner.
int poll_udp_payloads(int64_t handle, uint16_t queue_id, uint32_t local_ip_nbo,
                      uint16_t local_port_nbo, uint16_t remote_port_nbo,
                      uint16_t budget, uint8_t* out_payload, uint16_t stride,
                      uint16_t* out_lens);

// rte_flow akış-yönlendirme (per-core / shared-nothing demux).
//
// Bir IPv4 + (TCP|UDP) kuralı kurar: dst L4 portu `dst_port_spec & dst_port_mask`
// eşleşen paketleri `queue_id` kuyruğuna yönlendirir. Shard `s`, kendi ephemeral
// port kümesini `port & mask == s` olacak biçimde seçer; böylece dönüş trafiği
// deterministik olarak shard'ın kuyruğuna düşer (RSS-hash yerine kesin steering).
//
// `l4_proto`: IPPROTO_TCP (6) veya IPPROTO_UDP (17).
// `dst_port_spec` / `dst_port_mask`: host byte order; PMD'ye verilirken
// network byte order'a çevrilir.
//
// PMD rte_flow'u veya bu kuralı desteklemezse `false` döner (çağıran tek-wire
// dpdk_direct'e degrade eder). SAMURAI_WITH_DPDK tanımlı değilse daima `false`.
bool steer_l4_dst_port_to_queue(int64_t handle, uint8_t l4_proto, uint16_t queue_id,
                                uint16_t dst_port_spec, uint16_t dst_port_mask,
                                std::string& err);

// Sayaç + donanım istatistik anlık görüntüsü.
Snapshot snapshot(int64_t handle);

// Port bağlamını kapat (son kullanıcı çıkınca portu teardown eder).
void close_port(int64_t handle);

}  // namespace samurai::dpdk
