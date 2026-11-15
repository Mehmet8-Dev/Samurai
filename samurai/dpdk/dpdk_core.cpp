//
// dpdk_core.cpp — Samurai native DPDK çekirdeği (Python bağımsız).
//
// Bu dosya, eski dpdk_pmd_core.cpp'nin (CPython C extension) tüm DPDK mantığını
// içerir; CPython kabuğu (Python.h, PyObject, PyMethodDef, PyInit_*) çıkarılmış
// ve saf C++ API'ye (dpdk_core.hpp) dönüştürülmüştür. Üretimdeki tek DPDK yolu
// olan dpdk_worker.cpp bu çekirdeği doğrudan link'ler.
//
// DPDK yalnızca SAMURAI_WITH_DPDK tanımlıyken derlenir. Tanımlı değilse tüm
// genel API güvenli biçimde başarısızlık/0 döndürür; böylece libdpdk kurulu
// olmayan ortamlarda tüketiciler yine derlenir.
//
#include "dpdk_core.hpp"

#ifdef SAMURAI_WITH_DPDK

extern "C" {
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_udp.h>
}

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

constexpr uint16_t kMaxBurst = 1024;
constexpr uint16_t kMinBurst = 1;
constexpr uint32_t kDefaultMbufDataSize = RTE_MBUF_DEFAULT_BUF_SIZE;
constexpr uint32_t kDefaultMempoolCache = 256;
constexpr std::size_t kMaxUdpPayloadBytes = 1400u;
constexpr std::size_t kL2UdpFrameHdrBytes =
    sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr) + sizeof(rte_udp_hdr);

struct PortState {
    rte_mempool* mempool = nullptr;
    bool mempool_owned = false;
    int socket_id = 0;
    uint16_t tx_queues = 0;
    uint16_t rx_queues = 0;
    bool started = false;
    bool rx_enabled = false;
    uint32_t users = 0;
    samurai::dpdk::PortCapabilities caps{};
    // K3: capability'ye göre etkinleştirilen TX checksum offload'ları.
    bool hw_tx_cksum_ipv4 = false;
    bool hw_tx_cksum_udp = false;
    // Zero-copy mempool template pre-population and header mutation.
    bool pool_prepopulated = false;
    uint16_t prepopulated_pkt_size = 0;
};

struct Context {
    uint16_t port_id = 0;
    uint16_t queue_id = 0;
    uint16_t burst_size = 64;
    uint32_t mempool_size = 8192;
    bool rx_enable = false;
    int socket_id = 0;

    std::atomic<uint64_t> tx_packets{0};
    std::atomic<uint64_t> tx_bytes{0};
    std::atomic<uint64_t> tx_errors{0};
    std::atomic<uint64_t> tx_dropped{0};
    std::atomic<uint64_t> rx_packets{0};
    std::atomic<uint64_t> rx_bytes{0};
    std::atomic<uint64_t> rx_dropped{0};
    std::atomic<uint64_t> mbuf_alloc_failures{0};

    bool udp_template_ready = false;
    rte_ether_addr udp_src_mac{};
    rte_ether_addr udp_dst_mac{};
    uint32_t udp_src_ip_nbo = 0;
    uint32_t udp_dst_ip_nbo = 0;
    uint16_t udp_src_port_nbo = 0;
    uint16_t udp_dst_port_nbo = 0;
    std::atomic<uint16_t> udp_ip_id{1};
};

// Hot path (tx_burst/poll_*) shared_lock ile paralel okuyucu olarak ilerler;
// open/close/configure exclusive lock alır. unordered_map referans kararlılığı
// sayesinde shared_lock altında alınan Context& güvenlidir (close exclusive
// beklediği için TX in-flight iken teardown olmaz).
std::shared_mutex g_mu;
bool g_eal_initialized = false;
std::string g_locked_eal_args;
long g_next_handle = 1;
std::unordered_map<long, Context> g_contexts;
std::unordered_map<uint16_t, PortState> g_ports;

std::vector<std::string> split_ws(const std::string& text) {
    std::vector<std::string> out;
    std::istringstream iss(text);
    std::string token;
    while (iss >> token) {
        if (!token.empty()) {
            out.push_back(token);
        }
    }
    return out;
}

// EAL başlatma. Çağıran exclusive lock tutmalıdır.
bool ensure_eal_locked(const std::string& eal_args, std::string& err) {
    if (!g_eal_initialized) {
        std::vector<std::string> argv_store;
        argv_store.emplace_back("samurai_dpdk");
        auto extra = split_ws(eal_args);
        for (auto& tok : extra) {
            argv_store.push_back(tok);
        }
        if (const char* vdev_env = std::getenv("SAMURAI_DPDK_VDEV")) {
            if (vdev_env[0] != '\0' && eal_args.find("--vdev") == std::string::npos) {
                argv_store.emplace_back("--vdev");
                argv_store.emplace_back(vdev_env);
            }
        }

        std::vector<char*> argv;
        argv.reserve(argv_store.size());
        for (auto& s : argv_store) {
            argv.push_back(const_cast<char*>(s.c_str()));
        }

        int rc = rte_eal_init(static_cast<int>(argv.size()), argv.data());
        if (rc < 0) {
            err = std::string("dpdk_eal_init_failed:") + rte_strerror(rte_errno);
            return false;
        }
        g_eal_initialized = true;
        g_locked_eal_args = eal_args;
        return true;
    }

    if (g_locked_eal_args != eal_args) {
        err = "dpdk_eal_duplicate_init";
        return false;
    }
    return true;
}

void teardown_port_unlocked(uint16_t port_id, PortState& st) {
    if (st.started) {
        (void)rte_eth_dev_stop(port_id);
    }
    (void)rte_eth_dev_close(port_id);
    if (st.mempool && st.mempool_owned) {
        rte_mempool_free(st.mempool);
    }
    st.mempool = nullptr;
    st.mempool_owned = false;
    st.started = false;
    st.rx_enabled = false;
    st.tx_queues = 0;
    st.rx_queues = 0;
}

samurai::dpdk::PortCapabilities probe_caps(const rte_eth_dev_info& dev_info) {
    samurai::dpdk::PortCapabilities caps{};
    caps.tx_offload_capa = dev_info.tx_offload_capa;
    caps.rx_offload_capa = dev_info.rx_offload_capa;
    caps.max_tx_queues = dev_info.max_tx_queues;
    caps.max_rx_queues = dev_info.max_rx_queues;
    caps.supports_tx_cksum_ipv4 =
        !!(dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM);
    caps.supports_tx_cksum_udp =
        !!(dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_UDP_CKSUM);
    caps.supports_rss = (dev_info.flow_type_rss_offloads != 0);
    return caps;
}

// Portu (yoksa) yapılandırır ve başlatır. Çağıran exclusive lock tutmalıdır.
bool ensure_port_ready(uint16_t port_id, uint16_t num_tx_queues,
                       uint16_t num_rx_queues, bool enable_rss,
                       uint32_t mempool_size, PortState& out, std::string& err) {
    if (!rte_eth_dev_is_valid_port(port_id)) {
        err = "dpdk_port_invalid";
        return false;
    }

    const uint16_t txq = std::max<uint16_t>(1, num_tx_queues);
    const uint16_t rxq = num_rx_queues;
    const bool rx_enable = rxq > 0;

    auto it = g_ports.find(port_id);
    if (it != g_ports.end() && it->second.started) {
        if (txq > it->second.tx_queues) {
            err = "dpdk_queue_unavailable";
            return false;
        }
        if (rx_enable && !it->second.rx_enabled) {
            err = "dpdk_rx_not_configured";
            return false;
        }
        if (rx_enable && rxq > it->second.rx_queues) {
            err = "dpdk_rx_queue_unavailable";
            return false;
        }
        out = it->second;
        return true;
    }

    rte_eth_dev_info dev_info;
    std::memset(&dev_info, 0, sizeof(dev_info));
    if (rte_eth_dev_info_get(port_id, &dev_info) != 0) {
        err = "dpdk_dev_info_failed";
        return false;
    }

    const samurai::dpdk::PortCapabilities caps = probe_caps(dev_info);
    if (txq > dev_info.max_tx_queues) {
        err = "dpdk_tx_queue_count_exceeds_max";
        return false;
    }
    if (rxq > dev_info.max_rx_queues) {
        err = "dpdk_rx_queue_count_exceeds_max";
        return false;
    }

    rte_eth_conf port_conf;
    std::memset(&port_conf, 0, sizeof(port_conf));

    // K3: NIC destekliyorsa TX checksum offload'larını etkinleştir (yoksa SW
    // fallback — probe'a göre otomatik; VDEV gibi desteklemeyen PMD'lerde kapalı).
    uint64_t tx_offloads = 0;
    const bool hw_ipv4 = caps.supports_tx_cksum_ipv4;
    const bool hw_udp = caps.supports_tx_cksum_udp;
    if (hw_ipv4) {
        tx_offloads |= RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
    }
    if (hw_udp) {
        tx_offloads |= RTE_ETH_TX_OFFLOAD_UDP_CKSUM;
    }
    port_conf.txmode.offloads |= tx_offloads;

    // RSS (O3) — RX yolu kapsamda; çok kuyruklu RX'te donanım hash dağıtımı.
    if (rx_enable && enable_rss && rxq > 1 && dev_info.flow_type_rss_offloads) {
        port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
        port_conf.rx_adv_conf.rss_conf.rss_key = nullptr;
        port_conf.rx_adv_conf.rss_conf.rss_hf =
            (RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_TCP) &
            dev_info.flow_type_rss_offloads;
    }

    if (rte_eth_dev_configure(port_id, rxq, txq, &port_conf) < 0) {
        err = std::string("dpdk_dev_configure_failed:") + rte_strerror(rte_errno);
        return false;
    }

    int socket_id = rte_eth_dev_socket_id(port_id);
    if (socket_id < 0) {
        socket_id = 0;
    }

    char mp_name[64];
    std::snprintf(mp_name, sizeof(mp_name), "samurai_dpdk_mp_%u",
                  static_cast<unsigned>(port_id));

    rte_mempool* mp = rte_mempool_lookup(mp_name);
    bool mp_owned = false;
    if (!mp) {
        const uint32_t cache_sz = std::min<uint32_t>(
            kDefaultMempoolCache, std::max<uint32_t>(1u, mempool_size / 8u));
        mp = rte_pktmbuf_pool_create(mp_name, mempool_size, cache_sz, 0,
                                     kDefaultMbufDataSize, socket_id);
        mp_owned = (mp != nullptr);
    }
    if (!mp) {
        err = std::string("dpdk_mempool_create_failed:") + rte_strerror(rte_errno);
        return false;
    }

    rte_eth_txconf tx_conf = dev_info.default_txconf;
    tx_conf.offloads |= tx_offloads;  // K3: per-queue offload (port offload'un alt kümesi)
    for (uint16_t q = 0; q < txq; ++q) {
        if (rte_eth_tx_queue_setup(port_id, q, 1024, socket_id, &tx_conf) < 0) {
            err = std::string("dpdk_tx_queue_setup_failed:") + rte_strerror(rte_errno);
            PortState cleanup;
            cleanup.mempool = mp;
            cleanup.mempool_owned = mp_owned;
            teardown_port_unlocked(port_id, cleanup);
            return false;
        }
    }

    if (rx_enable) {
        rte_eth_rxconf rx_conf = dev_info.default_rxconf;
        for (uint16_t q = 0; q < rxq; ++q) {
            if (rte_eth_rx_queue_setup(port_id, q, 1024, socket_id, &rx_conf, mp) < 0) {
                err = std::string("dpdk_rx_queue_setup_failed:") + rte_strerror(rte_errno);
                PortState cleanup;
                cleanup.mempool = mp;
                cleanup.mempool_owned = mp_owned;
                teardown_port_unlocked(port_id, cleanup);
                return false;
            }
        }
    }

    if (rte_eth_dev_start(port_id) < 0) {
        err = std::string("dpdk_dev_start_failed:") + rte_strerror(rte_errno);
        PortState cleanup;
        cleanup.mempool = mp;
        cleanup.mempool_owned = mp_owned;
        teardown_port_unlocked(port_id, cleanup);
        return false;
    }

    PortState st;
    st.mempool = mp;
    st.mempool_owned = mp_owned;
    st.socket_id = socket_id;
    st.tx_queues = txq;
    st.rx_queues = rxq;
    st.started = true;
    st.rx_enabled = rx_enable;
    st.users = 0;
    st.caps = caps;
    st.hw_tx_cksum_ipv4 = hw_ipv4;
    st.hw_tx_cksum_udp = hw_udp;

    g_ports[port_id] = st;
    out = st;
    return true;
}

struct PrepopulateArg {
    const uint8_t* data;
    uint16_t len;
};

static void prepopulate_mbuf_cb(struct rte_mempool* mp, void* opaque, void* obj, unsigned obj_idx) {
    (void)mp; (void)obj_idx;
    auto* arg = static_cast<const PrepopulateArg*>(opaque);
    struct rte_mbuf* m = static_cast<struct rte_mbuf*>(obj);
    uint8_t* dst = rte_pktmbuf_mtod(m, uint8_t*);
    std::memcpy(dst, arg->data, arg->len);
    m->data_len = arg->len;
    m->pkt_len = arg->len;
}

// Tek burst gönderiminin ortak gövdesi. Çağıran shared_lock tutuyor olmalıdır.
// src en az batch*packet_size bayt içermelidir.
samurai::dpdk::TxResult do_tx_burst(uint16_t port_id, uint16_t queue_id,
                                    rte_mempool* mempool, const uint8_t* src,
                                    uint16_t packet_size, uint16_t batch) {
    samurai::dpdk::TxResult r{};
    if (batch == 0) {
        return r;
    }

    constexpr uint16_t kHeaderMutationBytes = 64;
    auto it_port = g_ports.find(port_id);
    const bool use_fast_mutation = (packet_size > kHeaderMutationBytes);
    if (it_port != g_ports.end() && use_fast_mutation) {
        PortState& pst = it_port->second;
        if (!pst.pool_prepopulated || pst.prepopulated_pkt_size != packet_size) {
            PrepopulateArg arg{src, packet_size};
            rte_mempool_obj_iter(mempool, prepopulate_mbuf_cb, &arg);
            pst.pool_prepopulated = true;
            pst.prepopulated_pkt_size = packet_size;
        }
    }

    rte_mbuf* mbufs[kMaxBurst];
    if (rte_pktmbuf_alloc_bulk(mempool, mbufs, batch) != 0) {
        r.alloc_failures += batch;
        r.errors += batch;
        r.dropped += batch;
        return r;
    }

    const uint16_t copy_bytes = (it_port != g_ports.end() && it_port->second.pool_prepopulated && use_fast_mutation)
                                    ? kHeaderMutationBytes
                                    : packet_size;

    for (uint16_t i = 0; i < batch; ++i) {
        const uint8_t* s = src + static_cast<std::size_t>(i) * packet_size;
        uint8_t* dst = rte_pktmbuf_mtod(mbufs[i], uint8_t*);
        std::memcpy(dst, s, copy_bytes);
        mbufs[i]->data_len = packet_size;
        mbufs[i]->pkt_len = packet_size;
    }

    uint16_t offset = 0;
    uint16_t remaining = batch;
    int retry = 0;
    while (remaining > 0 && retry < 8) {
        const uint16_t n = rte_eth_tx_burst(port_id, queue_id, &mbufs[offset], remaining);
        offset += n;
        remaining = static_cast<uint16_t>(remaining - n);
        if (remaining > 0) {
            ++retry;
            rte_pause();
        }
    }

    r.sent += offset;
    if (remaining > 0) {
        for (uint16_t i = 0; i < remaining; ++i) {
            rte_pktmbuf_free(mbufs[offset + i]);
        }
        r.dropped += remaining;
        r.errors += remaining;
    }
    return r;
}

}  // namespace

namespace samurai::dpdk {

bool available() { return true; }

bool ensure_eal(const std::string& eal_args, std::string& err) {
    std::unique_lock<std::shared_mutex> lock(g_mu);
    return ensure_eal_locked(eal_args, err);
}

uint16_t port_count() {
    std::unique_lock<std::shared_mutex> lock(g_mu);
    if (!g_eal_initialized) {
        return 0;
    }
    return static_cast<uint16_t>(rte_eth_dev_count_avail());
}

int64_t open_port(const OpenConfig& cfg, std::string& err) {
    const uint16_t port_id = cfg.port_id;
    const uint16_t num_tx = std::max<uint16_t>(1, cfg.num_tx_queues);
    const uint16_t num_rx = cfg.num_rx_queues;
    const uint16_t burst_size = std::clamp<uint16_t>(cfg.burst_size, kMinBurst, kMaxBurst);
    const uint32_t mempool_size = std::max<uint32_t>(128u, cfg.mempool_size);

    std::unique_lock<std::shared_mutex> lock(g_mu);

    if (!ensure_eal_locked(cfg.eal_args, err)) {
        return -1;
    }

    PortState st;
    if (!ensure_port_ready(port_id, num_tx, num_rx, cfg.enable_rss, mempool_size, st, err)) {
        return -1;
    }

    // Context, atomic üyeler içerdiği için taşınamaz/kopyalanamaz; map içinde
    // yerinde (default) kurulup alanları atanır.
    const long handle = g_next_handle++;
    Context& ctx = g_contexts.try_emplace(handle).first->second;
    ctx.port_id = port_id;
    ctx.queue_id = 0;
    ctx.burst_size = burst_size;
    ctx.mempool_size = mempool_size;
    ctx.rx_enable = num_rx > 0;
    ctx.socket_id = st.socket_id;

    g_ports[port_id].users += 1;
    return static_cast<int64_t>(handle);
}

bool capabilities(int64_t handle, PortCapabilities& out) {
    std::shared_lock<std::shared_mutex> lock(g_mu);
    auto it = g_contexts.find(static_cast<long>(handle));
    if (it == g_contexts.end()) {
        return false;
    }
    auto pt = g_ports.find(it->second.port_id);
    if (pt == g_ports.end()) {
        return false;
    }
    out = pt->second.caps;
    return true;
}

bool query_capabilities(uint16_t port_id, PortCapabilities& out, std::string& err) {
    std::shared_lock<std::shared_mutex> lock(g_mu);
    if (!g_eal_initialized) {
        err = "dpdk_eal_not_initialized";
        return false;
    }
    if (!rte_eth_dev_is_valid_port(port_id)) {
        err = "dpdk_port_invalid";
        return false;
    }
    rte_eth_dev_info dev_info;
    std::memset(&dev_info, 0, sizeof(dev_info));
    if (rte_eth_dev_info_get(port_id, &dev_info) != 0) {
        err = "dpdk_dev_info_failed";
        return false;
    }
    out = probe_caps(dev_info);
    return true;
}

int port_socket_id(int64_t handle) {
    std::shared_lock<std::shared_mutex> lock(g_mu);
    auto it = g_contexts.find(static_cast<long>(handle));
    if (it == g_contexts.end()) {
        return -1;
    }
    return rte_eth_dev_socket_id(it->second.port_id);
}

bool register_lcore_thread() { return rte_thread_register() == 0; }

void unregister_lcore_thread() { rte_thread_unregister(); }

TxResult tx_burst(int64_t handle, uint16_t queue_id, const uint8_t* src,
                  uint16_t packet_size, uint16_t batch) {
    TxResult r{};
    if (src == nullptr || packet_size == 0) {
        return r;
    }
    if (batch > kMaxBurst) {
        batch = kMaxBurst;
    }

    std::shared_lock<std::shared_mutex> lock(g_mu);
    auto it = g_contexts.find(static_cast<long>(handle));
    if (it == g_contexts.end()) {
        return r;
    }
    auto pt = g_ports.find(it->second.port_id);
    if (pt == g_ports.end() || !pt->second.mempool) {
        return r;
    }
    if (queue_id >= pt->second.tx_queues) {
        return r;
    }

    r = do_tx_burst(it->second.port_id, queue_id, pt->second.mempool, src,
                    packet_size, batch);

    it->second.tx_packets.fetch_add(r.sent, std::memory_order_relaxed);
    it->second.tx_bytes.fetch_add(r.sent * static_cast<uint64_t>(packet_size),
                                  std::memory_order_relaxed);
    it->second.tx_errors.fetch_add(r.errors, std::memory_order_relaxed);
    it->second.tx_dropped.fetch_add(r.dropped, std::memory_order_relaxed);
    it->second.mbuf_alloc_failures.fetch_add(r.alloc_failures, std::memory_order_relaxed);
    return r;
}

TxResult send_batch(int64_t handle, uint16_t queue_id, const uint8_t* buf,
                    uint16_t packet_size, uint64_t count) {
    TxResult total{};
    if (buf == nullptr || packet_size == 0 || count == 0) {
        return total;
    }

    std::shared_lock<std::shared_mutex> lock(g_mu);
    auto it = g_contexts.find(static_cast<long>(handle));
    if (it == g_contexts.end()) {
        return total;
    }
    auto pt = g_ports.find(it->second.port_id);
    if (pt == g_ports.end() || !pt->second.mempool) {
        return total;
    }
    if (queue_id >= pt->second.tx_queues) {
        return total;
    }
    rte_mempool* mempool = pt->second.mempool;
    const uint16_t burst = it->second.burst_size;

    uint64_t done = 0;  // sent + dropped
    while (done < count) {
        const uint16_t batch =
            static_cast<uint16_t>(std::min<uint64_t>(burst, count - done));
        const uint8_t* src = buf + done * static_cast<uint64_t>(packet_size);
        const TxResult r = do_tx_burst(it->second.port_id, queue_id, mempool, src,
                                       packet_size, batch);
        total.sent += r.sent;
        total.dropped += r.dropped;
        total.errors += r.errors;
        total.alloc_failures += r.alloc_failures;
        done += r.sent + r.dropped;
    }

    it->second.tx_packets.fetch_add(total.sent, std::memory_order_relaxed);
    it->second.tx_bytes.fetch_add(total.sent * static_cast<uint64_t>(packet_size),
                                  std::memory_order_relaxed);
    it->second.tx_errors.fetch_add(total.errors, std::memory_order_relaxed);
    it->second.tx_dropped.fetch_add(total.dropped, std::memory_order_relaxed);
    it->second.mbuf_alloc_failures.fetch_add(total.alloc_failures, std::memory_order_relaxed);
    return total;
}

bool prepopulate_tx_pool(int64_t handle, const uint8_t* template_pkt, uint16_t packet_size) {
    if (template_pkt == nullptr || packet_size == 0) {
        return false;
    }
    std::unique_lock<std::shared_mutex> lock(g_mu);
    auto it = g_contexts.find(static_cast<long>(handle));
    if (it == g_contexts.end()) {
        return false;
    }
    auto pt = g_ports.find(it->second.port_id);
    if (pt == g_ports.end() || !pt->second.mempool) {
        return false;
    }
    PrepopulateArg arg{template_pkt, packet_size};
    rte_mempool_obj_iter(pt->second.mempool, prepopulate_mbuf_cb, &arg);
    pt->second.pool_prepopulated = true;
    pt->second.prepopulated_pkt_size = packet_size;
    return true;
}

static void noop_extbuf_free_cb(void* addr, void* opaque) {
    (void)addr;
    (void)opaque;
}

bool register_extmem_region(int64_t handle, void* vaddr, std::size_t len,
                            uint64_t iova, uint32_t page_size, std::string& err) {
    if (!vaddr || len == 0 || iova == 0u) {
        err = "dpdk_extmem_invalid_args_or_zero_iova";
        return false;
    }
    const uint32_t pg_sz = (page_size > 0u) ? page_size : 4096u;
    const std::size_t aligned_len = (len + pg_sz - 1u) & ~static_cast<std::size_t>(pg_sz - 1u);
    std::unique_lock<std::shared_mutex> lock(g_mu);
    auto it = g_contexts.find(static_cast<long>(handle));
    if (it == g_contexts.end()) {
        err = "dpdk_invalid_handle";
        return false;
    }
    const uint16_t port_id = it->second.port_id;
    rte_eth_dev_info dev_info{};
    if (rte_eth_dev_info_get(port_id, &dev_info) != 0 || dev_info.device == nullptr) {
        err = "dpdk_extmem_missing_rte_device";
        return false;
    }

    const std::size_t n_pages = aligned_len / pg_sz;
    std::vector<rte_iova_t> iovas(n_pages);
    for (std::size_t i = 0; i < n_pages; ++i) {
        iovas[i] = static_cast<rte_iova_t>(iova + i * pg_sz);
    }
    const int reg_rc = rte_extmem_register(
        vaddr,
        aligned_len,
        iovas.data(),
        static_cast<unsigned int>(iovas.size()),
        pg_sz);
    if (reg_rc < 0 && rte_errno != EEXIST) {
        err = std::string("rte_extmem_register_failed:") + rte_strerror(rte_errno);
        return false;
    }
    const int dma_rc = rte_dev_dma_map(
        dev_info.device, vaddr, static_cast<rte_iova_t>(iova), aligned_len);
    if (dma_rc < 0 && rte_errno != EEXIST) {
        const int saved_errno = rte_errno;
        if (reg_rc == 0) {
            (void)rte_extmem_unregister(vaddr, aligned_len);
        }
        err = std::string("rte_dev_dma_map_failed:") + rte_strerror(saved_errno);
        return false;
    }
    return true;
}

TxResult tx_burst_extbuf_zero_copy(int64_t handle, uint16_t queue_id,
                                   void* bar1_base_vaddr, uint64_t bar1_base_iova,
                                   std::size_t region_len, std::size_t offset,
                                   uint16_t packet_size, uint16_t batch) {
    TxResult r{};
    if (!bar1_base_vaddr || packet_size == 0 || batch == 0 || region_len < packet_size) {
        return r;
    }
    const uint16_t clamped_batch = std::min<uint16_t>(batch, kMaxBurst);
    if (bar1_base_iova == 0u) {
        // BAR1 IOVA doğrulanmadan sessizce CPU kopyasına düşülmez (fail-closed).
        r.errors += clamped_batch;
        r.dropped += clamped_batch;
        return r;
    }

    uint16_t port_id = 0;
    rte_mempool* mempool = nullptr;
    Context* ctx = nullptr;
    {
        std::shared_lock<std::shared_mutex> lock(g_mu);
        auto it = g_contexts.find(static_cast<long>(handle));
        if (it == g_contexts.end()) {
            return r;
        }
        ctx = &it->second;
        port_id = ctx->port_id;
        auto pt = g_ports.find(port_id);
        if (pt == g_ports.end() || !pt->second.started || !pt->second.mempool) {
            return r;
        }
        if (queue_id >= pt->second.tx_queues) {
            queue_id = 0;
        }
        mempool = pt->second.mempool;
    }

    rte_mbuf* mbufs[kMaxBurst];
    if (rte_pktmbuf_alloc_bulk(mempool, mbufs, clamped_batch) != 0) {
        r.alloc_failures += clamped_batch;
        r.errors += clamped_batch;
        r.dropped += clamped_batch;
        ctx->mbuf_alloc_failures.fetch_add(clamped_batch, std::memory_order_relaxed);
        ctx->tx_errors.fetch_add(clamped_batch, std::memory_order_relaxed);
        ctx->tx_dropped.fetch_add(clamped_batch, std::memory_order_relaxed);
        return r;
    }

    thread_local rte_mbuf_ext_shared_info shinfo_pool[4096];
    thread_local uint32_t shinfo_cursor = 0;
    for (uint16_t i = 0; i < clamped_batch; ++i) {
        const std::size_t pkt_off =
            (offset + static_cast<std::size_t>(i) * packet_size) % (region_len - packet_size + 1u);
        void* buf_va = static_cast<uint8_t*>(bar1_base_vaddr) + pkt_off;
        const rte_iova_t buf_iova = static_cast<rte_iova_t>(bar1_base_iova + pkt_off);
        const uint32_t sidx = (shinfo_cursor++) & 4095u;
        shinfo_pool[sidx].free_cb = noop_extbuf_free_cb;
        shinfo_pool[sidx].fcb_opaque = nullptr;
        rte_mbuf_ext_refcnt_set(&shinfo_pool[sidx], 2);
        rte_pktmbuf_attach_extbuf(mbufs[i], buf_va, buf_iova, packet_size, &shinfo_pool[sidx]);
        mbufs[i]->data_len = packet_size;
        mbufs[i]->pkt_len = packet_size;
    }

    uint16_t sent_off = 0;
    uint16_t remaining = clamped_batch;
    int retry = 0;
    while (remaining > 0 && retry < 8) {
        const uint16_t n = rte_eth_tx_burst(port_id, queue_id, &mbufs[sent_off], remaining);
        sent_off += n;
        remaining = static_cast<uint16_t>(remaining - n);
        if (remaining > 0) {
            ++retry;
            rte_pause();
        }
    }

    r.sent += sent_off;
    if (remaining > 0) {
        for (uint16_t i = 0; i < remaining; ++i) {
            rte_pktmbuf_free(mbufs[sent_off + i]);
        }
        r.dropped += remaining;
        r.errors += remaining;
    }

    ctx->tx_packets.fetch_add(r.sent, std::memory_order_relaxed);
    ctx->tx_bytes.fetch_add(r.sent * static_cast<uint64_t>(packet_size), std::memory_order_relaxed);
    ctx->tx_errors.fetch_add(r.errors, std::memory_order_relaxed);
    ctx->tx_dropped.fetch_add(r.dropped, std::memory_order_relaxed);
    return r;
}

TxResult tx_burst_extbuf_slots(int64_t handle, uint16_t queue_id,
                               void* bar1_base_vaddr, uint64_t bar1_base_iova,
                               uint32_t slot_stride, const uint32_t* slot_indices,
                               const uint16_t* pkt_lengths, uint16_t count,
                               ExtbufSlotFreeCallback free_cb,
                               void* free_cb_opaque) {
    TxResult r{};
    if (!bar1_base_vaddr || bar1_base_iova == 0u || slot_stride == 0u ||
        !slot_indices || !pkt_lengths || count == 0u) {
        return r;
    }
    const uint16_t clamped_batch = std::min<uint16_t>(count, kMaxBurst);

    uint16_t port_id = 0;
    rte_mempool* mempool = nullptr;
    Context* ctx = nullptr;
    {
        std::shared_lock<std::shared_mutex> lock(g_mu);
        auto it = g_contexts.find(static_cast<long>(handle));
        if (it == g_contexts.end()) {
            return r;
        }
        ctx = &it->second;
        port_id = ctx->port_id;
        auto pt = g_ports.find(port_id);
        if (pt == g_ports.end() || !pt->second.started || !pt->second.mempool) {
            return r;
        }
        if (queue_id >= pt->second.tx_queues) {
            queue_id = 0;
        }
        mempool = pt->second.mempool;
    }

    rte_mbuf* mbufs[kMaxBurst];
    if (rte_pktmbuf_alloc_bulk(mempool, mbufs, clamped_batch) != 0) {
        r.alloc_failures += clamped_batch;
        r.errors += clamped_batch;
        r.dropped += clamped_batch;
        ctx->mbuf_alloc_failures.fetch_add(clamped_batch, std::memory_order_relaxed);
        ctx->tx_errors.fetch_add(clamped_batch, std::memory_order_relaxed);
        ctx->tx_dropped.fetch_add(clamped_batch, std::memory_order_relaxed);
        return r;
    }

    thread_local rte_mbuf_ext_shared_info shinfo_ring[4096];
    for (uint16_t i = 0; i < clamped_batch; ++i) {
        const uint32_t slot_idx = slot_indices[i];
        const uint16_t pkt_len = (pkt_lengths[i] > 0u) ? pkt_lengths[i] : 64u;
        const std::size_t pkt_off = static_cast<std::size_t>(slot_idx) * slot_stride;
        void* buf_va = static_cast<uint8_t*>(bar1_base_vaddr) + pkt_off;
        const rte_iova_t buf_iova = static_cast<rte_iova_t>(bar1_base_iova + pkt_off);
        const uint32_t sidx = slot_idx & 4095u;
        if (free_cb != nullptr) {
            shinfo_ring[sidx].free_cb = free_cb;
            shinfo_ring[sidx].fcb_opaque = free_cb_opaque;
            rte_mbuf_ext_refcnt_set(&shinfo_ring[sidx], 1);
        } else {
            shinfo_ring[sidx].free_cb = noop_extbuf_free_cb;
            shinfo_ring[sidx].fcb_opaque = nullptr;
            rte_mbuf_ext_refcnt_set(&shinfo_ring[sidx], 2);
        }
        rte_pktmbuf_attach_extbuf(mbufs[i], buf_va, buf_iova, pkt_len, &shinfo_ring[sidx]);
        mbufs[i]->data_len = pkt_len;
        mbufs[i]->pkt_len = pkt_len;
    }

    uint16_t sent_off = 0;
    uint16_t remaining = clamped_batch;
    int retry = 0;
    while (remaining > 0 && retry < 8) {
        const uint16_t n = rte_eth_tx_burst(port_id, queue_id, &mbufs[sent_off], remaining);
        sent_off += n;
        remaining = static_cast<uint16_t>(remaining - n);
        if (remaining > 0) {
            ++retry;
            rte_pause();
        }
    }

    uint64_t sent_bytes = 0;
    for (uint16_t i = 0; i < sent_off; ++i) {
        sent_bytes += (pkt_lengths[i] > 0u) ? pkt_lengths[i] : 64u;
    }
    r.sent += sent_off;
    if (remaining > 0) {
        for (uint16_t i = 0; i < remaining; ++i) {
            rte_pktmbuf_free(mbufs[sent_off + i]);
        }
        r.dropped += remaining;
        r.errors += remaining;
    }

    ctx->tx_packets.fetch_add(r.sent, std::memory_order_relaxed);
    ctx->tx_bytes.fetch_add(sent_bytes, std::memory_order_relaxed);
    ctx->tx_errors.fetch_add(r.errors, std::memory_order_relaxed);
    ctx->tx_dropped.fetch_add(r.dropped, std::memory_order_relaxed);
    return r;
}

int rx_burst_to_bar1_slots(int64_t handle, uint16_t queue_id,
                           void* bar1_base_vaddr, uint32_t slot_stride,
                           const uint32_t* slot_indices, uint16_t max_slots,
                           uint16_t* out_lengths) {
    if (!bar1_base_vaddr || slot_stride == 0u || !slot_indices || !out_lengths || max_slots == 0u) {
        return -1;
    }
    const uint16_t budget = std::min<uint16_t>(max_slots, kMaxBurst);

    std::shared_lock<std::shared_mutex> lock(g_mu);
    auto it = g_contexts.find(static_cast<long>(handle));
    if (it == g_contexts.end() || !it->second.rx_enable) {
        return -1;
    }
    auto pt = g_ports.find(it->second.port_id);
    if (pt == g_ports.end() || !pt->second.started || queue_id >= pt->second.rx_queues) {
        return -1;
    }
    const uint16_t port_id = it->second.port_id;

    rte_mbuf* mbufs[kMaxBurst];
    const uint16_t n = rte_eth_rx_burst(port_id, queue_id, mbufs, budget);

    uint64_t rx_bytes = 0;
    for (uint16_t i = 0; i < n; ++i) {
        const uint16_t pkt_len = rte_pktmbuf_pkt_len(mbufs[i]);
        const uint16_t copy_len =
            static_cast<uint16_t>(std::min<uint32_t>(pkt_len, slot_stride));
        const void* data = rte_pktmbuf_mtod(mbufs[i], const void*);
        uint8_t* dst = static_cast<uint8_t*>(bar1_base_vaddr) +
                       static_cast<std::size_t>(slot_indices[i]) * slot_stride;
        std::memcpy(dst, data, copy_len);
        out_lengths[i] = copy_len;
        rx_bytes += copy_len;
        rte_pktmbuf_free(mbufs[i]);
    }

    it->second.rx_packets.fetch_add(n, std::memory_order_relaxed);
    it->second.rx_bytes.fetch_add(rx_bytes, std::memory_order_relaxed);
    return static_cast<int>(n);
}

bool configure_udp_flow(int64_t handle, const UdpFlowConfig& cfg, std::string& err) {
    std::unique_lock<std::shared_mutex> lock(g_mu);
    auto it = g_contexts.find(static_cast<long>(handle));
    if (it == g_contexts.end()) {
        err = "dpdk_invalid_handle";
        return false;
    }
    std::memcpy(it->second.udp_src_mac.addr_bytes, cfg.src_mac, RTE_ETHER_ADDR_LEN);
    std::memcpy(it->second.udp_dst_mac.addr_bytes, cfg.dst_mac, RTE_ETHER_ADDR_LEN);
    it->second.udp_src_ip_nbo = cfg.src_ip_nbo;
    it->second.udp_dst_ip_nbo = cfg.dst_ip_nbo;
    it->second.udp_src_port_nbo = cfg.src_port_nbo;
    it->second.udp_dst_port_nbo = cfg.dst_port_nbo;
    uint16_t ip_id = cfg.initial_ip_id;
    if (ip_id == 0) {
        ip_id = 1;
    }
    it->second.udp_ip_id.store(ip_id, std::memory_order_relaxed);
    it->second.udp_template_ready = true;
    return true;
}

int send_udp_payload(int64_t handle, uint16_t queue_id, const uint8_t* payload,
                     std::size_t payload_len, std::string& err) {
    if (payload == nullptr || payload_len == 0) {
        err = "empty payload";
        return 0;
    }
    if (payload_len > kMaxUdpPayloadBytes) {
        err = "payload too large";
        return 0;
    }

    std::shared_lock<std::shared_mutex> lock(g_mu);
    auto it = g_contexts.find(static_cast<long>(handle));
    if (it == g_contexts.end()) {
        err = "dpdk_invalid_handle";
        return 0;
    }
    auto pt = g_ports.find(it->second.port_id);
    if (pt == g_ports.end() || !pt->second.mempool) {
        err = "dpdk_port_not_ready";
        return 0;
    }
    if (!it->second.udp_template_ready) {
        err = "dpdk_udp_template_not_configured";
        return 0;
    }
    if (queue_id >= pt->second.tx_queues) {
        err = "dpdk_queue_unavailable";
        return 0;
    }

    const uint16_t port_id = it->second.port_id;
    rte_mempool* mempool = pt->second.mempool;
    // K3: port açılışında probe'a göre etkinleştirilmiş HW checksum offload'ları.
    const bool hw_ipv4 = pt->second.hw_tx_cksum_ipv4;
    const bool hw_udp = pt->second.hw_tx_cksum_udp;
    const rte_ether_addr src_mac = it->second.udp_src_mac;
    const rte_ether_addr dst_mac = it->second.udp_dst_mac;
    const uint32_t src_ip_nbo = it->second.udp_src_ip_nbo;
    const uint32_t dst_ip_nbo = it->second.udp_dst_ip_nbo;
    const uint16_t src_port_nbo = it->second.udp_src_port_nbo;
    const uint16_t dst_port_nbo = it->second.udp_dst_port_nbo;
    uint16_t ip_id = it->second.udp_ip_id.fetch_add(1, std::memory_order_relaxed);
    if (ip_id == 0) {
        ip_id = 1;
    }

    const std::size_t frame_len = kL2UdpFrameHdrBytes + payload_len;
    rte_mbuf* mbuf = rte_pktmbuf_alloc(mempool);
    if (mbuf == nullptr) {
        it->second.tx_errors.fetch_add(1, std::memory_order_relaxed);
        it->second.tx_dropped.fetch_add(1, std::memory_order_relaxed);
        it->second.mbuf_alloc_failures.fetch_add(1, std::memory_order_relaxed);
        err = "dpdk_mbuf_alloc_failed";
        return 0;
    }

    auto* base = rte_pktmbuf_mtod(mbuf, uint8_t*);
    auto* eth = reinterpret_cast<rte_ether_hdr*>(base);
    rte_ether_addr_copy(&dst_mac, &eth->dst_addr);
    rte_ether_addr_copy(&src_mac, &eth->src_addr);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    auto* ip = reinterpret_cast<rte_ipv4_hdr*>(base + sizeof(rte_ether_hdr));
    std::memset(ip, 0, sizeof(*ip));
    ip->version_ihl = RTE_IPV4_VHL_DEF;
    ip->type_of_service = 0;
    ip->total_length = rte_cpu_to_be_16(
        static_cast<uint16_t>(sizeof(rte_ipv4_hdr) + sizeof(rte_udp_hdr) + payload_len));
    ip->packet_id = rte_cpu_to_be_16(ip_id);
    ip->fragment_offset = rte_cpu_to_be_16(static_cast<uint16_t>(0x4000u));
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_UDP;
    ip->src_addr = src_ip_nbo;
    ip->dst_addr = dst_ip_nbo;

    // K3: HW offload açıksa NIC hesaplasın (checksum alanı 0 + ol_flags/len).
    const bool hw_offload = hw_ipv4 || hw_udp;
    if (hw_offload) {
        mbuf->l2_len = sizeof(rte_ether_hdr);
        mbuf->l3_len = sizeof(rte_ipv4_hdr);
        mbuf->ol_flags |= RTE_MBUF_F_TX_IPV4;
    }
    if (hw_ipv4) {
        ip->hdr_checksum = 0;
        mbuf->ol_flags |= RTE_MBUF_F_TX_IP_CKSUM;
    } else {
        ip->hdr_checksum = rte_ipv4_cksum(ip);
    }

    auto* udp = reinterpret_cast<rte_udp_hdr*>(
        base + sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr));
    udp->src_port = src_port_nbo;
    udp->dst_port = dst_port_nbo;
    udp->dgram_len =
        rte_cpu_to_be_16(static_cast<uint16_t>(sizeof(rte_udp_hdr) + payload_len));
    udp->dgram_cksum = 0;
    std::memcpy(base + sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr) + sizeof(rte_udp_hdr),
                payload, payload_len);
    if (hw_udp) {
        // HW UDP checksum: pseudo-header checksum'u önceden doldurulmalı.
        mbuf->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;
        udp->dgram_cksum = rte_ipv4_phdr_cksum(ip, mbuf->ol_flags);
    } else {
        udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);
        if (udp->dgram_cksum == 0) {
            udp->dgram_cksum = 0xFFFFu;
        }
    }

    mbuf->data_len = static_cast<uint16_t>(frame_len);
    mbuf->pkt_len = static_cast<uint32_t>(frame_len);

    uint16_t sent = 0;
    int retry = 0;
    while (sent == 0 && retry < 8) {
        sent = rte_eth_tx_burst(port_id, queue_id, &mbuf, 1);
        if (sent == 0) {
            ++retry;
            rte_pause();
        }
    }

    if (sent == 0) {
        rte_pktmbuf_free(mbuf);
        it->second.tx_errors.fetch_add(1, std::memory_order_relaxed);
        it->second.tx_dropped.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }
    it->second.tx_packets.fetch_add(1, std::memory_order_relaxed);
    it->second.tx_bytes.fetch_add(static_cast<uint64_t>(frame_len), std::memory_order_relaxed);
    return 1;
}

int poll_rx(int64_t handle, uint16_t queue_id, uint16_t budget, uint8_t* out_frames,
            uint16_t stride, uint16_t* out_lens) {
    if (out_frames == nullptr || out_lens == nullptr || stride == 0 || budget == 0) {
        return 0;
    }
    if (budget > kMaxBurst) {
        budget = kMaxBurst;
    }

    std::shared_lock<std::shared_mutex> lock(g_mu);
    auto it = g_contexts.find(static_cast<long>(handle));
    if (it == g_contexts.end() || !it->second.rx_enable) {
        return 0;
    }
    auto pt = g_ports.find(it->second.port_id);
    if (pt == g_ports.end() || queue_id >= pt->second.rx_queues) {
        return 0;
    }
    const uint16_t port_id = it->second.port_id;

    rte_mbuf* mbufs[kMaxBurst];
    const uint16_t n = rte_eth_rx_burst(port_id, queue_id, mbufs, budget);

    uint16_t stored = 0;
    uint64_t rx_bytes = 0;
    for (uint16_t i = 0; i < n; ++i) {
        const uint16_t pkt_len = rte_pktmbuf_pkt_len(mbufs[i]);
        const uint16_t copy_len = std::min<uint16_t>(pkt_len, stride);
        const void* data = rte_pktmbuf_mtod(mbufs[i], const void*);
        std::memcpy(out_frames + static_cast<std::size_t>(stored) * stride, data, copy_len);
        out_lens[stored] = copy_len;
        rx_bytes += copy_len;
        ++stored;
        rte_pktmbuf_free(mbufs[i]);
    }

    it->second.rx_packets.fetch_add(stored, std::memory_order_relaxed);
    it->second.rx_bytes.fetch_add(rx_bytes, std::memory_order_relaxed);
    return static_cast<int>(stored);
}

int poll_udp_payloads(int64_t handle, uint16_t queue_id, uint32_t local_ip_nbo,
                      uint16_t local_port_nbo, uint16_t remote_port_nbo, uint16_t budget,
                      uint8_t* out_payload, uint16_t stride, uint16_t* out_lens) {
    if (out_payload == nullptr || out_lens == nullptr || stride == 0 || budget == 0) {
        return 0;
    }
    if (budget > kMaxBurst) {
        budget = kMaxBurst;
    }

    std::shared_lock<std::shared_mutex> lock(g_mu);
    auto it = g_contexts.find(static_cast<long>(handle));
    if (it == g_contexts.end() || !it->second.rx_enable) {
        return 0;
    }
    auto pt = g_ports.find(it->second.port_id);
    if (pt == g_ports.end() || queue_id >= pt->second.rx_queues) {
        return 0;
    }
    const uint16_t port_id = it->second.port_id;

    for (uint16_t i = 0; i < budget; ++i) {
        out_lens[i] = 0;
    }

    rte_mbuf* mbufs[kMaxBurst];
    const uint16_t n = rte_eth_rx_burst(port_id, queue_id, mbufs, budget);

    uint16_t accepted = 0;
    uint64_t rx_bytes = 0;
    for (uint16_t i = 0; i < n; ++i) {
        const uint16_t pkt_len = rte_pktmbuf_pkt_len(mbufs[i]);
        const auto* frame = static_cast<const uint8_t*>(rte_pktmbuf_mtod(mbufs[i], const void*));
        if (frame != nullptr &&
            pkt_len >= (sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr) + sizeof(rte_udp_hdr))) {
            const auto* eth = reinterpret_cast<const rte_ether_hdr*>(frame);
            if (eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
                const auto* ip = reinterpret_cast<const rte_ipv4_hdr*>(frame + sizeof(rte_ether_hdr));
                const uint8_t ihl = static_cast<uint8_t>(ip->version_ihl & 0x0Fu);
                const std::size_t ihl_bytes = static_cast<std::size_t>(ihl) * 4u;
                if (ihl >= 5 && ip->next_proto_id == IPPROTO_UDP &&
                    sizeof(rte_ether_hdr) + ihl_bytes + sizeof(rte_udp_hdr) <= pkt_len) {
                    const auto* udp = reinterpret_cast<const rte_udp_hdr*>(
                        frame + sizeof(rte_ether_hdr) + ihl_bytes);
                    if (udp->dst_port == local_port_nbo && udp->src_port == remote_port_nbo &&
                        ip->dst_addr == local_ip_nbo) {
                        const uint16_t udp_len = rte_be_to_cpu_16(udp->dgram_len);
                        if (udp_len >= sizeof(rte_udp_hdr)) {
                            const std::size_t payload_len =
                                static_cast<std::size_t>(udp_len - sizeof(rte_udp_hdr));
                            const std::size_t payload_off =
                                sizeof(rte_ether_hdr) + ihl_bytes + sizeof(rte_udp_hdr);
                            if (accepted < budget && payload_len <= stride &&
                                payload_off + payload_len <= pkt_len) {
                                std::memcpy(out_payload + static_cast<std::size_t>(accepted) * stride,
                                            frame + payload_off, payload_len);
                                out_lens[accepted] = static_cast<uint16_t>(payload_len);
                                ++accepted;
                                rx_bytes += payload_len;
                            }
                        }
                    }
                }
            }
        }
        rte_pktmbuf_free(mbufs[i]);
    }

    it->second.rx_packets.fetch_add(accepted, std::memory_order_relaxed);
    it->second.rx_bytes.fetch_add(rx_bytes, std::memory_order_relaxed);
    if (n > accepted) {
        it->second.rx_dropped.fetch_add(static_cast<uint64_t>(n - accepted),
                                        std::memory_order_relaxed);
    }
    return static_cast<int>(accepted);
}

bool steer_l4_dst_port_to_queue(int64_t handle, uint8_t l4_proto, uint16_t queue_id,
                                uint16_t dst_port_spec, uint16_t dst_port_mask,
                                std::string& err) {
    if (l4_proto != IPPROTO_TCP && l4_proto != IPPROTO_UDP) {
        err = "dpdk_steer_bad_proto";
        return false;
    }

    std::shared_lock<std::shared_mutex> lock(g_mu);
    auto it = g_contexts.find(static_cast<long>(handle));
    if (it == g_contexts.end()) {
        err = "dpdk_invalid_handle";
        return false;
    }
    auto pt = g_ports.find(it->second.port_id);
    if (pt == g_ports.end() || !pt->second.started) {
        err = "dpdk_port_not_ready";
        return false;
    }
    if (queue_id >= pt->second.rx_queues) {
        err = "dpdk_steer_queue_unavailable";
        return false;
    }
    const uint16_t port_id = it->second.port_id;

    // Attr: ingress (dönüş trafiği).
    rte_flow_attr attr;
    std::memset(&attr, 0, sizeof(attr));
    attr.ingress = 1;

    // Pattern: ETH / IPV4 / (TCP|UDP dst port spec+mask) / END.
    rte_flow_item_eth eth_spec;
    rte_flow_item_eth eth_mask;
    std::memset(&eth_spec, 0, sizeof(eth_spec));
    std::memset(&eth_mask, 0, sizeof(eth_mask));

    rte_flow_item_ipv4 ip_spec;
    rte_flow_item_ipv4 ip_mask;
    std::memset(&ip_spec, 0, sizeof(ip_spec));
    std::memset(&ip_mask, 0, sizeof(ip_mask));

    rte_flow_item_tcp tcp_spec;
    rte_flow_item_tcp tcp_mask;
    rte_flow_item_udp udp_spec;
    rte_flow_item_udp udp_mask;
    std::memset(&tcp_spec, 0, sizeof(tcp_spec));
    std::memset(&tcp_mask, 0, sizeof(tcp_mask));
    std::memset(&udp_spec, 0, sizeof(udp_spec));
    std::memset(&udp_mask, 0, sizeof(udp_mask));

    rte_flow_item pattern[4];
    std::memset(pattern, 0, sizeof(pattern));

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[0].spec = &eth_spec;
    pattern[0].mask = &eth_mask;

    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[1].spec = &ip_spec;
    pattern[1].mask = &ip_mask;

    if (l4_proto == IPPROTO_TCP) {
        tcp_spec.hdr.dst_port = rte_cpu_to_be_16(dst_port_spec);
        tcp_mask.hdr.dst_port = rte_cpu_to_be_16(dst_port_mask);
        pattern[2].type = RTE_FLOW_ITEM_TYPE_TCP;
        pattern[2].spec = &tcp_spec;
        pattern[2].mask = &tcp_mask;
    } else {
        udp_spec.hdr.dst_port = rte_cpu_to_be_16(dst_port_spec);
        udp_mask.hdr.dst_port = rte_cpu_to_be_16(dst_port_mask);
        pattern[2].type = RTE_FLOW_ITEM_TYPE_UDP;
        pattern[2].spec = &udp_spec;
        pattern[2].mask = &udp_mask;
    }
    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;

    // Action: QUEUE(queue_id) / END.
    rte_flow_action_queue queue_action;
    std::memset(&queue_action, 0, sizeof(queue_action));
    queue_action.index = queue_id;

    rte_flow_action actions[2];
    std::memset(actions, 0, sizeof(actions));
    actions[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
    actions[0].conf = &queue_action;
    actions[1].type = RTE_FLOW_ACTION_TYPE_END;

    rte_flow_error flow_err;
    std::memset(&flow_err, 0, sizeof(flow_err));
    if (rte_flow_validate(port_id, &attr, pattern, actions, &flow_err) != 0) {
        err = std::string("dpdk_flow_validate_failed:") +
              (flow_err.message ? flow_err.message : "unknown");
        return false;
    }

    rte_flow* flow = rte_flow_create(port_id, &attr, pattern, actions, &flow_err);
    if (flow == nullptr) {
        err = std::string("dpdk_flow_create_failed:") +
              (flow_err.message ? flow_err.message : "unknown");
        return false;
    }
    // Kural port teardown'unda rte_flow_flush(rte_eth_dev_close içinde) ile
    // temizlenir; handle'ı ayrıca saklamaya gerek yok (port kapanınca hepsi gider).
    return true;
}

Snapshot snapshot(int64_t handle) {
    Snapshot snap{};
    uint16_t port_id = 0;
    PortState port;
    bool has_port = false;
    {
        std::shared_lock<std::shared_mutex> lock(g_mu);
        auto it = g_contexts.find(static_cast<long>(handle));
        if (it == g_contexts.end()) {
            return snap;
        }
        snap.valid = true;
        snap.port_id = it->second.port_id;
        snap.socket_id = it->second.socket_id;
        snap.burst_size = it->second.burst_size;
        snap.tx_packets = it->second.tx_packets.load(std::memory_order_relaxed);
        snap.tx_bytes = it->second.tx_bytes.load(std::memory_order_relaxed);
        snap.tx_errors = it->second.tx_errors.load(std::memory_order_relaxed);
        snap.tx_dropped = it->second.tx_dropped.load(std::memory_order_relaxed);
        snap.rx_packets = it->second.rx_packets.load(std::memory_order_relaxed);
        snap.rx_bytes = it->second.rx_bytes.load(std::memory_order_relaxed);
        snap.rx_dropped = it->second.rx_dropped.load(std::memory_order_relaxed);
        snap.mbuf_alloc_failures =
            it->second.mbuf_alloc_failures.load(std::memory_order_relaxed);
        port_id = it->second.port_id;
        auto pt = g_ports.find(port_id);
        if (pt != g_ports.end()) {
            port = pt->second;
            has_port = true;
        }
    }

    if (has_port && port.started) {
        rte_eth_link link;
        std::memset(&link, 0, sizeof(link));
        if (rte_eth_link_get_nowait(port_id, &link) == 0) {
            snap.link_up = link.link_status ? 1 : 0;
        }
        // HW stats (O6) — NIC donanım sayaçları.
        rte_eth_stats hw{};
        if (rte_eth_stats_get(port_id, &hw) == 0) {
            snap.hw_stats_valid = true;
            snap.hw_ipackets = hw.ipackets;
            snap.hw_opackets = hw.opackets;
            snap.hw_ibytes = hw.ibytes;
            snap.hw_obytes = hw.obytes;
            snap.hw_ierrors = hw.ierrors;
            snap.hw_oerrors = hw.oerrors;
            snap.hw_imissed = hw.imissed;
            snap.hw_rx_nombuf = hw.rx_nombuf;
        }
    }
    if (has_port && port.mempool) {
        snap.mempool_avail = rte_mempool_avail_count(port.mempool);
    }
    return snap;
}

bool resolve_direct_queue(int64_t handle, uint16_t queue_id, DirectQueueEndpoint& out) {
    out = DirectQueueEndpoint{};
    std::shared_lock<std::shared_mutex> lock(g_mu);
    auto it = g_contexts.find(static_cast<long>(handle));
    if (it == g_contexts.end()) {
        return false;
    }
    auto pt = g_ports.find(it->second.port_id);
    if (pt == g_ports.end() || !pt->second.started || !pt->second.mempool) {
        return false;
    }
    if (queue_id >= pt->second.tx_queues) {
        return false;
    }
    out.mempool = pt->second.mempool;
    out.ctx = &it->second;
    out.port_id = it->second.port_id;
    out.queue_id = queue_id;
    out.burst_size = it->second.burst_size;
    out.can_rx = it->second.rx_enable && queue_id < pt->second.rx_queues;
    out.valid = true;
    return true;
}

int rx_burst_mbufs(const DirectQueueEndpoint& ep, uint16_t budget, void** out_mbufs,
                   uint64_t* out_bytes) {
    if (!ep.valid || !ep.can_rx || !out_mbufs || budget == 0) {
        return 0;
    }
    const uint16_t clamped = std::min<uint16_t>(budget, kMaxBurst);
    rte_mbuf** mbufs = reinterpret_cast<rte_mbuf**>(out_mbufs);
    const uint16_t n = rte_eth_rx_burst(ep.port_id, ep.queue_id, mbufs, clamped);
    if (n == 0) {
        return 0;
    }
    uint64_t bytes = 0;
    for (uint16_t i = 0; i < n; ++i) {
        bytes += rte_pktmbuf_pkt_len(mbufs[i]);
    }
    if (out_bytes) {
        *out_bytes += bytes;
    }
    if (auto* ctx = static_cast<Context*>(ep.ctx)) {
        ctx->rx_packets.fetch_add(n, std::memory_order_relaxed);
        ctx->rx_bytes.fetch_add(bytes, std::memory_order_relaxed);
    }
    return static_cast<int>(n);
}

namespace {

TxResult submit_tx_mbuf_chunk(const DirectQueueEndpoint& ep, rte_mbuf** mbufs, uint16_t count) {
    TxResult r{};
    if (count == 0) {
        return r;
    }
    // PMD owns mbufs immediately on rte_eth_tx_burst success; snapshot lengths first.
    uint32_t pkt_lens[kMaxBurst];
    for (uint16_t i = 0; i < count; ++i) {
        pkt_lens[i] = rte_pktmbuf_pkt_len(mbufs[i]);
    }

    uint16_t offset = 0;
    uint16_t remaining = count;
    int retry = 0;
    while (remaining > 0 && retry < 8) {
        const uint16_t n = rte_eth_tx_burst(ep.port_id, ep.queue_id, &mbufs[offset], remaining);
        offset = static_cast<uint16_t>(offset + n);
        remaining = static_cast<uint16_t>(remaining - n);
        if (remaining > 0 && n == 0) {
            ++retry;
            rte_pause();
        }
    }

    uint64_t sent_bytes = 0;
    for (uint16_t i = 0; i < offset; ++i) {
        sent_bytes += pkt_lens[i];
    }
    for (uint16_t i = 0; i < remaining; ++i) {
        rte_pktmbuf_free(mbufs[offset + i]);
    }

    r.sent = offset;
    r.dropped = remaining;
    if (auto* ctx = static_cast<Context*>(ep.ctx)) {
        ctx->tx_packets.fetch_add(r.sent, std::memory_order_relaxed);
        ctx->tx_bytes.fetch_add(sent_bytes, std::memory_order_relaxed);
        ctx->tx_dropped.fetch_add(r.dropped, std::memory_order_relaxed);
    }
    return r;
}

}  // namespace

TxResult tx_burst_mbufs(const DirectQueueEndpoint& ep, void** mbufs, uint16_t count) {
    TxResult total{};
    if (!ep.valid || !mbufs || count == 0) {
        return total;
    }
    rte_mbuf** m = reinterpret_cast<rte_mbuf**>(mbufs);
    uint16_t pos = 0;
    while (pos < count) {
        const uint16_t chunk = std::min<uint16_t>(static_cast<uint16_t>(count - pos), kMaxBurst);
        const TxResult r = submit_tx_mbuf_chunk(ep, m + pos, chunk);
        total.sent += r.sent;
        total.dropped += r.dropped;
        pos = static_cast<uint16_t>(pos + chunk);
        if (r.sent < chunk) {
            for (uint16_t i = pos; i < count; ++i) {
                rte_pktmbuf_free(m[i]);
            }
            const uint64_t unattempted = static_cast<uint64_t>(count - pos);
            total.dropped += unattempted;
            if (auto* ctx = static_cast<Context*>(ep.ctx)) {
                ctx->tx_dropped.fetch_add(unattempted, std::memory_order_relaxed);
            }
            break;
        }
    }
    return total;
}

TxResult tx_burst_strided(const DirectQueueEndpoint& ep, const uint8_t* base,
                          uint16_t packet_size, std::size_t stride, uint32_t count) {
    TxResult total{};
    if (!ep.valid || !ep.mempool || !base || packet_size == 0 || count == 0) {
        return total;
    }
    rte_mempool* mp = static_cast<rte_mempool*>(ep.mempool);
    const std::size_t step = (stride == 0) ? static_cast<std::size_t>(packet_size) : stride;
    const uint16_t max_chunk = std::clamp<uint16_t>(ep.burst_size, kMinBurst, kMaxBurst);

    uint32_t pos = 0;
    while (pos < count) {
        const uint16_t req = static_cast<uint16_t>(
            std::min<uint32_t>(count - pos, static_cast<uint32_t>(max_chunk)));
        rte_mbuf* mbufs[kMaxBurst];
        uint16_t alloc_n = 0;
        if (rte_pktmbuf_alloc_bulk(mp, mbufs, req) == 0) {
            alloc_n = req;
        } else {
            for (uint16_t i = 0; i < req; ++i) {
                rte_mbuf* m = rte_pktmbuf_alloc(mp);
                if (!m) break;
                mbufs[alloc_n++] = m;
            }
        }
        if (alloc_n < req) {
            const uint64_t fail_n = static_cast<uint64_t>(req - alloc_n);
            total.alloc_failures += fail_n;
            total.errors += fail_n;
            total.dropped += fail_n;
            if (auto* ctx = static_cast<Context*>(ep.ctx)) {
                ctx->mbuf_alloc_failures.fetch_add(fail_n, std::memory_order_relaxed);
                ctx->tx_errors.fetch_add(fail_n, std::memory_order_relaxed);
                ctx->tx_dropped.fetch_add(fail_n, std::memory_order_relaxed);
            }
        }
        if (alloc_n == 0) {
            break;
        }

        uint16_t ready = 0;
        for (uint16_t i = 0; i < alloc_n; ++i) {
            if (packet_size > rte_pktmbuf_tailroom(mbufs[i])) {
                for (uint16_t j = i; j < alloc_n; ++j) {
                    rte_pktmbuf_free(mbufs[j]);
                }
                const uint64_t err_n = static_cast<uint64_t>(alloc_n - i);
                total.errors += err_n;
                total.dropped += err_n;
                if (auto* ctx = static_cast<Context*>(ep.ctx)) {
                    ctx->tx_errors.fetch_add(err_n, std::memory_order_relaxed);
                    ctx->tx_dropped.fetch_add(err_n, std::memory_order_relaxed);
                }
                break;
            }
            const uint8_t* src = base + static_cast<std::size_t>(pos + i) * step;
            uint8_t* dst = rte_pktmbuf_mtod(mbufs[i], uint8_t*);
            std::memcpy(dst, src, packet_size);
            mbufs[i]->data_len = packet_size;
            mbufs[i]->pkt_len = packet_size;
            ++ready;
        }
        if (ready == 0) {
            break;
        }

        const TxResult r = submit_tx_mbuf_chunk(ep, mbufs, ready);
        total.sent += r.sent;
        total.dropped += r.dropped;
        pos += req;
        if (r.sent < req) {
            break;
        }
    }
    return total;
}

void close_port(int64_t handle) {
    std::unique_lock<std::shared_mutex> lock(g_mu);
    auto it = g_contexts.find(static_cast<long>(handle));
    if (it == g_contexts.end()) {
        return;
    }
    const uint16_t port_id = it->second.port_id;
    auto pt = g_ports.find(port_id);
    if (pt != g_ports.end()) {
        if (pt->second.users > 0) {
            pt->second.users -= 1;
        }
        if (pt->second.users == 0) {
            teardown_port_unlocked(port_id, pt->second);
            g_ports.erase(pt);
        }
    }
    g_contexts.erase(it);
}

}  // namespace samurai::dpdk

#else  // !SAMURAI_WITH_DPDK — libdpdk yokken güvenli saplamalar.

namespace samurai::dpdk {

bool available() { return false; }
bool ensure_eal(const std::string&, std::string& err) {
    err = "dpdk_not_built";
    return false;
}
uint16_t port_count() { return 0; }
int64_t open_port(const OpenConfig&, std::string& err) {
    err = "dpdk_not_built";
    return -1;
}
bool capabilities(int64_t, PortCapabilities&) { return false; }
bool query_capabilities(uint16_t, PortCapabilities&, std::string& err) {
    err = "dpdk_not_built";
    return false;
}
int port_socket_id(int64_t) { return -1; }
bool register_lcore_thread() { return false; }
void unregister_lcore_thread() {}
TxResult tx_burst(int64_t, uint16_t, const uint8_t*, uint16_t, uint16_t) { return {}; }
TxResult send_batch(int64_t, uint16_t, const uint8_t*, uint16_t, uint64_t) { return {}; }
bool prepopulate_tx_pool(int64_t, const uint8_t*, uint16_t) { return false; }
bool register_extmem_region(int64_t, void*, std::size_t, uint64_t, uint32_t, std::string& err) {
    err = "dpdk_not_built";
    return false;
}
TxResult tx_burst_extbuf_zero_copy(int64_t, uint16_t, void*, uint64_t, std::size_t, std::size_t,
                                   uint16_t, uint16_t) {
    return {};
}
TxResult tx_burst_extbuf_slots(int64_t, uint16_t, void*, uint64_t, uint32_t, const uint32_t*,
                               const uint16_t*, uint16_t, ExtbufSlotFreeCallback, void*) {
    return {};
}
int rx_burst_to_bar1_slots(int64_t, uint16_t, void*, uint32_t, const uint32_t*, uint16_t,
                           uint16_t*) {
    return -1;
}
bool configure_udp_flow(int64_t, const UdpFlowConfig&, std::string& err) {
    err = "dpdk_not_built";
    return false;
}
int send_udp_payload(int64_t, uint16_t, const uint8_t*, std::size_t, std::string& err) {
    err = "dpdk_not_built";
    return 0;
}
int poll_rx(int64_t, uint16_t, uint16_t, uint8_t*, uint16_t, uint16_t*) { return 0; }
int poll_udp_payloads(int64_t, uint16_t, uint32_t, uint16_t, uint16_t, uint16_t, uint8_t*,
                      uint16_t, uint16_t*) {
    return 0;
}
bool steer_l4_dst_port_to_queue(int64_t, uint8_t, uint16_t, uint16_t, uint16_t,
                                std::string& err) {
    err = "dpdk_not_built";
    return false;
}
Snapshot snapshot(int64_t) { return {}; }
bool resolve_direct_queue(int64_t, uint16_t, DirectQueueEndpoint& out) {
    out = DirectQueueEndpoint{};
    return false;
}
int rx_burst_mbufs(const DirectQueueEndpoint&, uint16_t, void**, uint64_t*) { return 0; }
TxResult tx_burst_mbufs(const DirectQueueEndpoint&, void**, uint16_t) { return {}; }
TxResult tx_burst_strided(const DirectQueueEndpoint&, const uint8_t*, uint16_t, std::size_t,
                          uint32_t) {
    return {};
}
void close_port(int64_t) {}

}  // namespace samurai::dpdk

#endif  // SAMURAI_WITH_DPDK

extern "C" {

__attribute__((visibility("default"))) int samurai_dpdk_p2p_register_extmem(
    int64_t handle, void* vaddr, std::size_t len, uint64_t iova, uint32_t page_size) {
    std::string err;
    return samurai::dpdk::register_extmem_region(handle, vaddr, len, iova, page_size, err) ? 0 : -1;
}

__attribute__((visibility("default"))) int samurai_dpdk_p2p_tx_burst_slots(
    int64_t handle, uint16_t queue_id, void* bar1_base_vaddr, uint64_t bar1_base_iova,
    uint32_t slot_stride, const uint32_t* slot_indices, const uint16_t* pkt_lengths,
    uint16_t count, samurai::dpdk::ExtbufSlotFreeCallback free_cb, void* free_cb_opaque,
    uint64_t* out_sent, uint64_t* out_dropped) {
    if (!samurai::dpdk::available() || handle < 0) {
        return -1;
    }
    const auto res = samurai::dpdk::tx_burst_extbuf_slots(
        handle, queue_id, bar1_base_vaddr, bar1_base_iova, slot_stride, slot_indices,
        pkt_lengths, count, free_cb, free_cb_opaque);
    if (out_sent) *out_sent = res.sent;
    if (out_dropped) *out_dropped = res.dropped;
    return static_cast<int>(res.sent);
}

__attribute__((visibility("default"))) int samurai_dpdk_p2p_rx_burst_slots(
    int64_t handle, uint16_t queue_id, void* bar1_base_vaddr, uint32_t slot_stride,
    const uint32_t* slot_indices, uint16_t max_slots, uint16_t* out_lengths) {
    if (!samurai::dpdk::available() || handle < 0) {
        return -1;
    }
    return samurai::dpdk::rx_burst_to_bar1_slots(
        handle, queue_id, bar1_base_vaddr, slot_stride, slot_indices, max_slots, out_lengths);
}

}  // extern "C"
