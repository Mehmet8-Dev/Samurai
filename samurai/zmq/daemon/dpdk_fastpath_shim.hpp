#pragma once
//
// dpdk_fastpath_shim — DPDK TX/RX taşıma shim'i (StatefulFastpathDriver için).
//
// dpdk_worker ve scenario_worker bu shim'i PAYLAŞIR: ikisi de aynı userspace
// stateful TCP fast-path sürücüsünü DPDK wire'ı üzerinde koşar (dpdk_worker envelope
// profilini, scenario_worker senaryodan derlenen zengin L7 profilini sürer).
//
// Yalnız SAMURAI_WITH_DPDK altında tanımlıdır; libdpdk yokken include eden TU'ya
// hiçbir sembol getirmez (guard boş). Bir başlıkta tanımlı struct + inline üye
// fonksiyonlardır; birden çok TU'da include edilmesi ODR-güvenlidir.
//
#ifdef SAMURAI_WITH_DPDK

#include <netinet/in.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>

#include "dpdk/dpdk_core.hpp"
#include "stateful_fastpath.hpp"

namespace samurai::daemon {

// Multi-queue DPDK shim yapılandırması. Her worker kendi queue_id'si üzerinde
// kilitsiz DirectQueueEndpoint + rte_mbuf zero-copy RX burst ve strided bulk TX
// ile çalışır. mempool_size == 0 iken kuyruk sayısına göre otomatik ölçeklenir
// (1024 RX + 1024 TX desc + per-lcore cache açlık riskini önler).
struct DpdkShimConfig {
  std::uint16_t port_id = 0;
  std::uint16_t queue_id = 0;
  std::uint16_t num_tx_queues = 1;
  std::uint16_t num_rx_queues = 1;
  bool enable_rss = false;
  std::uint16_t burst_size = 64;
  std::uint32_t mempool_size = 0;
  std::string eal_args;
};

// DPDK taşıma shim'i: doğrudan DirectQueueEndpoint (g_mu kilitsiz) üzerinde
// zero-copy rte_mbuf RX burst (IngestDpdkRxBurst) ve toplu strided TX
// (tx_burst_strided) yürütür; EAL lcore per-thread mempool cache'ini kaydeder.
struct DpdkShim : FastpathTxRxShim {
  std::int64_t handle{-1};
  std::uint16_t queue{0};
  samurai::dpdk::DirectQueueEndpoint endpoint{};
  bool lcore_registered{false};
  std::string open_err;

  explicit DpdkShim(const DpdkShimConfig& s) {
    lcore_registered = samurai::dpdk::register_lcore_thread();
    const std::uint16_t min_q = static_cast<std::uint16_t>(s.queue_id + 1u);
    const std::uint16_t tx_q = std::max<std::uint16_t>(s.num_tx_queues, min_q);
    const std::uint16_t rx_q = std::max<std::uint16_t>(s.num_rx_queues, min_q);
    const std::uint32_t max_q = static_cast<std::uint32_t>(std::max(tx_q, rx_q));
    const std::uint32_t auto_mp = std::max<std::uint32_t>(8192u, max_q * 4096u);

    samurai::dpdk::OpenConfig cfg{};
    cfg.port_id = s.port_id;
    cfg.num_tx_queues = tx_q;
    cfg.num_rx_queues = rx_q;  // stateful: SYN-ACK'leri almak için RX şart
    cfg.enable_rss = s.enable_rss || (rx_q > 1);
    cfg.burst_size = s.burst_size > 0 ? s.burst_size : 64u;
    cfg.mempool_size = s.mempool_size > 0 ? s.mempool_size : auto_mp;
    cfg.eal_args = s.eal_args;

    handle = samurai::dpdk::open_port(cfg, open_err);
    queue = s.queue_id;
    if (handle >= 0) {
      if (!samurai::dpdk::resolve_direct_queue(handle, queue, endpoint)) {
        open_err = "dpdk_direct_queue_resolve_failed";
        samurai::dpdk::close_port(handle);
        handle = -1;
      }
    }
    if (handle < 0 && lcore_registered) {
      samurai::dpdk::unregister_lcore_thread();
      lcore_registered = false;
    }
  }

  // Tek-kuyruk uyumlu yapıcı (queue_id >= 0 için en az queue_id + 1 kuyruk açar).
  DpdkShim(std::uint16_t port_id, std::uint16_t queue_id, const std::string& eal_args)
      : DpdkShim(DpdkShimConfig{
            port_id,
            queue_id,
            static_cast<std::uint16_t>(queue_id + 1u),
            static_cast<std::uint16_t>(queue_id + 1u),
            /*enable_rss=*/false,
            /*burst_size=*/64u,
            /*mempool_size=*/0u,
            eal_args}) {}

  DpdkShim(const DpdkShim&) = delete;
  DpdkShim& operator=(const DpdkShim&) = delete;

  ~DpdkShim() override {
    endpoint.valid = false;
    endpoint.ctx = nullptr;
    if (handle >= 0) samurai::dpdk::close_port(handle);
    if (lcore_registered) samurai::dpdk::unregister_lcore_thread();
  }

  bool ok() const { return handle >= 0 && endpoint.valid; }

  int Send(const std::uint8_t* base, std::size_t psize, std::size_t stride,
           std::uint32_t count, std::string& err) override {
    if (psize == 0 || count == 0) return 0;
    if (psize > 0xFFFFu) {
      err = "dpdk_packet_too_large";
      return -1;
    }
    if (!ok()) {
      err = open_err.empty() ? "dpdk_port_not_open" : open_err;
      return -1;
    }
    const auto r = samurai::dpdk::tx_burst_strided(
        endpoint, base, static_cast<std::uint16_t>(psize), stride, count);
    if (r.sent == 0 && r.errors > 0 && r.alloc_failures == 0) {
      err = "dpdk_tx_packet_too_large";
      return -1;
    }
    return static_cast<int>(r.sent);
  }

  int Recv(std::uint8_t* out, std::uint16_t stride, std::uint16_t* lens,
           std::uint16_t max, std::string& err) override {
    (void)err;
    return samurai::dpdk::poll_rx(handle, queue, max, out, stride, lens);
  }

  bool SupportsDirectMbufBurst() const override {
    return endpoint.valid && endpoint.can_rx;
  }

  int RecvRawMbufs(void** out_mbufs, std::uint16_t max_burst,
                   std::uint64_t& out_bytes, std::string& err) override {
    (void)err;
    return samurai::dpdk::rx_burst_mbufs(endpoint, max_burst, out_mbufs, &out_bytes);
  }

  bool RxAvailable() const override { return endpoint.valid && endpoint.can_rx; }
};

// Çok-kuyruklu stateful DPDK çalıştırmada yönetici port handle'ını ve kurulu
// rte_flow yönlendirme kurallarını iş bitene kadar canlı tutar.
struct DpdkMultiQueueGuard {
  std::int64_t manager_handle{-1};
  std::uint16_t active_queues{1};
  std::string note;

  DpdkMultiQueueGuard() = default;
  DpdkMultiQueueGuard(const DpdkMultiQueueGuard&) = delete;
  DpdkMultiQueueGuard& operator=(const DpdkMultiQueueGuard&) = delete;
  DpdkMultiQueueGuard(DpdkMultiQueueGuard&& o) noexcept
      : manager_handle(o.manager_handle),
        active_queues(o.active_queues),
        note(std::move(o.note)) {
    o.manager_handle = -1;
  }
  DpdkMultiQueueGuard& operator=(DpdkMultiQueueGuard&& o) noexcept {
    if (this != &o) {
      reset();
      manager_handle = o.manager_handle;
      active_queues = o.active_queues;
      note = std::move(o.note);
      o.manager_handle = -1;
    }
    return *this;
  }
  void reset() {
    if (manager_handle >= 0) {
      samurai::dpdk::close_port(manager_handle);
      manager_handle = -1;
    }
  }
  ~DpdkMultiQueueGuard() { reset(); }
};

// `requested_queues > 1` ise portu N RX+TX kuyruğuyla açar ve her shard kuyruğu
// için `dst_port & (pow2(N)-1) == q` rte_flow kuralı kurar. PMD yetenekleri veya
// rte_flow desteklemiyorsa sessiz veri kaybı yerine güvenli biçimde 1 kuyruğa düşer.
// Dönüş değeri false ise port açılamamıştır (`err` doldurulur).
inline bool PrepareDpdkMultiQueueStateful(std::uint16_t port_id,
                                          std::uint16_t requested_queues,
                                          std::uint32_t max_flows,
                                          const std::string& eal_args,
                                          DpdkMultiQueueGuard& out,
                                          std::string& err) {
  out.reset();
  out.active_queues = 1;
  out.note.clear();

  std::uint32_t nq = std::max<std::uint32_t>(1u, requested_queues);
  if (max_flows > 0 && nq > max_flows) {
    nq = max_flows;
  }

  samurai::dpdk::PortCapabilities caps{};
  std::string cap_err;
  if (samurai::dpdk::query_capabilities(port_id, caps, cap_err)) {
    if (caps.max_tx_queues > 0) {
      nq = std::min<std::uint32_t>(nq, caps.max_tx_queues);
    }
    if (caps.max_rx_queues > 0) {
      nq = std::min<std::uint32_t>(nq, caps.max_rx_queues);
    }
  }
  nq = std::clamp<std::uint32_t>(nq, 1u, 64u);
  if (nq <= 1u) {
    return true;
  }

  samurai::dpdk::OpenConfig mcfg{};
  mcfg.port_id = port_id;
  mcfg.num_tx_queues = static_cast<std::uint16_t>(nq);
  mcfg.num_rx_queues = static_cast<std::uint16_t>(nq);
  mcfg.enable_rss = true;
  mcfg.burst_size = 64u;
  mcfg.mempool_size = std::max<std::uint32_t>(8192u, nq * 4096u);
  mcfg.eal_args = eal_args;

  const std::int64_t mgr = samurai::dpdk::open_port(mcfg, err);
  if (mgr < 0) {
    return false;
  }

  std::uint16_t stride = 1;
  while (stride < nq) stride <<= 1;
  const std::uint16_t mask = static_cast<std::uint16_t>(stride - 1u);

  for (std::uint16_t q = 0; q < static_cast<std::uint16_t>(nq); ++q) {
    std::string ferr;
    if (!samurai::dpdk::steer_l4_dst_port_to_queue(mgr, IPPROTO_TCP, q, q, mask, ferr)) {
      samurai::dpdk::close_port(mgr);
      out.active_queues = 1;
      out.note = "rte_flow_fallback_single_queue:" + ferr;
      return true;
    }
  }

  out.manager_handle = mgr;
  out.active_queues = static_cast<std::uint16_t>(nq);
  return true;
}

}  // namespace samurai::daemon

#endif  // SAMURAI_WITH_DPDK
