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

#include <cstddef>
#include <cstdint>
#include <string>

#include "dpdk/dpdk_core.hpp"
#include "stateful_fastpath.hpp"

namespace samurai::daemon {

// DPDK taşıma shim'i: paylaşılan StatefulFastpathDriver'ın byte-oriented Send/Recv
// arayüzünü dpdk_core üzerine oturtur. Portu RX etkin (num_rx_queues=1) açar; RAII
// ile teardown eder. tcpdp strided peek'te psize==stride olduğundan send_batch
// birebir uyar; güvenlik için stride!=psize durumunda per-paket tx_burst yapılır.
struct DpdkShim : FastpathTxRxShim {
  std::int64_t handle{-1};
  std::uint16_t queue{0};
  std::string open_err;

  DpdkShim(std::uint16_t port_id, std::uint16_t queue_id, const std::string& eal_args) {
    samurai::dpdk::OpenConfig cfg{};
    cfg.port_id = port_id;
    cfg.num_tx_queues = 1;
    cfg.num_rx_queues = 1;  // stateful: SYN-ACK'leri almak için RX şart
    cfg.enable_rss = false;
    cfg.burst_size = 64;
    cfg.mempool_size = 8192u;
    cfg.eal_args = eal_args;
    handle = samurai::dpdk::open_port(cfg, open_err);
    queue = queue_id;
  }
  ~DpdkShim() override {
    if (handle >= 0) samurai::dpdk::close_port(handle);
  }
  bool ok() const { return handle >= 0; }

  int Send(const std::uint8_t* base, std::size_t psize, std::size_t stride,
           std::uint32_t count, std::string& err) override {
    (void)err;
    if (psize == 0) return 0;
    if (stride == psize) {
      const auto r = samurai::dpdk::send_batch(
          handle, queue, base, static_cast<std::uint16_t>(psize), count);
      return static_cast<int>(r.sent);
    }
    std::uint32_t sent = 0;
    for (std::uint32_t i = 0; i < count; ++i) {
      const auto r = samurai::dpdk::tx_burst(
          handle, queue, base + static_cast<std::size_t>(i) * stride,
          static_cast<std::uint16_t>(psize), 1);
      if (r.sent == 0) break;
      ++sent;
    }
    return static_cast<int>(sent);
  }
  int Recv(std::uint8_t* out, std::uint16_t stride, std::uint16_t* lens,
           std::uint16_t max, std::string& err) override {
    (void)err;
    return samurai::dpdk::poll_rx(handle, queue, max, out, stride, lens);
  }
  bool RxAvailable() const override { return true; }
};

}  // namespace samurai::daemon

#endif  // SAMURAI_WITH_DPDK
