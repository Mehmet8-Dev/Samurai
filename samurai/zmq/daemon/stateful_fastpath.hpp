#pragma once
//
// stateful_fastpath — paylaşılan userspace stateful TCP fast-path sürücüsü.
//
// TRex-benzeri model: worker NIC portunu sahiplenir ve TcpDataplaneCore'u (l4/
// tcp_dataplane_ffi.h) kendi sürecinde koşar; syscall hot-path'e girmez. DPDK ve
// AF_XDP worker'ları TEK bu sürücüyü paylaşır; yalnız TX/RX taşıma shim'i farklıdır.
//
// Bu başlık kasıtlı olarak <rte_*.h> veya xdp header'ı İÇERMEZ — sadece tcpdp FFI,
// wire ve pacing tiplerini kullanır. Böylece SAMURAI_WITH_DPDK olsun olmasın her
// worker TU'sunda sorunsuz derlenir. Somut shim'i (DpdkShim / XdpShim) her worker
// kendi TU'sunda sağlar.
//
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "pacing_engine.h"
#include "wire_protocol.h"

namespace samurai::tcpdp {
class TcpDataplaneCore;
}

namespace samurai::daemon {

// Byte-oriented, simetrik TX/RX taşıma arayüzü. DPDK ve AF_XDP bu arayüzü
// implemente eder; sürücü loop'u her ikisinde aynıdır.
struct FastpathTxRxShim {
  virtual ~FastpathTxRxShim() = default;

  // `count` paketi gönderir; her paket `packet_size` bayt, `base` içinde `stride`
  // aralığıyla yerleşik (tcpdp PeekTxPacketsStrided ile aynı düzen). Kabul edilen
  // paket sayısını (>=0) veya ölümcül hatada <0 döner (err doldurulur).
  virtual int Send(const std::uint8_t* base, std::size_t packet_size,
                   std::size_t stride, std::uint32_t count, std::string& err) = 0;

  // En fazla `max` frame'i `out_frames` (max*stride bayt düz tampon) içine alır,
  // her frame uzunluğunu `out_lens[i]`e yazar. Alınan frame sayısını (>=0, 0 ok)
  // veya ölümcül hatada <0 döner.
  virtual int Recv(std::uint8_t* out_frames, std::uint16_t stride,
                   std::uint16_t* out_lens, std::uint16_t max, std::string& err) = 0;

  // Taşıma RX ingest destekliyor mu? false ise handshake tamamlanamaz (half-duplex)
  // — sürücü bunu tespit edip raporlar, asmaz.
  virtual bool RxAvailable() const = 0;
};

// Sürücünün job envelope'undan türettiği çalışma parametreleri.
struct FastpathParams {
  std::uint32_t dst_ip = 0;          // host byte order
  std::uint16_t dst_port = 0;
  std::uint32_t src_ip = 0;          // 0 => otomatik çözümle (route/env)
  std::uint32_t target_flows = 1;    // açılacak connect sayısı
  std::string payload;               // her flow'a connect sonrası gönderilecek (opsiyonel)
  // tcpdp_configure knob'ları (env fallback'li).
  std::string mode = "required";
  std::string backend = "custom_tcp";  // dpdk_worker "dpdk", afxdp_worker "af_xdp"
  std::uint32_t initial_rto_ms = 200;
  std::uint32_t max_retransmits = 5;
  std::uint32_t connect_timeout_ms = 3000;
  std::uint32_t idle_timeout_ms = 10000;
  // Yürütme sınırları.
  std::uint64_t max_duration_ms = 15000;  // sabit üst sınır
  std::uint64_t drain_ms = 500;           // son flow'lar boşalsın diye ek pump
  std::uint16_t rx_budget = 256;          // RX burst başına frame
};

// Sürücünün çıktısı — snapshot'tan türetilir, metrik ve JOB_DONE için.
struct FastpathResult {
  std::uint64_t tx_packets = 0;
  std::uint64_t tx_bytes = 0;
  std::uint64_t tx_errors = 0;
  std::uint64_t rx_frames = 0;
  std::uint64_t connect_attempts = 0;
  std::uint64_t connect_established = 0;
  std::uint64_t retransmit_count = 0;
  std::uint64_t retransmit_exhausted = 0;
  std::uint64_t connect_timeout = 0;
  bool rx_available = false;
};

// Worker'ın sağladığı emit kancaları (zmq bağımlılığını sürücüden uzak tutar).
struct FastpathHooks {
  std::function<void()> emit_heartbeat;                                  // 1 sn
  std::function<void(const samurai::wire::MetricSnapshotV2&)> emit_metric;  // 2 sn
};

class StatefulFastpathDriver {
 public:
  explicit StatefulFastpathDriver(FastpathTxRxShim& shim) : shim_(shim) {}

  // tcpdp'yi yapılandırır (process-global singleton). false => tcpdp_configure hata.
  bool Configure(const FastpathParams& p, std::string& err);

  // target_flows kadar connect (+opsiyonel payload send) enqueue eder.
  // Kaç connect enqueue edildiğini döner.
  std::uint32_t SeedL4(const FastpathParams& p);

  // Pump loop: RX->ingest, poll, peek->Send->consume.
  //
  // l7_runner boş ise pure-L4 modudur: SeedL4 ile açılan connect'ler handshake'i
  // tamamlayana / süre-flow bütçesi dolana kadar sürülür.
  //
  // l7_runner doluysa (L7 modu) sürücü thread'i TEK wire sahibi olarak pump eder;
  // l7_runner ikinci bir thread'te koşar (run_profile_json => connect/send enqueue +
  // HTTP durum makinesi). Sürücü, l7_runner bitene kadar wire'ı sürer, sonra döner.
  // l7_runner, stop bayrağına saygı göstermeli ve işi bitince dönmelidir.
  FastpathResult Run(const FastpathParams& p,
                     const std::function<void(const std::atomic<bool>&)>& l7_runner,
                     const std::atomic<bool>& stop,
                     const FastpathHooks& hooks);

 private:
  FastpathTxRxShim& shim_;
};

// Shared-nothing çok-çekirdek stateful fast-path sürücüsü (TRex modeli). N pinli
// worker thread; her worker KENDİ TcpDataplaneCore instance'ı + KENDİ wire shim'ini
// (factory ile) sahiplenir. Flow'lar worker'lara paylaştırılır; worker'lar arası
// paylaşılan durum YOKTUR (cross-core lock yok, tek TX ring yok). Böylece tek-singleton
// StatefulFastpathDriver'ın "tek wire poller" pps tavanı kaldırılır ve çekirdek başına
// TCP durum motoru lineer ölçeklenir.
struct ShardedFastpathConfig {
  std::uint32_t workers = 0;  // 0 => std::thread::hardware_concurrency()
  int cpu_base = -1;          // >=0 ise worker w, (cpu_base + w) çekirdeğine pinlenir
};

class ShardedFastpathDriver {
 public:
  // factory(worker_idx): her worker için ayrı taşıma shim'i (kendi RX kuyruğu) üretir.
  using ShimFactory = std::function<std::unique_ptr<FastpathTxRxShim>(std::uint32_t worker_idx)>;

  ShardedFastpathDriver(ShimFactory factory, ShardedFastpathConfig cfg)
      : factory_(std::move(factory)), cfg_(cfg) {}

  // target_flows'u worker'lara böler; her worker kendi core'unda seed + pump eder.
  // stop tetiklenince ya da tüm flow'lar/deadline bitince döner. Birleşik sonucu döner;
  // per_worker != nullptr ise her worker'ın kendi FastpathResult'ı da yazılır.
  FastpathResult Run(const FastpathParams& p, const std::atomic<bool>& stop,
                     std::vector<FastpathResult>* per_worker = nullptr);

  // L7 shared-nothing modu: her worker kendi core'u ve shim'i üzerinde izole çalışır.
  using ShardL7Runner = std::function<void(std::uint32_t worker_idx,
                                           samurai::tcpdp::TcpDataplaneCore& core,
                                           FastpathTxRxShim& shim,
                                           const std::atomic<bool>& stop)>;
  FastpathResult RunL7(const FastpathParams& p,
                       const ShardL7Runner& runner,
                       const std::atomic<bool>& stop,
                       std::vector<FastpathResult>* per_worker = nullptr);

  std::uint32_t worker_count() const { return resolved_workers_; }

 private:
  ShimFactory factory_;
  ShardedFastpathConfig cfg_;
  std::uint32_t resolved_workers_ = 0;
};

// V1/V2 envelope'un stateful fast-path'i seçip seçmediği (protocol/attack_vector).
bool IsStatefulFastpathJob(const samurai::wire::JobEnvelopeV1& base);

// Envelope'tan (V1 taban) fast-path parametrelerini türetir. backend çağıran
// worker tarafından set edilmeli (dpdk_worker "dpdk", afxdp_worker "af_xdp").
FastpathParams FastpathParamsFromEnvelope(const samurai::wire::JobEnvelopeV1& base);

}  // namespace samurai::daemon
