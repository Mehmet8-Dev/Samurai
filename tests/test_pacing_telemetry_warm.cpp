#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#define SAMURAI_CHECK(cond)                                                            \
  do {                                                                                 \
    if (!(cond)) {                                                                     \
      std::cerr << "CHECK FAILED at " << __FILE__ << ":" << __LINE__ << ": " #cond     \
                << "\n";                                                               \
      std::exit(1);                                                                    \
    }                                                                                  \
  } while (0)

#include "job_builder.hpp"
#include "pacing_engine.h"
#include "run_summary.hpp"
#include "supervisor.hpp"
#include "wire_protocol.h"
#include "worker_registry.hpp"
#include "zmq_worker_base.hpp"

#ifndef SAMURAI_WORKER_DIR
#define SAMURAI_WORKER_DIR "."
#endif

namespace {

std::string WorkerDir() {
  if (const char* env = std::getenv("SAMURAI_TEST_WORKER_DIR")) {
    if (*env) return std::string(env);
  }
  return std::string(SAMURAI_WORKER_DIR);
}

struct UdpCollector {
  int fd = -1;
  uint16_t port = 0;

  ~UdpCollector() {
    if (fd >= 0) ::close(fd);
  }

  bool BindLoopback(int timeout_ms = 2000) {
    fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (::bind(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
      ::close(fd);
      fd = -1;
      return false;
    }
    socklen_t len = sizeof(addr);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
      ::close(fd);
      fd = -1;
      return false;
    }
    port = ntohs(addr.sin_port);
    return port > 0;
  }

  std::vector<uint8_t> RecvPacket() const {
    std::vector<uint8_t> buf(4096);
    const ssize_t n = ::recvfrom(fd, buf.data(), buf.size(), 0, nullptr, nullptr);
    if (n <= 0) return {};
    buf.resize(static_cast<std::size_t>(n));
    return buf;
  }
};

void TestConsolidatedPacing() {
  std::cout << "[TEST] Consolidated pacing_engine_static...\n";
  samurai_pacing_calibrate();
  const uint64_t t0 = samurai_pacing_time_ns();
  SAMURAI_CHECK(t0 > 0);
  (void)samurai_pacing_tsc_hz();

  samurai_pacing_config_t cfg{};
  cfg.mode = SAMURAI_PACING_RPS;
  cfg.target_rps = 50000.0;
  cfg.burst_size = 1;
  cfg.jitter_model = SAMURAI_JITTER_UNIFORM;
  cfg.jitter_pct = 0.05;
  cfg.disable_busywait = 1;

  samurai_pacing_state_t st{};
  samurai_pacing_init(&st, &cfg);
  for (int i = 0; i < 20; ++i) {
    samurai_pacing_wait_next(&st, &cfg);
  }
  SAMURAI_CHECK(st.sent == 20);
  SAMURAI_CHECK(samurai_pacing_get_mean_ipg_ns(&st) > 0.0);
  SAMURAI_CHECK(samurai_pacing_get_jitter_p99_ns(&st) >= 0.0);

  samurai_pacing_config_t cfg2 = cfg;
  cfg2.target_rps = 100000.0;
  samurai_pacing_reconfigure(&st, &cfg2);
  for (int i = 0; i < 10; ++i) {
    samurai_pacing_wait_next(&st, &cfg2);
  }
  SAMURAI_CHECK(st.sent == 30);

  const uint64_t t1 = samurai_pacing_time_ns();
  SAMURAI_CHECK(t1 >= t0);
  SAMURAI_CHECK(samurai_pacing_tb_try_consume(&st, &cfg2, t1) == 1);
  std::cout << "  -> TestConsolidatedPacing PASSED\n";
}

void TestWarmWorkerPoolReconfigureAndCancel() {
  std::cout << "[TEST] WarmWorkerPool reuse + RECONFIGURE_JOB + cancel...\n";
  ::setenv("SAMURAI_AFPACKET_TX", "0", 1);
  ::setenv("SAMURAI_WARM_WORKERS", "1", 1);

  const auto cpu = samurai::orchestrator::LookupWorker("cpu");
  SAMURAI_CHECK(cpu.has_value());

  samurai::orchestrator::WarmWorkerPool pool;
  SAMURAI_CHECK(pool.Enabled());

  samurai::orchestrator::SupervisorConfig cfg;
  cfg.worker = *cpu;
  cfg.worker_dir = WorkerDir();
  cfg.recv_timeout_ms = 500;
  cfg.max_idle_recvs = 20;

  // Job 1 (cold spawn into pool)
  samurai::orchestrator::JobOptions job1;
  job1.target_ip = "127.0.0.1";
  job1.target_port = 19991;
  job1.packet_count = 400;
  job1.packet_size = 64;
  job1.protocol = "udp";

  samurai::orchestrator::RunStats stats1;
  const int rc1 = samurai::orchestrator::RunJob(cfg, job1, stats1, &pool, nullptr, "warm-shard-1");
  SAMURAI_CHECK(rc1 == 0);
  SAMURAI_CHECK(stats1.sent == 400);
  SAMURAI_CHECK(pool.SpawnCount() == 1);
  SAMURAI_CHECK(pool.ReuseCount() == 0);
  SAMURAI_CHECK(pool.WarmSlotCount() == 1);
  const long pid1 = pool.LastWorkerPid(samurai::wire::WorkerKind::CPU);
  SAMURAI_CHECK(pid1 > 0);

  // Job 2 (reuses identical worker PID)
  samurai::orchestrator::JobOptions job2 = job1;
  job2.packet_count = 650;
  samurai::orchestrator::RunStats stats2;
  const int rc2 = samurai::orchestrator::RunJob(cfg, job2, stats2, &pool, nullptr, "warm-shard-2");
  SAMURAI_CHECK(rc2 == 0);
  SAMURAI_CHECK(stats2.sent == 650);
  SAMURAI_CHECK(pool.SpawnCount() == 1);
  SAMURAI_CHECK(pool.ReuseCount() == 1);
  SAMURAI_CHECK(pool.LastWorkerPid(samurai::wire::WorkerKind::CPU) == pid1);

  // Job 3 (paced long job interrupted mid-flight by RECONFIGURE_JOB + cancel)
  samurai::orchestrator::JobOptions job3 = job1;
  job3.packet_count = 200000;
  job3.pacing_mode = SAMURAI_PACING_RPS;
  job3.target_rps = 2000.0;

  std::atomic<bool> cancel{false};
  samurai::orchestrator::RunStats stats3;
  int rc3 = -1;
  const auto t_start = std::chrono::steady_clock::now();
  std::thread t([&]() {
    rc3 = samurai::orchestrator::RunJob(cfg, job3, stats3, &pool, &cancel, "warm-shard-cancel");
  });

  bool reconf_sent = false;
  for (int i = 0; i < 40; ++i) {
    if (pool.ActiveSlotCount() == 1) {
      samurai::wire::ReconfigureWindowV1 win{};
      win.flags = samurai::wire::ReconfigureFlag::kRps | samurai::wire::ReconfigureFlag::kPacingMode;
      win.pacing_mode = SAMURAI_PACING_RPS;
      win.target_rps = 5000.0;
      reconf_sent = pool.ReconfigureActiveShard("warm-shard-cancel", win);
      if (reconf_sent) break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(25));
  }
  SAMURAI_CHECK(reconf_sent);
  std::this_thread::sleep_for(std::chrono::milliseconds(80));
  cancel.store(true);
  t.join();
  const auto elapsed_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t_start)
          .count();
  SAMURAI_CHECK(elapsed_ms < 5000);
  SAMURAI_CHECK(stats3.sent < job3.packet_count);
  (void)rc3;

  pool.ShutdownAll();
  SAMURAI_CHECK(pool.WarmSlotCount() == 0);
  SAMURAI_CHECK(pool.ActiveSlotCount() == 0);
  std::cout << "  -> TestWarmWorkerPoolReconfigureAndCancel PASSED (pid=" << pid1
            << ", cancel_ms=" << elapsed_ms << ")\n";
}

void TestLiveIpfixAndNetflowV9UdpExport() {
  std::cout << "[TEST] Live UDP IPFIX v10 + NetFlow v9 export from worker...\n";
  ::setenv("SAMURAI_AFPACKET_TX", "0", 1);
  ::setenv("SAMURAI_WARM_WORKERS", "1", 1);

  UdpCollector collector;
  SAMURAI_CHECK(collector.BindLoopback(2500));

  const auto cpu = samurai::orchestrator::LookupWorker("cpu");
  SAMURAI_CHECK(cpu.has_value());

  samurai::orchestrator::WarmWorkerPool pool;
  samurai::orchestrator::SupervisorConfig cfg;
  cfg.worker = *cpu;
  cfg.worker_dir = WorkerDir();
  cfg.recv_timeout_ms = 500;
  cfg.max_idle_recvs = 20;

  // First run: IPFIX v10
  samurai::orchestrator::JobOptions job_ipfix;
  job_ipfix.target_ip = "127.0.0.1";
  job_ipfix.target_port = 18080;
  job_ipfix.packet_count = 300;
  job_ipfix.packet_size = 128;
  job_ipfix.protocol = "udp";
  job_ipfix.ipfix_enabled = true;
  job_ipfix.ipfix_collector = "127.0.0.1";
  job_ipfix.ipfix_port = collector.port;
  job_ipfix.ipfix_sample_rate = 1;
  job_ipfix.ipfix_netflow_v9 = false;
  job_ipfix.ipfix_domain_id = 42;
  job_ipfix.ipfix_export_interval_ms = 50;

  samurai::orchestrator::RunStats stats_ipfix;
  const int rc1 = samurai::orchestrator::RunJob(cfg, job_ipfix, stats_ipfix, &pool, nullptr, "ipfix-1");
  SAMURAI_CHECK(rc1 == 0);
  SAMURAI_CHECK(stats_ipfix.sent == 300);
  SAMURAI_CHECK(stats_ipfix.ipfix_exported_packets >= 1);
  SAMURAI_CHECK(stats_ipfix.ipfix_exported_records >= 1);

  const std::vector<uint8_t> pkt_v10 = collector.RecvPacket();
  SAMURAI_CHECK(pkt_v10.size() >= 16);
  const uint16_t ver_v10 = static_cast<uint16_t>((pkt_v10[0] << 8) | pkt_v10[1]);
  SAMURAI_CHECK(ver_v10 == 10);
  uint32_t domain_be = 0;
  std::memcpy(&domain_be, pkt_v10.data() + 12, 4);
  SAMURAI_CHECK(ntohl(domain_be) == 42u);

  // Second run on SAME warm worker: reconfigure to NetFlow v9 + domain_id=77
  samurai::orchestrator::JobOptions job_nf9 = job_ipfix;
  job_nf9.packet_count = 200;
  job_nf9.ipfix_netflow_v9 = true;
  job_nf9.ipfix_domain_id = 77;

  // Drain any extra buffered IPFIX packets before starting NetFlow v9 job
  timeval short_tv{};
  short_tv.tv_usec = 10000;
  ::setsockopt(collector.fd, SOL_SOCKET, SO_RCVTIMEO, &short_tv, sizeof(short_tv));
  while (!collector.RecvPacket().empty()) {}
  timeval normal_tv{};
  normal_tv.tv_sec = 2;
  ::setsockopt(collector.fd, SOL_SOCKET, SO_RCVTIMEO, &normal_tv, sizeof(normal_tv));

  samurai::orchestrator::RunStats stats_nf9;
  const int rc2 = samurai::orchestrator::RunJob(cfg, job_nf9, stats_nf9, &pool, nullptr, "nf9-1");
  SAMURAI_CHECK(rc2 == 0);
  SAMURAI_CHECK(pool.ReuseCount() == 1);
  SAMURAI_CHECK(stats_nf9.ipfix_exported_packets >= 1);

  const std::vector<uint8_t> pkt_v9 = collector.RecvPacket();
  SAMURAI_CHECK(pkt_v9.size() >= 20);
  const uint16_t ver_v9 = static_cast<uint16_t>((pkt_v9[0] << 8) | pkt_v9[1]);
  SAMURAI_CHECK(ver_v9 == 9);

  pool.ShutdownAll();
  std::cout << "  -> TestLiveIpfixAndNetflowV9UdpExport PASSED (ipfix_pkts="
            << stats_ipfix.ipfix_exported_packets << ", nf9_pkts="
            << stats_nf9.ipfix_exported_packets << ")\n";
}

void TestDistributedTelcoEnvelopeAndWarmSwitch() {
  std::cout << "[TEST] Distributed TelcoJobEnvelopeV1 + warm switch + IPFIX...\n";
  ::setenv("SAMURAI_WARM_WORKERS", "1", 1);

  UdpCollector collector;
  SAMURAI_CHECK(collector.BindLoopback(2500));

  const auto telco = samurai::orchestrator::LookupWorker("telco");
  SAMURAI_CHECK(telco.has_value());

  samurai::orchestrator::WarmWorkerPool pool;
  samurai::orchestrator::SupervisorConfig cfg;
  cfg.worker = *telco;
  cfg.worker_dir = WorkerDir();
  cfg.recv_timeout_ms = 500;
  cfg.max_idle_recvs = 30;

  // Job A: SCTP signaling
  samurai::orchestrator::JobOptions job_sctp;
  job_sctp.target_ip = "127.0.0.1";
  job_sctp.target_port = 36412;
  job_sctp.protocol = "sctp";
  job_sctp.packet_count = 0;
  job_sctp.telco_subscribers = 32;
  job_sctp.telco_rate_cps = 1000;
  job_sctp.sctp_rate = 1000;
  job_sctp.telco_duration_ms = 250;
  job_sctp.telco_base_ip = "10.10.0.1";
  job_sctp.telco_gateway_ip = "10.10.0.254";
  job_sctp.telco_db_port = 5099;

  samurai::orchestrator::RunStats stats_sctp;
  const int rc1 =
      samurai::orchestrator::RunJob(cfg, job_sctp, stats_sctp, &pool, nullptr, "telco-sctp-0");
  SAMURAI_CHECK(rc1 == 0);
  SAMURAI_CHECK(stats_sctp.sent > 0);
  SAMURAI_CHECK(stats_sctp.bytes_sent > 0);
  SAMURAI_CHECK(stats_sctp.telco_active_sessions == 32);
  SAMURAI_CHECK(stats_sctp.telco_avg_setup_latency_us >= 1);
  SAMURAI_CHECK(stats_sctp.telco_p99_setup_latency_us >= stats_sctp.telco_avg_setup_latency_us);
  SAMURAI_CHECK(pool.SpawnCount() == 1);
  const long telco_pid = pool.LastWorkerPid(samurai::wire::WorkerKind::TELCO);
  SAMURAI_CHECK(telco_pid > 0);

  // Job B on SAME warm telco worker: SIP-RTP + SRTP + IPFIX
  samurai::orchestrator::JobOptions job_sip;
  job_sip.target_ip = "127.0.0.1";
  job_sip.target_port = 5060;
  job_sip.protocol = "sip-rtp";
  job_sip.packet_count = 0;
  job_sip.telco_subscribers = 16;
  job_sip.telco_rate_cps = 1000;
  job_sip.sip_rate = 1000;
  job_sip.enable_srtp = true;
  job_sip.telco_duration_ms = 250;
  job_sip.telco_base_ip = "10.20.0.1";
  job_sip.telco_gateway_ip = "10.20.0.254";
  job_sip.telco_db_port = 5099;
  job_sip.ipfix_enabled = true;
  job_sip.ipfix_collector = "127.0.0.1";
  job_sip.ipfix_port = collector.port;
  job_sip.ipfix_sample_rate = 1;
  job_sip.ipfix_domain_id = 99;
  job_sip.ipfix_export_interval_ms = 50;

  samurai::orchestrator::RunStats stats_sip;
  const int rc2 =
      samurai::orchestrator::RunJob(cfg, job_sip, stats_sip, &pool, nullptr, "telco-sip-0");
  SAMURAI_CHECK(rc2 == 0);
  SAMURAI_CHECK(pool.ReuseCount() == 1);
  SAMURAI_CHECK(pool.LastWorkerPid(samurai::wire::WorkerKind::TELCO) == telco_pid);
  SAMURAI_CHECK(stats_sip.sent > 0);
  SAMURAI_CHECK(stats_sip.telco_active_sessions == 16);
  SAMURAI_CHECK(stats_sip.ipfix_exported_packets >= 1);
  SAMURAI_CHECK(stats_sip.ipfix_exported_records >= 16);

  const std::vector<uint8_t> telco_ipfix = collector.RecvPacket();
  SAMURAI_CHECK(telco_ipfix.size() >= 16);
  const uint16_t telco_ver = static_cast<uint16_t>((telco_ipfix[0] << 8) | telco_ipfix[1]);
  SAMURAI_CHECK(telco_ver == 10);

  pool.ShutdownAll();
  SAMURAI_CHECK(pool.WarmSlotCount() == 0);
  std::cout << "  -> TestDistributedTelcoEnvelopeAndWarmSwitch PASSED (pid=" << telco_pid
            << ", sctp_tx=" << stats_sctp.sent << ", sip_tx=" << stats_sip.sent << ")\n";
}

void TestWireProtocolV3AbiAndLiveWorkers() {
  std::cout << "[TEST] Aligned Versionable Wire ABI V3 + Forward Compat + Live Workers...\n";
  using namespace samurai::wire;

  static_assert(alignof(SamuraiWireHeaderV3) == 8 && sizeof(SamuraiWireHeaderV3) == 64);
  static_assert(alignof(JobExtHeaderV3) == 8 && sizeof(JobExtHeaderV3) == 16);
  static_assert(alignof(JobEnvelopeV3) == 8 && sizeof(JobEnvelopeV3) % 8 == 0);
  static_assert(alignof(JobSectionL7V3) == 8 && sizeof(JobSectionL7V3) % 8 == 0);
  static_assert(alignof(JobSectionTelcoV3) == 8 && sizeof(JobSectionTelcoV3) % 8 == 0);
  static_assert(alignof(JobSectionTelemetryV3) == 8 && sizeof(JobSectionTelemetryV3) % 8 == 0);

  // Round-trip L7 V2 -> V3 -> V2 + Telemetry section + Unknown future extension skip
  samurai::orchestrator::JobOptions l7_opt;
  l7_opt.target_ip = "127.0.0.1";
  l7_opt.target_port = 8443;
  l7_opt.protocol = "http2";
  l7_opt.packet_count = 77;
  l7_opt.concurrency = 8;
  l7_opt.max_connections = 64;
  l7_opt.host_header = "api.internal.local";
  l7_opt.request_mix = 3;
  l7_opt.source_rotation = 2;

  JobV3Payload p;
  FromJobEnvelopeV2(samurai::orchestrator::BuildJobEnvelopeV2(l7_opt), p.base, p.l7);
  p.has_l7 = true;
  p.has_telemetry = true;
  p.telemetry.enabled = 1;
  p.telemetry.collector_port = 4739;
  p.telemetry.sample_rate = 10;
  p.telemetry.domain_id = 42;
  std::memcpy(p.telemetry.collector_ip, "127.0.0.1", 10);

  std::uint8_t ext_cnt = 0;
  std::vector<std::uint8_t> raw = SerializeJobV3Payload(p, &ext_cnt);
  SAMURAI_CHECK(ext_cnt == 2);

  // Inject an unknown future extension section right after `base` to prove forward compat.
  JobExtHeaderV3 unknown_hdr{};
  unknown_hdr.kind = 0xBEEFu;
  unknown_hdr.version = 9;
  unknown_hdr.section_bytes = 16;
  std::vector<std::uint8_t> with_unknown;
  with_unknown.insert(with_unknown.end(), raw.begin(), raw.begin() + sizeof(JobEnvelopeV3));
  with_unknown.insert(
      with_unknown.end(),
      reinterpret_cast<const std::uint8_t*>(&unknown_hdr),
      reinterpret_cast<const std::uint8_t*>(&unknown_hdr) + sizeof(unknown_hdr));
  with_unknown.resize(with_unknown.size() + 16, 0xAAu);
  with_unknown.insert(with_unknown.end(), raw.begin() + sizeof(JobEnvelopeV3), raw.end());

  JobV3Payload parsed{};
  SAMURAI_CHECK(ParseJobV3Payload(with_unknown.data(), with_unknown.size(), ext_cnt + 1, parsed));
  SAMURAI_CHECK(parsed.has_l7 && parsed.has_telemetry);
  const JobEnvelopeV2 rt_v2 = ToJobEnvelopeV2(parsed.base, parsed.l7);
  SAMURAI_CHECK(rt_v2.base.target_port == 8443);
  SAMURAI_CHECK(rt_v2.base.packet_count == 77);
  SAMURAI_CHECK(rt_v2.concurrency == 8 && rt_v2.max_connections == 64);
  SAMURAI_CHECK(rt_v2.request_mix == 3 && rt_v2.source_rotation == 2);
  SAMURAI_CHECK(std::string(rt_v2.host_header) == "api.internal.local");
  SAMURAI_CHECK(parsed.telemetry.domain_id == 42);

  // DecodeWireFrame seamless V1 vs V3 framing check
  SamuraiWireHeaderV3 h3 = samurai::daemon::MakeHeaderV3(
      static_cast<std::uint8_t>(MessageType::START_JOB),
      static_cast<std::uint32_t>(raw.size()), 9001ull, WorkerKind::L7, "v3-test", ext_cnt);
  std::vector<std::uint8_t> frame_buf(sizeof(h3) + raw.size());
  std::memcpy(frame_buf.data(), &h3, sizeof(h3));
  std::memcpy(frame_buf.data() + sizeof(h3), raw.data(), raw.size());
  DecodedWireFrame frm{};
  SAMURAI_CHECK(DecodeWireFrame(frame_buf.data(), frame_buf.size(), frm));
  SAMURAI_CHECK(frm.version == kVersionV3 && frm.ext_count == 2 && frm.correlation_id == 9001ull);
  SAMURAI_CHECK(frm.job_id == "v3-test");

  // Live ZMQ execution using V3 wire framing against cpu and telco workers
  UdpCollector collector;
  SAMURAI_CHECK(collector.BindLoopback(2500));

  samurai::orchestrator::WarmWorkerPool pool;
  const auto cpu = samurai::orchestrator::LookupWorker("cpu");
  const auto telco = samurai::orchestrator::LookupWorker("telco");
  SAMURAI_CHECK(cpu.has_value() && telco.has_value());

  samurai::orchestrator::SupervisorConfig cpu_cfg;
  cpu_cfg.worker = *cpu;
  cpu_cfg.worker_dir = WorkerDir();
  cpu_cfg.recv_timeout_ms = 500;
  cpu_cfg.max_idle_recvs = 30;
  cpu_cfg.use_wire_v3 = true;

  samurai::orchestrator::JobOptions cpu_job;
  cpu_job.target_ip = "127.0.0.1";
  cpu_job.target_port = 18080;
  cpu_job.protocol = "udp";
  cpu_job.packet_count = 32;
  cpu_job.packet_size = 64;
  cpu_job.target_rps = 500.0;
  samurai::orchestrator::RunStats cpu_stats;
  SAMURAI_CHECK(
      samurai::orchestrator::RunJob(cpu_cfg, cpu_job, cpu_stats, &pool, nullptr, "v3-cpu") == 0);
  SAMURAI_CHECK(cpu_stats.sent == 32);

  samurai::orchestrator::SupervisorConfig telco_cfg;
  telco_cfg.worker = *telco;
  telco_cfg.worker_dir = WorkerDir();
  telco_cfg.recv_timeout_ms = 500;
  telco_cfg.max_idle_recvs = 30;
  telco_cfg.use_wire_v3 = true;

  samurai::orchestrator::JobOptions telco_job;
  telco_job.target_ip = "127.0.0.1";
  telco_job.target_port = 5060;
  telco_job.protocol = "sip-rtp";
  telco_job.packet_count = 0;
  telco_job.telco_subscribers = 12;
  telco_job.telco_rate_cps = 1000;
  telco_job.sip_rate = 1000;
  telco_job.telco_duration_ms = 200;
  telco_job.ipfix_enabled = true;
  telco_job.ipfix_collector = "127.0.0.1";
  telco_job.ipfix_port = collector.port;
  telco_job.ipfix_sample_rate = 1;
  telco_job.ipfix_domain_id = 303;
  telco_job.ipfix_export_interval_ms = 50;
  samurai::orchestrator::RunStats telco_stats;
  SAMURAI_CHECK(
      samurai::orchestrator::RunJob(
          telco_cfg, telco_job, telco_stats, &pool, nullptr, "v3-telco") == 0);
  SAMURAI_CHECK(telco_stats.sent > 0);
  SAMURAI_CHECK(telco_stats.telco_active_sessions == 12);
  SAMURAI_CHECK(telco_stats.ipfix_exported_packets >= 1);

  pool.ShutdownAll();
  std::cout << "  -> TestWireProtocolV3AbiAndLiveWorkers PASSED (cpu_sent=" << cpu_stats.sent
            << ", telco_tx=" << telco_stats.sent << ")\n";
}

}  // namespace

int main() {
  TestConsolidatedPacing();
  TestWarmWorkerPoolReconfigureAndCancel();
  TestLiveIpfixAndNetflowV9UdpExport();
  TestDistributedTelcoEnvelopeAndWarmSwitch();
  TestWireProtocolV3AbiAndLiveWorkers();
  std::cout << "ALL PACING / TELEMETRY / WARM WORKER / TELCO / WIRE-V3 TESTS PASSED!\n";
  return 0;
}
