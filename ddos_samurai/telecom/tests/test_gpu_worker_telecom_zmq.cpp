#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <zmq.h>

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "ddos_samurai/gpu_packet_cuda/zero_copy_dataplane_contract.cuh"
#include "ddos_samurai/orchestrator/job_builder.hpp"
#include "ddos_samurai/zmq/daemon/wire_protocol.h"
#include "ddos_samurai/zmq/daemon/worker_common.hpp"

using namespace samurai::wire;
using namespace samurai::daemon;
using namespace ddos_samurai::gpu_packet_cuda::zero_copy;

namespace {

const char* kJobsEp = "ipc:///tmp/test_samurai_gpu_worker_jobs.ipc";
const char* kEventsEp = "ipc:///tmp/test_samurai_gpu_worker_events.ipc";
const char* kJobsPath = "/tmp/test_samurai_gpu_worker_jobs.ipc";
const char* kEventsPath = "/tmp/test_samurai_gpu_worker_events.ipc";

void CleanupIpcFiles() {
  unlink(kJobsPath);
  unlink(kEventsPath);
}

void TestStaticAsserts() {
  std::printf("[TEST 1] Verifying wire protocol struct layout and static invariants...\n");
  static_assert(sizeof(JobEnvelopeV1) == 480, "JobEnvelopeV1 must remain exactly 480 bytes");
  static_assert(sizeof(JobEnvelopeV2) == 786, "JobEnvelopeV2 must remain exactly 786 bytes");
  static_assert(sizeof(TelcoJobPayload) == 104, "TelcoJobPayload must remain exactly 104 bytes");
  static_assert(sizeof(TelcoGpuJobEnvelopeV1) == 528, "TelcoGpuJobEnvelopeV1 must be exactly 528 bytes");
  static_assert(sizeof(TelcoGpuTunnelUpsertV1) == 16, "TelcoGpuTunnelUpsertV1 must be exactly 16 bytes");
  static_assert(sizeof(TelcoGpuTunnelEntryV1) == 64, "TelcoGpuTunnelEntryV1 must be exactly 64 bytes");
  static_assert(alignof(TelcoGpuTunnelEntryV1) == 64, "TelcoGpuTunnelEntryV1 must be 64-byte aligned");

  // Field offset checks
  assert(offsetof(TelcoGpuJobEnvelopeV1, base) == 0);
  assert(offsetof(TelcoGpuJobEnvelopeV1, teid_start) == 480);
  assert(offsetof(TelcoGpuJobEnvelopeV1, ue_src_ip_start) == 488);
  assert(offsetof(TelcoGpuJobEnvelopeV1, inner_dst_ip) == 496);
  assert(offsetof(TelcoGpuJobEnvelopeV1, qfi) == 508);

  std::printf("  -> [PASS] Static asserts and memory offsets verified.\n");
}

void TestJobBuilderSerialization() {
  std::printf("[TEST 2] Testing JobBuilder GTP-U & 5G QFI serialization...\n");
  samurai::orchestrator::JobOptions opt{};
  opt.protocol = "gtpu";
  opt.target_ip = "192.168.1.1";
  opt.target_port = 2152;
  opt.teid_start = 50000;
  opt.teid_count = 1000;
  opt.vlan_depth = 1;
  opt.svlan_tci = 100;
  opt.qfi = 9;
  opt.with_qfi_ext = 1;
  opt.with_seq = 1;
  opt.inner_proto = 17; // UDP
  opt.ue_src_ip_start = 0x0A2D0000; // 10.45.0.0
  opt.inner_dst_ip = 0x08080404;    // 8.8.4.4
  opt.packet_count = 1000;
  opt.target_rps = 50000;

  TelcoGpuJobEnvelopeV1 env = samurai::orchestrator::BuildTelcoGpuJobEnvelope(opt);
  assert(std::string(env.base.protocol) == "gtpu");
  assert(env.teid_start == 50000);
  assert(env.teid_count == 1000);
  assert(env.vlan_depth == 1);
  assert(env.svlan_tci == 100);
  assert(env.qfi == 9);
  assert(env.pdu_type == 1);
  assert(env.inner_proto == 17);
  assert(env.ue_src_ip_start == 0x0A2D0000);
  assert(env.inner_dst_ip == 0x08080404);

  // Verify standard UDP job (even with default qfi = 9) does NOT trigger GTP-U
  samurai::orchestrator::JobOptions udp_opt{};
  udp_opt.protocol = "udp";
  udp_opt.target_ip = "192.168.1.1";
  udp_opt.target_port = 80;
  udp_opt.qfi = 9;
  assert(!samurai::orchestrator::IsTelcoGtpuProtocol(udp_opt.protocol) && "UDP must not be classified as GTP-U");
  assert(!samurai::orchestrator::IsTelcoGtpuProtocol("tcp") && "TCP must not be classified as GTP-U");
  assert(samurai::orchestrator::IsTelcoGtpuProtocol("gtpu") && "GTPU must be classified as GTP-U");
  assert(samurai::orchestrator::IsTelcoGtpuProtocol("5g-gtpu") && "5G-GTPU must be classified as GTP-U");

  std::printf("  -> [PASS] JobBuilder GTP-U and 5G QFI serialization verified.\n");
}

void TestGpuWorkerZmqIntegration() {
  std::printf("[TEST 3] Testing live samurai_gpu_worker ZMQ IPC control & data plane...\n");
  CleanupIpcFiles();

  pid_t pid = fork();
  assert(pid >= 0);

  if (pid == 0) {
    // Child process: execute samurai_gpu_worker
    // Disable raw socket AF_PACKET tx in test environment (unprivileged unit test)
    setenv("SAMURAI_AFPACKET_TX", "0", 1);
    const char* candidates[] = {
      "./build/zmq/samurai_gpu_worker",
      "./zmq/samurai_gpu_worker",
      "../zmq/samurai_gpu_worker",
      "../../build/zmq/samurai_gpu_worker",
      nullptr
    };
    const char* worker_bin = nullptr;
    for (int i = 0; candidates[i]; ++i) {
      if (access(candidates[i], X_OK) == 0) {
        worker_bin = candidates[i];
        break;
      }
    }
    if (!worker_bin) worker_bin = "samurai_gpu_worker";
    execl(worker_bin, "samurai_gpu_worker",
          "--job-endpoint", kJobsEp,
          "--event-endpoint", kEventsEp,
          "--jobs-mode", "connect",
          "--events-mode", "connect",
          "--gpu-batch-size", "16",
          nullptr);
    std::perror("execl samurai_gpu_worker failed");
    std::exit(127);
  }

  // Parent process: Controller - initialize ZeroMQ cleanly after fork()
  void* ctx = zmq_ctx_new();
  assert(ctx != nullptr);

  void* jobs_push = zmq_socket(ctx, ZMQ_PUSH);
  void* events_pull = zmq_socket(ctx, ZMQ_PULL);
  assert(jobs_push != nullptr && events_pull != nullptr);

  // Set 8-second timeout so test fails gracefully if worker fails
  int timeout_ms = 8000;
  zmq_setsockopt(events_pull, ZMQ_RCVTIMEO, &timeout_ms, sizeof(timeout_ms));

  int rc = zmq_bind(jobs_push, kJobsEp);
  assert(rc == 0 && "zmq_bind jobs failed");
  rc = zmq_bind(events_pull, kEventsEp);
  assert(rc == 0 && "zmq_bind events failed");

  // Give worker a moment to connect its sockets
  usleep(300000); // 300ms

  // Step 0a: Verify robust rejection of malformed/truncated TELCO_TUNNEL_UPSERT
  {
    std::printf("  -> Sending truncated TELCO_TUNNEL_UPSERT to verify robust rejection...\n");
    TelcoGpuTunnelUpsertV1 up_hdr{};
    up_hdr.count = 5;
    up_hdr.flags = 0;
    std::vector<uint8_t> bad_payload(sizeof(TelcoGpuTunnelUpsertV1) + 32); // incorrect entry bytes
    std::memcpy(bad_payload.data(), &up_hdr, sizeof(up_hdr));

    int send_rc = SendFrame(jobs_push, static_cast<uint8_t>(MessageType::TELCO_TUNNEL_UPSERT), 99, WorkerKind::GPU, "bad-upsert", bad_payload);
    assert(send_rc > 0);

    zmq_msg_t msg;
    zmq_msg_init(&msg);
    int recv_rc = zmq_msg_recv(&msg, events_pull, 0);
    assert(recv_rc >= static_cast<int>(sizeof(SamuraiWireHeaderV1)));
    auto* hdr = static_cast<SamuraiWireHeaderV1*>(zmq_msg_data(&msg));
    assert(hdr->msg_type == static_cast<uint8_t>(MessageType::ERROR) && "Worker must reject truncated upsert with ERROR frame");
    assert(hdr->correlation_id == 99);
    zmq_msg_close(&msg);
    std::printf("     Received response: ERROR for truncated upsert (cid=99).\n");
  }

  // Step 0b: Test clear-only (count=0) upsert with kTelcoTunnelUpsertFlagClearBeforeUpsert
  {
    std::printf("  -> Sending count=0 clear-only TELCO_TUNNEL_UPSERT...\n");
    TelcoGpuTunnelUpsertV1 clear_hdr{};
    clear_hdr.count = 0;
    clear_hdr.flags = samurai::wire::kTelcoTunnelUpsertFlagClearBeforeUpsert;
    std::vector<uint8_t> clear_payload(sizeof(clear_hdr));
    std::memcpy(clear_payload.data(), &clear_hdr, sizeof(clear_hdr));

    int send_rc = SendFrame(jobs_push, static_cast<uint8_t>(MessageType::TELCO_TUNNEL_UPSERT), 100, WorkerKind::GPU, "clear-upsert", clear_payload);
    assert(send_rc > 0);

    zmq_msg_t msg;
    zmq_msg_init(&msg);
    int recv_rc = zmq_msg_recv(&msg, events_pull, 0);
    assert(recv_rc >= static_cast<int>(sizeof(SamuraiWireHeaderV1)));
    auto* hdr = static_cast<SamuraiWireHeaderV1*>(zmq_msg_data(&msg));
    assert(hdr->msg_type == static_cast<uint8_t>(MessageType::ACK) && "Worker must ACK clear-only upsert");
    assert(hdr->correlation_id == 100);
    zmq_msg_close(&msg);
    std::printf("     Received response: ACK for clear-only upsert (cid=100).\n");
  }

  // Step 1: Send TELCO_TUNNEL_UPSERT (initial tunnel population)
  {
    std::printf("  -> Sending TELCO_TUNNEL_UPSERT (2 initial tunnels) to worker...\n");
    TelcoGpuTunnelUpsertV1 up_hdr{};
    up_hdr.count = 2;
    up_hdr.flags = 1; // clear_before_upsert

    std::vector<TelcoGpuTunnelEntryV1> entries(2);
    entries[0].flags = static_cast<uint8_t>(TelcoGpuTunnelFlags::kActive) |
                       static_cast<uint8_t>(TelcoGpuTunnelFlags::kWithQfiExt);
    entries[0].uplink_teid = 1111;
    entries[0].qfi = 5;
    entries[0].outer_dst_ip = 0x0A000002;
    entries[0].ue_src_ip = 0x0A640001;
    entries[0].inner_dst_ip = 0x08080808;

    entries[1].flags = static_cast<uint8_t>(TelcoGpuTunnelFlags::kActive) |
                       static_cast<uint8_t>(TelcoGpuTunnelFlags::kWithQfiExt);
    entries[1].uplink_teid = 2222;
    entries[1].qfi = 9;
    entries[1].outer_dst_ip = 0x0A000002;
    entries[1].ue_src_ip = 0x0A640002;
    entries[1].inner_dst_ip = 0x08080808;

    std::vector<uint8_t> payload(sizeof(TelcoGpuTunnelUpsertV1) + 2 * sizeof(TelcoGpuTunnelEntryV1));
    std::memcpy(payload.data(), &up_hdr, sizeof(up_hdr));
    std::memcpy(payload.data() + sizeof(up_hdr), entries.data(), 2 * sizeof(TelcoGpuTunnelEntryV1));

    int send_rc = SendFrame(jobs_push, static_cast<uint8_t>(MessageType::TELCO_TUNNEL_UPSERT), 101, WorkerKind::GPU, "init-upsert", payload);
    assert(send_rc > 0);

    zmq_msg_t msg;
    zmq_msg_init(&msg);
    int recv_rc = zmq_msg_recv(&msg, events_pull, 0);
    assert(recv_rc >= static_cast<int>(sizeof(SamuraiWireHeaderV1)));
    auto* hdr = static_cast<SamuraiWireHeaderV1*>(zmq_msg_data(&msg));
    assert(hdr->msg_type == static_cast<uint8_t>(MessageType::ACK) && "Worker must ACK TELCO_TUNNEL_UPSERT");
    assert(hdr->correlation_id == 101);
    zmq_msg_close(&msg);
    std::printf("     Received response: ACK for TELCO_TUNNEL_UPSERT (cid=101).\n");
  }

  // Step 2: Send START_JOB with TelcoGpuJobEnvelopeV1 (GTP-U 5G QFI stream)
  {
    std::printf("  -> Sending START_JOB (TelcoGpuJobEnvelopeV1 GTP-U 5G QFI, count=32) to worker...\n");
    samurai::orchestrator::JobOptions opt{};
    opt.protocol = "gtpu";
    opt.target_ip = "192.168.1.1";
    opt.target_port = 2152;
    opt.packet_count = 32;
    opt.target_rps = 1000;
    opt.teid_start = 1000;
    opt.teid_count = 10;
    opt.qfi = 9;
    opt.with_qfi_ext = 1;
    opt.with_seq = 1;
    opt.ue_src_ip_start = 0x0A500001; // 10.80.0.1
    opt.inner_dst_ip = 0x08080808;

    TelcoGpuJobEnvelopeV1 env = samurai::orchestrator::BuildTelcoGpuJobEnvelope(opt);
    std::vector<uint8_t> payload(sizeof(env));
    std::memcpy(payload.data(), &env, sizeof(env));

    int send_rc = SendFrame(jobs_push, static_cast<uint8_t>(MessageType::START_JOB), 102, WorkerKind::GPU, "gtpu-job-001", payload);
    assert(send_rc > 0);

    // Expect initial ACK for START_JOB
    zmq_msg_t msg;
    zmq_msg_init(&msg);
    int recv_rc = zmq_msg_recv(&msg, events_pull, 0);
    assert(recv_rc >= static_cast<int>(sizeof(SamuraiWireHeaderV1)));
    auto* hdr = static_cast<SamuraiWireHeaderV1*>(zmq_msg_data(&msg));
    assert(hdr->msg_type == static_cast<uint8_t>(MessageType::ACK));
    assert(hdr->correlation_id == 102);
    zmq_msg_close(&msg);
    std::printf("     Received response: ACK for START_JOB (cid=102).\n");

    // Wait for JOB_DONE (and any intermediate METRIC_SNAPSHOTs)
    bool job_done_seen = false;
    while (!job_done_seen) {
      zmq_msg_t event_msg;
      zmq_msg_init(&event_msg);
      int ev_rc = zmq_msg_recv(&event_msg, events_pull, 0);
      assert(ev_rc >= static_cast<int>(sizeof(SamuraiWireHeaderV1)));
      auto* ev_hdr = static_cast<SamuraiWireHeaderV1*>(zmq_msg_data(&event_msg));

      if (ev_hdr->msg_type == static_cast<uint8_t>(MessageType::JOB_DONE)) {
        job_done_seen = true;
        std::printf("     Received response: JOB_DONE for gtpu-job-001.\n");
      } else if (ev_hdr->msg_type == static_cast<uint8_t>(MessageType::METRIC_SNAPSHOT)) {
        std::printf("     Received METRIC_SNAPSHOT stream...\n");
      }
      zmq_msg_close(&event_msg);
    }
  }

  // Step 3: Send SHUTDOWN to terminate worker
  {
    std::printf("  -> Sending SHUTDOWN to worker...\n");
    (void)SendFrame(jobs_push, static_cast<uint8_t>(MessageType::SHUTDOWN), 103, WorkerKind::GPU, "shutdown");
  }

  // Wait for worker child process to exit cleanly
  int status = 0;
  pid_t waited = waitpid(pid, &status, 0);
  assert(waited == pid);
  assert(WIFEXITED(status) && WEXITSTATUS(status) == 0 && "samurai_gpu_worker must exit with code 0");
  std::printf("  -> [PASS] samurai_gpu_worker process terminated with exit code 0.\n");

  zmq_close(jobs_push);
  zmq_close(events_pull);
  zmq_ctx_term(ctx);
  CleanupIpcFiles();
  std::printf("  -> [PASS] ZMQ IPC integration suite verified.\n");
}

} // namespace

int main() {
  std::printf("=================================================================\n");
  std::printf("     GPU WORKER TELECOM & ZMQ PROTOCOL INTEGRATION TEST SUITE    \n");
  std::printf("=================================================================\n");

  TestStaticAsserts();
  TestJobBuilderSerialization();
  TestGpuWorkerZmqIntegration();

  std::printf("=================================================================\n");
  std::printf("  ALL GPU WORKER TELECOM ZMQ TESTS PASSED SUCCESSFULLY!          \n");
  std::printf("=================================================================\n");
  return 0;
}
