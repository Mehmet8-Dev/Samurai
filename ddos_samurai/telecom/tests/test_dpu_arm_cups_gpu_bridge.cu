#include <cuda_runtime.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "ddos_samurai/gpu_packet_cuda.hpp"
#include "ddos_samurai/gpu_packet_cuda/zero_copy_dataplane_contract.cuh"
#include "ddos_samurai/telecom/cups/dpu_arm_cups_bridge.hpp"
#include "ddos_samurai/telecom/core/session_manager.hpp"
#include "ddos_samurai/telecom/core/hierarchical_timing_wheel.hpp"
#include "ddos_samurai/telecom/protocols/stateful/mobile/pfcp_engine.hpp"
#include "ddos_samurai/telecom/protocols/stateful/mobile/gtpu_engine.hpp"
#include "ddos_samurai/zmq/daemon/wire_protocol.h"

using namespace ddos_samurai::gpu_packet_cuda::zero_copy;
using namespace samurai::telecom::cups;
using namespace ddos_samurai::telecom;
using namespace ddos_samurai::telecom::mobile;

namespace {

const char* kCupsShmPath = "/dev/shm/test_samurai_cups_bridge_shm.bin";

void CleanupShm() {
  unlink(kCupsShmPath);
}

void CheckCuda(cudaError_t err, const char* msg) {
  if (err != cudaSuccess) {
    std::fprintf(stderr, "CUDA error in %s: %s\n", msg, cudaGetErrorString(err));
    std::exit(1);
  }
}

void TestDpuArmCupsGpuBridgeLifecycle() {
  std::printf("-----------------------------------------------------------------\n");
  std::printf("[TEST] Running End-to-End DPU ARM CUPS Bridge <-> GPU Dataplane Test\n");
  std::printf("-----------------------------------------------------------------\n");
  CleanupShm();

  constexpr uint32_t kMaxSubs = 64;
  SessionManager session_mgr(kMaxSubs);
  HierarchicalTimingWheel timing_wheel(2400000000ULL);

  ProtocolConfig proto_cfg{};
  proto_cfg.max_sessions = kMaxSubs;
  proto_cfg.rate_cps = 1000;
  proto_cfg.retransmit_timeout_ms = 500;
  proto_cfg.max_retries = 3;

  PfcpEngine pfcp_engine(session_mgr, &timing_wheel);
  pfcp_engine.Init(proto_cfg);

  DpuArmCupsSessionController cups_ctrl(session_mgr, pfcp_engine, kMaxSubs);
  bool init_ok = cups_ctrl.InitializeSharedRegion(kCupsShmPath, true);
  assert(init_ok && "cups_ctrl.InitializeSharedRegion failed");

  // Step 1: Attach GPU runtime to the DPU CUPS shared memory region via C ABI
  int attach_rc = samurai_gpu_packet_telco_attach_cups_shm_v1(kCupsShmPath, 0);
  if (attach_rc != 0) {
    std::fprintf(stderr, "Attach failed: %s\n", samurai_gpu_packet_last_error());
  }
  assert(attach_rc == 0 && "samurai_gpu_packet_telco_attach_cups_shm_v1 failed");
  std::printf("  -> [PASS] Attached GPU user plane to CUPS shared memory region.\n");

  // Step 2: Establish 4 subscriber sessions via DPU ARM controller (N4 PFCP)
  CupsTunnelParams p0{};
  p0.uplink_teid = 1001;
  p0.downlink_teid = 2001;
  p0.qfi = 5;
  p0.ue_src_ip = 0x0A3C0001; // 10.60.0.1
  p0.inner_dst_ip = 0x08080808;
  p0.inner_proto = 17; // UDP
  p0.inner_src_port = 5001;
  p0.inner_dst_port = 80;
  p0.with_seq = true;
  p0.with_qfi_ext = true;

  CupsTunnelParams p1{};
  p1.uplink_teid = 1002;
  p1.downlink_teid = 2002;
  p1.qfi = 9;
  p1.ue_src_ip = 0x0A3C0002; // 10.60.0.2
  p1.inner_dst_ip = 0x08080808;
  p1.inner_proto = 17;
  p1.inner_src_port = 5002;
  p1.inner_dst_port = 80;
  p1.with_seq = true;
  p1.with_qfi_ext = true;

  CupsTunnelParams p2{};
  p2.uplink_teid = 1003;
  p2.downlink_teid = 2003;
  p2.qfi = 1;
  p2.ue_src_ip = 0x0A3C0003; // 10.60.0.3
  p2.inner_dst_ip = 0x08080808;
  p2.inner_proto = 6; // TCP
  p2.inner_src_port = 5003;
  p2.inner_dst_port = 443;
  p2.with_seq = true;
  p2.with_qfi_ext = true;

  CupsTunnelParams p3{};
  p3.uplink_teid = 1004;
  p3.downlink_teid = 2004;
  p3.qfi = 8;
  p3.ue_src_ip = 0x0A3C0004; // 10.60.0.4
  p3.inner_dst_ip = 0x08080808;
  p3.inner_proto = 1; // ICMP
  p3.with_seq = true;
  p3.with_qfi_ext = true;

  std::vector<uint8_t> n4_req0, n4_req1, n4_req2, n4_req3;
  assert(cups_ctrl.EstablishSubscriberSession(0, 10001, p0, &n4_req0));
  assert(cups_ctrl.EstablishSubscriberSession(1, 10002, p1, &n4_req1));
  assert(cups_ctrl.EstablishSubscriberSession(2, 10003, p2, &n4_req2));
  assert(cups_ctrl.EstablishSubscriberSession(3, 10004, p3, &n4_req3));
  assert(!n4_req0.empty() && !n4_req1.empty() && "N4 PFCP establishment requests must be built");

  const auto* hdr = cups_ctrl.GetHeader();
  assert(hdr->active_sessions == 4);
  assert(hdr->established_total == 4);
  assert(hdr->active_span == 4);
  std::printf("  -> [PASS] Established 4 subscriber sessions via DPU ARM N4 PFCP.\n");

  // Step 3: Run GPU packet generation utilizing the live CUPS shared table
  const char* config_json =
      "{\n"
      "  \"stream_type\": \"gtpu\",\n"
      "  \"teid_start\": 1001,\n"
      "  \"teid_count\": 4,\n"
      "  \"with_qfi\": true,\n"
      "  \"qfi\": 9,\n"
      "  \"pdu_type\": 1\n"
      "}";

  void* out_pkts = nullptr;
  size_t total_bytes = 0;
  int pkt_size = 0;
  int gen_rc = samurai_gpu_packet_generate_gtpu_packets(config_json, 4, &out_pkts, &total_bytes, &pkt_size);
  assert(gen_rc == 0 && "samurai_gpu_packet_generate_gtpu_packets failed");
  assert(out_pkts != nullptr && pkt_size > 0);

  // Decapsulate each packet generated by GPU and verify against DPU subscriber table
  std::vector<uint8_t> h_batch(total_bytes);
  CheckCuda(cudaMemcpy(h_batch.data(), out_pkts, total_bytes, cudaMemcpyDeviceToHost), "cp pkts");

  for (uint32_t i = 0; i < 4; ++i) {
    const uint8_t* pkt = h_batch.data() + i * static_cast<size_t>(pkt_size);
    GtpuDecapInfo decap{};
    bool dec_ok = GtpuEngine::Decapsulate(pkt, pkt_size, decap);
    assert(dec_ok && "Decapsulation must succeed on GPU generated packet");
    assert(decap.teid >= 1001 && decap.teid <= 1004 && "TEID must match subscriber range");
    assert(decap.has_seq && "GTP-U sequence/extension container must be present");
    assert(decap.payload_len > 0 && "Inner payload must be non-empty");
  }
  samurai_gpu_packet_free(out_pkts);
  std::printf("  -> [PASS] GPU GTP-U generation verified against live CUPS shared table.\n");

  // Step 4: Modify Subscriber 1 (QFI update 9 -> 12, TEID update 1002 -> 9999)
  std::vector<uint8_t> mod_req;
  assert(cups_ctrl.ModifySubscriberSession(1, 12, 9999, &mod_req));
  assert(!mod_req.empty());
  assert(hdr->modified_total == 1);
  const auto* e1 = cups_ctrl.GetTunnelEntry(1);
  assert(e1 != nullptr && e1->qfi == 12 && e1->uplink_teid == 9999);
  std::printf("  -> [PASS] Modified Subscriber 1 QFI and TEID via N4 PFCP.\n");

  // Step 5: Delete Subscriber 0
  std::vector<uint8_t> del_req;
  assert(cups_ctrl.DeleteSubscriberSession(0, &del_req));
  assert(!del_req.empty());
  assert(hdr->active_sessions == 3);
  assert(hdr->deleted_total == 1);
  const auto* e0 = cups_ctrl.GetTunnelEntry(0);
  assert(e0 != nullptr && (e0->flags & static_cast<uint8_t>(TelcoGpuTunnelFlags::kActive)) == 0);
  std::printf("  -> [PASS] Deleted Subscriber 0 cleanly via N4 PFCP.\n");

  // Step 6: Test ZMQ TELCO_TUNNEL_UPSERT serialization parity
  std::vector<uint8_t> zmq_payload = cups_ctrl.BuildZmqUpsertPayload(0, 4, 1);
  assert(zmq_payload.size() == sizeof(samurai::wire::TelcoGpuTunnelUpsertV1) + 4 * sizeof(TelcoGpuTunnelEntryV1));
  auto* upsert_hdr = reinterpret_cast<const samurai::wire::TelcoGpuTunnelUpsertV1*>(zmq_payload.data());
  assert(upsert_hdr->count == 4);
  assert(upsert_hdr->flags == 1);
  auto* upsert_entries = reinterpret_cast<const TelcoGpuTunnelEntryV1*>(zmq_payload.data() + sizeof(samurai::wire::TelcoGpuTunnelUpsertV1));
  assert(upsert_entries[1].qfi == 12);
  assert(upsert_entries[1].uplink_teid == 9999);
  std::printf("  -> [PASS] ZMQ TELCO_TUNNEL_UPSERT payload parity verified.\n");

  // Step 7: Detach CUPS shared memory
  int detach_rc = samurai_gpu_packet_telco_detach_cups_shm_v1();
  assert(detach_rc == 0 && "samurai_gpu_packet_telco_detach_cups_shm_v1 failed");
  cups_ctrl.DetachSharedRegion();
  CleanupShm();
  std::printf("  -> [PASS] Cleanly detached CUPS shared memory.\n");
}

} // namespace

int main() {
  std::printf("=================================================================\n");
  std::printf("   DPU ARM CUPS BRIDGE & GPU TELECOM VERIFICATION SUITE          \n");
  std::printf("=================================================================\n");

  int dev_count = 0;
  if (cudaGetDeviceCount(&dev_count) != cudaSuccess || dev_count <= 0) {
    std::printf("[SKIP] No CUDA GPU available.\n");
    return 0;
  }

  TestDpuArmCupsGpuBridgeLifecycle();

  std::printf("=================================================================\n");
  std::printf("  DPU ARM CUPS BRIDGE SUITE PASSED SUCCESSFULLY!                 \n");
  std::printf("=================================================================\n");
  return 0;
}
