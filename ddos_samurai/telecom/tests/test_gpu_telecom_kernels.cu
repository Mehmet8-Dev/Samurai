#include <cuda_runtime.h>
#include <arpa/inet.h>

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include "ddos_samurai/gpu_packet_cuda.hpp"
#include "ddos_samurai/gpu_packet_cuda/zero_copy_dataplane_contract.cuh"
#include "ddos_samurai/gpu_packet_cuda/kernels_telecom.cuh"
#include "ddos_samurai/telecom/protocols/stateful/mobile/gtpu_engine.hpp"
#include "ddos_samurai/telecom/protocols/stateful/mobile/gtpu_types.hpp"

using namespace ddos_samurai::gpu_packet_cuda::zero_copy;
using namespace ddos_samurai::gpu_packet_cuda::telecom;
using namespace ddos_samurai::telecom::mobile;

namespace {

void CheckCuda(cudaError_t err, const char* msg) {
  if (err != cudaSuccess) {
    std::fprintf(stderr, "CUDA error in %s: %s\n", msg, cudaGetErrorString(err));
    std::exit(1);
  }
}

uint16_t CalculateIpv4Checksum(const uint8_t* ip_hdr, size_t hdr_len) {
  uint32_t sum = 0;
  for (size_t i = 0; i < hdr_len; i += 2) {
    sum += (static_cast<uint32_t>(ip_hdr[i]) << 8) | ip_hdr[i + 1];
  }
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }
  return static_cast<uint16_t>(~sum & 0xFFFF);
}

uint16_t CalculateL4Checksum(
    uint32_t src_ip,
    uint32_t dst_ip,
    uint8_t proto,
    const uint8_t* l4_data,
    size_t l4_len) {
  uint32_t sum = 0;
  // Pseudo-header
  sum += (src_ip >> 16) & 0xFFFF;
  sum += src_ip & 0xFFFF;
  sum += (dst_ip >> 16) & 0xFFFF;
  sum += dst_ip & 0xFFFF;
  sum += proto;
  sum += static_cast<uint32_t>(l4_len);

  for (size_t i = 0; i < (l4_len & ~1ULL); i += 2) {
    sum += (static_cast<uint32_t>(l4_data[i]) << 8) | l4_data[i + 1];
  }
  if (l4_len & 1) {
    sum += static_cast<uint32_t>(l4_data[l4_len - 1]) << 8;
  }
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }
  return static_cast<uint16_t>(~sum & 0xFFFF);
}

// ---------------------------------------------------------------------------
// Test 1: Basic 4G GTP-U Generation + Decapsulation & Dual Checksums
// ---------------------------------------------------------------------------
void TestBasic4gGtpuGeneration() {
  std::printf("[TEST 1] Testing basic 4G GTP-U packet generation & decapsulation...\n");
  constexpr uint32_t kCount = 16;
  constexpr uint32_t kSlotStride = 2048;

  uint8_t* d_arena = nullptr;
  uint16_t* d_pkt_lens = nullptr;
  CheckCuda(cudaMalloc(&d_arena, kCount * kSlotStride), "alloc arena");
  CheckCuda(cudaMalloc(&d_pkt_lens, kCount * sizeof(uint16_t)), "alloc lens");

  TelcoGtpuStreamConfig h_cfg{};
  h_cfg.outer_src_ip = 0x0A000001;
  h_cfg.outer_dst_ip = 0x0A000002;
  h_cfg.ue_ip_start = 0x0AC80001;
  h_cfg.ue_ip_count = 100;
  h_cfg.inner_dst_ip = 0x08080808;
  h_cfg.inner_proto = 17; // UDP
  h_cfg.inner_src_port = 10000;
  h_cfg.inner_dst_port = 8080;
  h_cfg.inner_payload_size = 32;
  h_cfg.teid_start = 1000;
  h_cfg.teid_count = 100;
  h_cfg.vlan_depth = 0;
  h_cfg.with_seq = 0;
  h_cfg.with_qfi_ext = 0;

  TelcoGtpuStreamConfig* d_cfg = nullptr;
  CheckCuda(cudaMalloc(&d_cfg, sizeof(TelcoGtpuStreamConfig)), "alloc cfg");
  CheckCuda(cudaMemcpy(d_cfg, &h_cfg, sizeof(TelcoGtpuStreamConfig), cudaMemcpyHostToDevice), "cp cfg");

  telco_gtpu_batch_kernel<<<1, 32>>>(
      d_arena, kSlotStride, kCount, d_cfg, nullptr, 0, d_pkt_lens);
  CheckCuda(cudaDeviceSynchronize(), "sync batch");

  std::vector<uint16_t> h_lens(kCount);
  CheckCuda(cudaMemcpy(h_lens.data(), d_pkt_lens, kCount * sizeof(uint16_t), cudaMemcpyDeviceToHost), "cp lens");
  std::vector<uint8_t> h_arena(kCount * kSlotStride);
  CheckCuda(cudaMemcpy(h_arena.data(), d_arena, kCount * kSlotStride, cudaMemcpyDeviceToHost), "cp arena");

  for (uint32_t i = 0; i < kCount; ++i) {
    const uint8_t* pkt = h_arena.data() + i * kSlotStride;
    const uint32_t len = h_lens[i];
    assert(len >= 14 + 20 + 8 + 8 + 20 + 8 + 32 && "Packet length too small");

    // 1. Ethernet Header
    assert(pkt[12] == 0x08 && pkt[13] == 0x00); // IPv4

    // 2. Outer IPv4 Header
    const uint8_t* outer_ip = pkt + 14;
    assert((outer_ip[0] >> 4) == 4);
    assert((outer_ip[0] & 0x0F) == 5);
    assert(outer_ip[9] == 17); // UDP
    assert(CalculateIpv4Checksum(outer_ip, 20) == 0 && "Outer IPv4 checksum mismatch");

    // 3. Outer UDP Header
    const uint8_t* outer_udp = outer_ip + 20;
    const uint16_t outer_dport = (static_cast<uint16_t>(outer_udp[2]) << 8) | outer_udp[3];
    assert(outer_dport == 2152 && "GTP-U UDP port mismatch");

    // 4. GTP-U Header (TS 29.281)
    const uint8_t* gtp = outer_udp + 8;
    assert(gtp[0] == 0x30 && "GTPv1-U version and PT flags mismatch");
    assert(gtp[1] == 255 && "GTP-U G-PDU message type mismatch");
    const uint32_t expected_teid = 1000 + (i % 100);
    const uint32_t teid = (static_cast<uint32_t>(gtp[4]) << 24) |
                          (static_cast<uint32_t>(gtp[5]) << 16) |
                          (static_cast<uint32_t>(gtp[6]) << 8)  |
                          gtp[7];
    assert(teid == expected_teid && "TEID value mismatch");

    // 5. Cross-validate with CPU GtpuEngine::Decapsulate
    GtpuDecapInfo decap{};
    bool dec_ok = GtpuEngine::Decapsulate(pkt, len, decap);
    assert(dec_ok && "CPU GtpuEngine::Decapsulate failed on GPU-generated packet");
    assert(decap.teid == expected_teid && "Decapsulated TEID mismatch");
    assert(decap.msg_type == 255 && "Decapsulated msg_type mismatch");
    assert(!decap.has_seq && "Basic GTP-U must not have sequence number");

    // 6. Inner IPv4 Header
    const uint8_t* inner_ip = gtp + 8;
    assert((inner_ip[0] >> 4) == 4);
    assert(inner_ip[9] == 17); // Inner UDP
    assert(CalculateIpv4Checksum(inner_ip, 20) == 0 && "Inner IPv4 checksum mismatch");

    // 7. Inner UDP Header & Payload
    const uint8_t* inner_udp = inner_ip + 20;
    const uint16_t inner_sport = (static_cast<uint16_t>(inner_udp[0]) << 8) | inner_udp[1];
    const uint16_t inner_dport = (static_cast<uint16_t>(inner_udp[2]) << 8) | inner_udp[3];
    assert(inner_sport == 10000);
    assert(inner_dport == 8080);
    const uint32_t inner_src_ip = (static_cast<uint32_t>(inner_ip[12]) << 24) |
                                  (static_cast<uint32_t>(inner_ip[13]) << 16) |
                                  (static_cast<uint32_t>(inner_ip[14]) << 8)  |
                                  inner_ip[15];
    assert(inner_src_ip == h_cfg.ue_ip_start + (i % 100));
    assert(CalculateL4Checksum(inner_src_ip, h_cfg.inner_dst_ip, 17, inner_udp, 8 + 32) == 0 &&
           "Inner UDP checksum mismatch");
  }

  cudaFree(d_arena);
  cudaFree(d_pkt_lens);
  cudaFree(d_cfg);
  std::printf("  -> [PASS] Basic 4G GTP-U generation, CPU decapsulation & dual checksums verified.\n");
}

// ---------------------------------------------------------------------------
// Test 2: 5G GTP-U with QFI Extension Header (3GPP TS 38.415 PDU Session Container)
// ---------------------------------------------------------------------------
void Test5gGtpuQfiGeneration() {
  std::printf("[TEST 2] Testing 5G GTP-U QFI (0x85) PDU session container generation...\n");
  constexpr uint32_t kCount = 8;
  constexpr uint32_t kSlotStride = 2048;
  constexpr uint8_t kTargetQfi = 9;

  uint8_t* d_arena = nullptr;
  uint16_t* d_pkt_lens = nullptr;
  CheckCuda(cudaMalloc(&d_arena, kCount * kSlotStride), "alloc arena");
  CheckCuda(cudaMalloc(&d_pkt_lens, kCount * sizeof(uint16_t)), "alloc lens");

  TelcoGtpuStreamConfig h_cfg{};
  h_cfg.outer_src_ip = 0x0A000001;
  h_cfg.outer_dst_ip = 0x0A000002;
  h_cfg.ue_ip_start = 0x0AC80001;
  h_cfg.ue_ip_count = 50;
  h_cfg.inner_dst_ip = 0x08080808;
  h_cfg.inner_proto = 17;
  h_cfg.inner_src_port = 12000;
  h_cfg.inner_dst_port = 9000;
  h_cfg.inner_payload_size = 64;
  h_cfg.teid_start = 5000;
  h_cfg.teid_count = 50;
  h_cfg.vlan_depth = 0;
  h_cfg.with_seq = 1;
  h_cfg.with_qfi_ext = 1;
  h_cfg.qfi = kTargetQfi;
  h_cfg.pdu_type = 1; // UL

  TelcoGtpuStreamConfig* d_cfg = nullptr;
  CheckCuda(cudaMalloc(&d_cfg, sizeof(TelcoGtpuStreamConfig)), "alloc cfg");
  CheckCuda(cudaMemcpy(d_cfg, &h_cfg, sizeof(TelcoGtpuStreamConfig), cudaMemcpyHostToDevice), "cp cfg");

  telco_gtpu_batch_kernel<<<1, 32>>>(
      d_arena, kSlotStride, kCount, d_cfg, nullptr, 0, d_pkt_lens);
  CheckCuda(cudaDeviceSynchronize(), "sync 5g");

  std::vector<uint16_t> h_lens(kCount);
  CheckCuda(cudaMemcpy(h_lens.data(), d_pkt_lens, kCount * sizeof(uint16_t), cudaMemcpyDeviceToHost), "cp lens");
  std::vector<uint8_t> h_arena(kCount * kSlotStride);
  CheckCuda(cudaMemcpy(h_arena.data(), d_arena, kCount * kSlotStride, cudaMemcpyDeviceToHost), "cp arena");

  for (uint32_t i = 0; i < kCount; ++i) {
    const uint8_t* pkt = h_arena.data() + i * kSlotStride;
    const uint32_t len = h_lens[i];
    const uint8_t* gtp = pkt + 14 + 20 + 8;

    // GTP-U Flags: Version 1 (0x20) | PT (0x10) | Ext (0x04) | Seq (0x02) = 0x36
    assert(gtp[0] == 0x36 && "GTP-U flags must have E=1 and S=1 for 5G QFI container");
    assert(gtp[1] == 255); // G-PDU

    // GTP-U Optional fields (4 bytes): Seq (2B), N-PDU (1B), NextExt (1B)
    const uint8_t* opt = gtp + 8;
    const uint8_t next_ext = opt[3];
    assert(next_ext == 0x85 && "Next extension header must be 0x85 (3GPP PDU Session Container)");

    // 5G PDU Session Container (4 bytes):
    // ext_len (1B, units of 4 octets) = 0x01
    // [PDU Type: 4 bits in octet 2 | Spare: 4 bits]
    // [Spare/PPI: 2 bits | QFI: 6 bits in octet 3]
    // Next extension header = 0x00
    const uint8_t* pdu_ext = opt + 4;
    assert(pdu_ext[0] == 0x01 && "PDU session container length must be 1 (4 octets)");
    const uint8_t observed_pdu_type = (pdu_ext[1] >> 4) & 0x0F;
    const uint8_t observed_qfi = pdu_ext[2] & 0x3F;
    assert(observed_pdu_type == 1 && "PDU type mismatch (expected UL=1)");
    assert(observed_qfi == kTargetQfi && "QFI mismatch (expected 9)");
    assert(pdu_ext[3] == 0x00 && "Terminating next_ext must be 0x00");

    // Cross-validate decapsulation
    GtpuDecapInfo decap{};
    bool dec_ok = GtpuEngine::Decapsulate(pkt, len, decap);
    assert(dec_ok && "CPU GtpuEngine::Decapsulate must parse 5G GTP-U with QFI header");
    assert(decap.has_seq && "Decapsulated packet must recognize sequence number");
  }

  cudaFree(d_arena);
  cudaFree(d_pkt_lens);
  cudaFree(d_cfg);
  std::printf("  -> [PASS] 5G GTP-U QFI (0x85) PDU session container byte-exact structure verified.\n");
}

// ---------------------------------------------------------------------------
// Test 3: 802.1Q Single VLAN & 802.1ad QinQ Dual VLAN Encapsulations
// ---------------------------------------------------------------------------
void TestVlanAndQinqEncapsulation() {
  std::printf("[TEST 3] Testing 802.1Q Single VLAN & 802.1ad QinQ encapsulations...\n");
  constexpr uint32_t kSlotStride = 2048;

  uint8_t* d_arena = nullptr;
  uint16_t* d_pkt_lens = nullptr;
  CheckCuda(cudaMalloc(&d_arena, 2 * kSlotStride), "alloc arena");
  CheckCuda(cudaMalloc(&d_pkt_lens, 2 * sizeof(uint16_t)), "alloc lens");

  // 1. Single VLAN (802.1Q, VID 100)
  TelcoGtpuStreamConfig h_cfg1{};
  h_cfg1.outer_src_ip = 0x0A000001;
  h_cfg1.outer_dst_ip = 0x0A000002;
  h_cfg1.ue_ip_start = 0x0AC80001;
  h_cfg1.ue_ip_count = 10;
  h_cfg1.inner_dst_ip = 0x08080808;
  h_cfg1.inner_proto = 17;
  h_cfg1.inner_src_port = 10000;
  h_cfg1.inner_dst_port = 8080;
  h_cfg1.inner_payload_size = 32;
  h_cfg1.teid_start = 2000;
  h_cfg1.teid_count = 10;
  h_cfg1.vlan_depth = 1;
  h_cfg1.svlan_tci = 100;

  // 2. QinQ Dual VLAN (802.1ad S-VLAN 200 + 802.1Q C-VLAN 300)
  TelcoGtpuStreamConfig h_cfg2 = h_cfg1;
  h_cfg2.teid_start = 3000;
  h_cfg2.vlan_depth = 2;
  h_cfg2.svlan_tci = 200;
  h_cfg2.cvlan_tci = 300;

  TelcoGtpuStreamConfig* d_cfg1 = nullptr;
  TelcoGtpuStreamConfig* d_cfg2 = nullptr;
  CheckCuda(cudaMalloc(&d_cfg1, sizeof(TelcoGtpuStreamConfig)), "alloc cfg1");
  CheckCuda(cudaMalloc(&d_cfg2, sizeof(TelcoGtpuStreamConfig)), "alloc cfg2");
  CheckCuda(cudaMemcpy(d_cfg1, &h_cfg1, sizeof(TelcoGtpuStreamConfig), cudaMemcpyHostToDevice), "cp cfg1");
  CheckCuda(cudaMemcpy(d_cfg2, &h_cfg2, sizeof(TelcoGtpuStreamConfig), cudaMemcpyHostToDevice), "cp cfg2");

  telco_gtpu_batch_kernel<<<1, 1>>>(d_arena, kSlotStride, 1, d_cfg1, nullptr, 0, d_pkt_lens);
  telco_gtpu_batch_kernel<<<1, 1>>>(d_arena + kSlotStride, kSlotStride, 1, d_cfg2, nullptr, 0, d_pkt_lens + 1);
  CheckCuda(cudaDeviceSynchronize(), "sync vlan");

  std::vector<uint16_t> h_lens(2);
  CheckCuda(cudaMemcpy(h_lens.data(), d_pkt_lens, 2 * sizeof(uint16_t), cudaMemcpyDeviceToHost), "cp lens");
  std::vector<uint8_t> h_arena(2 * kSlotStride);
  CheckCuda(cudaMemcpy(h_arena.data(), d_arena, 2 * kSlotStride, cudaMemcpyDeviceToHost), "cp arena");

  // Verify Single VLAN
  {
    const uint8_t* pkt = h_arena.data();
    const uint16_t ethertype = (static_cast<uint16_t>(pkt[12]) << 8) | pkt[13];
    assert(ethertype == 0x8100 && "Ethertype must be 0x8100 for single VLAN");
    const uint16_t tci = (static_cast<uint16_t>(pkt[14]) << 8) | pkt[15];
    assert((tci & 0x0FFF) == 100 && "VLAN VID mismatch (expected 100)");
    const uint16_t inner_ethertype = (static_cast<uint16_t>(pkt[16]) << 8) | pkt[17];
    assert(inner_ethertype == 0x0800 && "Inner ethertype after 802.1Q must be IPv4");
    GtpuDecapInfo decap{};
    assert(GtpuEngine::Decapsulate(pkt, h_lens[0], decap));
    assert(decap.teid == 2000);
  }

  // Verify QinQ Dual VLAN
  {
    const uint8_t* pkt = h_arena.data() + kSlotStride;
    const uint16_t stag_tpid = (static_cast<uint16_t>(pkt[12]) << 8) | pkt[13];
    assert(stag_tpid == 0x88A8 && "S-Tag TPID must be 0x88A8 (802.1ad)");
    const uint16_t s_tci = (static_cast<uint16_t>(pkt[14]) << 8) | pkt[15];
    assert((s_tci & 0x0FFF) == 200 && "S-VLAN VID mismatch (expected 200)");
    const uint16_t ctag_tpid = (static_cast<uint16_t>(pkt[16]) << 8) | pkt[17];
    assert(ctag_tpid == 0x8100 && "C-Tag TPID must be 0x8100 (802.1Q)");
    const uint16_t c_tci = (static_cast<uint16_t>(pkt[18]) << 8) | pkt[19];
    assert((c_tci & 0x0FFF) == 300 && "C-VLAN VID mismatch (expected 300)");
    const uint16_t inner_ethertype = (static_cast<uint16_t>(pkt[20]) << 8) | pkt[21];
    assert(inner_ethertype == 0x0800 && "Inner ethertype after QinQ must be IPv4");
    GtpuDecapInfo decap{};
    assert(GtpuEngine::Decapsulate(pkt, h_lens[1], decap));
    assert(decap.teid == 3000);
  }

  cudaFree(d_arena);
  cudaFree(d_pkt_lens);
  cudaFree(d_cfg1);
  cudaFree(d_cfg2);
  std::printf("  -> [PASS] 802.1Q Single VLAN & 802.1ad QinQ dual VLAN encapsulation verified.\n");
}

// ---------------------------------------------------------------------------
// Test 4: Inner TCP and ICMP Protocols & GPU Dual-Layer Checksums
// ---------------------------------------------------------------------------
void TestInnerTcpAndIcmpChecksums() {
  std::printf("[TEST 4] Testing inner TCP & ICMP dual-layer checksum calculations...\n");
  constexpr uint32_t kSlotStride = 2048;

  uint8_t* d_arena = nullptr;
  uint16_t* d_pkt_lens = nullptr;
  CheckCuda(cudaMalloc(&d_arena, 2 * kSlotStride), "alloc arena");
  CheckCuda(cudaMalloc(&d_pkt_lens, 2 * sizeof(uint16_t)), "alloc lens");

  // 1. Inner TCP (inner_proto = 6)
  TelcoGtpuStreamConfig h_cfg_tcp{};
  h_cfg_tcp.outer_src_ip = 0x0A000001;
  h_cfg_tcp.outer_dst_ip = 0x0A000002;
  h_cfg_tcp.ue_ip_start = 0x0AC80001;
  h_cfg_tcp.ue_ip_count = 1;
  h_cfg_tcp.inner_dst_ip = 0x08080808;
  h_cfg_tcp.inner_proto = 6; // TCP
  h_cfg_tcp.inner_src_port = 10001;
  h_cfg_tcp.inner_dst_port = 443;
  h_cfg_tcp.inner_payload_size = 64;
  h_cfg_tcp.teid_start = 4001;
  h_cfg_tcp.teid_count = 1;

  // 2. Inner ICMP (inner_proto = 1)
  TelcoGtpuStreamConfig h_cfg_icmp = h_cfg_tcp;
  h_cfg_icmp.inner_proto = 1; // ICMP
  h_cfg_icmp.teid_start = 4002;
  h_cfg_icmp.inner_payload_size = 32;

  TelcoGtpuStreamConfig* d_cfg_tcp = nullptr;
  TelcoGtpuStreamConfig* d_cfg_icmp = nullptr;
  CheckCuda(cudaMalloc(&d_cfg_tcp, sizeof(TelcoGtpuStreamConfig)), "alloc cfg tcp");
  CheckCuda(cudaMalloc(&d_cfg_icmp, sizeof(TelcoGtpuStreamConfig)), "alloc cfg icmp");
  CheckCuda(cudaMemcpy(d_cfg_tcp, &h_cfg_tcp, sizeof(TelcoGtpuStreamConfig), cudaMemcpyHostToDevice), "cp cfg tcp");
  CheckCuda(cudaMemcpy(d_cfg_icmp, &h_cfg_icmp, sizeof(TelcoGtpuStreamConfig), cudaMemcpyHostToDevice), "cp cfg icmp");

  telco_gtpu_batch_kernel<<<1, 1>>>(d_arena, kSlotStride, 1, d_cfg_tcp, nullptr, 0, d_pkt_lens);
  telco_gtpu_batch_kernel<<<1, 1>>>(d_arena + kSlotStride, kSlotStride, 1, d_cfg_icmp, nullptr, 0, d_pkt_lens + 1);
  CheckCuda(cudaDeviceSynchronize(), "sync tcp/icmp");

  std::vector<uint16_t> h_lens(2);
  CheckCuda(cudaMemcpy(h_lens.data(), d_pkt_lens, 2 * sizeof(uint16_t), cudaMemcpyDeviceToHost), "cp lens");
  std::vector<uint8_t> h_arena(2 * kSlotStride);
  CheckCuda(cudaMemcpy(h_arena.data(), d_arena, 2 * kSlotStride, cudaMemcpyDeviceToHost), "cp arena");

  // Verify Inner TCP
  {
    const uint8_t* pkt = h_arena.data();
    const uint8_t* inner_ip = pkt + 14 + 20 + 8 + 8;
    assert(inner_ip[9] == 6 && "Inner IP proto must be 6 (TCP)");
    assert(CalculateIpv4Checksum(inner_ip, 20) == 0 && "Inner IPv4 checksum failed for TCP");
    const uint8_t* tcp = inner_ip + 20;
    const uint16_t dport = (static_cast<uint16_t>(tcp[2]) << 8) | tcp[3];
    assert(dport == 443 && "TCP dst port mismatch (expected 443)");
    const uint32_t src_ip = (static_cast<uint32_t>(inner_ip[12]) << 24) |
                            (static_cast<uint32_t>(inner_ip[13]) << 16) |
                            (static_cast<uint32_t>(inner_ip[14]) << 8)  |
                            inner_ip[15];
    const uint32_t dst_ip = (static_cast<uint32_t>(inner_ip[16]) << 24) |
                            (static_cast<uint32_t>(inner_ip[17]) << 16) |
                            (static_cast<uint32_t>(inner_ip[18]) << 8)  |
                            inner_ip[19];
    assert(CalculateL4Checksum(src_ip, dst_ip, 6, tcp, 20 + 64) == 0 &&
           "Inner TCP checksum verification failed");
  }

  // Verify Inner ICMP
  {
    const uint8_t* pkt = h_arena.data() + kSlotStride;
    const uint8_t* inner_ip = pkt + 14 + 20 + 8 + 8;
    assert(inner_ip[9] == 1 && "Inner IP proto must be 1 (ICMP)");
    assert(CalculateIpv4Checksum(inner_ip, 20) == 0 && "Inner IPv4 checksum failed for ICMP");
    const uint8_t* icmp = inner_ip + 20;
    assert(icmp[0] == 8 && "ICMP type must be Echo Request (8)");
    assert(icmp[1] == 0 && "ICMP code must be 0");
    uint32_t sum = 0;
    for (size_t i = 0; i < 8 + 32; i += 2) {
      sum += (static_cast<uint32_t>(icmp[i]) << 8) | icmp[i + 1];
    }
    while (sum >> 16) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    assert(static_cast<uint16_t>(~sum & 0xFFFF) == 0 && "Inner ICMP checksum verification failed");
  }

  cudaFree(d_arena);
  cudaFree(d_pkt_lens);
  cudaFree(d_cfg_tcp);
  cudaFree(d_cfg_icmp);
  std::printf("  -> [PASS] Inner TCP and ICMP protocols & GPU dual-layer checksums verified.\n");
}

// ---------------------------------------------------------------------------
// Test 5: Dynamic Tunnel Table Seqlock Upsert & Clear
// ---------------------------------------------------------------------------
void TestDynamicTunnelTableSeqlock() {
  std::printf("[TEST 5] Testing dynamic seqlock tunnel table upsert & clear...\n");
  constexpr uint32_t kNumTunnels = 4;
  constexpr uint32_t kSlotStride = 2048;

  std::vector<TelcoGpuTunnelEntryV1> entries(kNumTunnels);
  for (uint32_t i = 0; i < kNumTunnels; ++i) {
    entries[i].version = 0;
    entries[i].flags = static_cast<uint8_t>(TelcoGpuTunnelFlags::kActive) |
                       static_cast<uint8_t>(TelcoGpuTunnelFlags::kWithQfiExt);
    entries[i].vlan_depth = 1;
    entries[i].qfi = 40 + i;
    entries[i].pdu_type = 1; // UL
    entries[i].inner_proto = 17; // UDP
    entries[i].uplink_teid = 0xAA000000 + i;
    entries[i].downlink_teid = 0xBB000000 + i;
    entries[i].outer_src_ip = 0x0A010101;
    entries[i].outer_dst_ip = 0x0A020202;
    entries[i].ue_src_ip = 0x0AC80001 + i;
    entries[i].inner_dst_ip = 0x08080808;
    entries[i].svlan_tci = 500 + i;
    entries[i].cvlan_tci = 0;
    entries[i].inner_src_port = 15000 + i;
    entries[i].inner_dst_port = 80;
  }

  int up_rc = samurai_gpu_packet_telco_upsert_tunnels_v1(entries.data(), kNumTunnels);
  assert(up_rc == 0 && "samurai_gpu_packet_telco_upsert_tunnels_v1 failed");

  uint8_t* d_arena = nullptr;
  uint16_t* d_pkt_lens = nullptr;
  TelcoGpuTunnelEntryV1* d_tunnels = nullptr;
  CheckCuda(cudaMalloc(&d_arena, kNumTunnels * kSlotStride), "alloc arena");
  CheckCuda(cudaMalloc(&d_pkt_lens, kNumTunnels * sizeof(uint16_t)), "alloc lens");
  CheckCuda(cudaMalloc(&d_tunnels, kNumTunnels * sizeof(TelcoGpuTunnelEntryV1)), "alloc tunnels");
  CheckCuda(cudaMemcpy(d_tunnels, entries.data(), kNumTunnels * sizeof(TelcoGpuTunnelEntryV1), cudaMemcpyHostToDevice), "cp tunnels");

  telco_gtpu_batch_kernel<<<1, 32>>>(
      d_arena, kSlotStride, kNumTunnels, nullptr, d_tunnels, kNumTunnels, d_pkt_lens);
  CheckCuda(cudaDeviceSynchronize(), "sync tunnel batch");

  std::vector<uint16_t> h_lens(kNumTunnels);
  CheckCuda(cudaMemcpy(h_lens.data(), d_pkt_lens, kNumTunnels * sizeof(uint16_t), cudaMemcpyDeviceToHost), "cp lens");
  std::vector<uint8_t> h_arena(kNumTunnels * kSlotStride);
  CheckCuda(cudaMemcpy(h_arena.data(), d_arena, kNumTunnels * kSlotStride, cudaMemcpyDeviceToHost), "cp arena");

  for (uint32_t i = 0; i < kNumTunnels; ++i) {
    const uint8_t* pkt = h_arena.data() + i * kSlotStride;
    const uint32_t len = h_lens[i];
    GtpuDecapInfo decap{};
    bool dec_ok = GtpuEngine::Decapsulate(pkt, len, decap);
    assert(dec_ok && "Decapsulation failed for seqlock-driven tunnel packet");
    assert(decap.teid == entries[i].uplink_teid && "Uplink TEID must match seqlock table entry");

    // Check VLAN VID
    const uint16_t tci = (static_cast<uint16_t>(pkt[14]) << 8) | pkt[15];
    assert((tci & 0x0FFF) == (500 + i) && "VLAN VID must match seqlock table entry");

    // Check 5G QFI
    const uint8_t* gtp = pkt + 14 + 4 + 20 + 8; // Eth (14) + VLAN (4) + IP (20) + UDP (8)
    const uint8_t* opt = gtp + 8;
    const uint8_t* pdu_ext = opt + 4;
    const uint8_t qfi = pdu_ext[2] & 0x3F;
    assert(qfi == (40 + i) && "QFI must match seqlock table entry");
  }

  // Clear tunnels
  int clr_rc = samurai_gpu_packet_telco_clear_tunnels_v1();
  assert(clr_rc == 0 && "samurai_gpu_packet_telco_clear_tunnels_v1 failed");

  cudaFree(d_arena);
  cudaFree(d_pkt_lens);
  cudaFree(d_tunnels);
  std::printf("  -> [PASS] Dynamic seqlock tunnel table upsert & clear verified.\n");
}

// ---------------------------------------------------------------------------
// Test 6: BAR1 RX Verification & SLA Kernel
// ---------------------------------------------------------------------------
void TestBar1RxVerificationAndSlaKernel() {
  std::printf("[TEST 6] Testing BAR1 RX GTP-U verification and SLA telemetries...\n");
  constexpr uint32_t kCount = 8;
  constexpr uint32_t kSlotStride = 2048;
  constexpr uint8_t kTargetQfi = 15;

  uint8_t* d_arena = nullptr;
  uint16_t* d_pkt_lens = nullptr;
  CheckCuda(cudaMalloc(&d_arena, kCount * kSlotStride), "alloc arena");
  CheckCuda(cudaMalloc(&d_pkt_lens, kCount * sizeof(uint16_t)), "alloc lens");

  TelcoGtpuStreamConfig h_cfg{};
  h_cfg.outer_src_ip = 0x0A000001;
  h_cfg.outer_dst_ip = 0x0A000002;
  h_cfg.ue_ip_start = 0x0AC80001;
  h_cfg.ue_ip_count = 10;
  h_cfg.inner_dst_ip = 0x08080808;
  h_cfg.inner_proto = 17;
  h_cfg.inner_src_port = 10000;
  h_cfg.inner_dst_port = 8080;
  h_cfg.inner_payload_size = 32;
  h_cfg.teid_start = 7000;
  h_cfg.teid_count = 10;
  h_cfg.vlan_depth = 0;
  h_cfg.with_seq = 1;
  h_cfg.with_qfi_ext = 1;
  h_cfg.qfi = kTargetQfi;
  h_cfg.pdu_type = 1;

  TelcoGtpuStreamConfig* d_cfg = nullptr;
  CheckCuda(cudaMalloc(&d_cfg, sizeof(TelcoGtpuStreamConfig)), "alloc cfg");
  CheckCuda(cudaMemcpy(d_cfg, &h_cfg, sizeof(TelcoGtpuStreamConfig), cudaMemcpyHostToDevice), "cp cfg");

  telco_gtpu_batch_kernel<<<1, 32>>>(
      d_arena, kSlotStride, kCount, d_cfg, nullptr, 0, d_pkt_lens);
  CheckCuda(cudaDeviceSynchronize(), "sync gen");

  // Run BAR1 RX verification
  TelcoGpuRxStatsV1 stats{};
  int ver_rc = samurai_gpu_packet_telco_verify_rx_batch_v1(d_arena, kSlotStride, kCount, &stats);
  assert(ver_rc == 0 && "samurai_gpu_packet_telco_verify_rx_batch_v1 failed");
  CheckCuda(cudaDeviceSynchronize(), "sync rx verify");

  assert(stats.rx_packets == kCount && "rx_packets stat mismatch");
  assert(stats.rx_gtpu_packets == kCount && "rx_gtpu_packets stat mismatch");
  assert(stats.rx_qfi_packets[kTargetQfi] == kCount && "rx_qfi_packets bucket mismatch");
  assert(stats.rx_invalid_checksum == 0 && "rx_invalid_checksum must be zero for valid packets");

  // Intentionally corrupt the inner IPv4 checksum of slot 0 to test error detection
  uint8_t corrupt_byte = 0xFF;
  // slot 0 inner IP csum offset: Eth(14) + IP(20) + UDP(8) + GTP(8) + Seq(4) + QFI(4) + InnerIP_csum(10)
  CheckCuda(cudaMemcpy(d_arena + 14 + 20 + 8 + 8 + 4 + 4 + 10, &corrupt_byte, 1, cudaMemcpyHostToDevice), "corrupt csum");

  // Run verification again
  TelcoGpuRxStatsV1 stats2{};
  ver_rc = samurai_gpu_packet_telco_verify_rx_batch_v1(d_arena, kSlotStride, kCount, &stats2);
  assert(ver_rc == 0);
  CheckCuda(cudaDeviceSynchronize(), "sync corrupt verify");
  assert(stats2.rx_invalid_checksum >= 1 && "Corrupted packet must increment rx_invalid_checksum");

  cudaFree(d_arena);
  cudaFree(d_pkt_lens);
  cudaFree(d_cfg);
  std::printf("  -> [PASS] BAR1 RX GTP-U verification and SLA telemetries verified.\n");
}

// ---------------------------------------------------------------------------
// Test 7: Exported C ABI Generation with JSON Profile
// ---------------------------------------------------------------------------
void TestExportedCAbiJsonGeneration() {
  std::printf("[TEST 7] Testing samurai_gpu_packet_generate_gtpu_packets C ABI with JSON profile...\n");
  const char* config_json =
      "{\n"
      "  \"stream_type\": \"gtpu\",\n"
      "  \"teid_start\": 8888,\n"
      "  \"teid_count\": 5,\n"
      "  \"ue_subnet\": \"10.88.0.0/24\",\n"
      "  \"inner_dst_ip\": \"1.1.1.1\",\n"
      "  \"inner_proto\": \"udp\",\n"
      "  \"with_qfi\": true,\n"
      "  \"qfi\": 7,\n"
      "  \"pdu_type\": 1\n"
      "}";

  void* out_pkts = nullptr;
  size_t total_bytes = 0;
  int pkt_size = 0;
  int rc = samurai_gpu_packet_generate_gtpu_packets(config_json, 10, &out_pkts, &total_bytes, &pkt_size);
  assert(rc == 0 && "samurai_gpu_packet_generate_gtpu_packets failed");
  assert(out_pkts != nullptr);
  assert(total_bytes > 0);
  assert(pkt_size > 0);

  std::vector<uint8_t> h_pkt(pkt_size);
  CheckCuda(cudaMemcpy(h_pkt.data(), out_pkts, pkt_size, cudaMemcpyDeviceToHost), "cp C ABI pkt");
  GtpuDecapInfo decap{};
  bool dec_ok = GtpuEngine::Decapsulate(h_pkt.data(), pkt_size, decap);
  assert(dec_ok && "Decapsulate failed on C ABI generated packet");
  assert(decap.teid == 8888 && "TEID mismatch on C ABI generated packet");
  assert(decap.has_seq && "Sequence number expected on C ABI packet");

  cudaFree(out_pkts);

  std::printf("  -> [PASS] Exported C ABI JSON profile generation verified (pkt_size=%d, total_bytes=%zu).\n",
              pkt_size, total_bytes);
}

} // namespace

int main() {
  std::printf("=================================================================\n");
  std::printf("      CUDA GEFORCE TELECOM GTP-U / 5G QFI VERIFICATION SUITE     \n");
  std::printf("=================================================================\n");

  int dev_count = 0;
  if (cudaGetDeviceCount(&dev_count) != cudaSuccess || dev_count <= 0) {
    std::printf("[SKIP] No CUDA GPU available.\n");
    return 0;
  }

  TestBasic4gGtpuGeneration();
  Test5gGtpuQfiGeneration();
  TestVlanAndQinqEncapsulation();
  TestInnerTcpAndIcmpChecksums();
  TestDynamicTunnelTableSeqlock();
  TestBar1RxVerificationAndSlaKernel();
  TestExportedCAbiJsonGeneration();

  std::printf("=================================================================\n");
  std::printf("  ALL CUDA GEFORCE TELECOM KERNEL TESTS PASSED SUCCESSFULLY!     \n");
  std::printf("=================================================================\n");
  return 0;
}
