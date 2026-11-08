#pragma once

#include <cuda_runtime.h>
#include <cstdint>

#include "ddos_samurai/gpu_packet_cuda/zero_copy_dataplane_contract.cuh"

namespace ddos_samurai::gpu_packet_cuda::telecom {

using ::ddos_samurai::gpu_packet_cuda::zero_copy::TelcoGpuTunnelEntryV1;
using ::ddos_samurai::gpu_packet_cuda::zero_copy::TelcoGpuRxStatsV1;
using ::ddos_samurai::gpu_packet_cuda::zero_copy::TelcoGpuTunnelFlags;
using ::ddos_samurai::gpu_packet_cuda::zero_copy::DpuCupsSharedRegionHeaderV1;

// 3GPP TS 29.281 & 38.415 Constants
constexpr uint16_t kGtpuUdpPort = 2152;
constexpr uint8_t  kGtpuVersion1BaseFlags = 0x30; // Version 1, PT = 1
constexpr uint8_t  kGtpuFlagE = 0x04;            // Extension header present
constexpr uint8_t  kGtpuFlagS = 0x02;            // Sequence number present
constexpr uint8_t  kGtpuFlagPn = 0x01;           // N-PDU present

constexpr uint8_t  kGtpuMsgEchoRequest = 1;
constexpr uint8_t  kGtpuMsgEchoResponse = 2;
constexpr uint8_t  kGtpuMsgErrorIndication = 26;
constexpr uint8_t  kGtpuMsgGPdu = 255;

constexpr uint8_t  kGtpuExtType5gPduSessionContainer = 0x85; // 3GPP TS 38.415

// Ethernet EtherTypes (Network Endian)
constexpr uint16_t kEthTypeIpv4Net = 0x0008; // 0x0800 in LE representation when bytes swapped
constexpr uint16_t kEthTypeDot1QNet = 0x0081; // 0x8100
constexpr uint16_t kEthTypeDot1AdNet = 0xA888; // 0x88A8

struct TelcoGtpuStreamConfig {
  uint32_t teid_start;
  uint32_t teid_count;
  uint32_t ue_ip_start;     // Host-order IPv4 or network order
  uint32_t ue_ip_count;
  uint32_t inner_dst_ip;    // Network order IPv4
  uint32_t outer_src_ip;    // Network order IPv4
  uint32_t outer_dst_ip;    // Network order IPv4
  uint16_t inner_src_port;
  uint16_t inner_dst_port;
  uint16_t svlan_tci;
  uint16_t cvlan_tci;
  uint8_t  qfi;             // 0..63
  uint8_t  pdu_type;        // 1=UL, 0=DL
  uint8_t  inner_proto;     // 17=UDP, 6=TCP, 1=ICMP
  uint8_t  vlan_depth;      // 0, 1, 2
  uint8_t  with_seq;
  uint8_t  with_qfi_ext;
  uint8_t  echo_mode;
  uint8_t  outer_src_mac[6];
  uint8_t  outer_dst_mac[6];
  uint16_t inner_payload_size; // Inner L4 payload size (default e.g. 32-64 bytes)
};

// ---------------------------------------------------------------------------
// Device Checksum Utilities (Ones' Complement)
// ---------------------------------------------------------------------------

__device__ __forceinline__ uint16_t device_ip_checksum(const uint8_t* buf, int len) {
  uint32_t sum = 0;
  for (int i = 0; i < (len & ~1); i += 2) {
    sum += (static_cast<uint32_t>(buf[i]) << 8) | buf[i + 1];
  }
  if (len & 1) {
    sum += static_cast<uint32_t>(buf[len - 1]) << 8;
  }
  while (sum >> 16) {
    sum = (sum & 0xFFFFu) + (sum >> 16);
  }
  return static_cast<uint16_t>(~sum & 0xFFFFu);
}

__device__ __forceinline__ uint16_t device_l4_checksum(
    uint32_t src_ip_net,
    uint32_t dst_ip_net,
    uint8_t proto,
    const uint8_t* l4_data,
    int l4_len) {
  uint32_t sum = 0;
  // Pseudo-header: Src IP & Dst IP
  sum += (src_ip_net >> 16) & 0xFFFFu;
  sum += src_ip_net & 0xFFFFu;
  sum += (dst_ip_net >> 16) & 0xFFFFu;
  sum += dst_ip_net & 0xFFFFu;
  sum += static_cast<uint32_t>(proto);
  sum += static_cast<uint32_t>(l4_len);

  for (int i = 0; i < (l4_len & ~1); i += 2) {
    sum += (static_cast<uint32_t>(l4_data[i]) << 8) | l4_data[i + 1];
  }
  if (l4_len & 1) {
    sum += static_cast<uint32_t>(l4_data[l4_len - 1]) << 8;
  }
  while (sum >> 16) {
    sum = (sum & 0xFFFFu) + (sum >> 16);
  }
  uint16_t csum = static_cast<uint16_t>(~sum & 0xFFFFu);
  return (csum == 0) ? 0xFFFFu : csum;
}

// ---------------------------------------------------------------------------
// Device Packet Builder
// ---------------------------------------------------------------------------

__device__ __forceinline__ void device_write16(uint8_t* dst, uint16_t val) {
  dst[0] = static_cast<uint8_t>((val >> 8) & 0xFFu);
  dst[1] = static_cast<uint8_t>(val & 0xFFu);
}

__device__ __forceinline__ void device_write32(uint8_t* dst, uint32_t val) {
  dst[0] = static_cast<uint8_t>((val >> 24) & 0xFFu);
  dst[1] = static_cast<uint8_t>((val >> 16) & 0xFFu);
  dst[2] = static_cast<uint8_t>((val >> 8) & 0xFFu);
  dst[3] = static_cast<uint8_t>(val & 0xFFu);
}

__device__ __forceinline__ uint32_t device_resolve_telco_tunnel_span(
    uint32_t configured_count,
    const DpuCupsSharedRegionHeaderV1* cups_hdr) {
  if (!cups_hdr) {
    return configured_count;
  }
  const volatile DpuCupsSharedRegionHeaderV1* vhdr = cups_hdr;
  if (vhdr->magic != ::ddos_samurai::gpu_packet_cuda::zero_copy::kDpuCupsSharedMagicV1 ||
      vhdr->version != ::ddos_samurai::gpu_packet_cuda::zero_copy::kDpuCupsSharedVersionV1) {
    return 0u;
  }
  __threadfence_system();
  const uint32_t cap = vhdr->capacity;
  const uint32_t span = vhdr->active_span;
  const uint32_t bound = (configured_count > 0u && configured_count < cap) ? configured_count : cap;
  return (span <= bound) ? span : bound;
}

__device__ __forceinline__ uint32_t device_write_gtpu_packet(
    uint8_t* buf,
    uint32_t max_buf_len,
    uint32_t packet_index,
    const TelcoGtpuStreamConfig* cfg,
    const TelcoGpuTunnelEntryV1* tunnel_table,
    uint32_t tunnel_table_count) {
  if (!buf || max_buf_len < 50u) {
    return 0u;
  }

  // Determine Tunnel Parameters (Seqlock dynamic lookup vs Algorithmic sweep)
  uint32_t teid = 0u;
  uint32_t outer_src_ip = 0u;
  uint32_t outer_dst_ip = 0u;
  uint32_t ue_src_ip = 0u;
  uint32_t inner_dst_ip = 0u;
  uint16_t svlan_tci = 0u;
  uint16_t cvlan_tci = 0u;
  uint16_t inner_src_port = 0u;
  uint16_t inner_dst_port = 0u;
  uint8_t  qfi = 0u;
  uint8_t  pdu_type = 1u;
  uint8_t  inner_proto = 17u;
  uint8_t  vlan_depth = 0u;
  uint8_t  flags = 0u;
  uint8_t  dst_mac[6] = {0x00, 0x0F, 0x53, 0x21, 0x52, 0x01};
  uint8_t  src_mac[6] = {0x00, 0x0F, 0x53, 0x21, 0x52, 0x02};

  if (cfg) {
    for (int i = 0; i < 6; ++i) {
      src_mac[i] = cfg->outer_src_mac[i];
      dst_mac[i] = cfg->outer_dst_mac[i];
    }
  }

  const TelcoGpuTunnelEntryV1* matched_tunnel = nullptr;
  bool resolved_from_tunnel = false;

  if (tunnel_table && tunnel_table_count > 0u) {
    const uint32_t max_probes = (tunnel_table_count < 8u) ? tunnel_table_count : 8u;
    for (uint32_t probe = 0u; probe < max_probes && !resolved_from_tunnel; ++probe) {
      const uint32_t t_idx = (packet_index + probe) % tunnel_table_count;
      const TelcoGpuTunnelEntryV1* t = &tunnel_table[t_idx];
      const volatile TelcoGpuTunnelEntryV1* vt = t;
      uint64_t v0 = 0ull, v1 = 0ull;
      uint32_t cand_ul_teid = 0u;
      uint32_t cand_dl_teid = 0u;
      uint32_t cand_outer_src_ip = 0u;
      uint32_t cand_outer_dst_ip = 0u;
      uint32_t cand_ue_src_ip = 0u;
      uint32_t cand_inner_dst_ip = 0u;
      uint16_t cand_svlan_tci = 0u;
      uint16_t cand_cvlan_tci = 0u;
      uint16_t cand_inner_src_port = 0u;
      uint16_t cand_inner_dst_port = 0u;
      uint8_t  cand_qfi = 0u;
      uint8_t  cand_pdu_type = 1u;
      uint8_t  cand_inner_proto = 17u;
      uint8_t  cand_vlan_depth = 0u;
      uint8_t  cand_flags = 0u;
      uint8_t  cand_dmac[6] = {0};

      bool snap_ok = false;
      for (int spin = 0; spin < 16; ++spin) {
        v0 = vt->version;
        __threadfence_system();
        if ((v0 & 1ull) != 0ull) {
          continue;
        }
        cand_ul_teid = vt->uplink_teid;
        cand_dl_teid = vt->downlink_teid;
        cand_outer_src_ip = vt->outer_src_ip;
        cand_outer_dst_ip = vt->outer_dst_ip;
        cand_ue_src_ip = vt->ue_src_ip;
        cand_inner_dst_ip = vt->inner_dst_ip;
        cand_svlan_tci = vt->svlan_tci;
        cand_cvlan_tci = vt->cvlan_tci;
        cand_inner_src_port = vt->inner_src_port;
        cand_inner_dst_port = vt->inner_dst_port;
        cand_qfi = vt->qfi;
        cand_pdu_type = vt->pdu_type;
        cand_inner_proto = vt->inner_proto;
        cand_vlan_depth = vt->vlan_depth;
        cand_flags = vt->flags;
        for (int i = 0; i < 6; ++i) {
          cand_dmac[i] = vt->outer_dst_mac[i];
        }
        __threadfence_system();
        v1 = vt->version;
        if (v0 == v1 && (v0 & 1ull) == 0ull) {
          snap_ok = true;
          break;
        }
      }

      if (snap_ok && (cand_flags & static_cast<uint8_t>(TelcoGpuTunnelFlags::kActive)) != 0u) {
        teid = (cand_pdu_type == 0u && cand_dl_teid != 0u)
                   ? cand_dl_teid
                   : (cand_ul_teid != 0u ? cand_ul_teid : cand_dl_teid);
        outer_src_ip = cand_outer_src_ip;
        outer_dst_ip = cand_outer_dst_ip;
        ue_src_ip = cand_ue_src_ip;
        inner_dst_ip = cand_inner_dst_ip;
        svlan_tci = cand_svlan_tci;
        cvlan_tci = cand_cvlan_tci;
        inner_src_port = cand_inner_src_port ? cand_inner_src_port
                                             : static_cast<uint16_t>(10000u + (packet_index & 0x3FFFu));
        inner_dst_port = cand_inner_dst_port ? cand_inner_dst_port : 80u;
        qfi = cand_qfi;
        pdu_type = cand_pdu_type;
        inner_proto = cand_inner_proto ? cand_inner_proto : 17u;
        vlan_depth = cand_vlan_depth;
        flags = cand_flags;
        bool has_custom_dmac = false;
        for (int i = 0; i < 6; ++i) {
          if (cand_dmac[i] != 0u) {
            has_custom_dmac = true;
            break;
          }
        }
        if (has_custom_dmac) {
          for (int i = 0; i < 6; ++i) {
            dst_mac[i] = cand_dmac[i];
          }
        }
        matched_tunnel = t;
        resolved_from_tunnel = true;
      }
    }
  }

  if (!resolved_from_tunnel) {
    if (!cfg) {
      return 0u;
    }
    const uint32_t teid_c = (cfg->teid_count > 0u) ? cfg->teid_count : 1u;
    const uint32_t ue_c = (cfg->ue_ip_count > 0u) ? cfg->ue_ip_count : 1u;
    teid = cfg->teid_start + (packet_index % teid_c);

    // Calculate algorithmic UE IP
    const uint32_t ue_off = packet_index % ue_c;
    ue_src_ip = cfg->ue_ip_start + ue_off;

    outer_src_ip = cfg->outer_src_ip;
    outer_dst_ip = cfg->outer_dst_ip;
    inner_dst_ip = cfg->inner_dst_ip;
    svlan_tci = cfg->svlan_tci;
    cvlan_tci = cfg->cvlan_tci;
    inner_src_port = cfg->inner_src_port ? cfg->inner_src_port : static_cast<uint16_t>(10000 + (packet_index & 0x3FFF));
    inner_dst_port = cfg->inner_dst_port ? cfg->inner_dst_port : 80;
    qfi = cfg->qfi;
    pdu_type = cfg->pdu_type;
    inner_proto = cfg->inner_proto ? cfg->inner_proto : 17;
    vlan_depth = cfg->vlan_depth;
    if (cfg->with_seq) flags |= static_cast<uint8_t>(TelcoGpuTunnelFlags::kWithSeq);
    if (cfg->with_qfi_ext) flags |= static_cast<uint8_t>(TelcoGpuTunnelFlags::kWithQfiExt);
    if (cfg->echo_mode) flags |= static_cast<uint8_t>(TelcoGpuTunnelFlags::kEchoMode);
  }

  if (vlan_depth > 2u) {
    vlan_depth = 2u;
  }

  const bool is_echo = (flags & static_cast<uint8_t>(TelcoGpuTunnelFlags::kEchoMode)) != 0;
  const bool with_seq = (flags & static_cast<uint8_t>(TelcoGpuTunnelFlags::kWithSeq)) != 0 || is_echo;
  const bool with_qfi = (flags & static_cast<uint8_t>(TelcoGpuTunnelFlags::kWithQfiExt)) != 0 && !is_echo;
  const int user_data_len = (cfg && cfg->inner_payload_size >= 16) ? static_cast<int>(cfg->inner_payload_size) : 32;

  // Strict pre-write bounds check (prevents any BAR1/VRAM out-of-bounds write)
  const uint32_t eth_hdr_bytes = 14u + (vlan_depth == 2u ? 8u : (vlan_depth == 1u ? 4u : 0u));
  const uint32_t gtp_hdr_bytes = 8u + ((with_seq || with_qfi) ? 4u : 0u) + (with_qfi ? 4u : 0u);
  const uint32_t inner_l4_hdr_bytes = (inner_proto == 6u) ? 20u : 8u;
  const uint32_t inner_total_bytes = is_echo ? 0u : (20u + inner_l4_hdr_bytes + static_cast<uint32_t>(user_data_len));
  const uint32_t outer_ip_total_bytes = 20u + 8u + gtp_hdr_bytes + inner_total_bytes;
  const uint32_t required_frame_bytes = eth_hdr_bytes + outer_ip_total_bytes;
  if (outer_ip_total_bytes > 65535u || max_buf_len < required_frame_bytes) {
    return 0u;
  }

  // Offsets and layout construction
  int off = 0;
  // 1. Ethernet Header (DMAC + SMAC)
  for (int i = 0; i < 6; ++i) buf[off++] = dst_mac[i];
  for (int i = 0; i < 6; ++i) buf[off++] = src_mac[i];

  if (vlan_depth == 2) {
    // 802.1ad QinQ: Outer SVLAN (0x88A8) + Inner CVLAN (0x8100)
    device_write16(buf + off, 0x88A8); off += 2;
    device_write16(buf + off, svlan_tci); off += 2;
    device_write16(buf + off, 0x8100); off += 2;
    device_write16(buf + off, cvlan_tci); off += 2;
  } else if (vlan_depth == 1) {
    // 802.1Q: Single VLAN (0x8100)
    device_write16(buf + off, 0x8100); off += 2;
    device_write16(buf + off, cvlan_tci ? cvlan_tci : svlan_tci); off += 2;
  }
  // EtherType: IPv4 (0x0800)
  device_write16(buf + off, 0x0800); off += 2;

  // 2. Outer IPv4 Header
  const int outer_ip_off = off;
  buf[off++] = 0x45; // Version 4, IHL 5
  buf[off++] = 0x00; // DSCP / ECN
  const int outer_ip_len_off = off;
  off += 2; // Outer IP Total Length (filled later)
  device_write16(buf + off, static_cast<uint16_t>(packet_index & 0xFFFFu)); off += 2;
  device_write16(buf + off, 0x4000); off += 2; // Don't fragment
  buf[off++] = 64;   // TTL
  buf[off++] = 17;   // Protocol: UDP
  const int outer_ip_csum_off = off;
  off += 2; // IP Checksum (filled later)
  device_write32(buf + off, outer_src_ip); off += 4;
  device_write32(buf + off, outer_dst_ip); off += 4;

  // 3. Outer UDP Header
  const int outer_udp_off = off;
  device_write16(buf + off, kGtpuUdpPort); off += 2;
  device_write16(buf + off, kGtpuUdpPort); off += 2;
  const int outer_udp_len_off = off;
  off += 2; // UDP Total Length (filled later)
  buf[off++] = 0x00; buf[off++] = 0x00; // UDP Checksum (0 = optional in IPv4 GTP-U)

  // 4. GTP-U Header (3GPP TS 29.281)
  const int gtp_hdr_off = off;
  uint8_t gtp_flags = kGtpuVersion1BaseFlags;
  if (with_seq) gtp_flags |= kGtpuFlagS;
  if (with_qfi) gtp_flags |= kGtpuFlagE;

  buf[off++] = gtp_flags;
  buf[off++] = is_echo ? kGtpuMsgEchoRequest : kGtpuMsgGPdu;
  const int gtp_len_off = off;
  off += 2; // GTP Payload Length (following bytes after 8B header)
  device_write32(buf + off, teid); off += 4;

  if (with_seq || with_qfi) {
    // 4-byte Optional Fields: Sequence (2B) + N-PDU (1B) + Next Extension Type (1B)
    const uint16_t seq_val = static_cast<uint16_t>((packet_index + 1u) & 0xFFFFu);
    device_write16(buf + off, with_seq ? seq_val : 0u); off += 2;
    buf[off++] = 0x00; // N-PDU
    buf[off++] = with_qfi ? kGtpuExtType5gPduSessionContainer : 0x00; // Next Ext
  }

  if (with_qfi) {
    // 3GPP TS 38.415: PDU Session Container (Type 0x85)
    // Ext Hdr Len: 1 (1 x 4 = 4 bytes total including len & next_ext)
    buf[off++] = 1; // 4-byte unit
    // Octet 2: PDU Type (bits 7-4: 1=UL, 0=DL), Spare (bits 3-0)
    buf[off++] = static_cast<uint8_t>((pdu_type & 0x0F) << 4);
    // Octet 3: Spare/PPI (bits 7-6), QFI (bits 5-0: 0..63)
    buf[off++] = static_cast<uint8_t>(qfi & 0x3F);
    // Octet 4: Next extension header type (0 = No more extension headers)
    buf[off++] = 0x00;
  }

  if (is_echo) {
    // GTP-U Echo Request payload: empty or 0 bytes inner payload
  } else {
    // 5. Inner IPv4 Header
    const int inner_ip_off = off;
    buf[off++] = 0x45;
    buf[off++] = 0x00;
    const int inner_ip_len_off = off;
    off += 2; // Inner IP Total Length
    device_write16(buf + off, static_cast<uint16_t>((packet_index ^ 0x5A5A) & 0xFFFFu)); off += 2;
    device_write16(buf + off, 0x4000); off += 2; // DF
    buf[off++] = 64;   // TTL
    buf[off++] = inner_proto;
    const int inner_ip_csum_off = off;
    off += 2; // Inner IP Checksum
    device_write32(buf + off, ue_src_ip); off += 4;
    device_write32(buf + off, inner_dst_ip); off += 4;

    // 6. Inner L4 Header + Payload
    const int inner_l4_off = off;

    if (inner_proto == 17) {
      // Inner UDP
      device_write16(buf + off, inner_src_port); off += 2;
      device_write16(buf + off, inner_dst_port); off += 2;
      const int inner_udp_len_off = off;
      off += 2;
      const int inner_udp_csum_off = off;
      off += 2;

      // Inner Payload pattern
      for (int i = 0; i < user_data_len; ++i) {
        buf[off++] = static_cast<uint8_t>((packet_index + i) & 0xFF);
      }
      const int inner_udp_len = off - inner_l4_off;
      device_write16(buf + inner_udp_len_off, static_cast<uint16_t>(inner_udp_len));

      // Calculate Inner UDP Checksum
      buf[inner_udp_csum_off] = 0;
      buf[inner_udp_csum_off + 1] = 0;
      uint16_t csum = device_l4_checksum(ue_src_ip, inner_dst_ip, 17, buf + inner_l4_off, inner_udp_len);
      device_write16(buf + inner_udp_csum_off, csum);

    } else if (inner_proto == 6) {
      // Inner TCP (20B min header)
      device_write16(buf + off, inner_src_port); off += 2;
      device_write16(buf + off, inner_dst_port); off += 2;
      device_write32(buf + off, packet_index * 1460u + 1u); off += 4; // Seq
      device_write32(buf + off, 0x12345678u); off += 4;               // Ack
      buf[off++] = 0x50; // Data offset: 5 words (20 bytes)
      buf[off++] = 0x18; // Flags: ACK | PSH
      device_write16(buf + off, 64240); off += 2; // Window
      const int inner_tcp_csum_off = off;
      off += 2;
      buf[off++] = 0; buf[off++] = 0; // Urgent pointer

      for (int i = 0; i < user_data_len; ++i) {
        buf[off++] = static_cast<uint8_t>((packet_index + i) & 0xFF);
      }
      const int inner_tcp_len = off - inner_l4_off;
      buf[inner_tcp_csum_off] = 0;
      buf[inner_tcp_csum_off + 1] = 0;
      uint16_t csum = device_l4_checksum(ue_src_ip, inner_dst_ip, 6, buf + inner_l4_off, inner_tcp_len);
      device_write16(buf + inner_tcp_csum_off, csum);

    } else {
      // Inner ICMP Echo (8B header + data)
      buf[off++] = 0x08; // Type: Echo Request
      buf[off++] = 0x00; // Code: 0
      const int icmp_csum_off = off;
      off += 2;
      device_write16(buf + off, 0x1234); off += 2; // Identifier
      device_write16(buf + off, static_cast<uint16_t>(packet_index & 0xFFFF)); off += 2; // Seq

      for (int i = 0; i < user_data_len; ++i) {
        buf[off++] = static_cast<uint8_t>((packet_index + i) & 0xFF);
      }
      const int icmp_len = off - inner_l4_off;
      buf[icmp_csum_off] = 0;
      buf[icmp_csum_off + 1] = 0;
      uint16_t csum = device_ip_checksum(buf + inner_l4_off, icmp_len);
      device_write16(buf + icmp_csum_off, csum);
    }

    // Finalize Inner IPv4 Header
    const int inner_ip_len = off - inner_ip_off;
    device_write16(buf + inner_ip_len_off, static_cast<uint16_t>(inner_ip_len));
    buf[inner_ip_csum_off] = 0;
    buf[inner_ip_csum_off + 1] = 0;
    uint16_t inner_ip_csum = device_ip_checksum(buf + inner_ip_off, 20);
    device_write16(buf + inner_ip_csum_off, inner_ip_csum);
  }

  // Finalize GTP-U Header Length
  const int gtp_payload_len = off - (gtp_hdr_off + 8);
  device_write16(buf + gtp_len_off, static_cast<uint16_t>(gtp_payload_len));

  // Finalize Outer UDP Header Length
  const int outer_udp_len = off - outer_udp_off;
  device_write16(buf + outer_udp_len_off, static_cast<uint16_t>(outer_udp_len));

  // Finalize Outer IPv4 Header Length & Checksum
  const int outer_ip_len = off - outer_ip_off;
  device_write16(buf + outer_ip_len_off, static_cast<uint16_t>(outer_ip_len));
  buf[outer_ip_csum_off] = 0;
  buf[outer_ip_csum_off + 1] = 0;
  uint16_t outer_ip_csum = device_ip_checksum(buf + outer_ip_off, 20);
  device_write16(buf + outer_ip_csum_off, outer_ip_csum);

  if (matched_tunnel) {
    TelcoGpuTunnelEntryV1* mut_t = const_cast<TelcoGpuTunnelEntryV1*>(matched_tunnel);
    atomicAdd(&mut_t->tx_packets, 1u);
    atomicAdd(&mut_t->tx_bytes, static_cast<uint32_t>(off));
  }

  return static_cast<uint32_t>(off);
}

// ---------------------------------------------------------------------------
// Global Batch Kernel (Batch C ABI & Zero-Copy GeforceP2pRingInstance Burst)
// ---------------------------------------------------------------------------

__global__ void telco_gtpu_batch_kernel(
    uint8_t* dev_base_ptr,
    uint32_t slot_stride,
    uint32_t count,
    const TelcoGtpuStreamConfig* dev_cfg,
    const TelcoGpuTunnelEntryV1* dev_tunnels,
    uint32_t tunnel_count,
    uint16_t* out_pkt_lengths,
    const DpuCupsSharedRegionHeaderV1* dev_cups_hdr = nullptr) {
  const uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
  const uint32_t stride = blockDim.x * gridDim.x;
  const uint32_t eff_tunnel_count = device_resolve_telco_tunnel_span(tunnel_count, dev_cups_hdr);

  for (uint32_t i = tid; i < count; i += stride) {
    uint8_t* slot = dev_base_ptr + static_cast<uint64_t>(i) * slot_stride;
    uint32_t len = device_write_gtpu_packet(
        slot,
        slot_stride,
        i,
        dev_cfg,
        dev_tunnels,
        eff_tunnel_count);
    if (out_pkt_lengths) {
      out_pkt_lengths[i] = static_cast<uint16_t>(len);
    }
  }
}

__global__ void telco_gtpu_ring_batch_kernel(
    uint8_t* dev_ring_base_ptr,
    uint32_t slot_stride,
    uint32_t ring_slot_count,
    uint32_t start_slot,
    uint32_t count,
    uint32_t packet_seq_base,
    const TelcoGtpuStreamConfig* dev_cfg,
    const TelcoGpuTunnelEntryV1* dev_tunnels,
    uint32_t tunnel_count,
    const DpuCupsSharedRegionHeaderV1* dev_cups_hdr,
    uint32_t* out_slot_indices,
    uint16_t* out_pkt_lengths) {
  if (!dev_ring_base_ptr || ring_slot_count == 0u || slot_stride == 0u) {
    return;
  }
  const uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
  const uint32_t stride = blockDim.x * gridDim.x;
  const uint32_t eff_tunnel_count = device_resolve_telco_tunnel_span(tunnel_count, dev_cups_hdr);
  bool wrote_any = false;

  for (uint32_t i = tid; i < count; i += stride) {
    const uint32_t ring_slot = (start_slot + i) % ring_slot_count;
    uint8_t* slot_ptr = dev_ring_base_ptr + static_cast<uint64_t>(ring_slot) * slot_stride;
    const uint32_t len = device_write_gtpu_packet(
        slot_ptr,
        slot_stride,
        packet_seq_base + i,
        dev_cfg,
        dev_tunnels,
        eff_tunnel_count);
    if (out_slot_indices) {
      out_slot_indices[i] = ring_slot;
    }
    if (out_pkt_lengths) {
      out_pkt_lengths[i] = static_cast<uint16_t>(len);
    }
    wrote_any = true;
  }
  if (wrote_any) {
    __threadfence_system();
  }
}

// ---------------------------------------------------------------------------
// BAR1 RX Verification & SLA Kernel
// ---------------------------------------------------------------------------

__global__ void telco_gtpu_rx_verify_kernel(
    const uint8_t* dev_rx_base_ptr,
    uint32_t slot_stride,
    uint32_t count,
    TelcoGpuRxStatsV1* dev_stats) {
  if (!dev_rx_base_ptr || !dev_stats) {
    return;
  }
  const uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
  const uint32_t stride = blockDim.x * gridDim.x;

  for (uint32_t i = tid; i < count; i += stride) {
    const uint8_t* frame = dev_rx_base_ptr + static_cast<uint64_t>(i) * slot_stride;
    atomicAdd(&dev_stats->rx_packets, 1ULL);

    // Minimum Ethernet (14) + IPv4 (20) + UDP (8) + GTP-U (8) = 50 bytes
    if (slot_stride < 50u) {
      atomicAdd(&dev_stats->rx_corrupt_packets, 1ULL);
      continue;
    }

    uint32_t off = 12u; // Start at EtherType
    uint16_t eth_type = (static_cast<uint16_t>(frame[off]) << 8) | frame[off + 1u];
    off += 2u;

    if (eth_type == 0x88A8) { // 802.1ad QinQ
      if (off + 4u > slot_stride) {
        atomicAdd(&dev_stats->rx_corrupt_packets, 1ULL);
        continue;
      }
      off += 2u; // SVLAN TCI
      uint16_t next_type = (static_cast<uint16_t>(frame[off]) << 8) | frame[off + 1u];
      off += 2u;
      if (next_type == 0x8100) {
        if (off + 4u > slot_stride) {
          atomicAdd(&dev_stats->rx_corrupt_packets, 1ULL);
          continue;
        }
        off += 2u; // CVLAN TCI
        eth_type = (static_cast<uint16_t>(frame[off]) << 8) | frame[off + 1u];
        off += 2u;
      } else {
        eth_type = next_type;
      }
    } else if (eth_type == 0x8100) { // 802.1Q
      if (off + 4u > slot_stride) {
        atomicAdd(&dev_stats->rx_corrupt_packets, 1ULL);
        continue;
      }
      off += 2u; // VLAN TCI
      eth_type = (static_cast<uint16_t>(frame[off]) << 8) | frame[off + 1u];
      off += 2u;
    }

    if (eth_type != 0x0800 || off + 20u > slot_stride) {
      atomicAdd(&dev_stats->rx_corrupt_packets, 1ULL);
      continue;
    }

    // Outer IPv4 Header
    const uint32_t outer_ip_off = off;
    const uint8_t ip_ver = frame[outer_ip_off] >> 4;
    const uint8_t ip_ihl = frame[outer_ip_off] & 0x0Fu;
    const uint32_t ip_hdr_bytes = static_cast<uint32_t>(ip_ihl) * 4u;
    const uint8_t ip_proto = frame[outer_ip_off + 9u];
    const uint16_t ip_tot_len =
        (static_cast<uint16_t>(frame[outer_ip_off + 2u]) << 8) | frame[outer_ip_off + 3u];

    if (ip_ver != 4u || ip_proto != 17u || ip_ihl < 5u ||
        ip_tot_len < ip_hdr_bytes + 16u || outer_ip_off + ip_tot_len > slot_stride) {
      atomicAdd(&dev_stats->rx_corrupt_packets, 1ULL);
      continue;
    }

    const uint32_t frame_end = outer_ip_off + static_cast<uint32_t>(ip_tot_len);
    atomicAdd(&dev_stats->rx_bytes, static_cast<unsigned long long>(frame_end));

    // Verify Outer IP Checksum
    if (device_ip_checksum(frame + outer_ip_off, static_cast<int>(ip_hdr_bytes)) != 0) {
      atomicAdd(&dev_stats->rx_invalid_checksum, 1ULL);
      continue;
    }

    off += ip_hdr_bytes; // UDP offset
    if (off + 16u > frame_end) { // UDP (8) + Mandatory GTP-U (8)
      atomicAdd(&dev_stats->rx_corrupt_packets, 1ULL);
      continue;
    }
    const uint16_t udp_dst_port = (static_cast<uint16_t>(frame[off + 2u]) << 8) | frame[off + 3u];
    if (udp_dst_port != kGtpuUdpPort) {
      atomicAdd(&dev_stats->rx_corrupt_packets, 1ULL);
      continue;
    }

    off += 8u; // GTP-U header offset
    const uint8_t gtp_flags = frame[off];
    const uint8_t gtp_msg_type = frame[off + 1u];
    const uint16_t gtp_len = (static_cast<uint16_t>(frame[off + 2u]) << 8) | frame[off + 3u];
    if (off + 8u + static_cast<uint32_t>(gtp_len) > frame_end) {
      atomicAdd(&dev_stats->rx_corrupt_packets, 1ULL);
      continue;
    }
    const uint32_t gtp_end = off + 8u + static_cast<uint32_t>(gtp_len);

    // Check for Extension Header (5G QFI PDU Session Container)
    const bool has_ext = (gtp_flags & kGtpuFlagE) != 0;
    const bool has_seq = (gtp_flags & kGtpuFlagS) != 0;
    const bool has_pn = (gtp_flags & kGtpuFlagPn) != 0;

    bool ext_corrupt = false;
    uint8_t observed_qfis[8] = {0};
    int observed_qfi_count = 0;

    if (has_ext || has_seq || has_pn) {
      if (off + 12u > gtp_end) {
        atomicAdd(&dev_stats->rx_corrupt_packets, 1ULL);
        continue;
      }
      off += 8u; // Past mandatory GTP-U
      uint8_t next_ext = frame[off + 3u];
      off += 4u; // Past Seq/NPDU/NextExt

      int ext_hops = 0;
      while (has_ext && next_ext != 0x00) {
        if (++ext_hops > 8 || off >= gtp_end) {
          ext_corrupt = true;
          break;
        }
        const uint8_t ext_len_units = frame[off];
        const uint32_t ext_bytes = static_cast<uint32_t>(ext_len_units) * 4u;
        if (ext_bytes < 4u || off + ext_bytes > gtp_end) {
          ext_corrupt = true;
          break;
        }

        if (next_ext == kGtpuExtType5gPduSessionContainer) {
          const uint8_t qfi = frame[off + 2u] & 0x3Fu;
          if (observed_qfi_count < 8) {
            observed_qfis[observed_qfi_count++] = qfi;
          }
        }
        next_ext = frame[off + ext_bytes - 1u];
        off += ext_bytes;
      }
    } else {
      off += 8u; // Past mandatory GTP-U
    }

    if (ext_corrupt) {
      atomicAdd(&dev_stats->rx_corrupt_packets, 1ULL);
      continue;
    }

    atomicAdd(&dev_stats->rx_gtpu_packets, 1ULL);
    for (int qi = 0; qi < observed_qfi_count; ++qi) {
      atomicAdd(&dev_stats->rx_qfi_packets[observed_qfis[qi]], 1ULL);
    }

    if (gtp_msg_type == kGtpuMsgEchoRequest) {
      atomicAdd(&dev_stats->rx_echo_req, 1ULL);
    } else if (gtp_msg_type == kGtpuMsgEchoResponse) {
      atomicAdd(&dev_stats->rx_echo_resp, 1ULL);
    } else if (gtp_msg_type == kGtpuMsgErrorIndication) {
      atomicAdd(&dev_stats->rx_error_ind, 1ULL);
    }

    // Check inner IPv4 header checksum if present
    if (gtp_msg_type == kGtpuMsgGPdu && off < gtp_end) {
      if (off + 20u > gtp_end) {
        atomicAdd(&dev_stats->rx_corrupt_packets, 1ULL);
        continue;
      }
      if ((frame[off] >> 4) == 4u) {
        const uint32_t inner_ip_off = off;
        const uint8_t in_ihl = frame[inner_ip_off] & 0x0Fu;
        const uint32_t in_hdr_bytes = static_cast<uint32_t>(in_ihl) * 4u;
        if (in_ihl < 5u || inner_ip_off + in_hdr_bytes > gtp_end) {
          atomicAdd(&dev_stats->rx_corrupt_packets, 1ULL);
          continue;
        }
        if (device_ip_checksum(frame + inner_ip_off, static_cast<int>(in_hdr_bytes)) != 0) {
          atomicAdd(&dev_stats->rx_invalid_checksum, 1ULL);
          continue;
        }
      }
    }
  }
}

} // namespace ddos_samurai::gpu_packet_cuda::telecom
