#include "ipfix_exporter.hpp"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <iostream>

namespace samurai::telemetry {

namespace {

#pragma pack(push, 1)
struct TemplateRecordHeader {
  uint16_t template_id; // e.g. 256
  uint16_t field_count; // Number of fields
};
#pragma pack(pop)

void append_bytes(std::vector<uint8_t>& dest, const void* src, size_t len) {
  const auto* p = reinterpret_cast<const uint8_t*>(src);
  dest.insert(dest.end(), p, p + len);
}

void append_u16(std::vector<uint8_t>& dest, uint16_t val) {
  uint16_t be = htons(val);
  append_bytes(dest, &be, 2);
}

void append_u32(std::vector<uint8_t>& dest, uint32_t val) {
  uint32_t be = htonl(val);
  append_bytes(dest, &be, 4);
}

void append_u64(std::vector<uint8_t>& dest, uint64_t val) {
  // 64-bit big endian
  uint32_t hi = htonl(static_cast<uint32_t>(val >> 32));
  uint32_t lo = htonl(static_cast<uint32_t>(val & 0xFFFFFFFFULL));
  append_bytes(dest, &hi, 4);
  append_bytes(dest, &lo, 4);
}

}  // namespace

IpfixExporter::IpfixExporter(const ExporterConfig& cfg)
    : cfg_(cfg) {
  BuildTemplateSet();
}

IpfixExporter::~IpfixExporter() {
  CloseSocket();
}

bool IpfixExporter::InitSocket() {
  if (socket_fd_ >= 0 && dest_ip_valid_) return true;

  struct in_addr resolved{};
  if (cfg_.collector_ip.empty() || inet_pton(AF_INET, cfg_.collector_ip.c_str(), &resolved) != 1) {
    dest_ip_valid_ = false;
    return false;
  }
  dest_ip_be_ = resolved.s_addr;
  dest_ip_valid_ = true;

  if (socket_fd_ < 0) {
    socket_fd_ = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd_ < 0) return false;

    // Set non-blocking socket
    int flags = fcntl(socket_fd_, F_GETFL, 0);
    if (flags >= 0) {
      fcntl(socket_fd_, F_SETFL, flags | O_NONBLOCK);
    }
  }

  return true;
}

void IpfixExporter::CloseSocket() {
  if (socket_fd_ >= 0) {
    ::close(socket_fd_);
    socket_fd_ = -1;
  }
  dest_ip_valid_ = false;
}

void IpfixExporter::BuildTemplateSet() {
  template_set_bytes_.clear();

  // Set Header: Set ID = 2 (IPFIX Template) or 0 (NetFlow v9 Template)
  uint16_t set_id = cfg_.enable_netflow_v9 ? 0 : 2;

  // We define 13 fields: 10 standard IANA, 3 Samurai Enterprise (PEN 59888)
  uint16_t field_count = cfg_.enable_netflow_v9 ? 10 : 13;

  // Total template set size:
  // SetHeader (4) + TemplateRecordHeader (4) + (10 * 4 bytes) + (if IPFIX: 3 * 8 bytes)
  size_t set_len = sizeof(IpfixSetHeader) + sizeof(TemplateRecordHeader) + (10 * sizeof(IpfixFieldSpecifier));
  if (!cfg_.enable_netflow_v9) {
    set_len += (3 * sizeof(IpfixEnterpriseFieldSpecifier));
  }

  template_set_bytes_.reserve(set_len);

  // Set Header
  append_u16(template_set_bytes_, set_id);
  append_u16(template_set_bytes_, static_cast<uint16_t>(set_len));

  // Template Record Header
  append_u16(template_set_bytes_, cfg_.template_id);
  append_u16(template_set_bytes_, field_count);

  // Standard Fields
  // 1. sourceIPv4Address (8) - 4 bytes
  append_u16(template_set_bytes_, static_cast<uint16_t>(IanaElementId::sourceIPv4Address));
  append_u16(template_set_bytes_, 4);

  // 2. destinationIPv4Address (12) - 4 bytes
  append_u16(template_set_bytes_, static_cast<uint16_t>(IanaElementId::destinationIPv4Address));
  append_u16(template_set_bytes_, 4);

  // 3. sourceTransportPort (7) - 2 bytes
  append_u16(template_set_bytes_, static_cast<uint16_t>(IanaElementId::sourceTransportPort));
  append_u16(template_set_bytes_, 2);

  // 4. destinationTransportPort (11) - 2 bytes
  append_u16(template_set_bytes_, static_cast<uint16_t>(IanaElementId::destinationTransportPort));
  append_u16(template_set_bytes_, 2);

  // 5. protocolIdentifier (4) - 1 byte
  append_u16(template_set_bytes_, static_cast<uint16_t>(IanaElementId::protocolIdentifier));
  append_u16(template_set_bytes_, 1);

  // 6. tcpControlBits (6) - 1 byte
  append_u16(template_set_bytes_, static_cast<uint16_t>(IanaElementId::tcpControlBits));
  append_u16(template_set_bytes_, 1);

  // 7. packetDeltaCount (2) - 8 bytes
  append_u16(template_set_bytes_, static_cast<uint16_t>(IanaElementId::packetDeltaCount));
  append_u16(template_set_bytes_, 8);

  // 8. octetDeltaCount (1) - 8 bytes
  append_u16(template_set_bytes_, static_cast<uint16_t>(IanaElementId::octetDeltaCount));
  append_u16(template_set_bytes_, 8);

  // 9. flowStartSysUpTime (22) - 4 bytes
  append_u16(template_set_bytes_, static_cast<uint16_t>(IanaElementId::flowStartSysUpTime));
  append_u16(template_set_bytes_, 4);

  // 10. flowEndSysUpTime (21) - 4 bytes
  append_u16(template_set_bytes_, static_cast<uint16_t>(IanaElementId::flowEndSysUpTime));
  append_u16(template_set_bytes_, 4);

  if (!cfg_.enable_netflow_v9) {
    // Enterprise Field 11: rttMicroseconds (PEN bit 0x8000 | 1) - 2 bytes
    append_u16(template_set_bytes_, 0x8000 | static_cast<uint16_t>(SamuraiEnterpriseId::rttMicroseconds));
    append_u16(template_set_bytes_, 2);
    append_u32(template_set_bytes_, SAMURAI_ENTERPRISE_PEN);

    // Enterprise Field 12: retransmitPacketCount (PEN bit 0x8000 | 2) - 2 bytes
    append_u16(template_set_bytes_, 0x8000 | static_cast<uint16_t>(SamuraiEnterpriseId::retransmitPacketCount));
    append_u16(template_set_bytes_, 2);
    append_u32(template_set_bytes_, SAMURAI_ENTERPRISE_PEN);

    // Enterprise Field 13: flowSecurityFlags (PEN bit 0x8000 | 4) - 4 bytes
    append_u16(template_set_bytes_, 0x8000 | static_cast<uint16_t>(SamuraiEnterpriseId::flowSecurityFlags));
    append_u16(template_set_bytes_, 4);
    append_u32(template_set_bytes_, SAMURAI_ENTERPRISE_PEN);
  }
}

std::vector<uint8_t> IpfixExporter::BuildExportPacket(
    const SamuraiFlowRecord* records, size_t count,
    uint32_t unix_secs, uint32_t sys_uptime_ms, bool include_template) {

  std::vector<uint8_t> packet;
  size_t header_size = cfg_.enable_netflow_v9 ? sizeof(NetFlowV9Header) : sizeof(IpfixHeader);
  size_t template_size = include_template ? template_set_bytes_.size() : 0;

  // Single data record size
  size_t data_record_len = cfg_.enable_netflow_v9 ? (4 + 4 + 2 + 2 + 1 + 1 + 8 + 8 + 4 + 4) : 46;
  size_t data_set_len = sizeof(IpfixSetHeader) + (count * data_record_len);

  // 4-byte padding alignment for IPFIX sets (RFC 7011 Section 3.3.1)
  size_t pad_bytes = (4 - (data_set_len % 4)) % 4;
  data_set_len += pad_bytes;

  size_t total_length = header_size + template_size + data_set_len;
  packet.reserve(total_length);

  // 1. Packet Header
  if (cfg_.enable_netflow_v9) {
    NetFlowV9Header hdr{};
    hdr.version = htons(9);
    hdr.count = htons(static_cast<uint16_t>((include_template ? 1 : 0) + count));
    hdr.sys_uptime_ms = htonl(sys_uptime_ms);
    hdr.unix_secs = htonl(unix_secs);
    hdr.sequence_number = htonl(sequence_number_++);
    hdr.source_id = htonl(cfg_.observation_domain_id);
    append_bytes(packet, &hdr, sizeof(hdr));
  } else {
    IpfixHeader hdr{};
    hdr.version = htons(10);
    hdr.length = htons(static_cast<uint16_t>(total_length));
    hdr.export_time = htonl(unix_secs);
    hdr.sequence_number = htonl(sequence_number_++);
    hdr.observation_domain_id = htonl(cfg_.observation_domain_id);
    append_bytes(packet, &hdr, sizeof(hdr));
  }

  // 2. Template Set (if included)
  if (include_template) {
    packet.insert(packet.end(), template_set_bytes_.begin(), template_set_bytes_.end());
  }

  // 3. Data Set Header
  append_u16(packet, cfg_.template_id); // Set ID = Template ID (>= 256)
  append_u16(packet, static_cast<uint16_t>(data_set_len));

  // 4. Data Records
  for (size_t i = 0; i < count; ++i) {
    const auto& rec = records[i];
    append_bytes(packet, &rec.key.src_ip, 4);
    append_bytes(packet, &rec.key.dst_ip, 4);
    append_bytes(packet, &rec.key.src_port, 2);
    append_bytes(packet, &rec.key.dst_port, 2);
    append_bytes(packet, &rec.key.protocol, 1);
    append_bytes(packet, &rec.tcp_flags_or, 1);
    append_u64(packet, rec.packet_count);
    append_u64(packet, rec.byte_count);
    append_u32(packet, static_cast<uint32_t>(rec.start_tsc));
    append_u32(packet, static_cast<uint32_t>(rec.last_tsc));

    if (!cfg_.enable_netflow_v9) {
      append_u16(packet, rec.rtt_us);
      append_u16(packet, rec.retransmit_cnt);
      append_u32(packet, rec.security_flags);
    }
  }

  // 5. Padding
  for (size_t p = 0; p < pad_bytes; ++p) {
    packet.push_back(0);
  }

  exported_packets_++;
  exported_records_ += count;
  return packet;
}

bool IpfixExporter::ExportRecords(
    const SamuraiFlowRecord* records, size_t count,
    uint32_t unix_secs, uint32_t sys_uptime_ms) {

  if (!records || count == 0) return true;
  if (!InitSocket()) return false;

  struct sockaddr_in dest{};
  dest.sin_family = AF_INET;
  dest.sin_port = htons(cfg_.collector_port);
  dest.sin_addr.s_addr = dest_ip_be_;

  // Chunk below standard Ethernet UDP MTU (~1472 B) so large flow flushes never EMSGSIZE.
  constexpr size_t kMaxRecordsPerDatagram = 24;
  bool all_ok = true;
  for (size_t offset = 0; offset < count; offset += kMaxRecordsPerDatagram) {
    const size_t chunk = std::min(kMaxRecordsPerDatagram, count - offset);
    // Send template periodically (e.g. every 20 packets or first packet)
    const bool include_template = (template_send_counter_++ % 20 == 0);
    auto packet = BuildExportPacket(
        records + offset, chunk, unix_secs, sys_uptime_ms, include_template);

    const ssize_t sent = ::sendto(socket_fd_, packet.data(), packet.size(), MSG_DONTWAIT,
                                  reinterpret_cast<const struct sockaddr*>(&dest), sizeof(dest));
    if (sent != static_cast<ssize_t>(packet.size())) {
      if (exported_packets_ > 0) exported_packets_--;
      if (exported_records_ >= chunk) exported_records_ -= chunk;
      send_errors_++;
      all_ok = false;
    }
  }
  return all_ok;
}

}  // namespace samurai::telemetry
