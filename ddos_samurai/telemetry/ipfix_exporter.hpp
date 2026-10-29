#pragma once

#include "ipfix_types.hpp"

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

namespace ddos_samurai::telemetry {

struct ExporterConfig {
  std::string collector_ip{"127.0.0.1"};
  uint16_t collector_port{4739}; // Standard IPFIX port (4739), NetFlow is 2055
  uint32_t observation_domain_id{1};
  uint16_t template_id{256};     // First available dynamic template ID
  bool enable_netflow_v9{false};  // False = IPFIX (v10), True = NetFlow v9
};

class IpfixExporter {
 public:
  explicit IpfixExporter(const ExporterConfig& cfg = ExporterConfig{});
  ~IpfixExporter();

  // Kopyalama engellenir
  IpfixExporter(const IpfixExporter&) = delete;
  IpfixExporter& operator=(const IpfixExporter&) = delete;

  // Soket başlatma (non-blocking UDP)
  bool InitSocket();
  void CloseSocket();

  // Tahliye edilen akışları ikili IPFIX / NetFlow v9 mesajına dönüştürür
  std::vector<uint8_t> BuildExportPacket(
      const SamuraiFlowRecord* records, size_t count,
      uint32_t unix_secs, uint32_t sys_uptime_ms, bool include_template = true);

  // Doğrudan UDP soketi üzerinden Collector'a basar (Wire-speed transmit)
  bool ExportRecords(
      const SamuraiFlowRecord* records, size_t count,
      uint32_t unix_secs, uint32_t sys_uptime_ms);

  uint32_t exported_packets() const noexcept { return exported_packets_; }
  uint64_t exported_records() const noexcept { return exported_records_; }
  uint32_t sequence_number() const noexcept { return sequence_number_; }

 private:
  ExporterConfig cfg_;
  int socket_fd_{-1};
  uint32_t sequence_number_{1};
  uint32_t exported_packets_{0};
  uint64_t exported_records_{0};
  uint32_t template_send_counter_{0};

  // Pre-built template packet buffer
  std::vector<uint8_t> template_set_bytes_;
  void BuildTemplateSet();
};

}  // namespace ddos_samurai::telemetry
