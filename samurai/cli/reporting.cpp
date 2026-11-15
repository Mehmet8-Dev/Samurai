#include "reporting.hpp"

#include <cstdio>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>

namespace samurai::cli {

namespace {

std::string EscapeJson(const std::string& in) {
  std::string out;
  out.reserve(in.size() + 8);
  for (unsigned char c : in) {
    switch (c) {
      case '"':  out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          char hex[8];
          std::snprintf(hex, sizeof(hex), "\\u%04x", static_cast<unsigned>(c));
          out += hex;
        } else {
          out.push_back(static_cast<char>(c));
        }
        break;
    }
  }
  return out;
}

}  // namespace

std::string ReportJson(const RunReport& r) {
  const auto& j = r.job;
  const auto& s = r.stats;
  std::ostringstream os;
  os << std::fixed
     << "{\n"
     << "  \"schema\": \"samurai.run_report.v1\",\n"
     << "  \"worker\": \"" << EscapeJson(r.worker_name) << "\",\n"
     << "  \"target\": {\"ip\": \"" << EscapeJson(j.target_ip)
     << "\", \"port\": " << static_cast<unsigned>(j.target_port)
     << ", \"protocol\": \"" << EscapeJson(j.protocol)
     << "\", \"attack_vector\": \"" << EscapeJson(j.attack_vector) << "\"},\n"
     << "  \"request\": {\"packet_count\": " << j.packet_count
     << ", \"packet_size\": " << j.packet_size
     << ", \"target_rps\": " << std::setprecision(2) << j.target_rps
     << ", \"spoof\": " << (j.spoof ? "true" : "false") << "},\n"
     << "  \"stats\": {\"attempted\": " << static_cast<unsigned long long>(s.attempted)
     << ", \"sent\": " << static_cast<unsigned long long>(s.sent)
     << ", \"errors\": " << static_cast<unsigned long long>(s.errors)
     << ", \"bytes_sent\": " << static_cast<unsigned long long>(s.bytes_sent) << ",\n"
     << "             \"actual_rps\": " << std::setprecision(2) << s.actual_rps
     << ", \"rate_accuracy_pct\": " << std::setprecision(2) << s.rate_accuracy_pct << ",\n"
     << "             \"wire_loss_est_packets\": " << static_cast<unsigned long long>(s.wire_loss_est_packets)
     << ", \"wire_loss_est_pct\": " << std::setprecision(4) << s.wire_loss_est_pct << "},\n"
     << "  \"ipfix_telemetry\": {\"exported_packets\": "
     << static_cast<unsigned long long>(s.ipfix_exported_packets)
     << ", \"exported_records\": "
     << static_cast<unsigned long long>(s.ipfix_exported_records) << "},\n"
     << "  \"telco_telemetry\": {\"active_sessions\": "
     << static_cast<unsigned long long>(s.telco_active_sessions)
     << ", \"established_sessions\": "
     << static_cast<unsigned long long>(s.telco_established_sessions)
     << ", \"failed_sessions\": "
     << static_cast<unsigned long long>(s.telco_failed_sessions)
     << ", \"current_cps\": " << s.telco_current_cps
     << ", \"avg_setup_latency_us\": " << s.telco_avg_setup_latency_us
     << ", \"p99_setup_latency_us\": " << s.telco_p99_setup_latency_us
     << ", \"retransmit_count\": "
     << static_cast<unsigned long long>(s.telco_retransmit_count) << "},\n"
     << "  \"kpi_gate\": {\"evaluated\": " << (r.gate.evaluated ? "true" : "false")
     << ", \"passed\": " << (r.gate.passed ? "true" : "false") << "},\n"
     << "  \"exit_status\": " << r.exit_status << "\n"
     << "}";
  return os.str();
}

std::string ReportText(const RunReport& r) {
  const auto& j = r.job;
  const auto& s = r.stats;
  std::ostringstream os;
  os << std::fixed
     << "Samurai run report\n"
     << "==================\n"
     << "worker            : " << r.worker_name << "\n"
     << "target            : " << j.target_ip << ":" << static_cast<unsigned>(j.target_port)
     << "  (" << j.protocol << " / " << j.attack_vector << ")\n"
     << "request           : count=" << j.packet_count << " size=" << j.packet_size
     << " rps=" << std::setprecision(2) << j.target_rps
     << " spoof=" << (j.spoof ? "true" : "false") << "\n"
     << "------------------\n"
     << "attempted         : " << static_cast<unsigned long long>(s.attempted) << "\n"
     << "sent              : " << static_cast<unsigned long long>(s.sent) << "\n"
     << "errors            : " << static_cast<unsigned long long>(s.errors) << "\n"
     << "bytes_sent        : " << static_cast<unsigned long long>(s.bytes_sent) << "\n"
     << "actual_rps        : " << std::setprecision(2) << s.actual_rps << "\n"
     << "rate_accuracy_pct : " << std::setprecision(2) << s.rate_accuracy_pct << "\n"
     << "wire_loss_est     : " << static_cast<unsigned long long>(s.wire_loss_est_packets)
     << " pkt (" << std::setprecision(4) << s.wire_loss_est_pct << "%)\n"
     << "ipfix_telemetry   : exported_packets="
     << static_cast<unsigned long long>(s.ipfix_exported_packets)
     << " exported_records="
     << static_cast<unsigned long long>(s.ipfix_exported_records) << "\n"
     << "telco_telemetry   : active=" << static_cast<unsigned long long>(s.telco_active_sessions)
     << " established=" << static_cast<unsigned long long>(s.telco_established_sessions)
     << " failed=" << static_cast<unsigned long long>(s.telco_failed_sessions)
     << " cps=" << s.telco_current_cps
     << " avg_us=" << s.telco_avg_setup_latency_us
     << " p99_us=" << s.telco_p99_setup_latency_us
     << " retransmit=" << static_cast<unsigned long long>(s.telco_retransmit_count) << "\n"
     << "kpi_gate          : " << (r.gate.evaluated ? (r.gate.passed ? "PASS" : "FAIL") : "n/a") << "\n"
     << "exit_status       : " << r.exit_status << "\n";
  return os.str();
}

bool WriteReportFile(const std::string& path, const std::string& content) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    return false;
  }
  out << content;
  return static_cast<bool>(out);
}

}  // namespace samurai::cli
