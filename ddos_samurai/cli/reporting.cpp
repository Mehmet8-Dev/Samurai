#include "reporting.hpp"

#include <cstdio>
#include <fstream>
#include <string>

namespace samurai::cli {

std::string ReportJson(const RunReport& r) {
  const auto& j = r.job;
  const auto& s = r.stats;
  char buf[2048];
  std::snprintf(
      buf, sizeof(buf),
      "{\n"
      "  \"schema\": \"samurai.run_report.v1\",\n"
      "  \"worker\": \"%s\",\n"
      "  \"target\": {\"ip\": \"%s\", \"port\": %u, \"protocol\": \"%s\", \"attack_vector\": \"%s\"},\n"
      "  \"request\": {\"packet_count\": %u, \"packet_size\": %u, \"target_rps\": %.2f, \"spoof\": %s},\n"
      "  \"stats\": {\"attempted\": %llu, \"sent\": %llu, \"errors\": %llu, \"bytes_sent\": %llu,\n"
      "             \"actual_rps\": %.2f, \"rate_accuracy_pct\": %.2f,\n"
      "             \"wire_loss_est_packets\": %llu, \"wire_loss_est_pct\": %.4f},\n"
      "  \"kpi_gate\": {\"evaluated\": %s, \"passed\": %s},\n"
      "  \"exit_status\": %d\n"
      "}",
      r.worker_name.c_str(),
      j.target_ip.c_str(), static_cast<unsigned>(j.target_port), j.protocol.c_str(), j.attack_vector.c_str(),
      j.packet_count, j.packet_size, j.target_rps, j.spoof ? "true" : "false",
      static_cast<unsigned long long>(s.attempted),
      static_cast<unsigned long long>(s.sent),
      static_cast<unsigned long long>(s.errors),
      static_cast<unsigned long long>(s.bytes_sent),
      s.actual_rps, s.rate_accuracy_pct,
      static_cast<unsigned long long>(s.wire_loss_est_packets), s.wire_loss_est_pct,
      r.gate.evaluated ? "true" : "false",
      r.gate.passed ? "true" : "false",
      r.exit_status);
  return std::string(buf);
}

std::string ReportText(const RunReport& r) {
  const auto& j = r.job;
  const auto& s = r.stats;
  char buf[2048];
  std::snprintf(
      buf, sizeof(buf),
      "Samurai run report\n"
      "==================\n"
      "worker            : %s\n"
      "target            : %s:%u  (%s / %s)\n"
      "request           : count=%u size=%u rps=%.2f spoof=%s\n"
      "------------------\n"
      "attempted         : %llu\n"
      "sent              : %llu\n"
      "errors            : %llu\n"
      "bytes_sent        : %llu\n"
      "actual_rps        : %.2f\n"
      "rate_accuracy_pct : %.2f\n"
      "wire_loss_est     : %llu pkt (%.4f%%)\n"
      "kpi_gate          : %s\n"
      "exit_status       : %d\n",
      r.worker_name.c_str(),
      j.target_ip.c_str(), static_cast<unsigned>(j.target_port), j.protocol.c_str(), j.attack_vector.c_str(),
      j.packet_count, j.packet_size, j.target_rps, j.spoof ? "true" : "false",
      static_cast<unsigned long long>(s.attempted),
      static_cast<unsigned long long>(s.sent),
      static_cast<unsigned long long>(s.errors),
      static_cast<unsigned long long>(s.bytes_sent),
      s.actual_rps, s.rate_accuracy_pct,
      static_cast<unsigned long long>(s.wire_loss_est_packets), s.wire_loss_est_pct,
      r.gate.evaluated ? (r.gate.passed ? "PASS" : "FAIL") : "n/a",
      r.exit_status);
  return std::string(buf);
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
