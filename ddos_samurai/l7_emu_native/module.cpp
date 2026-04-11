#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <map>
#include <stdexcept>
#include <string>

#include "engine.hpp"
#include "../l4/tcp_dataplane_ffi.h"

namespace py = pybind11;
using namespace ddos_samurai::l7_emu_native;

namespace {

std::vector<unsigned char> pybytes_to_vec(const py::object& obj) {
  if (obj.is_none()) return {};
  std::string s = py::cast<std::string>(py::bytes(obj));
  return std::vector<unsigned char>(s.begin(), s.end());
}

FlowOp parse_op(const py::dict& obj) {
  FlowOp op;
  op.opcode = py::cast<std::string>(obj["opcode"]);
  if (obj.contains("method")) op.method = py::cast<std::string>(obj["method"]);
  if (obj.contains("path")) op.path = py::cast<std::string>(obj["path"]);
  if (obj.contains("headers")) op.headers = py::cast<std::map<std::string, std::string>>(obj["headers"]);
  if (obj.contains("body")) op.body = pybytes_to_vec(obj["body"]);
  if (obj.contains("expect") && !obj["expect"].is_none()) {
    py::dict expect = py::cast<py::dict>(obj["expect"]);
    op.has_expect = true;
    if (expect.contains("kind")) op.expect.kind = py::cast<std::string>(expect["kind"]);
    if (expect.contains("name")) op.expect.name = py::cast<std::string>(expect["name"]);
    if (expect.contains("value")) op.expect.value = py::cast<std::string>(expect["value"]);
    if (expect.contains("status_min")) op.expect.status_min = py::cast<int>(expect["status_min"]);
    if (expect.contains("status_max")) op.expect.status_max = py::cast<int>(expect["status_max"]);
  }
  if (obj.contains("capture_name")) op.capture_name = py::cast<std::string>(obj["capture_name"]);
  if (obj.contains("capture_source")) op.capture_source = py::cast<std::string>(obj["capture_source"]);
  if (obj.contains("think_time_ms")) op.think_time_ms = py::cast<int>(obj["think_time_ms"]);
  if (obj.contains("loop_count")) op.loop_count = py::cast<int>(obj["loop_count"]);
  return op;
}

std::string normalize_runtime_backend(const std::string& raw) {
  std::string out = raw;
  for (char& c : out) {
    if (c >= 'A' && c <= 'Z') {
      c = static_cast<char>(c - 'A' + 'a');
    }
  }
  if (out != "afxdp" && out != "dpdk") {
    return "afxdp";
  }
  return out;
}

Profile parse_profile(const py::dict& profile_dict) {
  Profile profile;
  profile.protocol = py::cast<std::string>(profile_dict["protocol"]);
  profile.sender_path = py::cast<std::string>(profile_dict["sender_path"]);
  profile.flow_attempted = py::cast<int>(profile_dict["flow_attempted"]);
  py::dict conn = py::cast<py::dict>(profile_dict["connection_template"]);
  if (conn.contains("transport_backend")) {
    profile.transport_backend = py::cast<std::string>(conn["transport_backend"]);
  }
  if (conn.contains("stateful_runtime_backend")) {
    profile.stateful_runtime_backend = py::cast<std::string>(conn["stateful_runtime_backend"]);
  }
  if (conn.contains("stateful_runtime_strict")) {
    profile.stateful_runtime_strict = py::cast<int>(conn["stateful_runtime_strict"]);
  }
  if (conn.contains("legacy_mode")) {
    profile.legacy_mode = py::cast<int>(conn["legacy_mode"]);
  }
  profile.target_ip = py::cast<std::string>(conn["target_ip"]);
  profile.target_port = py::cast<int>(conn["target_port"]);
  profile.scheme = py::cast<std::string>(conn["scheme"]);
  profile.host_header = py::cast<std::string>(conn["host_header"]);
  profile.verify = py::cast<int>(conn["verify"]);
  profile.keepalive = py::cast<int>(conn["keepalive"]);
  profile.timeout_ms = py::cast<int>(conn["timeout_ms"]);
  profile.max_connections = py::cast<int>(conn["max_connections"]);
  profile.max_streams_per_connection = py::cast<int>(conn["max_streams_per_connection"]);
  profile.session_repeats = py::cast<int>(conn["session_repeats"]);
  py::dict flow_program = py::cast<py::dict>(profile_dict["flow_program"]);
  for (const auto& item : py::cast<py::list>(flow_program["ops"])) {
    profile.ops.push_back(parse_op(py::cast<py::dict>(item)));
  }
  return profile;
}

RuntimeConfig parse_runtime_cfg(const py::dict& cfg_dict) {
  RuntimeConfig cfg;
  if (cfg_dict.contains("concurrency")) cfg.concurrency = py::cast<int>(cfg_dict["concurrency"]);
  if (cfg_dict.contains("profile_l7")) cfg.profile_l7 = py::cast<int>(cfg_dict["profile_l7"]);
  if (cfg_dict.contains("profile_sample_limit")) cfg.profile_sample_limit = py::cast<int>(cfg_dict["profile_sample_limit"]);
  return cfg;
}

}  // namespace

PYBIND11_MODULE(_l7_emu_native, m) {
  m.doc() = "Native L7 emulation runtime";
  m.def("run_profile", [](const py::dict& profile_dict, const py::dict& cfg_dict) {
    const Profile profile = parse_profile(profile_dict);
    const RuntimeConfig cfg = parse_runtime_cfg(cfg_dict);
    const RuntimeCapabilities caps = detect_capabilities();
    const std::string runtime_backend = normalize_runtime_backend(profile.stateful_runtime_backend);
    const bool strict_runtime = profile.stateful_runtime_strict != 0;
    const bool runtime_requires_custom_tcp = strict_runtime;
    const TransportBackend transport_backend =
        profile.transport_backend == "custom_tcp" ? TransportBackend::CustomTcp : TransportBackend::KernelSocket;
    if (runtime_requires_custom_tcp && transport_backend != TransportBackend::CustomTcp) {
      py::dict failed;
      failed["sender_path"] = py::str(profile.sender_path);
      failed["sender_fallback_reason"] = py::str("stateful_runtime_transport_unavailable");
      failed["l7_engine_path_used"] = py::str("L7_EMU_NATIVE");
      failed["l7_fallback_reason"] = py::str("stateful_runtime_transport_unavailable");
      failed["stateful_runtime_reason"] = py::str("stateful_runtime_transport_unavailable");
      failed["stateful_runtime_detail"] =
          py::str("strict stateful runtime requires custom_tcp transport; kernel_socket fallback is disabled");
      failed["attempted"] = py::int_(profile.flow_attempted);
      failed["sent"] = py::int_(0);
      failed["errors"] = py::int_(profile.flow_attempted);
      failed["l7_flow_attempted"] = py::int_(profile.flow_attempted);
      failed["l7_flow_completed"] = py::int_(0);
      failed["l7_expectation_failures"] = py::int_(profile.flow_attempted);
      failed["runtime_reactor_backend"] = py::str("socket_epoll");
      failed["runtime_transport_backend"] = py::str(transport_backend_name(transport_backend));
      failed["runtime_tls_backend"] = py::str(caps.openssl ? "openssl" : "unavailable");
      failed["runtime_http2_backend"] = py::str(caps.nghttp2 ? "nghttp2_native" : "unavailable");
      failed["runtime_native_hot_path_level"] = py::str("userspace_reactor_templates");
      failed["runtime_transport_custom_tcp_requested"] = py::int_(0);
      failed["runtime_transport_custom_tcp_bridge_ready"] = py::int_(0);
      failed["runtime_transport_custom_tcp_rx_bridge_active"] = py::int_(0);
      failed["runtime_transport_seam_ready"] = py::int_(0);
      return failed;
    }

    std::map<std::string, double> out;
    {
      py::gil_scoped_release release;
      out = run_profile(profile, cfg);
    }
    const ReactorBackend reactor_backend = ReactorBackend::SocketEpoll;
    const TlsBackend tls_backend = caps.openssl ? TlsBackend::OpenSSL : TlsBackend::Unavailable;
    const Http2Backend http2_backend = caps.nghttp2 ? Http2Backend::Nghttp2Native : Http2Backend::Unavailable;
    const NativeHotPathLevel hot_path_level = NativeHotPathLevel::UserspaceReactorTemplates;
    py::dict result;
    result["sender_path"] = py::str(profile.sender_path);
    result["sender_fallback_reason"] = py::str("none");
    result["l7_engine_path_used"] = py::str("L7_EMU_NATIVE");
    result["l7_fallback_reason"] = py::str("none");
    result["runtime_reactor_backend"] = py::str(reactor_backend_name(reactor_backend));
    result["runtime_transport_backend"] = py::str(transport_backend_name(transport_backend));
    result["runtime_tls_backend"] = py::str(tls_backend_name(tls_backend));
    result["runtime_http2_backend"] = py::str(http2_backend_name(http2_backend));
    result["runtime_native_hot_path_level"] = py::str(native_hot_path_level_name(hot_path_level));
    const auto custom_tcp_bridge_ready = out.find("runtime_transport_custom_tcp_bridge_ready");
    if (
        transport_backend == TransportBackend::CustomTcp &&
        custom_tcp_bridge_ready != out.end() &&
        custom_tcp_bridge_ready->second == 0.0) {
      result["sender_fallback_reason"] = py::str("custom_tcp_transport_not_yet_wired");
      result["l7_fallback_reason"] = py::str("custom_tcp_transport_not_yet_wired");
      result["stateful_runtime_reason"] = py::str("custom_tcp_transport_not_yet_wired");
      result["stateful_runtime_detail"] = py::str("custom TCP bridge is not ready in native runtime");
    }
    if (profile.protocol == "http2") {
      result["h2_transport"] = py::str("nghttp2_native");
      if (!(caps.openssl && caps.nghttp2)) {
        result["sender_fallback_reason"] = py::str("capability_unavailable:nghttp2_native");
        result["l7_fallback_reason"] = py::str("capability_unavailable:nghttp2_native");
      }
    }
    if (!result.contains("stateful_runtime_reason")) {
      result["stateful_runtime_reason"] = py::str("none");
      result["stateful_runtime_detail"] = py::str("");
    }
    for (const auto& [key, value] : out) {
      if (
          key == "l7_engine_path_used" ||
          key == "sender_path" ||
          key == "sender_fallback_reason" ||
          key == "l7_fallback_reason") {
        continue;
      }
      const double rounded = value;
      const double integral = static_cast<double>(static_cast<long long>(rounded));
      if (rounded == integral) {
        result[py::str(key)] = py::int_(static_cast<long long>(integral));
      } else {
        result[py::str(key)] = py::float_(rounded);
      }
    }
    return result;
  });
  m.def("drain_custom_tcp_tx_packets", []() {
    const uint8_t** packets = nullptr;
    size_t* packet_lens = nullptr;
    uint32_t count = 0;
    if (tcpdp_drain_tx_packets(0, &packets, &packet_lens, &count) != 0) {
      throw std::runtime_error("failed to drain custom TCP TX packets");
    }
    py::list out;
    for (uint32_t i = 0; i < count; ++i) {
      out.append(py::bytes(reinterpret_cast<const char*>(packets[i]), static_cast<py::ssize_t>(packet_lens[i])));
    }
    tcpdp_free_drained_packets(packets, packet_lens, count);
    return out;
  });
  m.def("ingest_custom_tcp_rx_frame", [](py::bytes frame) {
    const std::string raw = py::cast<std::string>(frame);
    uint32_t updated = 0;
    if (tcpdp_ingest_rx_frame(
            reinterpret_cast<const uint8_t*>(raw.data()),
            raw.size(),
            &updated) != 0) {
      throw std::runtime_error("failed to ingest custom TCP RX frame");
    }
    return py::int_(static_cast<long long>(updated));
  });
  m.def("snapshot_custom_tcp_stats", []() {
    tcpdp_stats_snapshot_t stats{};
    if (tcpdp_snapshot_stats(&stats) != 0) {
      throw std::runtime_error("failed to snapshot custom TCP stats");
    }
    py::dict out;
    out["tcp_flows_active"] = py::int_(static_cast<long long>(stats.flows_active));
    out["tcp_connect_attempts"] = py::int_(static_cast<long long>(stats.connect_attempts));
    out["tcp_connect_established"] = py::int_(static_cast<long long>(stats.connect_established));
    out["tcp_retransmit_count"] = py::int_(static_cast<long long>(stats.retransmit_count));
    out["tcp_timeout_close_count"] = py::int_(static_cast<long long>(stats.timeout_close_count));
    out["tcp_connect_timeout_count"] = py::int_(static_cast<long long>(stats.connect_timeout_count));
    out["tcp_idle_timeout_count"] = py::int_(static_cast<long long>(stats.idle_timeout_count));
    out["tcp_retransmit_exhausted_count"] = py::int_(static_cast<long long>(stats.retransmit_exhausted_count));
    out["tcp_rx_ack_count"] = py::int_(static_cast<long long>(stats.rx_ack_count));
    out["tcp_dup_ack_count"] = py::int_(static_cast<long long>(stats.dup_ack_count));
    out["tcp_partial_ack_count"] = py::int_(static_cast<long long>(stats.partial_ack_count));
    out["tcp_fast_retransmit_count"] = py::int_(static_cast<long long>(stats.fast_retransmit_count));
    out["tcp_unexpected_ack_count"] = py::int_(static_cast<long long>(stats.unexpected_ack_count));
    out["tcp_tx_data_bytes"] = py::int_(static_cast<long long>(stats.tx_data_bytes));
    out["tcp_rx_data_bytes"] = py::int_(static_cast<long long>(stats.rx_data_bytes));
    out["tcp_out_of_order_rx_count"] = py::int_(static_cast<long long>(stats.out_of_order_rx_count));
    out["tcp_peer_rst_count"] = py::int_(static_cast<long long>(stats.peer_rst_count));
    out["tcp_peer_fin_count"] = py::int_(static_cast<long long>(stats.peer_fin_count));
    return out;
  });
}
