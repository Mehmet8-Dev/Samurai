#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <map>
#include <stdexcept>
#include <string>

#include "engine.hpp"

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

Profile parse_profile(const py::dict& profile_dict) {
  Profile profile;
  profile.protocol = py::cast<std::string>(profile_dict["protocol"]);
  profile.sender_path = py::cast<std::string>(profile_dict["sender_path"]);
  profile.flow_attempted = py::cast<int>(profile_dict["flow_attempted"]);
  py::dict conn = py::cast<py::dict>(profile_dict["connection_template"]);
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
  return cfg;
}

}  // namespace

PYBIND11_MODULE(_l7_emu_native, m) {
  m.doc() = "Native L7 emulation runtime";
  m.def("run_profile", [](const py::dict& profile_dict, const py::dict& cfg_dict) {
    const Profile profile = parse_profile(profile_dict);
    const RuntimeConfig cfg = parse_runtime_cfg(cfg_dict);
    auto out = run_profile(profile, cfg);
    const RuntimeCapabilities caps = detect_capabilities();
    py::dict result;
    result["sender_path"] = py::str(profile.sender_path);
    result["sender_fallback_reason"] = py::str("none");
    result["l7_engine_path_used"] = py::str("L7_EMU_NATIVE");
    result["l7_fallback_reason"] = py::str("none");
    if (profile.protocol == "http2") {
      result["h2_transport"] = py::str("nghttp2_native");
      if (!(caps.openssl && caps.nghttp2)) {
        result["sender_fallback_reason"] = py::str("capability_unavailable:nghttp2_native");
        result["l7_fallback_reason"] = py::str("capability_unavailable:nghttp2_native");
      }
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
}
