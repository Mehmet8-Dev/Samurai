#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <map>
#include <stdexcept>
#include <string>
#include <vector>
#include <cstdint>

#include "engine.hpp"
#include "custom_quic_stack/h3_minimal_client.hpp"
#include "../l4/tcp_dataplane_ffi.h"

namespace py = pybind11;
using namespace ddos_samurai::l7_emu_native;

namespace {

constexpr const char* kDrainBufferCapsuleName = "samurai.tcpdp.drain_buffer";

void drain_buffer_capsule_destructor(PyObject* capsule) {
  void* ptr = PyCapsule_GetPointer(capsule, kDrainBufferCapsuleName);
  if (ptr != nullptr) {
    tcpdp_free_drained_buffer(reinterpret_cast<uint8_t*>(ptr));
  }
}

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

std::uint64_t ip_range_size(const py::handle& entry, int family) {
  py::module_ ip_mod = py::module_::import("ipaddress");
  if (py::isinstance<py::str>(entry)) {
    py::object net = ip_mod.attr("ip_network")(entry, py::arg("strict") = false);
    int version = py::cast<int>(net.attr("version"));
    if (version != family) {
      throw std::runtime_error("topology ip family mismatch");
    }
    return py::cast<std::uint64_t>(net.attr("num_addresses"));
  }
  if (py::isinstance<py::dict>(entry)) {
    py::dict d = py::cast<py::dict>(entry);
    if (!d.contains("start") || !d.contains("end")) {
      throw std::runtime_error("ip range object requires start/end");
    }
    py::object start_ip = ip_mod.attr("ip_address")(d["start"]);
    py::object end_ip = ip_mod.attr("ip_address")(d["end"]);
    int v_start = py::cast<int>(start_ip.attr("version"));
    int v_end = py::cast<int>(end_ip.attr("version"));
    if (v_start != family || v_end != family) {
      throw std::runtime_error("topology ip range wrong family");
    }
    std::uint64_t start_i = py::cast<std::uint64_t>(py::int_(start_ip));
    std::uint64_t end_i = py::cast<std::uint64_t>(py::int_(end_ip));
    if (end_i < start_i) {
      throw std::runtime_error("topology ip range start>end");
    }
    return static_cast<std::uint64_t>(end_i - start_i + 1ULL);
  }
  throw std::runtime_error("ip range must be cidr string or {start,end}");
}

std::uint64_t ip_ranges_size(const py::dict& ranges) {
  std::uint64_t total = 0;
  if (ranges.contains("v4")) {
    for (const auto& it : py::cast<py::list>(ranges["v4"])) {
      total += ip_range_size(it, 4);
    }
  }
  if (ranges.contains("v6")) {
    for (const auto& it : py::cast<py::list>(ranges["v6"])) {
      total += ip_range_size(it, 6);
    }
  }
  return total;
}

void require_list_field(const py::dict& root, const char* key, bool strict) {
  if (!root.contains(key)) {
    if (strict) throw std::runtime_error(std::string("missing required field: ") + key);
    return;
  }
  if (!py::isinstance<py::list>(root[key])) {
    throw std::runtime_error(std::string("field must be list: ") + key);
  }
}

py::dict parse_compile_topology_json_native(const std::string& json_text, int seed, bool strict) {
  py::module_ json_mod = py::module_::import("json");
  py::object loaded = json_mod.attr("loads")(py::str(json_text));
  if (!py::isinstance<py::dict>(loaded)) {
    throw std::runtime_error("topology root must be object");
  }
  py::dict root = py::cast<py::dict>(loaded);
  require_list_field(root, "clients", strict);
  require_list_field(root, "servers", strict);
  require_list_field(root, "templates", strict);
  require_list_field(root, "links", strict);

  py::list clients = root.contains("clients") ? py::cast<py::list>(root["clients"]) : py::list();
  py::list servers = root.contains("servers") ? py::cast<py::list>(root["servers"]) : py::list();
  py::list templates = root.contains("templates") ? py::cast<py::list>(root["templates"]) : py::list();
  py::list links = root.contains("links") ? py::cast<py::list>(root["links"]) : py::list();

  if (strict && (clients.empty() || servers.empty() || templates.empty() || links.empty())) {
    throw std::runtime_error("topology requires non-empty clients/servers/templates/links");
  }

  py::set client_names;
  std::uint64_t client_pool = 0;
  for (const auto& c_obj : clients) {
    if (!py::isinstance<py::dict>(c_obj)) throw std::runtime_error("client entry must be object");
    py::dict c = py::cast<py::dict>(c_obj);
    if (!c.contains("name") || !c.contains("ip_ranges") || !c.contains("port_ranges")) {
      throw std::runtime_error("client requires name/ip_ranges/port_ranges");
    }
    client_names.add(c["name"]);
    if (!py::isinstance<py::dict>(c["ip_ranges"])) throw std::runtime_error("client ip_ranges must be object");
    client_pool += ip_ranges_size(py::cast<py::dict>(c["ip_ranges"]));
  }

  py::set server_names;
  std::uint64_t server_pool = 0;
  for (const auto& s_obj : servers) {
    if (!py::isinstance<py::dict>(s_obj)) throw std::runtime_error("server entry must be object");
    py::dict s = py::cast<py::dict>(s_obj);
    if (!s.contains("name") || !s.contains("ip_ranges") || !s.contains("ports")) {
      throw std::runtime_error("server requires name/ip_ranges/ports");
    }
    server_names.add(s["name"]);
    if (!py::isinstance<py::dict>(s["ip_ranges"])) throw std::runtime_error("server ip_ranges must be object");
    server_pool += ip_ranges_size(py::cast<py::dict>(s["ip_ranges"]));
  }

  py::set template_names;
  for (const auto& t_obj : templates) {
    if (!py::isinstance<py::dict>(t_obj)) throw std::runtime_error("template entry must be object");
    py::dict t = py::cast<py::dict>(t_obj);
    if (!t.contains("name") || !t.contains("protocol")) throw std::runtime_error("template requires name/protocol");
    template_names.add(t["name"]);
  }

  for (const auto& l_obj : links) {
    if (!py::isinstance<py::dict>(l_obj)) throw std::runtime_error("link entry must be object");
    py::dict l = py::cast<py::dict>(l_obj);
    if (!l.contains("client_group") || !l.contains("server_group") || !l.contains("template")) {
      throw std::runtime_error("link requires client_group/server_group/template");
    }
    if (!client_names.contains(l["client_group"])) throw std::runtime_error("link client_group unknown");
    if (!server_names.contains(l["server_group"])) throw std::runtime_error("link server_group unknown");
    if (!template_names.contains(l["template"])) throw std::runtime_error("link template unknown");
  }

  py::dict digest_payload;
  digest_payload["seed"] = py::int_(seed);
  digest_payload["spec"] = root;
  py::str normalized = py::cast<py::str>(json_mod.attr("dumps")(digest_payload, py::arg("sort_keys") = true, py::arg("separators") = py::make_tuple(",", ":")));
  py::module_ hashlib = py::module_::import("hashlib");
  py::object sha = hashlib.attr("sha1")(py::bytes(normalized));
  std::string hexdigest = py::cast<std::string>(sha.attr("hexdigest")());
  std::string plan_id = hexdigest.substr(0, 16);

  py::dict out;
  out["plan_id"] = py::str(plan_id);
  out["seed"] = py::int_(seed);
  out["client_pool_size"] = py::int_(static_cast<long long>(client_pool));
  out["server_pool_size"] = py::int_(static_cast<long long>(server_pool));
  out["spec"] = root;
  return out;
}

py::list topology_tuple_preview_native(const py::dict& compiled_plan, int sample_size) {
  if (!compiled_plan.contains("spec")) {
    throw std::runtime_error("compiled topology plan missing spec");
  }
  py::dict spec = py::cast<py::dict>(compiled_plan["spec"]);
  py::list clients = spec.contains("clients") ? py::cast<py::list>(spec["clients"]) : py::list();
  py::list servers = spec.contains("servers") ? py::cast<py::list>(spec["servers"]) : py::list();
  py::list templates = spec.contains("templates") ? py::cast<py::list>(spec["templates"]) : py::list();
  py::list links = spec.contains("links") ? py::cast<py::list>(spec["links"]) : py::list();
  if (clients.empty() || servers.empty() || links.empty()) return py::list();

  int seed = compiled_plan.contains("seed") ? py::cast<int>(compiled_plan["seed"]) : 0;
  py::dict tuple_gen = spec.contains("tuple_gen") ? py::cast<py::dict>(spec["tuple_gen"]) : py::dict();
  std::string allocator = "hash";
  if (tuple_gen.contains("port_allocator")) {
    allocator = py::cast<std::string>(tuple_gen["port_allocator"]);
  }
  py::module_ hashlib = py::module_::import("hashlib");
  py::module_ ip_mod = py::module_::import("ipaddress");

  auto stable_u01 = [&](int idx, const std::string& salt) -> double {
    const std::string token = std::to_string(seed) + ":" + std::to_string(idx) + ":" + salt;
    const std::string raw = py::cast<std::string>(hashlib.attr("sha1")(py::bytes(token)).attr("digest")());
    std::uint64_t v = 0;
    for (int i = 0; i < 8 && i < static_cast<int>(raw.size()); ++i) {
      v = (v << 8) | static_cast<std::uint8_t>(raw[static_cast<std::size_t>(i)]);
    }
    const std::uint64_t frac = v & ((1ULL << 53) - 1ULL);
    return static_cast<double>(frac) / static_cast<double>(1ULL << 53);
  };

  auto find_group = [](const py::list& pool, const std::string& name) -> py::dict {
    for (const auto& item : pool) {
      if (!py::isinstance<py::dict>(item)) continue;
      py::dict d = py::cast<py::dict>(item);
      if (!d.contains("name")) continue;
      if (py::cast<std::string>(d["name"]) == name) return d;
    }
    return py::dict();
  };

  auto find_template = [](const py::list& pool, const std::string& name) -> py::dict {
    for (const auto& item : pool) {
      if (!py::isinstance<py::dict>(item)) continue;
      py::dict d = py::cast<py::dict>(item);
      if (!d.contains("name")) continue;
      if (py::cast<std::string>(d["name"]) == name) return d;
    }
    return py::dict();
  };

  auto pick_ip = [&](const py::dict& ip_ranges, int idx, const std::string& dist, const std::string& salt) -> std::string {
    py::list entries;
    int family = 4;
    if (ip_ranges.contains("v4") && !py::cast<py::list>(ip_ranges["v4"]).empty()) {
      entries = py::cast<py::list>(ip_ranges["v4"]);
      family = 4;
    } else if (ip_ranges.contains("v6") && !py::cast<py::list>(ip_ranges["v6"]).empty()) {
      entries = py::cast<py::list>(ip_ranges["v6"]);
      family = 6;
    } else {
      return std::string();
    }
    std::vector<std::pair<std::uint64_t, std::uint64_t>> spans;
    std::uint64_t total = 0;
    for (const auto& it : entries) {
      std::uint64_t start_i = 0;
      std::uint64_t end_i = 0;
      if (py::isinstance<py::str>(it)) {
        py::object net = ip_mod.attr("ip_network")(it, py::arg("strict") = false);
        int version = py::cast<int>(net.attr("version"));
        if (version != family) continue;
        start_i = py::cast<std::uint64_t>(py::int_(net.attr("network_address")));
        end_i = py::cast<std::uint64_t>(py::int_(net.attr("broadcast_address")));
      } else if (py::isinstance<py::dict>(it)) {
        py::dict d = py::cast<py::dict>(it);
        if (!d.contains("start") || !d.contains("end")) continue;
        py::object sip = ip_mod.attr("ip_address")(d["start"]);
        py::object eip = ip_mod.attr("ip_address")(d["end"]);
        int sv = py::cast<int>(sip.attr("version"));
        int ev = py::cast<int>(eip.attr("version"));
        if (sv != family || ev != family) continue;
        start_i = py::cast<std::uint64_t>(py::int_(sip));
        end_i = py::cast<std::uint64_t>(py::int_(eip));
      } else {
        continue;
      }
      if (end_i < start_i) continue;
      spans.emplace_back(start_i, end_i);
      total += static_cast<std::uint64_t>(end_i - start_i + 1ULL);
    }
    if (spans.empty() || total == 0) return std::string();
    std::uint64_t off = 0;
    if (dist == "seq") {
      off = static_cast<std::uint64_t>(idx) % total;
    } else if (dist == "zipf") {
      double u = stable_u01(idx, salt + ":zipf");
      off = static_cast<std::uint64_t>((u * u * u) * static_cast<double>(total - 1));
    } else {
      double u = stable_u01(idx, salt + ":uniform");
      off = static_cast<std::uint64_t>(u * static_cast<double>(total - 1));
    }
    for (const auto& span : spans) {
      std::uint64_t width = static_cast<std::uint64_t>(span.second - span.first + 1ULL);
      if (off < width) {
        py::object ip_obj = ip_mod.attr("ip_address")(py::int_(span.first + off));
        return py::cast<std::string>(py::str(ip_obj));
      }
      off -= width;
    }
    py::object ip_obj = ip_mod.attr("ip_address")(py::int_(spans.back().first));
    return py::cast<std::string>(py::str(ip_obj));
  };

  auto parse_port_range = [](const py::handle& item) -> std::pair<int, int> {
    if (py::isinstance<py::int_>(item)) {
      int p = py::cast<int>(item);
      return std::make_pair(p, p);
    }
    if (py::isinstance<py::str>(item)) {
      std::string token = py::cast<std::string>(item);
      auto dash = token.find('-');
      if (dash == std::string::npos) {
        int p = std::stoi(token);
        return std::make_pair(p, p);
      }
      int a = std::stoi(token.substr(0, dash));
      int b = std::stoi(token.substr(dash + 1));
      return std::make_pair(a, b);
    }
    if (py::isinstance<py::dict>(item)) {
      py::dict d = py::cast<py::dict>(item);
      int a = d.contains("start") ? py::cast<int>(d["start"]) : 0;
      int b = d.contains("end") ? py::cast<int>(d["end"]) : 0;
      return std::make_pair(a, b);
    }
    return std::make_pair(1024, 1024);
  };

  auto pick_client_port = [&](const py::list& ranges, int idx, const std::string& salt) -> int {
    std::vector<std::pair<int, int>> parsed;
    long long total = 0;
    for (const auto& it : ranges) {
      auto pr = parse_port_range(it);
      if (pr.first < 1) pr.first = 1;
      if (pr.second > 65535) pr.second = 65535;
      if (pr.second < pr.first) continue;
      parsed.push_back(pr);
      total += static_cast<long long>(pr.second - pr.first + 1);
    }
    if (parsed.empty() || total <= 0) return 1024;
    long long off = 0;
    if (allocator == "sequential") {
      off = static_cast<long long>(idx) % total;
    } else if (allocator == "random") {
      off = static_cast<long long>(stable_u01(idx, salt + ":cport_random") * static_cast<double>(total - 1));
    } else {
      off = static_cast<long long>(stable_u01(idx, salt + ":cport_hash") * static_cast<double>(total - 1));
    }
    for (const auto& pr : parsed) {
      long long width = static_cast<long long>(pr.second - pr.first + 1);
      if (off < width) return static_cast<int>(pr.first + off);
      off -= width;
    }
    return parsed.front().first;
  };

  auto pick_server_port = [&](const py::list& ports, int idx, const std::string& salt) -> int {
    if (ports.empty()) return 80;
    int pos = 0;
    if (allocator == "sequential") {
      pos = idx % py::len(ports);
    } else if (allocator == "random") {
      pos = static_cast<int>(stable_u01(idx, salt + ":sport_random") * static_cast<double>(py::len(ports)));
    } else {
      pos = static_cast<int>(stable_u01(idx, salt + ":sport_hash") * static_cast<double>(py::len(ports)));
    }
    if (pos < 0) pos = 0;
    if (pos >= py::len(ports)) pos = py::len(ports) - 1;
    return py::cast<int>(ports[static_cast<std::size_t>(pos)]);
  };

  py::list out;
  int n = sample_size < 0 ? 0 : sample_size;
  for (int i = 0; i < n; ++i) {
    py::dict l = py::cast<py::dict>(links[static_cast<std::size_t>(i % py::len(links))]);
    std::string client_name = l.contains("client_group") ? py::cast<std::string>(l["client_group"]) : std::string();
    std::string server_name = l.contains("server_group") ? py::cast<std::string>(l["server_group"]) : std::string();
    std::string template_name = l.contains("template") ? py::cast<std::string>(l["template"]) : std::string();
    py::dict c = find_group(clients, client_name);
    py::dict s = find_group(servers, server_name);
    py::dict t = find_template(templates, template_name);
    if (c.empty() || s.empty()) continue;
    py::dict c_ranges = c.contains("ip_ranges") ? py::cast<py::dict>(c["ip_ranges"]) : py::dict();
    py::dict s_ranges = s.contains("ip_ranges") ? py::cast<py::dict>(s["ip_ranges"]) : py::dict();
    std::string c_dist = c.contains("dist") ? py::cast<std::string>(c["dist"]) : std::string("uniform");
    std::string client_ip = pick_ip(c_ranges, i, c_dist, client_name + ":client_ip");
    std::string server_ip = pick_ip(s_ranges, i + 17, "uniform", server_name + ":server_ip");
    py::list c_port_ranges = c.contains("port_ranges") ? py::cast<py::list>(c["port_ranges"]) : py::list();
    py::list s_ports = s.contains("ports") ? py::cast<py::list>(s["ports"]) : py::list();
    int client_port = pick_client_port(c_port_ranges, i, client_ip + ":" + server_ip + ":" + template_name);
    int server_port = pick_server_port(s_ports, i, server_ip + ":" + client_ip + ":" + template_name);

    py::dict row;
    row["client_group"] = py::str(client_name);
    row["server_group"] = py::str(server_name);
    row["template"] = py::str(template_name);
    row["client_ip"] = py::str(client_ip);
    row["server_ip"] = py::str(server_ip);
    row["client_port"] = py::int_(client_port);
    row["server_port"] = py::int_(server_port);
    if (!t.empty()) {
      if (t.contains("protocol")) row["template_protocol"] = t["protocol"];
      if (t.contains("method")) row["template_method"] = t["method"];
      if (t.contains("path")) row["template_path"] = t["path"];
      if (t.contains("flags")) row["template_flags"] = t["flags"];
    }
    out.append(row);
  }
  return out;
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
    auto lower_copy = [](std::string s) {
      for (char& c : s) {
        if (c >= 'A' && c <= 'Z') {
          c = static_cast<char>(c - 'A' + 'a');
        }
      }
      return s;
    };
    const std::string requested_transport = lower_copy(profile.transport_backend);
    const bool requested_custom_tcp = requested_transport == "custom_tcp";
    const TransportBackend transport_backend = TransportBackend::CustomTcp;
    if (runtime_requires_custom_tcp && !requested_custom_tcp) {
      py::dict failed;
      failed["sender_path"] = py::str(profile.sender_path);
      failed["sender_fallback_reason"] = py::str("stateful_runtime_transport_unavailable");
      failed["l7_engine_path_used"] = py::str("L7_EMU_NATIVE");
      failed["l7_fallback_reason"] = py::str("stateful_runtime_transport_unavailable");
      failed["stateful_runtime_reason"] = py::str("stateful_runtime_transport_unavailable");
      failed["stateful_runtime_detail"] =
          py::str("kernel_socket fallback is disabled; strict stateful runtime requires custom_tcp transport.");
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
    result["sender_path"] = py::str(profile.protocol == "quic" ? "L7_QUIC_CUSTOM" : profile.sender_path);
    result["sender_fallback_reason"] = py::str("none");
    result["l7_engine_path_used"] = py::str(profile.protocol == "quic" ? "L7_QUIC_CUSTOM" : "L7_EMU_NATIVE");
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
      result["h2_transport"] = py::str(
          transport_backend == TransportBackend::CustomTcp ? "custom_tcp_native" : "nghttp2_native");
      if (transport_backend != TransportBackend::CustomTcp && !(caps.openssl && caps.nghttp2)) {
        result["sender_fallback_reason"] = py::str("capability_unavailable:nghttp2_native");
        result["l7_fallback_reason"] = py::str("capability_unavailable:nghttp2_native");
      }
    }
    if (profile.protocol == "quic") {
      const auto quic_capability_available_it = out.find("quic_capability_available");
      const bool quic_capability_available =
          quic_capability_available_it != out.end() && quic_capability_available_it->second > 0.0;
      result["runtime_http3_backend"] = py::str(quic_capability_available ? "nghttp3_native" : "unavailable");
      result["runtime_quic_transport_backend"] = py::str(quic_capability_available ? "custom_quic_stack" : "unavailable");
      result["quic_stack_mode"] = py::str(quic_capability_available ? "custom_native" : "unavailable");
      if (!quic_capability_available) {
        result["sender_fallback_reason"] = py::str("quic_capability_unavailable");
        result["l7_fallback_reason"] = py::str("quic_capability_unavailable");
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
  m.def("parse_compile_topology_json", [](const std::string& topo_spec_json, int topo_seed, bool topo_strict) {
    return parse_compile_topology_json_native(topo_spec_json, topo_seed, topo_strict);
  });
  m.def("topology_tuple_preview", [](const py::dict& compiled_plan, int sample_size) {
    return topology_tuple_preview_native(compiled_plan, sample_size);
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
  m.def("drain_custom_tcp_tx_buffer", []() {
    uint8_t* buffer = nullptr;
    size_t total_len = 0;
    uint32_t count = 0;
    size_t packet_size = 0;
    if (tcpdp_drain_tx_packets_concat(0, &buffer, &total_len, &count, &packet_size) != 0) {
      throw std::runtime_error("failed to drain custom TCP TX buffer");
    }
    py::object owner;
    if (buffer != nullptr) {
      PyObject* owner_raw = PyCapsule_New(reinterpret_cast<void*>(buffer), kDrainBufferCapsuleName, drain_buffer_capsule_destructor);
      if (!owner_raw) {
        tcpdp_free_drained_buffer(buffer);
        throw py::error_already_set();
      }
      owner = py::reinterpret_steal<py::object>(owner_raw);
    } else {
      owner = py::none();
    }
    PyObject* payload_raw = nullptr;
    if (total_len > 0 && buffer != nullptr) {
      payload_raw = PyMemoryView_FromMemory(reinterpret_cast<char*>(buffer), static_cast<Py_ssize_t>(total_len), PyBUF_READ);
    } else {
      payload_raw = PyMemoryView_FromMemory(const_cast<char*>(""), 0, PyBUF_READ);
    }
    if (!payload_raw) {
      throw py::error_already_set();
    }
    py::object payload = py::reinterpret_steal<py::object>(payload_raw);
    py::dict out;
    out["buffer"] = payload;
    out["owner"] = owner;
    out["count"] = py::int_(static_cast<long long>(count));
    out["packet_size"] = py::int_(static_cast<long long>(packet_size));
    out["uniform"] = py::int_((count == 0 || (packet_size > 0 && (packet_size * static_cast<size_t>(count)) == total_len)) ? 1 : 0);
    return out;
  });
  m.def("peek_custom_tcp_tx_buffer_strided", []() {
    const uint8_t* base = nullptr;
    uint32_t count = 0;
    size_t packet_size = 0;
    size_t stride = 0;
    if (tcpdp_peek_tx_packets_strided(0, &base, &count, &packet_size, &stride) != 0) {
      throw std::runtime_error("failed to peek custom TCP TX strided buffer");
    }
    PyObject* payload_raw = nullptr;
    if (base != nullptr && count > 0 && stride > 0) {
      const size_t total_len = stride * static_cast<size_t>(count);
      payload_raw = PyMemoryView_FromMemory(
          const_cast<char*>(reinterpret_cast<const char*>(base)),
          static_cast<Py_ssize_t>(total_len),
          PyBUF_READ);
    } else {
      payload_raw = PyMemoryView_FromMemory(const_cast<char*>(""), 0, PyBUF_READ);
    }
    if (!payload_raw) {
      throw py::error_already_set();
    }
    py::object payload = py::reinterpret_steal<py::object>(payload_raw);
    py::dict out;
    out["buffer"] = payload;
    out["owner"] = py::none();
    out["count"] = py::int_(static_cast<long long>(count));
    out["packet_size"] = py::int_(static_cast<long long>(packet_size));
    out["stride"] = py::int_(static_cast<long long>(stride));
    out["uniform"] = py::int_(1);
    return out;
  });
  m.def("consume_custom_tcp_tx_packets", [](std::uint32_t max_packets) {
    uint32_t consumed = 0;
    if (tcpdp_consume_tx_packets(max_packets, &consumed) != 0) {
      throw std::runtime_error("failed to consume custom TCP TX packets");
    }
    return py::int_(static_cast<long long>(consumed));
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
  m.def("quic_build_minimal_h3_request", [](const std::string& method, const std::string& path, py::bytes body) {
    const std::string raw_body = py::cast<std::string>(body);
    const std::vector<std::uint8_t> body_vec(raw_body.begin(), raw_body.end());
    const std::vector<std::uint8_t> packet =
        custom_quic_stack::build_minimal_h3_request(method, path, body_vec);
    return py::bytes(reinterpret_cast<const char*>(packet.data()), static_cast<py::ssize_t>(packet.size()));
  });
  m.def("quic_parse_minimal_h3_response", [](py::bytes response) {
    const std::string raw = py::cast<std::string>(response);
    const auto parsed = custom_quic_stack::parse_minimal_h3_response(
        reinterpret_cast<const std::uint8_t*>(raw.data()),
        raw.size());
    py::dict out;
    out["valid"] = py::int_(parsed.valid ? 1 : 0);
    out["headers_ok"] = py::int_(parsed.headers_ok ? 1 : 0);
    out["body_ok"] = py::int_(parsed.body_ok ? 1 : 0);
    out["expected_header_ok"] = py::int_(parsed.expected_header_ok ? 1 : 0);
    out["expected_body_match_ok"] = py::int_(parsed.expected_body_match_ok ? 1 : 0);
    return out;
  });
}
