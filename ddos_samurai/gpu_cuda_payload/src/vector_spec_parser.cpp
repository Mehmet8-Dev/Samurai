#include "../include/vector_spec.hpp"

#include <algorithm>
#include <cctype>
#include <stdexcept>

namespace py = pybind11;

namespace ddos_samurai::gpu_cuda_payload {

namespace {

std::vector<std::string> parse_string_list(const py::dict& payload, const char* key) {
  if (!payload.contains(py::str(key))) {
    return {};
  }
  py::object raw = payload[py::str(key)];
  if (!py::isinstance<py::list>(raw) && !py::isinstance<py::tuple>(raw)) {
    throw std::runtime_error(std::string("vector spec field '") + key + "' must be list/tuple");
  }
  std::vector<std::string> out;
  for (const auto& item : raw) {
    const std::string value = py::str(item);
    if (value.empty()) {
      throw std::runtime_error(std::string("vector spec field '") + key + "' cannot contain empty strings");
    }
    out.push_back(value);
  }
  return out;
}

std::uint32_t parse_u32_from_dict(const py::dict& payload, const char* key, std::uint32_t fallback) {
  if (!payload.contains(py::str(key))) {
    return fallback;
  }
  return py::cast<std::uint32_t>(payload[py::str(key)]);
}

std::uint64_t parse_u64_from_dict(const py::dict& payload, const char* key, std::uint64_t fallback) {
  if (!payload.contains(py::str(key))) {
    return fallback;
  }
  return py::cast<std::uint64_t>(payload[py::str(key)]);
}

bool parse_bool_from_dict(const py::dict& payload, const char* key, bool fallback) {
  if (!payload.contains(py::str(key))) {
    return fallback;
  }
  return py::cast<bool>(payload[py::str(key)]);
}

}  // namespace

VectorSpecV1 parse_vector_spec(const py::dict& payload) {
  VectorSpecV1 spec;
  spec.schema_version = parse_u32_from_dict(payload, "schema_version", 1U);
  if (spec.schema_version != 1U && spec.schema_version != 2U) {
    throw std::runtime_error("vector spec schema_version must be 1 or 2");
  }
  if (payload.contains(py::str("mode"))) {
    spec.mode = py::str(payload[py::str("mode")]);
  }
  std::transform(spec.mode.begin(), spec.mode.end(), spec.mode.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  if (spec.mode != "program" && spec.mode != "pcap" && spec.mode != "mixed") {
    throw std::runtime_error("vector spec mode must be one of: program|pcap|mixed");
  }

  auto methods = parse_string_list(payload, "methods");
  if (!methods.empty()) {
    spec.methods = std::move(methods);
  }
  auto paths = parse_string_list(payload, "paths");
  if (!paths.empty()) {
    spec.paths = std::move(paths);
  }
  auto header_profiles = parse_string_list(payload, "header_profiles");
  if (!header_profiles.empty()) {
    spec.header_profiles = std::move(header_profiles);
  }
  auto body_profiles = parse_string_list(payload, "body_profiles");
  if (!body_profiles.empty()) {
    spec.body_profiles = std::move(body_profiles);
  }
  if (payload.contains(py::str("max_steps"))) {
    const auto max_steps = py::cast<std::uint32_t>(payload[py::str("max_steps")]);
    if (max_steps == 0 || max_steps > 32) {
      throw std::runtime_error("vector spec max_steps must be in range [1, 32]");
    }
    spec.max_steps = max_steps;
  }

  if (payload.contains(py::str("topology"))) {
    py::object raw = payload[py::str("topology")];
    if (!py::isinstance<py::dict>(raw)) {
      throw std::runtime_error("vector spec field 'topology' must be an object");
    }
    const py::dict topo = py::cast<py::dict>(raw);
    spec.topology_enabled = parse_bool_from_dict(topo, "enabled", false);
    if (topo.contains(py::str("plan_id"))) {
      spec.topology_plan_id = py::str(topo[py::str("plan_id")]);
    }
    spec.client_pool_size = parse_u32_from_dict(topo, "client_pool_size", spec.client_pool_size);
    spec.server_pool_size = parse_u32_from_dict(topo, "server_pool_size", spec.server_pool_size);
  } else {
    spec.topology_enabled = parse_bool_from_dict(payload, "topology_enabled", false);
    spec.client_pool_size = parse_u32_from_dict(payload, "client_pool_size", spec.client_pool_size);
    spec.server_pool_size = parse_u32_from_dict(payload, "server_pool_size", spec.server_pool_size);
    if (payload.contains(py::str("topology_plan_id"))) {
      spec.topology_plan_id = py::str(payload[py::str("topology_plan_id")]);
    }
  }

  if (payload.contains(py::str("template_catalog"))) {
    py::object raw = payload[py::str("template_catalog")];
    if (!py::isinstance<py::dict>(raw)) {
      throw std::runtime_error("vector spec field 'template_catalog' must be an object");
    }
    const py::dict catalog = py::cast<py::dict>(raw);
    auto l4_templates = parse_string_list(catalog, "l4_templates");
    if (!l4_templates.empty()) {
      spec.l4_templates = std::move(l4_templates);
    }
    auto l7_templates = parse_string_list(catalog, "l7_templates");
    if (!l7_templates.empty()) {
      spec.l7_templates = std::move(l7_templates);
    }
  }

  if (payload.contains(py::str("flow"))) {
    py::object raw = payload[py::str("flow")];
    if (!py::isinstance<py::dict>(raw)) {
      throw std::runtime_error("vector spec field 'flow' must be an object");
    }
    const py::dict flow = py::cast<py::dict>(raw);
    spec.flow_count = parse_u32_from_dict(flow, "flow_count", spec.flow_count);
    spec.tuple_seed = parse_u64_from_dict(flow, "tuple_seed", spec.tuple_seed);
    auto step_graph = parse_string_list(flow, "step_graph");
    if (!step_graph.empty()) {
      spec.step_graph = std::move(step_graph);
    }
    if (flow.contains(py::str("transport"))) {
      spec.transport = py::str(flow[py::str("transport")]);
    }
  }

  if (payload.contains(py::str("pacing"))) {
    py::object raw = payload[py::str("pacing")];
    if (!py::isinstance<py::dict>(raw)) {
      throw std::runtime_error("vector spec field 'pacing' must be an object");
    }
    const py::dict pacing = py::cast<py::dict>(raw);
    spec.base_tx_timestamp_ns = parse_u64_from_dict(pacing, "base_tx_timestamp_ns", spec.base_tx_timestamp_ns);
    spec.base_ipg_ns = parse_u32_from_dict(pacing, "base_ipg_ns", spec.base_ipg_ns);
    spec.inter_flow_gap_ns = parse_u32_from_dict(pacing, "inter_flow_gap_ns", spec.inter_flow_gap_ns);
  } else {
    spec.base_tx_timestamp_ns =
        parse_u64_from_dict(payload, "base_tx_timestamp_ns", spec.base_tx_timestamp_ns);
    spec.base_ipg_ns = parse_u32_from_dict(payload, "base_ipg_ns", spec.base_ipg_ns);
    spec.inter_flow_gap_ns = parse_u32_from_dict(payload, "inter_flow_gap_ns", spec.inter_flow_gap_ns);
  }

  if (spec.schema_version >= 2U && spec.topology_enabled) {
    if (spec.client_pool_size == 0U || spec.server_pool_size == 0U) {
      throw std::runtime_error("vector spec v2 topology requires client_pool_size/server_pool_size > 0");
    }
  }

  if (spec.step_graph.empty()) {
    throw std::runtime_error("vector spec flow.step_graph cannot be empty");
  }
  return spec;
}

}  // namespace ddos_samurai::gpu_cuda_payload
