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

}  // namespace

VectorSpecV1 parse_vector_spec(const py::dict& payload) {
  VectorSpecV1 spec;
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
  return spec;
}

}  // namespace ddos_samurai::gpu_cuda_payload
