#include "../include/plan_batch.hpp"

#include <stdexcept>

namespace py = pybind11;

namespace ddos_samurai::gpu_cuda_payload {

namespace {

template <typename T>
py::list vector_to_py_list(const std::vector<T>& values) {
  py::list out;
  for (const auto& value : values) {
    out.append(py::int_(value));
  }
  return out;
}

template <typename T>
std::vector<T> py_list_to_vector(const py::dict& payload, const char* key) {
  if (!payload.contains(py::str(key))) {
    throw std::runtime_error(std::string("plan batch missing field: ") + key);
  }
  py::object raw = payload[py::str(key)];
  if (!py::isinstance<py::list>(raw) && !py::isinstance<py::tuple>(raw)) {
    throw std::runtime_error(std::string("plan batch field must be list: ") + key);
  }
  std::vector<T> out;
  for (const auto& item : raw) {
    out.push_back(py::cast<T>(item));
  }
  return out;
}

template <typename T>
std::vector<T> py_list_to_vector_optional(const py::dict& payload, const char* key, std::size_t fill_size, T fill_value) {
  if (!payload.contains(py::str(key))) {
    return std::vector<T>(fill_size, fill_value);
  }
  py::object raw = payload[py::str(key)];
  if (!py::isinstance<py::list>(raw) && !py::isinstance<py::tuple>(raw)) {
    throw std::runtime_error(std::string("plan batch field must be list: ") + key);
  }
  std::vector<T> out;
  for (const auto& item : raw) {
    out.push_back(py::cast<T>(item));
  }
  return out;
}

void validate_size_match(const PlanBatchV1& batch) {
  const std::size_t n = static_cast<std::size_t>(batch.count);
  if (batch.method_idx.size() != n || batch.path_idx.size() != n || batch.header_profile_idx.size() != n ||
      batch.body_kind.size() != n || batch.step_id.size() != n || batch.think_time_ms.size() != n ||
      batch.flags.size() != n || batch.template_id.size() != n || batch.flow_id.size() != n ||
      batch.client_idx.size() != n || batch.server_idx.size() != n || batch.tuple_hash.size() != n ||
      batch.state_op.size() != n) {
    throw std::runtime_error("plan batch column size mismatch");
  }
}

}  // namespace

py::dict plan_batch_to_dict(const PlanBatchV1& batch) {
  validate_size_match(batch);
  py::dict out;
  out["schema_version"] = py::int_(batch.schema_version);
  out["seed"] = py::int_(batch.seed);
  out["count"] = py::int_(batch.count);
  out["method_idx"] = vector_to_py_list(batch.method_idx);
  out["path_idx"] = vector_to_py_list(batch.path_idx);
  out["header_profile_idx"] = vector_to_py_list(batch.header_profile_idx);
  out["body_kind"] = vector_to_py_list(batch.body_kind);
  out["step_id"] = vector_to_py_list(batch.step_id);
  out["think_time_ms"] = vector_to_py_list(batch.think_time_ms);
  out["flags"] = vector_to_py_list(batch.flags);
  out["template_id"] = vector_to_py_list(batch.template_id);
  out["flow_id"] = vector_to_py_list(batch.flow_id);
  out["client_idx"] = vector_to_py_list(batch.client_idx);
  out["server_idx"] = vector_to_py_list(batch.server_idx);
  out["tuple_hash"] = vector_to_py_list(batch.tuple_hash);
  out["state_op"] = vector_to_py_list(batch.state_op);
  out["metadata"] = batch.metadata;
  return out;
}

PlanBatchV1 plan_batch_from_dict(const py::dict& payload) {
  PlanBatchV1 out;
  out.schema_version = payload.contains(py::str("schema_version")) ? py::cast<std::uint64_t>(payload[py::str("schema_version")]) : 1ULL;
  out.seed = payload.contains(py::str("seed")) ? py::cast<std::uint64_t>(payload[py::str("seed")]) : 0ULL;
  out.count = py::cast<std::uint32_t>(payload[py::str("count")]);
  out.method_idx = py_list_to_vector<std::uint16_t>(payload, "method_idx");
  out.path_idx = py_list_to_vector<std::uint16_t>(payload, "path_idx");
  out.header_profile_idx = py_list_to_vector<std::uint16_t>(payload, "header_profile_idx");
  out.body_kind = py_list_to_vector<std::uint8_t>(payload, "body_kind");
  out.step_id = py_list_to_vector<std::uint8_t>(payload, "step_id");
  out.think_time_ms = py_list_to_vector<std::uint16_t>(payload, "think_time_ms");
  out.flags = py_list_to_vector<std::uint32_t>(payload, "flags");
  const std::size_t n = static_cast<std::size_t>(out.count);
  out.template_id = py_list_to_vector_optional<std::uint16_t>(payload, "template_id", n, static_cast<std::uint16_t>(0));
  out.flow_id = py_list_to_vector_optional<std::uint32_t>(payload, "flow_id", n, static_cast<std::uint32_t>(0));
  out.client_idx = py_list_to_vector_optional<std::uint16_t>(payload, "client_idx", n, static_cast<std::uint16_t>(0));
  out.server_idx = py_list_to_vector_optional<std::uint16_t>(payload, "server_idx", n, static_cast<std::uint16_t>(0));
  out.tuple_hash = py_list_to_vector_optional<std::uint32_t>(payload, "tuple_hash", n, static_cast<std::uint32_t>(0));
  out.state_op = py_list_to_vector_optional<std::uint8_t>(payload, "state_op", n, static_cast<std::uint8_t>(0));
  if (payload.contains(py::str("metadata")) && py::isinstance<py::dict>(payload[py::str("metadata")])) {
    out.metadata = py::cast<py::dict>(payload[py::str("metadata")]);
  }
  validate_size_match(out);
  return out;
}

}  // namespace ddos_samurai::gpu_cuda_payload
