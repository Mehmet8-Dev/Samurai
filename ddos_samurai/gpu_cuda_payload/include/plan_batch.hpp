#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <pybind11/pybind11.h>

namespace ddos_samurai::gpu_cuda_payload {

struct PlanBatchV1 {
  std::uint64_t schema_version{1};
  std::uint64_t seed{0};
  std::uint32_t count{0};

  std::vector<std::uint16_t> method_idx{};
  std::vector<std::uint16_t> path_idx{};
  std::vector<std::uint16_t> header_profile_idx{};
  std::vector<std::uint8_t> body_kind{};
  std::vector<std::uint8_t> step_id{};
  std::vector<std::uint16_t> think_time_ms{};
  std::vector<std::uint32_t> flags{};
  std::vector<std::uint16_t> template_id{};
  std::vector<std::uint32_t> flow_id{};
  std::vector<std::uint16_t> client_idx{};
  std::vector<std::uint16_t> server_idx{};
  std::vector<std::uint32_t> tuple_hash{};
  std::vector<std::uint8_t> state_op{};

  pybind11::dict metadata{};
};

pybind11::dict plan_batch_to_dict(const PlanBatchV1& batch);
PlanBatchV1 plan_batch_from_dict(const pybind11::dict& payload);

}  // namespace ddos_samurai::gpu_cuda_payload
