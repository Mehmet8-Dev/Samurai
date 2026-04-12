#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <pybind11/pybind11.h>

namespace ddos_samurai::gpu_cuda_payload {

struct VectorSpecV1 {
  std::uint32_t schema_version{1};
  std::string mode{"program"};
  std::vector<std::string> methods{"GET"};
  std::vector<std::string> paths{"/"};
  std::vector<std::string> header_profiles{"default"};
  std::vector<std::string> body_profiles{"none"};
  std::uint32_t max_steps{4};

  bool topology_enabled{false};
  std::string topology_plan_id{};
  std::uint32_t client_pool_size{1};
  std::uint32_t server_pool_size{1};

  std::vector<std::string> l4_templates{};
  std::vector<std::string> l7_templates{};

  std::uint32_t flow_count{0};
  std::uint64_t tuple_seed{0};
  std::vector<std::string> step_graph{"open", "send", "expect", "close"};
  std::string transport{"custom_tcp"};
};

VectorSpecV1 parse_vector_spec(const pybind11::dict& payload);

}  // namespace ddos_samurai::gpu_cuda_payload
