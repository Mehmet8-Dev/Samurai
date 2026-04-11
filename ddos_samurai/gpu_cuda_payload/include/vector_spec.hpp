#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <pybind11/pybind11.h>

namespace ddos_samurai::gpu_cuda_payload {

struct VectorSpecV1 {
  std::string mode{"program"};
  std::vector<std::string> methods{"GET"};
  std::vector<std::string> paths{"/"};
  std::vector<std::string> header_profiles{"default"};
  std::vector<std::string> body_profiles{"none"};
  std::uint32_t max_steps{4};
};

VectorSpecV1 parse_vector_spec(const pybind11::dict& payload);

}  // namespace ddos_samurai::gpu_cuda_payload

