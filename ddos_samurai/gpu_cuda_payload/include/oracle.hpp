#pragma once

#include <string>
#include <vector>

#include <pybind11/pybind11.h>

namespace ddos_samurai::gpu_cuda_payload {

struct OracleReport {
  bool pass{false};
  std::vector<std::string> reasons{};
};

pybind11::dict evaluate_oracle(
    const pybind11::dict& plan_batch,
    const pybind11::dict& run_result,
    const pybind11::dict& checks);

}  // namespace ddos_samurai::gpu_cuda_payload

