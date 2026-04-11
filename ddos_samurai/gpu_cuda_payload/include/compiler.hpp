#pragma once

#include <cstddef>
#include <cstdint>

#include <pybind11/pybind11.h>

#include "plan_batch.hpp"
#include "vector_spec.hpp"

namespace ddos_samurai::gpu_cuda_payload {

PlanBatchV1 compile_vector_spec(
    const VectorSpecV1& spec,
    std::uint64_t seed,
    std::size_t batch_size);

pybind11::dict compile_vector_spec_dict(
    const pybind11::dict& spec_payload,
    std::uint64_t seed,
    std::size_t batch_size);

}  // namespace ddos_samurai::gpu_cuda_payload

