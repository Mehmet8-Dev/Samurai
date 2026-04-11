#include <pybind11/pybind11.h>

#include "../include/compiler.hpp"
#include "../include/oracle.hpp"
#include "../include/plan_batch.hpp"

namespace py = pybind11;

PYBIND11_MODULE(_gpu_cuda_payload_native, m) {
  m.doc() = "GPU ASTF Vector compiler bridge (C++/CUDA-ready ABI)";

  m.def(
      "compile_vector_spec",
      &ddos_samurai::gpu_cuda_payload::compile_vector_spec_dict,
      py::arg("spec"),
      py::arg("seed"),
      py::arg("batch_size"));

  m.def(
      "normalize_plan_batch",
      [](const py::dict& payload) {
        return ddos_samurai::gpu_cuda_payload::plan_batch_to_dict(
            ddos_samurai::gpu_cuda_payload::plan_batch_from_dict(payload));
      },
      py::arg("plan_batch"));

  m.def(
      "evaluate_oracle",
      &ddos_samurai::gpu_cuda_payload::evaluate_oracle,
      py::arg("plan_batch"),
      py::arg("run_result"),
      py::arg("checks"));
}

