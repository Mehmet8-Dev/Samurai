#include "../include/compiler.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <stdexcept>
#include <string>

#ifdef SAMURAI_GPU_CUDA_PAYLOAD_KERNELS
#include <cuda_runtime_api.h>
#endif

namespace py = pybind11;

namespace ddos_samurai::gpu_cuda_payload {

namespace {

std::uint64_t splitmix64(std::uint64_t& x) {
  x += 0x9E3779B97F4A7C15ULL;
  std::uint64_t z = x;
  z = (z ^ (z >> 30U)) * 0xBF58476D1CE4E5B9ULL;
  z = (z ^ (z >> 27U)) * 0x94D049BB133111EBULL;
  return z ^ (z >> 31U);
}

struct Xoroshiro128Plus {
  std::uint64_t s0;
  std::uint64_t s1;

  explicit Xoroshiro128Plus(std::uint64_t seed) {
    std::uint64_t sm = seed;
    s0 = splitmix64(sm);
    s1 = splitmix64(sm);
    if (s0 == 0ULL && s1 == 0ULL) {
      s1 = 0x9E3779B97F4A7C15ULL;
    }
  }

  static std::uint64_t rotl(const std::uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
  }

  std::uint64_t next() {
    const std::uint64_t out = s0 + s1;
    std::uint64_t x = s0;
    std::uint64_t y = s1;
    y ^= x;
    s0 = rotl(x, 55) ^ y ^ (y << 14);
    s1 = rotl(y, 36);
    return out;
  }

  std::uint32_t next_u32() {
    return static_cast<std::uint32_t>(next() & 0xFFFFFFFFULL);
  }

  std::size_t bounded(std::size_t upper) {
    if (upper == 0) {
      return 0;
    }
    return static_cast<std::size_t>(next() % static_cast<std::uint64_t>(upper));
  }
};

bool is_write_heavy_method(const std::string& method_raw) {
  std::string m = method_raw;
  std::transform(m.begin(), m.end(), m.begin(), [](unsigned char c) {
    return static_cast<char>(std::toupper(c));
  });
  return m == "POST" || m == "PUT" || m == "PATCH" || m == "DELETE";
}

std::uint8_t state_op_from_name(const std::string& raw) {
  std::string n = raw;
  std::transform(n.begin(), n.end(), n.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  if (n == "open") {
    return static_cast<std::uint8_t>(1);
  }
  if (n == "send") {
    return static_cast<std::uint8_t>(2);
  }
  if (n == "expect") {
    return static_cast<std::uint8_t>(3);
  }
  if (n == "close") {
    return static_cast<std::uint8_t>(4);
  }
  return static_cast<std::uint8_t>(0);
}

#ifdef SAMURAI_GPU_CUDA_PAYLOAD_KERNELS
extern "C" void samurai_gpu_cuda_payload_planner_kernel(
    unsigned short* method_idx,
    unsigned short* path_idx,
    unsigned short* header_profile_idx,
    unsigned char* body_kind,
    unsigned char* step_id,
    unsigned short* think_time_ms,
    unsigned int* flags,
    unsigned int count,
    unsigned int max_steps,
    unsigned int method_count,
    unsigned int path_count,
    unsigned int header_count,
    unsigned int body_count,
    unsigned int seed);

bool env_flag_enabled(const char* name, bool default_value) {
  const char* raw = std::getenv(name);
  if (!raw || raw[0] == '\0') {
    return default_value;
  }
  std::string val(raw);
  std::transform(val.begin(), val.end(), val.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return val == "1" || val == "true" || val == "yes" || val == "on";
}

bool try_compile_plan_prefix_with_cuda(
    PlanBatchV1& out,
    const VectorSpecV1& spec,
    std::uint64_t seed,
    std::size_t batch_size) {
  if (batch_size == 0) {
    return false;
  }
  if (!env_flag_enabled("SAMURAI_GPU_CUDA_PAYLOAD_PLANNER", true)) {
    return false;
  }
  int device_count = 0;
  if (cudaGetDeviceCount(&device_count) != cudaSuccess || device_count <= 0) {
    return false;
  }

  unsigned short* d_method_idx = nullptr;
  unsigned short* d_path_idx = nullptr;
  unsigned short* d_header_profile_idx = nullptr;
  unsigned char* d_body_kind = nullptr;
  unsigned char* d_step_id = nullptr;
  unsigned short* d_think_time_ms = nullptr;
  unsigned int* d_flags = nullptr;

  const auto cleanup = [&]() {
    if (d_method_idx) cudaFree(d_method_idx);
    if (d_path_idx) cudaFree(d_path_idx);
    if (d_header_profile_idx) cudaFree(d_header_profile_idx);
    if (d_body_kind) cudaFree(d_body_kind);
    if (d_step_id) cudaFree(d_step_id);
    if (d_think_time_ms) cudaFree(d_think_time_ms);
    if (d_flags) cudaFree(d_flags);
  };

  const std::size_t n = batch_size;
  auto alloc_u16 = [&](unsigned short** ptr) -> bool {
    return cudaMalloc(reinterpret_cast<void**>(ptr), n * sizeof(unsigned short)) == cudaSuccess;
  };
  auto alloc_u8 = [&](unsigned char** ptr) -> bool {
    return cudaMalloc(reinterpret_cast<void**>(ptr), n * sizeof(unsigned char)) == cudaSuccess;
  };
  auto alloc_u32 = [&](unsigned int** ptr) -> bool {
    return cudaMalloc(reinterpret_cast<void**>(ptr), n * sizeof(unsigned int)) == cudaSuccess;
  };
  if (!alloc_u16(&d_method_idx) || !alloc_u16(&d_path_idx) || !alloc_u16(&d_header_profile_idx) ||
      !alloc_u8(&d_body_kind) || !alloc_u8(&d_step_id) || !alloc_u16(&d_think_time_ms) || !alloc_u32(&d_flags)) {
    cleanup();
    return false;
  }

  unsigned int count_u32 = static_cast<unsigned int>(batch_size);
  unsigned int max_steps_u32 = spec.max_steps;
  const unsigned int blocks = (count_u32 + 255U) / 256U;
  const dim3 grid(blocks);
  const dim3 block(256U);
  void* args[] = {
      &d_method_idx,
      &d_path_idx,
      &d_header_profile_idx,
      &d_body_kind,
      &d_step_id,
      &d_think_time_ms,
      &d_flags,
      &count_u32,
      &max_steps_u32,
      nullptr,
      nullptr,
      nullptr,
      nullptr,
      nullptr,
  };
  unsigned int method_count = static_cast<unsigned int>(spec.methods.size());
  unsigned int path_count = static_cast<unsigned int>(spec.paths.size());
  unsigned int header_count = static_cast<unsigned int>(spec.header_profiles.size());
  unsigned int body_count = static_cast<unsigned int>(spec.body_profiles.size());
  unsigned int seed_u32 = static_cast<unsigned int>(seed & 0xFFFFFFFFULL);
  args[9] = &method_count;
  args[10] = &path_count;
  args[11] = &header_count;
  args[12] = &body_count;
  args[13] = &seed_u32;

  if (cudaLaunchKernel(
          reinterpret_cast<const void*>(samurai_gpu_cuda_payload_planner_kernel),
          grid,
          block,
          args,
          0,
          nullptr) != cudaSuccess) {
    cleanup();
    return false;
  }
  if (cudaDeviceSynchronize() != cudaSuccess) {
    cleanup();
    return false;
  }

  if (cudaMemcpy(out.method_idx.data(), d_method_idx, n * sizeof(unsigned short), cudaMemcpyDeviceToHost) != cudaSuccess ||
      cudaMemcpy(out.path_idx.data(), d_path_idx, n * sizeof(unsigned short), cudaMemcpyDeviceToHost) != cudaSuccess ||
      cudaMemcpy(out.header_profile_idx.data(), d_header_profile_idx, n * sizeof(unsigned short), cudaMemcpyDeviceToHost) != cudaSuccess ||
      cudaMemcpy(out.body_kind.data(), d_body_kind, n * sizeof(unsigned char), cudaMemcpyDeviceToHost) != cudaSuccess ||
      cudaMemcpy(out.step_id.data(), d_step_id, n * sizeof(unsigned char), cudaMemcpyDeviceToHost) != cudaSuccess ||
      cudaMemcpy(out.think_time_ms.data(), d_think_time_ms, n * sizeof(unsigned short), cudaMemcpyDeviceToHost) != cudaSuccess ||
      cudaMemcpy(out.flags.data(), d_flags, n * sizeof(unsigned int), cudaMemcpyDeviceToHost) != cudaSuccess) {
    cleanup();
    return false;
  }
  cleanup();
  return true;
}
#endif

}  // namespace

PlanBatchV1 compile_vector_spec(
    const VectorSpecV1& spec,
    std::uint64_t seed,
    std::size_t batch_size) {
  if (batch_size == 0) {
    throw std::runtime_error("batch_size must be > 0");
  }
  if (spec.methods.empty() || spec.paths.empty() || spec.header_profiles.empty() || spec.body_profiles.empty()) {
    throw std::runtime_error("vector spec must define non-empty methods/paths/header_profiles/body_profiles");
  }

  PlanBatchV1 out;
  out.schema_version = static_cast<std::uint64_t>(spec.schema_version);
  out.seed = seed;
  out.count = static_cast<std::uint32_t>(batch_size);
  out.method_idx.resize(batch_size);
  out.path_idx.resize(batch_size);
  out.header_profile_idx.resize(batch_size);
  out.body_kind.resize(batch_size);
  out.step_id.resize(batch_size);
  out.think_time_ms.resize(batch_size);
  out.flags.resize(batch_size);
  out.template_id.resize(batch_size);
  out.flow_id.resize(batch_size);
  out.client_idx.resize(batch_size);
  out.server_idx.resize(batch_size);
  out.tuple_hash.resize(batch_size);
  out.state_op.resize(batch_size);

  bool planner_cuda_kernel = false;
#ifdef SAMURAI_GPU_CUDA_PAYLOAD_KERNELS
  planner_cuda_kernel = try_compile_plan_prefix_with_cuda(out, spec, seed, batch_size);
#endif

  Xoroshiro128Plus rng(seed);
  const std::size_t total_template_count =
      static_cast<std::size_t>(spec.l4_templates.size() + spec.l7_templates.size());
  const std::uint32_t flow_count = std::max<std::uint32_t>(1U, spec.flow_count == 0U ? static_cast<std::uint32_t>(batch_size) : spec.flow_count);
  const std::uint32_t client_pool_size = std::max<std::uint32_t>(1U, spec.client_pool_size);
  const std::uint32_t server_pool_size = std::max<std::uint32_t>(1U, spec.server_pool_size);

  for (std::size_t i = 0; i < batch_size; ++i) {
    std::size_t m_idx = 0;
    if (planner_cuda_kernel) {
      m_idx = static_cast<std::size_t>(out.method_idx[i]) % spec.methods.size();
      out.path_idx[i] = static_cast<std::uint16_t>(static_cast<std::size_t>(out.path_idx[i]) % spec.paths.size());
      out.header_profile_idx[i] = static_cast<std::uint16_t>(
          static_cast<std::size_t>(out.header_profile_idx[i]) % spec.header_profiles.size());
      out.body_kind[i] = static_cast<std::uint8_t>(
          static_cast<std::size_t>(out.body_kind[i]) % std::max<std::size_t>(1U, spec.body_profiles.size()));
      out.step_id[i] = static_cast<std::uint8_t>(
          static_cast<std::size_t>(out.step_id[i]) % std::max<std::uint32_t>(1U, spec.max_steps));
    } else {
      m_idx = rng.bounded(spec.methods.size());
      const std::size_t p_idx = rng.bounded(spec.paths.size());
      const std::size_t h_idx = rng.bounded(spec.header_profiles.size());
      out.method_idx[i] = static_cast<std::uint16_t>(m_idx);
      out.path_idx[i] = static_cast<std::uint16_t>(p_idx);
      out.header_profile_idx[i] = static_cast<std::uint16_t>(h_idx);
      out.step_id[i] = static_cast<std::uint8_t>(rng.bounded(std::max<std::uint32_t>(1U, spec.max_steps)));

      const std::size_t max_body_kinds = std::min<std::size_t>(255, spec.body_profiles.size());
      std::uint8_t body_kind = static_cast<std::uint8_t>(rng.bounded(max_body_kinds));
      if (!is_write_heavy_method(spec.methods[m_idx])) {
        // HTTP polymorphism: read-heavy methods mostly stay bodyless.
        body_kind = static_cast<std::uint8_t>((rng.next_u32() & 0x7U) == 0U ? body_kind : 0U);
      }
      out.body_kind[i] = body_kind;

      if (out.step_id[i] == 0) {
        out.think_time_ms[i] = static_cast<std::uint16_t>(1000 + (rng.next_u32() % 6000U));
      } else {
        out.think_time_ms[i] = static_cast<std::uint16_t>(10 + (rng.next_u32() % 240U));
      }

      // Flags layout (polymorphic HTTP metadata hints):
      // bit0=header_shuffle, bit1=cookie, bit2=referer,
      // bit3-5=accept-language profile idx, bit6-7=accept profile idx,
      // bit8=body compression hint.
      const std::uint32_t r = rng.next_u32();
      std::uint32_t flags = 0U;
      flags |= ((r & 0x1U) << 0U);
      flags |= (((r >> 1U) & 0x1U) << 1U);
      flags |= (((r >> 2U) & 0x1U) << 2U);
      flags |= (((r >> 3U) & 0x7U) << 3U);
      flags |= (((r >> 6U) & 0x3U) << 6U);
      flags |= (((r >> 8U) & 0x1U) << 8U);
      out.flags[i] = flags;
    }

    if (total_template_count > 0U) {
      out.template_id[i] = static_cast<std::uint16_t>(rng.bounded(total_template_count));
    } else {
      out.template_id[i] = 0U;
    }
    out.flow_id[i] = static_cast<std::uint32_t>(rng.bounded(flow_count));
    out.client_idx[i] = static_cast<std::uint16_t>(rng.bounded(client_pool_size));
    out.server_idx[i] = static_cast<std::uint16_t>(rng.bounded(server_pool_size));
    out.tuple_hash[i] = static_cast<std::uint32_t>(
        (static_cast<std::uint32_t>(out.flow_id[i] * 0x9E37U) ^
         static_cast<std::uint32_t>(out.client_idx[i] * 0x85EBU) ^
         static_cast<std::uint32_t>(out.server_idx[i] * 0xC2B2U) ^
         rng.next_u32()));

    if (!spec.step_graph.empty()) {
      const std::size_t op_idx = static_cast<std::size_t>(out.step_id[i]) % spec.step_graph.size();
      out.state_op[i] = state_op_from_name(spec.step_graph[op_idx]);
    } else {
      out.state_op[i] = 0U;
    }
  }

  py::dict meta;
  meta["mode"] = py::str(spec.mode);
  meta["schema_version"] = py::int_(spec.schema_version);
  py::list methods;
  for (const auto& v : spec.methods) {
    methods.append(py::str(v));
  }
  py::list paths;
  for (const auto& v : spec.paths) {
    paths.append(py::str(v));
  }
  py::list header_profiles;
  for (const auto& v : spec.header_profiles) {
    header_profiles.append(py::str(v));
  }
  py::list body_profiles;
  for (const auto& v : spec.body_profiles) {
    body_profiles.append(py::str(v));
  }
  meta["methods"] = methods;
  meta["paths"] = paths;
  meta["header_profiles"] = header_profiles;
  meta["body_profiles"] = body_profiles;
  meta["max_steps"] = py::int_(spec.max_steps);
  meta["topology_enabled"] = py::bool_(spec.topology_enabled);
  meta["topology_plan_id"] = py::str(spec.topology_plan_id);
  meta["client_pool_size"] = py::int_(spec.client_pool_size);
  meta["server_pool_size"] = py::int_(spec.server_pool_size);
  py::list l4_templates;
  for (const auto& v : spec.l4_templates) {
    l4_templates.append(py::str(v));
  }
  py::list l7_templates;
  for (const auto& v : spec.l7_templates) {
    l7_templates.append(py::str(v));
  }
  py::list step_graph;
  for (const auto& v : spec.step_graph) {
    step_graph.append(py::str(v));
  }
  meta["l4_templates"] = l4_templates;
  meta["l7_templates"] = l7_templates;
  meta["flow_count"] = py::int_(spec.flow_count);
  meta["tuple_seed"] = py::int_(spec.tuple_seed);
  meta["step_graph"] = step_graph;
  meta["transport"] = py::str(spec.transport);
  meta["planner_rng"] = py::str("xoroshiro128plus");
  meta["planner_polymorphic_http"] = py::bool_(true);
  meta["planner_backend"] = py::str(planner_cuda_kernel ? "cuda_kernel" : "cpu_native");
  out.metadata = std::move(meta);
  return out;
}

pybind11::dict compile_vector_spec_dict(
    const py::dict& spec_payload,
    std::uint64_t seed,
    std::size_t batch_size) {
  const VectorSpecV1 spec = parse_vector_spec(spec_payload);
  PlanBatchV1 batch = compile_vector_spec(spec, seed, batch_size);
  return plan_batch_to_dict(batch);
}

}  // namespace ddos_samurai::gpu_cuda_payload
