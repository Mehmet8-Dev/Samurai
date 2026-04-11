#include "../include/compiler.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <stdexcept>
#include <string>

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
  out.schema_version = 1;
  out.seed = seed;
  out.count = static_cast<std::uint32_t>(batch_size);
  out.method_idx.resize(batch_size);
  out.path_idx.resize(batch_size);
  out.header_profile_idx.resize(batch_size);
  out.body_kind.resize(batch_size);
  out.step_id.resize(batch_size);
  out.think_time_ms.resize(batch_size);
  out.flags.resize(batch_size);

  Xoroshiro128Plus rng(seed);

  for (std::size_t i = 0; i < batch_size; ++i) {
    const std::size_t m_idx = rng.bounded(spec.methods.size());
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

  py::dict meta;
  meta["mode"] = py::str(spec.mode);
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
  meta["planner_rng"] = py::str("xoroshiro128plus");
  meta["planner_polymorphic_http"] = py::bool_(true);
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
