#include "rl_policy.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>

namespace samurai::control {

namespace {

// Little-endian readers over an in-memory buffer with bounds checks. The SRLP
// format is defined by ddos_samurai/models/rl/export.py — keep the two in lockstep.
struct Reader {
  const unsigned char* p;
  std::size_t n;
  std::size_t off = 0;
  bool ok = true;

  bool need(std::size_t k) {
    if (off + k > n) ok = false;
    return ok;
  }
  std::uint32_t u32() {
    if (!need(4)) return 0;
    std::uint32_t v;
    std::memcpy(&v, p + off, 4);
    off += 4;
    return v;  // host assumed little-endian (x86_64/aarch64 targets)
  }
  float f32() {
    if (!need(4)) return 0.0f;
    float v;
    std::memcpy(&v, p + off, 4);
    off += 4;
    return v;
  }
  void floats(std::vector<float>& out, std::size_t count) {
    if (!need(4 * count)) return;
    out.resize(count);
    std::memcpy(out.data(), p + off, 4 * count);
    off += 4 * count;
  }
};

}  // namespace

bool RlPolicy::Load(const std::string& path, std::string* err) {
  loaded_ = false;
  layers_.clear();
  norm_mean_.clear();
  norm_std_.clear();

  std::ifstream f(path, std::ios::binary | std::ios::ate);
  if (!f.is_open()) {
    if (err) *err = "cannot open " + path;
    return false;
  }
  const std::streamsize size = f.tellg();
  f.seekg(0);
  std::vector<unsigned char> buf(static_cast<std::size_t>(std::max<std::streamsize>(0, size)));
  if (size > 0 && !f.read(reinterpret_cast<char*>(buf.data()), size)) {
    if (err) *err = "short read on " + path;
    return false;
  }

  Reader r{buf.data(), buf.size()};
  if (buf.size() < 4 || std::memcmp(buf.data(), "SRLP", 4) != 0) {
    if (err) *err = "bad magic (not an SRLP policy file)";
    return false;
  }
  r.off = 4;
  const std::uint32_t version = r.u32();
  if (version != 1) {
    if (err) *err = "unsupported SRLP version";
    return false;
  }
  const std::uint32_t in_dim = r.u32();
  const std::uint32_t n_layers = r.u32();
  if (!r.ok || in_dim == 0 || n_layers == 0 || n_layers > 64) {
    if (err) *err = "corrupt header";
    return false;
  }
  std::vector<std::uint32_t> out_dims(n_layers);
  for (std::uint32_t i = 0; i < n_layers; ++i) out_dims[i] = r.u32();

  std::uint32_t prev = in_dim;
  layers_.reserve(n_layers);
  for (std::uint32_t i = 0; i < n_layers; ++i) {
    Layer L;
    L.in_dim = static_cast<int>(prev);
    L.out_dim = static_cast<int>(out_dims[i]);
    r.floats(L.w, static_cast<std::size_t>(out_dims[i]) * prev);
    r.floats(L.b, out_dims[i]);
    if (!r.ok) {
      if (err) *err = "truncated weights";
      return false;
    }
    layers_.push_back(std::move(L));
    prev = out_dims[i];
  }
  r.floats(norm_mean_, in_dim);
  r.floats(norm_std_, in_dim);
  action_lo_ = r.f32();
  action_hi_ = r.f32();
  if (!r.ok) {
    if (err) *err = "truncated norm/action footer";
    return false;
  }
  if (out_dims.back() != 1) {
    if (err) *err = "policy output must be 1-D (rps)";
    return false;
  }

  in_dim_ = static_cast<int>(in_dim);
  loaded_ = true;
  return true;
}

std::vector<float> RlPolicy::BuildFeatures(const RlStateInputs& in) {
  const double max_rps = in.max_rps > 0.0 ? in.max_rps : 1.0;
  const double step_h = in.step_horizon > 0.0 ? in.step_horizon : 1.0;

  // Maskable raw fields in the exact order the Python mask bits are appended.
  const double maskable[9] = {
      in.error_pct,       in.loss_pct,      in.rate_accuracy_pct,
      in.p99_ms,          in.rate_limited_ratio, in.overload_ratio,
      in.conn_drop_ratio, in.reset_pressure, in.challenge_rate,
  };
  auto impute = [](double v) { return v < 0.0 ? 0.0 : v; };

  std::vector<float> f;
  f.reserve(20);
  f.push_back(static_cast<float>(in.rps / max_rps));            // 0 rps_norm
  f.push_back(static_cast<float>(impute(in.error_pct)));        // 1 error_pct
  f.push_back(static_cast<float>(impute(in.loss_pct)));         // 2 loss_pct
  f.push_back(static_cast<float>(impute(in.rate_accuracy_pct)));// 3 rate_accuracy_pct
  f.push_back(static_cast<float>(impute(in.p99_ms)));           // 4 p99_ms
  f.push_back(static_cast<float>(in.win / step_h));             // 5 step_norm
  f.push_back(static_cast<float>(impute(in.rate_limited_ratio)));// 6
  f.push_back(static_cast<float>(impute(in.overload_ratio)));   // 7
  f.push_back(static_cast<float>(impute(in.conn_drop_ratio)));  // 8
  f.push_back(static_cast<float>(impute(in.reset_pressure)));   // 9
  f.push_back(static_cast<float>(impute(in.challenge_rate)));   // 10
  for (double m : maskable) f.push_back(m < 0.0 ? 0.0f : 1.0f); // 11..19 mask bits
  return f;
}

double RlPolicy::Propose(const std::vector<float>& features) const {
  if (!loaded_ || static_cast<int>(features.size()) != in_dim_) return -1.0;

  // Standardize.
  std::vector<float> x(features.size());
  for (std::size_t i = 0; i < features.size(); ++i) {
    const float sd = (norm_std_[i] == 0.0f) ? 1.0f : norm_std_[i];
    x[i] = (features[i] - norm_mean_[i]) / sd;
  }

  // Dense layers: ReLU on all but the last.
  for (std::size_t li = 0; li < layers_.size(); ++li) {
    const Layer& L = layers_[li];
    std::vector<float> y(L.out_dim);
    for (int o = 0; o < L.out_dim; ++o) {
      float acc = L.b[o];
      const float* wrow = L.w.data() + static_cast<std::size_t>(o) * L.in_dim;
      for (int i = 0; i < L.in_dim; ++i) acc += wrow[i] * x[i];
      y[o] = acc;
    }
    if (li + 1 < layers_.size()) {
      for (float& v : y) v = std::max(0.0f, v);
    }
    x = std::move(y);
  }

  const float out = x.empty() ? 0.0f : x[0];
  const float frac = std::max(0.0f, std::min(1.0f, out));
  return static_cast<double>(action_lo_) +
         static_cast<double>(frac) * (static_cast<double>(action_hi_) - action_lo_);
}

}  // namespace samurai::control
