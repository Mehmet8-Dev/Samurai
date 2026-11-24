#include "rl_policy.hpp"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <unistd.h>

namespace samurai::control {

namespace {

// Little-endian readers over an in-memory buffer with bounds checks. The SRLP
// format is defined by samurai/models/rl/export.py — keep the two in lockstep.
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
  dims_.clear();
  recurrent_ = false;
  state_dim_ = hidden_dim_ = token_dim_ = 0;
  gru_w_ih_.clear();
  gru_w_hh_.clear();
  gru_b_ih_.clear();
  gru_b_hh_.clear();
  hidden_.clear();
  prev_token_.clear();

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

  // SRLP v4 (RL² recurrent) has a distinct top-level layout — a GRU context encoder
  // before the MLP, and a state-only normalizer. Parse it here; v2/v3 fall through.
  if (version == 4) {
    const std::uint32_t state_dim = r.u32();
    const std::uint32_t hidden = r.u32();
    const std::uint32_t a_dim = r.u32();
    if (!r.ok || state_dim == 0 || hidden == 0 || hidden > 4096 || a_dim == 0 ||
        a_dim > 64) {
      if (err) *err = "corrupt v4 header";
      return false;
    }
    const std::uint32_t token = state_dim + a_dim;
    r.floats(gru_w_ih_, static_cast<std::size_t>(3) * hidden * token);
    r.floats(gru_w_hh_, static_cast<std::size_t>(3) * hidden * hidden);
    r.floats(gru_b_ih_, static_cast<std::size_t>(3) * hidden);
    r.floats(gru_b_hh_, static_cast<std::size_t>(3) * hidden);
    if (!r.ok) {
      if (err) *err = "truncated GRU weights";
      return false;
    }
    const std::uint32_t n_layers = r.u32();
    if (!r.ok || n_layers == 0 || n_layers > 64) {
      if (err) *err = "corrupt v4 header (layers)";
      return false;
    }
    std::vector<std::uint32_t> out_dims(n_layers);
    for (std::uint32_t i = 0; i < n_layers; ++i) out_dims[i] = r.u32();
    std::uint32_t prev = state_dim + hidden;  // first MLP layer consumes [state, hidden]
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
    r.floats(norm_mean_, state_dim);
    r.floats(norm_std_, state_dim);
    if (!r.ok) {
      if (err) *err = "truncated normalizer";
      return false;
    }
    const std::uint32_t out_width = out_dims.back();
    dims_.resize(a_dim);
    int off_out = 0;
    for (std::uint32_t k = 0; k < a_dim; ++k) {
      const std::uint32_t kind = r.u32();
      DimHead& d = dims_[k];
      d.out_offset = off_out;
      if (kind == 1) {  // categorical
        const std::uint32_t n_cat = r.u32();
        if (!r.ok || n_cat == 0 || n_cat > 4096) {
          if (err) *err = "bad categorical head";
          return false;
        }
        d.categorical = true;
        r.floats(d.cats, n_cat);
        // Per-dim [lo, hi] = category range, so NormalizeAction rebuilds the training
        // token action exactly (A = (value - lo)/span).
        if (!d.cats.empty()) {
          d.lo = *std::min_element(d.cats.begin(), d.cats.end());
          d.hi = *std::max_element(d.cats.begin(), d.cats.end());
          if (d.hi <= d.lo) d.hi = d.lo + 1.0f;
        }
        off_out += static_cast<int>(n_cat);
      } else {  // continuous
        d.categorical = false;
        d.lo = r.f32();
        d.hi = r.f32();
        off_out += 1;
      }
      if (!r.ok) {
        if (err) *err = "truncated v4 action footer";
        return false;
      }
    }
    if (off_out != static_cast<int>(out_width)) {
      if (err) *err = "v4 head widths do not sum to the output layer width";
      return false;
    }
    recurrent_ = true;
    state_dim_ = static_cast<int>(state_dim);
    hidden_dim_ = static_cast<int>(hidden);
    token_dim_ = static_cast<int>(token);
    in_dim_ = static_cast<int>(state_dim + hidden);
    action_dim_ = static_cast<int>(a_dim);
    output_width_ = static_cast<int>(out_width);
    ResetContext();
    loaded_ = true;
    return true;
  }

  if (version != 2 && version != 3) {
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
  const std::uint32_t action_dim = r.u32();
  const std::uint32_t out_width = out_dims.back();
  if (!r.ok || action_dim == 0 || action_dim > 64) {
    if (err) *err = "bad action_dim";
    return false;
  }

  // Footer: v2 is all-continuous (one output per dim, flat lo[]/hi[] arrays); v3
  // carries a per-dim head descriptor (continuous lo/hi or categorical n_cat+cats).
  dims_.resize(action_dim);
  int off_out = 0;
  if (version == 2) {
    if (action_dim != out_width) {
      if (err) *err = "v2 action_dim must equal the output layer width";
      return false;
    }
    std::vector<float> lo, hi;
    r.floats(lo, action_dim);
    r.floats(hi, action_dim);
    if (!r.ok) {
      if (err) *err = "truncated norm/action footer";
      return false;
    }
    for (std::uint32_t k = 0; k < action_dim; ++k) {
      dims_[k].categorical = false;
      dims_[k].out_offset = static_cast<int>(k);
      dims_[k].lo = lo[k];
      dims_[k].hi = hi[k];
    }
    off_out = static_cast<int>(action_dim);
  } else {  // version == 3
    for (std::uint32_t k = 0; k < action_dim; ++k) {
      const std::uint32_t kind = r.u32();
      DimHead& d = dims_[k];
      d.out_offset = off_out;
      if (kind == 1) {  // categorical
        const std::uint32_t n_cat = r.u32();
        if (!r.ok || n_cat == 0 || n_cat > 4096) {
          if (err) *err = "bad categorical head";
          return false;
        }
        d.categorical = true;
        r.floats(d.cats, n_cat);
        off_out += static_cast<int>(n_cat);
      } else {  // continuous
        d.categorical = false;
        d.lo = r.f32();
        d.hi = r.f32();
        off_out += 1;
      }
      if (!r.ok) {
        if (err) *err = "truncated v3 action footer";
        return false;
      }
    }
    if (off_out != static_cast<int>(out_width)) {
      if (err) *err = "v3 head widths do not sum to the output layer width";
      return false;
    }
  }

  in_dim_ = static_cast<int>(in_dim);
  state_dim_ = in_dim_;  // feedforward: state IS the full MLP input (no GRU hidden)
  action_dim_ = static_cast<int>(action_dim);
  output_width_ = static_cast<int>(out_width);
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

  // Path-aware block features (appended after the mask bits, matching the Python
  // dataset layout): all block ratios, then all known bits. A variant with best
  // success < 0 is unobserved => ratio imputed to 0, known bit 0.
  const std::vector<double>& blk = in.variant_block_success;
  for (double b : blk) f.push_back(b >= 0.0 ? static_cast<float>(1.0 - b) : 0.0f);
  for (double b : blk) f.push_back(b >= 0.0 ? 1.0f : 0.0f);

  // Persistent-ban features (appended after the block features, matching the Python
  // dataset layout): [ban_pressure, ban_known]. pressure < 0 => never observed =>
  // imputed 0, known bit 0.
  if (in.ban_features) {
    f.push_back(in.ban_pressure >= 0.0 ? static_cast<float>(in.ban_pressure) : 0.0f);
    f.push_back(in.ban_pressure >= 0.0 ? 1.0f : 0.0f);
  }

  // Flow-level IPS/NSM features (appended after the ban features, matching the
  // Python dataset layout): four flow rates then ONE shared flow_known bit. The
  // rates are imputed to 0 when unknown; the shared bit is 1 only on a flow-capable
  // transport with at least one measurable rate (else the whole group is masked,
  // exactly like a kernel-socket corpus).
  if (in.flow_features) {
    const double flow[4] = {in.rst_rate, in.connect_timeout_rate,
                            in.retransmit_rate, in.timeout_close_rate};
    bool any_known = false;
    for (double r : flow) any_known = any_known || (r >= 0.0);
    // When the transport can't measure flow the whole group is masked: impute the
    // values to 0 AND clear the known bit (matches dataset._encode_flow).
    if (in.flow_capable) {
      for (double r : flow) f.push_back(r < 0.0 ? 0.0f : static_cast<float>(r));
      f.push_back(any_known ? 1.0f : 0.0f);
    } else {
      for (int i = 0; i < 4; ++i) f.push_back(0.0f);
      f.push_back(0.0f);
    }
  }
  return f;
}

std::vector<float> RlPolicy::Standardize(const std::vector<float>& features) const {
  std::vector<float> x(features.size());
  for (std::size_t i = 0; i < features.size(); ++i) {
    const float sd = (norm_std_[i] == 0.0f) ? 1.0f : norm_std_[i];
    x[i] = (features[i] - norm_mean_[i]) / sd;
  }
  return x;
}

std::vector<double> RlPolicy::ForwardDecode(const std::vector<float>& mlp_input) const {
  std::vector<float> x = mlp_input;

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

  // Decode the flat output per dim: continuous -> clamp[0,1] + de-normalize;
  // categorical -> argmax over its logits mapped back to the category value.
  std::vector<double> action(action_dim_);
  for (int k = 0; k < action_dim_; ++k) {
    const DimHead& d = dims_[k];
    if (d.categorical) {
      int best = 0;
      float best_logit = x[d.out_offset];
      for (int c = 1; c < static_cast<int>(d.cats.size()); ++c) {
        const float v = x[d.out_offset + c];
        if (v > best_logit) { best_logit = v; best = c; }
      }
      action[k] = static_cast<double>(d.cats[best]);
    } else {
      const float frac = std::max(0.0f, std::min(1.0f, x[d.out_offset]));
      action[k] = static_cast<double>(d.lo) +
                  static_cast<double>(frac) * (static_cast<double>(d.hi) - d.lo);
    }
  }
  return action;
}

std::vector<double> RlPolicy::Propose(const std::vector<float>& features) const {
  if (!loaded_ || static_cast<int>(features.size()) != state_dim_) return {};
  std::vector<float> z = Standardize(features);
  // A recurrent policy scored context-free (isolated first window): append zero hidden.
  if (recurrent_) z.resize(static_cast<std::size_t>(state_dim_ + hidden_dim_), 0.0f);
  return ForwardDecode(z);
}

std::vector<float> RlPolicy::NormalizeAction(const std::vector<double>& action) const {
  std::vector<float> out(action_dim_, 0.0f);
  for (int k = 0; k < action_dim_ && k < static_cast<int>(action.size()); ++k) {
    const DimHead& d = dims_[k];
    const double span = (d.hi <= d.lo) ? 1.0 : (static_cast<double>(d.hi) - d.lo);
    double f = (action[k] - d.lo) / span;
    if (f < 0.0) f = 0.0;
    if (f > 1.0) f = 1.0;
    out[k] = static_cast<float>(f);
  }
  return out;
}

std::vector<float> RlPolicy::GruStep(const std::vector<float>& h,
                                     const std::vector<float>& token) const {
  const int H = hidden_dim_;
  const int T = token_dim_;
  std::vector<float> gi(static_cast<std::size_t>(3) * H);
  std::vector<float> gh(static_cast<std::size_t>(3) * H);
  for (int o = 0; o < 3 * H; ++o) {
    float acc = gru_b_ih_[o];
    const float* wr = gru_w_ih_.data() + static_cast<std::size_t>(o) * T;
    for (int i = 0; i < T; ++i) acc += wr[i] * token[i];
    gi[o] = acc;
  }
  for (int o = 0; o < 3 * H; ++o) {
    float acc = gru_b_hh_[o];
    const float* wr = gru_w_hh_.data() + static_cast<std::size_t>(o) * H;
    for (int i = 0; i < H; ++i) acc += wr[i] * h[i];
    gh[o] = acc;
  }
  // torch.nn.GRUCell, gate order (reset, update, new):
  //   r = σ(gi_r + gh_r), z = σ(gi_z + gh_z), n = tanh(gi_n + r*gh_n)
  //   h' = (1-z)*n + z*h
  std::vector<float> hn(H);
  for (int j = 0; j < H; ++j) {
    const float rr = 1.0f / (1.0f + std::exp(-(gi[j] + gh[j])));
    const float zz = 1.0f / (1.0f + std::exp(-(gi[H + j] + gh[H + j])));
    const float nn = std::tanh(gi[2 * H + j] + rr * gh[2 * H + j]);
    hn[j] = (1.0f - zz) * nn + zz * h[j];
  }
  return hn;
}

std::vector<double> RlPolicy::ProposeFor(const RlStateInputs& in) {
  const std::vector<float> feats = BuildFeatures(in);
  if (!recurrent_) return Propose(feats);
  if (!loaded_ || static_cast<int>(feats.size()) != state_dim_) return {};

  std::vector<float> z = Standardize(feats);
  // Advance the carried hidden state with the previous window's token (nothing to
  // fold on the first window of the episode; hidden stays zero there).
  if (!prev_token_.empty()) hidden_ = GruStep(hidden_, prev_token_);
  // MLP head consumes [standardized state, hidden].
  std::vector<float> mlp_in = z;
  mlp_in.insert(mlp_in.end(), hidden_.begin(), hidden_.end());
  const std::vector<double> action = ForwardDecode(mlp_in);
  // Remember this window's token = [standardized state, normalized action] to fold
  // on the next call (mirrors PolicyArtifact.act_sequence's token construction).
  const std::vector<float> anorm = NormalizeAction(action);
  prev_token_ = std::move(z);
  prev_token_.insert(prev_token_.end(), anorm.begin(), anorm.end());
  return action;
}

void RlPolicy::ResetContext() {
  hidden_.assign(static_cast<std::size_t>(hidden_dim_), 0.0f);
  prev_token_.clear();
}

std::string ResolveRlPolicyPath(const std::string& requested_path) {
  namespace fs = std::filesystem;
  std::error_code ec;
  const std::string target = requested_path.empty() ? "mahoraga-rl2.srlp" : requested_path;

  if (!requested_path.empty() && fs::is_regular_file(target, ec)) {
    return target;
  }

  const fs::path base = fs::path(target).filename();
  std::vector<fs::path> search_dirs;
  if (const char* env_dir = std::getenv("SAMURAI_RL_POLICY_DIR"); env_dir && env_dir[0] != '\0') {
    search_dirs.emplace_back(env_dir);
  }
  search_dirs.emplace_back("artifacts/rl");

  char buf[4096] = {0};
  const ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
  if (n > 0) {
    const fs::path exe_dir = fs::path(std::string(buf, static_cast<std::size_t>(n))).parent_path();
    search_dirs.push_back(exe_dir / "rl");
    search_dirs.push_back(exe_dir / "../rl");
    search_dirs.push_back(exe_dir / "../share/samurai/rl");
    search_dirs.push_back(exe_dir / "../../artifacts/rl");
    search_dirs.push_back(exe_dir / "../../../artifacts/rl");
  }
  search_dirs.emplace_back("/usr/local/share/samurai/rl");

  for (const auto& dir : search_dirs) {
    const fs::path cand = dir / base;
    if (fs::is_regular_file(cand, ec)) {
      return cand.string();
    }
  }
  return requested_path;
}

}  // namespace samurai::control
