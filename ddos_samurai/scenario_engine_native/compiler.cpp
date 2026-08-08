#include "compiler.hpp"

#include <algorithm>
#include <cstdint>
#include <random>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace ddos_samurai::scenario_native {

namespace json = samurai::core::json;

static StepType parse_step_type(const std::string& s) {
  if (s == "request") return StepType::Request;
  if (s == "pause") return StepType::Pause;
  if (s == "branch") return StepType::Branch;
  if (s == "loop") return StepType::Loop;
  if (s == "assert") return StepType::Assert;
  if (s == "tcp_connect") return StepType::TcpConnect;
  if (s == "tcp_send") return StepType::TcpSend;
  if (s == "tcp_expect") return StepType::TcpExpect;
  if (s == "tcp_close") return StepType::TcpClose;
  return StepType::EndSession;
}

static std::string GetStr(const json::Value& v, const std::string& key, const std::string& def = "") {
  const json::Value* p = v.find(key);
  return p != nullptr ? p->as_string(def) : def;
}

static int GetInt(const json::Value& v, const std::string& key, int def = 0) {
  const json::Value* p = v.find(key);
  return p != nullptr ? static_cast<int>(p->as_int(def)) : def;
}

static double GetDouble(const json::Value& v, const std::string& key, double def = 0.0) {
  const json::Value* p = v.find(key);
  return p != nullptr ? p->as_double(def) : def;
}

static std::unordered_map<std::string, std::string> GetStrMap(const json::Value& v, const std::string& key) {
  std::unordered_map<std::string, std::string> out{};
  const json::Value* p = v.find(key);
  if (p != nullptr && p->is_object()) {
    for (const auto& kv : p->members()) {
      out[kv.first] = kv.second.as_string();
    }
  }
  return out;
}

ScenarioSpecNative parse_spec(const json::Value& spec) {
  ScenarioSpecNative out{};
  const json::Value* lm = spec.find("load_model");
  if (lm != nullptr && lm->is_object()) {
    out.load_model.backend = GetStr(*lm, "backend", out.load_model.backend);
    out.load_model.concurrent_vus = GetInt(*lm, "concurrent_vus", out.load_model.concurrent_vus);
    out.load_model.ramp_seconds = GetInt(*lm, "ramp_seconds", out.load_model.ramp_seconds);
  }

  const json::Value* personas = spec.find("personas");
  if (personas != nullptr && personas->is_object()) {
    for (const auto& item : personas->members()) {
      const std::string pname = item.first;
      const json::Value& pd = item.second;
      Persona p{};
      p.name = pname;
      p.device_profile = GetStr(pd, "device_profile", p.device_profile);
      p.headers = GetStrMap(pd, "headers");
      p.cookies = GetStrMap(pd, "cookies");
      const json::Value* rp = pd.find("retry_policy");
      if (rp != nullptr && rp->is_object()) {
        p.max_retries = GetInt(*rp, "max_retries", p.max_retries);
      }
      const json::Value* tp = pd.find("timeout_policy");
      if (tp != nullptr && tp->is_object()) {
        p.request_timeout_ms = GetInt(*tp, "request_timeout_ms", p.request_timeout_ms);
        p.session_timeout_ms = std::max(0, GetInt(*tp, "session_timeout_ms", p.session_timeout_ms));
      }
      p.weight = std::max(0.000001, GetDouble(pd, "weight", p.weight));
      out.personas.emplace(pname, std::move(p));
    }
  }

  const json::Value* flows = spec.find("flows");
  if (flows != nullptr && flows->is_object()) {
    out.flows.reserve(flows->members().size());
    for (const auto& item : flows->members()) {
      const std::string fname = item.first;
      const json::Value& fd = item.second;
      Flow flow{};
      flow.name = fname;
      flow.persona = GetStr(fd, "persona");
      const json::Value* steps = fd.find("steps");
      if (steps != nullptr && steps->is_array()) {
        flow.steps.reserve(steps->elements().size());
        for (const auto& st_obj : steps->elements()) {
          if (!st_obj.is_object()) continue;
          Step step{};
          step.type = parse_step_type(GetStr(st_obj, "type", "request"));
          step.method = GetStr(st_obj, "method", step.method);
          step.path = GetStr(st_obj, "path", step.path);
          step.body_template = GetStr(st_obj, "body_template");
          step.flow = GetStr(st_obj, "flow");
          step.repeat = std::max(1, GetInt(st_obj, "repeat", step.repeat));
          step.probability = std::clamp(GetDouble(st_obj, "probability", step.probability), 0.0, 1.0);
          step.on_failure = GetStr(st_obj, "on_failure", step.on_failure);
          const int port = GetInt(st_obj, "dst_port", 0);
          step.dst_port = static_cast<std::uint16_t>(std::clamp(port, 0, 65535));
          step.payload_template = GetStr(st_obj, "payload_template");
          step.condition = GetStr(st_obj, "condition");
          step.timeout_ms = std::max(0, GetInt(st_obj, "timeout_ms", 0));
          const json::Value* tt = st_obj.find("think_time");
          if (tt != nullptr && tt->is_object()) {
            step.think_time.min_ms = std::max(0, GetInt(*tt, "min_ms", 0));
            step.think_time.max_ms = std::max(step.think_time.min_ms, GetInt(*tt, "max_ms", 0));
            step.think_time.distribution = GetStr(*tt, "distribution", step.think_time.distribution);
            step.think_time.mean_ms = std::max(0, GetInt(*tt, "mean_ms", 0));
            step.think_time.stddev_ms = std::max(0, GetInt(*tt, "stddev_ms", 0));
          }
          flow.steps.push_back(std::move(step));
        }
      }
      out.flow_index.emplace(flow.name, out.flows.size());
      out.flows.push_back(std::move(flow));
    }
  }

  return out;
}

struct CompileState {
  std::mt19937_64* rng{nullptr};
  std::string backend{"http"};
  int depth{0};
  int max_depth{8};
  int emitted{0};
  int max_events{200000};
  int attempted{0};
};

struct PackedEvents {
  std::vector<int> event_kind{};  // 0=request, 1=think_time, 2=tcp_connect, 3=tcp_send, 4=tcp_expect, 5=tcp_close
  std::vector<std::string> request_kind{};  // http_request | http2_headers | ""
  std::vector<std::string> method{};
  std::vector<std::string> path{};
  std::vector<std::string> body_template{};
  std::vector<int> headers_idx{};
  std::vector<int> cookies_idx{};
  std::vector<std::unordered_map<std::string, std::string>> headers_pool{};
  std::vector<std::unordered_map<std::string, std::string>> cookies_pool{};
  std::unordered_map<std::uint64_t, std::vector<int>> headers_hash_index{};
  std::unordered_map<std::uint64_t, std::vector<int>> cookies_hash_index{};
  std::vector<std::string> device_profile{};
  std::vector<int> timeout_ms{};
  std::vector<int> retry_count{};
  std::vector<std::string> on_failure{};
  std::vector<int> think_min_ms{};
  std::vector<int> think_max_ms{};
  std::vector<std::string> think_distribution{};
  std::vector<int> think_mean_ms{};
  std::vector<int> think_stddev_ms{};
  std::vector<int> tcp_dst_port{};
  std::vector<std::string> tcp_payload{};
  std::vector<std::string> tcp_expect_condition{};
  std::vector<int> tcp_expect_timeout_ms{};
};

struct CompiledPackedSession {
  std::string flow{};
  std::string persona{};
  int step_attempted{0};
  int session_timeout_ms{0};
  PackedEvents events{};
};

static void reserve_packed_events(PackedEvents& pe, std::size_t event_cap) {
  pe.event_kind.reserve(event_cap);
  pe.request_kind.reserve(event_cap);
  pe.method.reserve(event_cap);
  pe.path.reserve(event_cap);
  pe.body_template.reserve(event_cap);
  pe.headers_idx.reserve(event_cap);
  pe.cookies_idx.reserve(event_cap);
  pe.device_profile.reserve(event_cap);
  pe.timeout_ms.reserve(event_cap);
  pe.retry_count.reserve(event_cap);
  pe.on_failure.reserve(event_cap);
  pe.think_min_ms.reserve(event_cap);
  pe.think_max_ms.reserve(event_cap);
  pe.think_distribution.reserve(event_cap);
  pe.think_mean_ms.reserve(event_cap);
  pe.think_stddev_ms.reserve(event_cap);
  pe.tcp_dst_port.reserve(event_cap);
  pe.tcp_payload.reserve(event_cap);
  pe.tcp_expect_condition.reserve(event_cap);
  pe.tcp_expect_timeout_ms.reserve(event_cap);
}

static std::uint64_t fnv1a_update(std::uint64_t h, const char* data, std::size_t n) {
  constexpr std::uint64_t kPrime = 1099511628211ULL;
  for (std::size_t i = 0; i < n; ++i) {
    h ^= static_cast<std::uint8_t>(data[i]);
    h *= kPrime;
  }
  return h;
}

static std::uint64_t stable_map_hash(const std::unordered_map<std::string, std::string>& m) {
  // Order-independent hash composition for unordered_map.
  std::uint64_t acc = 1469598103934665603ULL;
  const std::size_t msize = m.size();
  acc = fnv1a_update(acc, reinterpret_cast<const char*>(&msize), sizeof(std::size_t));
  for (const auto& kv : m) {
    std::uint64_t h = 1469598103934665603ULL;
    h = fnv1a_update(h, kv.first.data(), kv.first.size());
    h = fnv1a_update(h, "=", 1);
    h = fnv1a_update(h, kv.second.data(), kv.second.size());
    // commutative mix; preserves order-independence
    acc ^= (h + 0x9e3779b97f4a7c15ULL + (acc << 6) + (acc >> 2));
  }
  return acc;
}

static bool maps_equal(
    const std::unordered_map<std::string, std::string>& a,
    const std::unordered_map<std::string, std::string>& b) {
  if (a.size() != b.size()) return false;
  for (const auto& [k, v] : a) {
    auto it = b.find(k);
    if (it == b.end() || it->second != v) return false;
  }
  return true;
}

static int intern_map(
    const std::unordered_map<std::string, std::string>& m,
    std::vector<std::unordered_map<std::string, std::string>>& pool,
    std::unordered_map<std::uint64_t, std::vector<int>>& hash_index) {
  const std::uint64_t h = stable_map_hash(m);
  auto hit = hash_index.find(h);
  if (hit != hash_index.end()) {
    for (int idx : hit->second) {
      if (idx >= 0 && static_cast<std::size_t>(idx) < pool.size() && maps_equal(pool[static_cast<std::size_t>(idx)], m)) {
        return idx;
      }
    }
  }
  pool.push_back(m);
  const int idx = static_cast<int>(pool.size() - 1);
  hash_index[h].push_back(idx);
  return idx;
}

static void compile_flow_recursive_packed(
    const ScenarioSpecNative& spec,
    const std::string& flow_name,
    CompileState& st,
    PackedEvents& out) {
  if (st.depth > st.max_depth || st.emitted >= st.max_events) return;
  auto itf = spec.flow_index.find(flow_name);
  if (itf == spec.flow_index.end()) return;
  const Flow& flow = spec.flows[itf->second];
  const Persona* persona = nullptr;
  auto itp = spec.personas.find(flow.persona);
  if (itp != spec.personas.end()) persona = &itp->second;

  std::uniform_real_distribution<double> uni(0.0, 1.0);
  for (const Step& step : flow.steps) {
    if (st.emitted >= st.max_events) break;
    switch (step.type) {
      case StepType::EndSession:
        return;
      case StepType::Pause: {
        out.event_kind.push_back(1);
        out.request_kind.emplace_back("");
        out.method.emplace_back("");
        out.path.emplace_back("");
        out.body_template.emplace_back("");
        out.headers_idx.push_back(intern_map({}, out.headers_pool, out.headers_hash_index));
        out.cookies_idx.push_back(intern_map({}, out.cookies_pool, out.cookies_hash_index));
        out.device_profile.emplace_back("");
        out.timeout_ms.push_back(0);
        out.retry_count.push_back(0);
        out.on_failure.emplace_back("retry");
        out.think_min_ms.push_back(step.think_time.min_ms);
        out.think_max_ms.push_back(std::max(step.think_time.min_ms, step.think_time.max_ms));
        out.think_distribution.push_back(step.think_time.distribution);
        out.think_mean_ms.push_back(step.think_time.mean_ms);
        out.think_stddev_ms.push_back(step.think_time.stddev_ms);
        out.tcp_dst_port.push_back(0);
        out.tcp_payload.emplace_back("");
        out.tcp_expect_condition.emplace_back("");
        out.tcp_expect_timeout_ms.push_back(0);
        st.emitted += 1;
        break;
      }
      case StepType::Assert:
        st.attempted += 1;
        break;
      case StepType::Branch:
        if (uni(*st.rng) <= step.probability && !step.flow.empty()) {
          st.depth += 1;
          compile_flow_recursive_packed(spec, step.flow, st, out);
          st.depth -= 1;
        }
        break;
      case StepType::Loop: {
        const std::string target = step.flow.empty() ? flow.name : step.flow;
        const int rep = std::max(1, step.repeat);
        for (int i = 0; i < rep; ++i) {
          st.depth += 1;
          compile_flow_recursive_packed(spec, target, st, out);
          st.depth -= 1;
          if (st.emitted >= st.max_events) break;
        }
        break;
      }
      case StepType::Request: {
        st.attempted += 1;
        std::unordered_map<std::string, std::string> headers{};
        std::unordered_map<std::string, std::string> cookies{};
        std::string device_profile = "web";
        int timeout_ms = 5000;
        int retry_count = 0;
        if (persona != nullptr) {
          headers = persona->headers;
          cookies = persona->cookies;
          device_profile = persona->device_profile;
          timeout_ms = persona->request_timeout_ms;
          retry_count = persona->max_retries;
        }
        out.event_kind.push_back(0);
        out.request_kind.push_back((st.backend == "http2") ? "http2_headers" : "http_request");
        out.method.push_back(step.method);
        out.path.push_back(step.path);
        out.body_template.push_back(step.body_template);
        out.headers_idx.push_back(intern_map(headers, out.headers_pool, out.headers_hash_index));
        out.cookies_idx.push_back(intern_map(cookies, out.cookies_pool, out.cookies_hash_index));
        out.device_profile.push_back(std::move(device_profile));
        out.timeout_ms.push_back(timeout_ms);
        out.retry_count.push_back(retry_count);
        out.on_failure.push_back(step.on_failure);
        out.think_min_ms.push_back(0);
        out.think_max_ms.push_back(0);
        out.think_distribution.emplace_back("uniform");
        out.think_mean_ms.push_back(0);
        out.think_stddev_ms.push_back(0);
        out.tcp_dst_port.push_back(0);
        out.tcp_payload.emplace_back("");
        out.tcp_expect_condition.emplace_back("");
        out.tcp_expect_timeout_ms.push_back(0);
        st.emitted += 1;
        break;
      }
      case StepType::TcpConnect: {
        st.attempted += 1;
        out.event_kind.push_back(2);
        out.request_kind.emplace_back("");
        out.method.emplace_back("");
        out.path.emplace_back("");
        out.body_template.emplace_back("");
        out.headers_idx.push_back(intern_map({}, out.headers_pool, out.headers_hash_index));
        out.cookies_idx.push_back(intern_map({}, out.cookies_pool, out.cookies_hash_index));
        out.device_profile.emplace_back("");
        out.timeout_ms.push_back(0);
        out.retry_count.push_back(0);
        out.on_failure.emplace_back("retry");
        out.think_min_ms.push_back(0);
        out.think_max_ms.push_back(0);
        out.think_distribution.emplace_back("uniform");
        out.think_mean_ms.push_back(0);
        out.think_stddev_ms.push_back(0);
        out.tcp_dst_port.push_back(static_cast<int>(step.dst_port));
        out.tcp_payload.emplace_back("");
        out.tcp_expect_condition.emplace_back("");
        out.tcp_expect_timeout_ms.push_back(0);
        st.emitted += 1;
        break;
      }
      case StepType::TcpSend: {
        st.attempted += 1;
        out.event_kind.push_back(3);
        out.request_kind.emplace_back("");
        out.method.emplace_back("");
        out.path.emplace_back("");
        out.body_template.emplace_back("");
        out.headers_idx.push_back(intern_map({}, out.headers_pool, out.headers_hash_index));
        out.cookies_idx.push_back(intern_map({}, out.cookies_pool, out.cookies_hash_index));
        out.device_profile.emplace_back("");
        out.timeout_ms.push_back(0);
        out.retry_count.push_back(0);
        out.on_failure.emplace_back("retry");
        out.think_min_ms.push_back(0);
        out.think_max_ms.push_back(0);
        out.think_distribution.emplace_back("uniform");
        out.think_mean_ms.push_back(0);
        out.think_stddev_ms.push_back(0);
        out.tcp_dst_port.push_back(0);
        out.tcp_payload.push_back(step.payload_template);
        out.tcp_expect_condition.emplace_back("");
        out.tcp_expect_timeout_ms.push_back(0);
        st.emitted += 1;
        break;
      }
      case StepType::TcpExpect: {
        st.attempted += 1;
        out.event_kind.push_back(4);
        out.request_kind.emplace_back("");
        out.method.emplace_back("");
        out.path.emplace_back("");
        out.body_template.emplace_back("");
        out.headers_idx.push_back(intern_map({}, out.headers_pool, out.headers_hash_index));
        out.cookies_idx.push_back(intern_map({}, out.cookies_pool, out.cookies_hash_index));
        out.device_profile.emplace_back("");
        out.timeout_ms.push_back(0);
        out.retry_count.push_back(0);
        out.on_failure.emplace_back("retry");
        out.think_min_ms.push_back(0);
        out.think_max_ms.push_back(0);
        out.think_distribution.emplace_back("uniform");
        out.think_mean_ms.push_back(0);
        out.think_stddev_ms.push_back(0);
        out.tcp_dst_port.push_back(0);
        out.tcp_payload.emplace_back("");
        out.tcp_expect_condition.push_back(step.condition);
        out.tcp_expect_timeout_ms.push_back(step.timeout_ms);
        st.emitted += 1;
        break;
      }
      case StepType::TcpClose: {
        st.attempted += 1;
        out.event_kind.push_back(5);
        out.request_kind.emplace_back("");
        out.method.emplace_back("");
        out.path.emplace_back("");
        out.body_template.emplace_back("");
        out.headers_idx.push_back(intern_map({}, out.headers_pool, out.headers_hash_index));
        out.cookies_idx.push_back(intern_map({}, out.cookies_pool, out.cookies_hash_index));
        out.device_profile.emplace_back("");
        out.timeout_ms.push_back(0);
        out.retry_count.push_back(0);
        out.on_failure.emplace_back("retry");
        out.think_min_ms.push_back(0);
        out.think_max_ms.push_back(0);
        out.think_distribution.emplace_back("uniform");
        out.think_mean_ms.push_back(0);
        out.think_stddev_ms.push_back(0);
        out.tcp_dst_port.push_back(0);
        out.tcp_payload.emplace_back("");
        out.tcp_expect_condition.emplace_back("");
        out.tcp_expect_timeout_ms.push_back(0);
        st.emitted += 1;
        break;
      }
    }
  }
}

static json::Value arr_ints(const std::vector<int>& v) {
  json::Value a = json::Value::Array();
  for (int x : v) a.push_back(json::Value::Int(x));
  return a;
}

static json::Value arr_strs(const std::vector<std::string>& v) {
  json::Value a = json::Value::Array();
  for (const auto& s : v) a.push_back(json::Value::Str(s));
  return a;
}

static json::Value arr_maps(const std::vector<std::unordered_map<std::string, std::string>>& v) {
  json::Value a = json::Value::Array();
  for (const auto& m : v) {
    json::Value o = json::Value::Object();
    for (const auto& kv : m) o.set(kv.first, json::Value::Str(kv.second));
    a.push_back(std::move(o));
  }
  return a;
}

static json::Value PackedEventsToJson(const PackedEvents& pe) {
  json::Value out = json::Value::Object();
  out.set("event_kind", arr_ints(pe.event_kind));
  out.set("request_kind", arr_strs(pe.request_kind));
  out.set("method", arr_strs(pe.method));
  out.set("path", arr_strs(pe.path));
  out.set("body_template", arr_strs(pe.body_template));
  out.set("headers_idx", arr_ints(pe.headers_idx));
  out.set("cookies_idx", arr_ints(pe.cookies_idx));
  out.set("headers_pool", arr_maps(pe.headers_pool));
  out.set("cookies_pool", arr_maps(pe.cookies_pool));
  out.set("device_profile", arr_strs(pe.device_profile));
  out.set("timeout_ms", arr_ints(pe.timeout_ms));
  out.set("retry_count", arr_ints(pe.retry_count));
  out.set("on_failure", arr_strs(pe.on_failure));
  out.set("think_min_ms", arr_ints(pe.think_min_ms));
  out.set("think_max_ms", arr_ints(pe.think_max_ms));
  out.set("think_distribution", arr_strs(pe.think_distribution));
  out.set("think_mean_ms", arr_ints(pe.think_mean_ms));
  out.set("think_stddev_ms", arr_ints(pe.think_stddev_ms));
  out.set("tcp_dst_port", arr_ints(pe.tcp_dst_port));
  out.set("tcp_payload", arr_strs(pe.tcp_payload));
  out.set("tcp_expect_condition", arr_strs(pe.tcp_expect_condition));
  out.set("tcp_expect_timeout_ms", arr_ints(pe.tcp_expect_timeout_ms));
  return out;
}

json::Value compile_session_plan_packed_native(const ScenarioSpecNative& spec, const std::string& flow_name, std::uint64_t seed) {
  if (spec.flow_index.find(flow_name) == spec.flow_index.end()) {
    throw std::runtime_error("flow not found: " + flow_name);
  }
  std::mt19937_64 rng(seed);
  CompileState st{};
  st.rng = &rng;
  st.backend = spec.load_model.backend;
  PackedEvents pe{};
  reserve_packed_events(pe, static_cast<std::size_t>(std::max(64, st.max_events / 16)));
  compile_flow_recursive_packed(spec, flow_name, st, pe);
  json::Value out = PackedEventsToJson(pe);
  out.set("flow", json::Value::Str(flow_name));
  out.set("persona", json::Value::Str(spec.flows[spec.flow_index.at(flow_name)].persona));
  out.set("packed", json::Value::Bool(true));
  out.set("step_attempted", json::Value::Int(st.attempted));
  const Persona* persona = nullptr;
  auto itp = spec.personas.find(spec.flows[spec.flow_index.at(flow_name)].persona);
  if (itp != spec.personas.end()) persona = &itp->second;
  out.set("session_timeout_ms", json::Value::Int(persona != nullptr ? std::max(0, persona->session_timeout_ms) : 0));
  return out;
}

static json::Value packed_session_to_json(const CompiledPackedSession& s) {
  json::Value out = PackedEventsToJson(s.events);
  out.set("flow", json::Value::Str(s.flow));
  out.set("persona", json::Value::Str(s.persona));
  out.set("packed", json::Value::Bool(true));
  out.set("step_attempted", json::Value::Int(s.step_attempted));
  out.set("session_timeout_ms", json::Value::Int(s.session_timeout_ms));
  return out;
}

static void ensure_flows_exist(
    const ScenarioSpecNative& spec,
    const std::vector<std::string>& flow_names) {
  for (const auto& flow_name : flow_names) {
    if (spec.flow_index.find(flow_name) == spec.flow_index.end()) {
      throw std::runtime_error("flow not found: " + flow_name);
    }
  }
}

json::Value compile_session_plans_packed_bulk_native(
    const ScenarioSpecNative& spec,
    const std::vector<std::string>& flow_names,
    const std::vector<std::uint64_t>& seeds) {
  ensure_flows_exist(spec, flow_names);
  const std::size_t n = flow_names.size();
  std::vector<CompiledPackedSession> compiled{};
  compiled.resize(n);
  for (std::size_t i = 0; i < n; ++i) {
    const std::string& flow_name = flow_names[i];
    auto itf = spec.flow_index.find(flow_name);
    std::mt19937_64 rng((i < seeds.size()) ? seeds[i] : static_cast<std::uint64_t>(i + 1));
    CompileState st{};
    st.rng = &rng;
    st.backend = spec.load_model.backend;
    CompiledPackedSession row{};
    row.flow = flow_name;
    row.persona = spec.flows[itf->second].persona;
    reserve_packed_events(row.events, static_cast<std::size_t>(std::max(32, st.max_events / 32)));
    compile_flow_recursive_packed(spec, flow_name, st, row.events);
    row.step_attempted = st.attempted;
    const Persona* persona = nullptr;
    auto itp = spec.personas.find(row.persona);
    if (itp != spec.personas.end()) {
      persona = &itp->second;
    }
    row.session_timeout_ms = (persona != nullptr) ? std::max(0, persona->session_timeout_ms) : 0;
    compiled[i] = std::move(row);
  }
  json::Value out = json::Value::Array();
  for (const auto& row : compiled) {
    out.push_back(packed_session_to_json(row));
  }
  return out;
}

json::Value compile_session_plans_packed_bulk_soa_native(
    const ScenarioSpecNative& spec,
    const std::vector<std::string>& flow_names,
    const std::vector<std::uint64_t>& seeds) {
  ensure_flows_exist(spec, flow_names);
  const std::size_t n = flow_names.size();
  std::vector<std::uint32_t> session_offsets{};
  std::vector<std::string> session_flow{};
  std::vector<std::string> session_persona{};
  std::vector<int> session_step_attempted{};
  std::vector<int> session_timeout_ms{};
  PackedEvents flat{};
  // SoA path accumulates all sessions into one flat buffer; pre-reserve to reduce realloc churn.
  reserve_packed_events(flat, n * 32U);
  flat.headers_pool.reserve(n + 8U);
  flat.cookies_pool.reserve(n + 8U);
  session_offsets.reserve(n + 1);
  session_flow.reserve(n);
  session_persona.reserve(n);
  session_step_attempted.reserve(n);
  session_timeout_ms.reserve(n);
  session_offsets.push_back(0);
  for (std::size_t i = 0; i < n; ++i) {
    const std::string& flow_name = flow_names[i];
    auto itf = spec.flow_index.find(flow_name);
    std::mt19937_64 rng((i < seeds.size()) ? seeds[i] : static_cast<std::uint64_t>(i + 1));
    CompileState st{};
    st.rng = &rng;
    st.backend = spec.load_model.backend;
    const std::string persona_name = spec.flows[itf->second].persona;
    const std::size_t ev_base = flat.event_kind.size();
    const std::size_t hbase = flat.headers_pool.size();
    const std::size_t cbase = flat.cookies_pool.size();
    compile_flow_recursive_packed(spec, flow_name, st, flat);
    for (std::size_t j = ev_base; j < flat.headers_idx.size(); ++j) {
      if (flat.headers_idx[j] >= 0) flat.headers_idx[j] += static_cast<int>(hbase);
    }
    for (std::size_t j = ev_base; j < flat.cookies_idx.size(); ++j) {
      if (flat.cookies_idx[j] >= 0) flat.cookies_idx[j] += static_cast<int>(cbase);
    }
    session_flow.push_back(flow_name);
    session_persona.push_back(persona_name);
    session_step_attempted.push_back(st.attempted);
    int timeout_ms = 0;
    auto itp = spec.personas.find(persona_name);
    if (itp != spec.personas.end()) timeout_ms = std::max(0, itp->second.session_timeout_ms);
    session_timeout_ms.push_back(timeout_ms);
    session_offsets.push_back(static_cast<std::uint32_t>(flat.event_kind.size()));
  }
  json::Value out = PackedEventsToJson(flat);
  out.set("packed_soa", json::Value::Bool(true));
  auto arr_u32 = [](const std::vector<std::uint32_t>& v) {
    json::Value a = json::Value::Array();
    for (std::uint32_t x : v) a.push_back(json::Value::Int(x));
    return a;
  };
  out.set("session_offsets", arr_u32(session_offsets));
  out.set("session_flow", arr_strs(session_flow));
  out.set("session_persona", arr_strs(session_persona));
  out.set("session_step_attempted", arr_ints(session_step_attempted));
  out.set("session_timeout_ms", arr_ints(session_timeout_ms));
  return out;
}

}  // namespace ddos_samurai::scenario_native
