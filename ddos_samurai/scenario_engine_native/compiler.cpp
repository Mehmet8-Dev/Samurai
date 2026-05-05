#include "compiler.hpp"

#include <algorithm>
#include <random>
#include <stdexcept>
#include <utility>

#include <pybind11/stl.h>

namespace py = pybind11;

namespace ddos_samurai::scenario_native {

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

ScenarioSpecNative parse_spec(const py::dict& spec) {
  ScenarioSpecNative out{};
  if (spec.contains("load_model")) {
    py::dict lm = py::reinterpret_borrow<py::dict>(spec["load_model"]);
    if (lm.contains("backend")) out.load_model.backend = py::str(lm["backend"]).cast<std::string>();
    if (lm.contains("concurrent_vus")) out.load_model.concurrent_vus = static_cast<int>(py::int_(lm["concurrent_vus"]));
    if (lm.contains("ramp_seconds")) out.load_model.ramp_seconds = static_cast<int>(py::int_(lm["ramp_seconds"]));
  }

  if (spec.contains("personas")) {
    py::dict personas = py::reinterpret_borrow<py::dict>(spec["personas"]);
    for (auto item : personas) {
      const std::string pname = py::str(item.first).cast<std::string>();
      py::dict pd = py::reinterpret_borrow<py::dict>(item.second);
      Persona p{};
      p.name = pname;
      if (pd.contains("device_profile")) p.device_profile = py::str(pd["device_profile"]).cast<std::string>();
      if (pd.contains("headers")) p.headers = py::cast<std::unordered_map<std::string, std::string>>(pd["headers"]);
      if (pd.contains("cookies")) p.cookies = py::cast<std::unordered_map<std::string, std::string>>(pd["cookies"]);
      if (pd.contains("retry_policy")) {
        py::dict rp = py::reinterpret_borrow<py::dict>(pd["retry_policy"]);
        if (rp.contains("max_retries")) p.max_retries = static_cast<int>(py::int_(rp["max_retries"]));
      }
      if (pd.contains("timeout_policy")) {
        py::dict tp = py::reinterpret_borrow<py::dict>(pd["timeout_policy"]);
        if (tp.contains("request_timeout_ms")) p.request_timeout_ms = static_cast<int>(py::int_(tp["request_timeout_ms"]));
        if (tp.contains("session_timeout_ms")) p.session_timeout_ms = std::max(0, static_cast<int>(py::int_(tp["session_timeout_ms"])));
      }
      if (pd.contains("weight")) p.weight = std::max(0.000001, static_cast<double>(py::float_(pd["weight"])));
      out.personas.emplace(pname, std::move(p));
    }
  }

  if (spec.contains("flows")) {
    py::dict flows = py::reinterpret_borrow<py::dict>(spec["flows"]);
    out.flows.reserve(static_cast<std::size_t>(py::len(flows)));
    for (auto item : flows) {
      const std::string fname = py::str(item.first).cast<std::string>();
      py::dict fd = py::reinterpret_borrow<py::dict>(item.second);
      Flow flow{};
      flow.name = fname;
      if (fd.contains("persona")) flow.persona = py::str(fd["persona"]).cast<std::string>();
      py::list steps = py::reinterpret_borrow<py::list>(fd["steps"]);
      flow.steps.reserve(static_cast<std::size_t>(py::len(steps)));
      for (auto st_obj : steps) {
        py::dict st = py::reinterpret_borrow<py::dict>(st_obj);
        Step step{};
        step.type = parse_step_type(py::str(st["type"]).cast<std::string>());
        if (st.contains("method")) step.method = py::str(st["method"]).cast<std::string>();
        if (st.contains("path")) step.path = py::str(st["path"]).cast<std::string>();
        if (st.contains("body_template")) step.body_template = py::str(st["body_template"]).cast<std::string>();
        if (st.contains("flow")) step.flow = py::str(st["flow"]).cast<std::string>();
        if (st.contains("repeat")) step.repeat = std::max(1, static_cast<int>(py::int_(st["repeat"])));
        if (st.contains("probability")) step.probability = std::clamp(static_cast<double>(py::float_(st["probability"])), 0.0, 1.0);
        if (st.contains("on_failure")) step.on_failure = py::str(st["on_failure"]).cast<std::string>();
        if (st.contains("dst_port")) {
          const int port = static_cast<int>(py::int_(st["dst_port"]));
          step.dst_port = static_cast<std::uint16_t>(std::clamp(port, 0, 65535));
        }
        if (st.contains("payload_template")) step.payload_template = py::str(st["payload_template"]).cast<std::string>();
        if (st.contains("condition")) step.condition = py::str(st["condition"]).cast<std::string>();
        if (st.contains("timeout_ms")) step.timeout_ms = std::max(0, static_cast<int>(py::int_(st["timeout_ms"])));
        if (st.contains("think_time")) {
          py::dict tt = py::reinterpret_borrow<py::dict>(st["think_time"]);
          if (tt.contains("min_ms")) step.think_time.min_ms = std::max(0, static_cast<int>(py::int_(tt["min_ms"])));
          if (tt.contains("max_ms")) step.think_time.max_ms = std::max(step.think_time.min_ms, static_cast<int>(py::int_(tt["max_ms"])));
          if (tt.contains("distribution")) step.think_time.distribution = py::str(tt["distribution"]).cast<std::string>();
          if (tt.contains("mean_ms")) step.think_time.mean_ms = std::max(0, static_cast<int>(py::int_(tt["mean_ms"])));
          if (tt.contains("stddev_ms")) step.think_time.stddev_ms = std::max(0, static_cast<int>(py::int_(tt["stddev_ms"])));
        }
        flow.steps.push_back(std::move(step));
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

static int intern_map(
    const std::unordered_map<std::string, std::string>& m,
    std::vector<std::unordered_map<std::string, std::string>>& pool) {
  for (std::size_t i = 0; i < pool.size(); ++i) {
    if (pool[i].size() != m.size()) continue;
    bool same = true;
    for (const auto& [k, v] : m) {
      auto it = pool[i].find(k);
      if (it == pool[i].end() || it->second != v) {
        same = false;
        break;
      }
    }
    if (same) return static_cast<int>(i);
  }
  pool.push_back(m);
  return static_cast<int>(pool.size() - 1);
}

static void compile_flow_recursive(const ScenarioSpecNative& spec, const std::string& flow_name, CompileState& st, py::list& events) {
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
        py::dict ev;
        ev["event_type"] = py::str("think_time");
        ev["min_ms"] = step.think_time.min_ms;
        ev["max_ms"] = std::max(step.think_time.min_ms, step.think_time.max_ms);
        ev["distribution"] = step.think_time.distribution;
        ev["mean_ms"] = step.think_time.mean_ms;
        ev["stddev_ms"] = step.think_time.stddev_ms;
        events.append(ev);
        st.emitted += 1;
        break;
      }
      case StepType::Assert:
        st.attempted += 1;
        break;
      case StepType::Branch:
        if (uni(*st.rng) <= step.probability && !step.flow.empty()) {
          st.depth += 1;
          compile_flow_recursive(spec, step.flow, st, events);
          st.depth -= 1;
        }
        break;
      case StepType::Loop: {
        const std::string target = step.flow.empty() ? flow.name : step.flow;
        const int rep = std::max(1, step.repeat);
        for (int i = 0; i < rep; ++i) {
          st.depth += 1;
          compile_flow_recursive(spec, target, st, events);
          st.depth -= 1;
          if (st.emitted >= st.max_events) break;
        }
        break;
      }
      case StepType::Request: {
        st.attempted += 1;
        py::dict ev;
        ev["event_type"] = (st.backend == "http2") ? py::str("http2_headers") : py::str("http_request");
        ev["method"] = step.method;
        ev["path"] = step.path;
        ev["body_template"] = step.body_template;
        py::dict headers;
        py::dict cookies;
        std::string device_profile = "web";
        int timeout_ms = 5000;
        int retry_count = 0;
        if (persona != nullptr) {
          headers = py::cast(persona->headers);
          cookies = py::cast(persona->cookies);
          device_profile = persona->device_profile;
          timeout_ms = persona->request_timeout_ms;
          retry_count = persona->max_retries;
        }
        ev["headers"] = headers;
        ev["cookies"] = cookies;
        ev["device_profile"] = device_profile;
        ev["timeout_ms"] = timeout_ms;
        ev["retry_count"] = retry_count;
        ev["on_failure"] = step.on_failure;
        events.append(ev);
        st.emitted += 1;
        break;
      }
      case StepType::TcpConnect: {
        st.attempted += 1;
        py::dict ev;
        ev["event_type"] = py::str("tcp_connect");
        ev["dst_port"] = py::int_(step.dst_port);
        events.append(ev);
        st.emitted += 1;
        break;
      }
      case StepType::TcpSend: {
        st.attempted += 1;
        py::dict ev;
        ev["event_type"] = py::str("tcp_send");
        ev["payload_template"] = step.payload_template;
        events.append(ev);
        st.emitted += 1;
        break;
      }
      case StepType::TcpExpect: {
        st.attempted += 1;
        py::dict ev;
        ev["event_type"] = py::str("tcp_expect");
        ev["condition"] = step.condition;
        ev["timeout_ms"] = py::int_(step.timeout_ms);
        events.append(ev);
        st.emitted += 1;
        break;
      }
      case StepType::TcpClose: {
        st.attempted += 1;
        py::dict ev;
        ev["event_type"] = py::str("tcp_close");
        events.append(ev);
        st.emitted += 1;
        break;
      }
    }
  }
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
        out.headers_idx.push_back(intern_map({}, out.headers_pool));
        out.cookies_idx.push_back(intern_map({}, out.cookies_pool));
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
        out.headers_idx.push_back(intern_map(headers, out.headers_pool));
        out.cookies_idx.push_back(intern_map(cookies, out.cookies_pool));
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
        out.headers_idx.push_back(intern_map({}, out.headers_pool));
        out.cookies_idx.push_back(intern_map({}, out.cookies_pool));
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
        out.headers_idx.push_back(intern_map({}, out.headers_pool));
        out.cookies_idx.push_back(intern_map({}, out.cookies_pool));
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
        out.headers_idx.push_back(intern_map({}, out.headers_pool));
        out.cookies_idx.push_back(intern_map({}, out.cookies_pool));
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
        out.headers_idx.push_back(intern_map({}, out.headers_pool));
        out.cookies_idx.push_back(intern_map({}, out.cookies_pool));
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

py::dict compile_session_plan_native(const ScenarioSpecNative& spec, const std::string& flow_name, std::uint64_t seed) {
  if (spec.flow_index.find(flow_name) == spec.flow_index.end()) {
    throw std::runtime_error("flow not found: " + flow_name);
  }
  std::mt19937_64 rng(seed);
  CompileState st{};
  st.rng = &rng;
  st.backend = spec.load_model.backend;
  py::list events;
  compile_flow_recursive(spec, flow_name, st, events);
  py::dict out;
  out["flow"] = flow_name;
  out["persona"] = spec.flows[spec.flow_index.at(flow_name)].persona;
  out["events"] = events;
  out["step_attempted"] = st.attempted;
  return out;
}

py::dict compile_session_plan_packed_native(const ScenarioSpecNative& spec, const std::string& flow_name, std::uint64_t seed) {
  if (spec.flow_index.find(flow_name) == spec.flow_index.end()) {
    throw std::runtime_error("flow not found: " + flow_name);
  }
  std::mt19937_64 rng(seed);
  CompileState st{};
  st.rng = &rng;
  st.backend = spec.load_model.backend;
  PackedEvents pe{};
  compile_flow_recursive_packed(spec, flow_name, st, pe);
  py::dict out;
  out["flow"] = flow_name;
  out["persona"] = spec.flows[spec.flow_index.at(flow_name)].persona;
  out["packed"] = py::bool_(true);
  out["event_kind"] = py::cast(pe.event_kind);
  out["request_kind"] = py::cast(pe.request_kind);
  out["method"] = py::cast(pe.method);
  out["path"] = py::cast(pe.path);
  out["body_template"] = py::cast(pe.body_template);
  out["headers_idx"] = py::cast(pe.headers_idx);
  out["cookies_idx"] = py::cast(pe.cookies_idx);
  out["headers_pool"] = py::cast(pe.headers_pool);
  out["cookies_pool"] = py::cast(pe.cookies_pool);
  out["device_profile"] = py::cast(pe.device_profile);
  out["timeout_ms"] = py::cast(pe.timeout_ms);
  out["retry_count"] = py::cast(pe.retry_count);
  out["on_failure"] = py::cast(pe.on_failure);
  out["think_min_ms"] = py::cast(pe.think_min_ms);
  out["think_max_ms"] = py::cast(pe.think_max_ms);
  out["think_distribution"] = py::cast(pe.think_distribution);
  out["think_mean_ms"] = py::cast(pe.think_mean_ms);
  out["think_stddev_ms"] = py::cast(pe.think_stddev_ms);
  out["tcp_dst_port"] = py::cast(pe.tcp_dst_port);
  out["tcp_payload"] = py::cast(pe.tcp_payload);
  out["tcp_expect_condition"] = py::cast(pe.tcp_expect_condition);
  out["tcp_expect_timeout_ms"] = py::cast(pe.tcp_expect_timeout_ms);
  out["step_attempted"] = st.attempted;
  const Persona* persona = nullptr;
  auto itp = spec.personas.find(spec.flows[spec.flow_index.at(flow_name)].persona);
  if (itp != spec.personas.end()) persona = &itp->second;
  out["session_timeout_ms"] = py::int_(persona != nullptr ? std::max(0, persona->session_timeout_ms) : 0);
  return out;
}

static py::dict packed_session_to_py_dict(const CompiledPackedSession& s) {
  py::dict out;
  out["flow"] = s.flow;
  out["persona"] = s.persona;
  out["packed"] = py::bool_(true);
  out["event_kind"] = py::cast(s.events.event_kind);
  out["request_kind"] = py::cast(s.events.request_kind);
  out["method"] = py::cast(s.events.method);
  out["path"] = py::cast(s.events.path);
  out["body_template"] = py::cast(s.events.body_template);
  out["headers_idx"] = py::cast(s.events.headers_idx);
  out["cookies_idx"] = py::cast(s.events.cookies_idx);
  out["headers_pool"] = py::cast(s.events.headers_pool);
  out["cookies_pool"] = py::cast(s.events.cookies_pool);
  out["device_profile"] = py::cast(s.events.device_profile);
  out["timeout_ms"] = py::cast(s.events.timeout_ms);
  out["retry_count"] = py::cast(s.events.retry_count);
  out["on_failure"] = py::cast(s.events.on_failure);
  out["think_min_ms"] = py::cast(s.events.think_min_ms);
  out["think_max_ms"] = py::cast(s.events.think_max_ms);
  out["think_distribution"] = py::cast(s.events.think_distribution);
  out["think_mean_ms"] = py::cast(s.events.think_mean_ms);
  out["think_stddev_ms"] = py::cast(s.events.think_stddev_ms);
  out["tcp_dst_port"] = py::cast(s.events.tcp_dst_port);
  out["tcp_payload"] = py::cast(s.events.tcp_payload);
  out["tcp_expect_condition"] = py::cast(s.events.tcp_expect_condition);
  out["tcp_expect_timeout_ms"] = py::cast(s.events.tcp_expect_timeout_ms);
  out["step_attempted"] = s.step_attempted;
  out["session_timeout_ms"] = s.session_timeout_ms;
  return out;
}

py::list compile_session_plans_packed_bulk_native(
    const ScenarioSpecNative& spec,
    const std::vector<std::string>& flow_names,
    const std::vector<std::uint64_t>& seeds) {
  const std::size_t n = flow_names.size();
  std::vector<CompiledPackedSession> compiled{};
  compiled.resize(n);
  {
    py::gil_scoped_release release;
    for (std::size_t i = 0; i < n; ++i) {
      const std::string& flow_name = flow_names[i];
      auto itf = spec.flow_index.find(flow_name);
      if (itf == spec.flow_index.end()) {
        continue;
      }
      std::mt19937_64 rng((i < seeds.size()) ? seeds[i] : static_cast<std::uint64_t>(i + 1));
      CompileState st{};
      st.rng = &rng;
      st.backend = spec.load_model.backend;
      CompiledPackedSession row{};
      row.flow = flow_name;
      row.persona = spec.flows[itf->second].persona;
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
  }
  py::list out;
  for (const auto& row : compiled) {
    out.append(packed_session_to_py_dict(row));
  }
  return out;
}

py::dict compile_session_plans_packed_bulk_soa_native(
    const ScenarioSpecNative& spec,
    const std::vector<std::string>& flow_names,
    const std::vector<std::uint64_t>& seeds) {
  const std::size_t n = flow_names.size();
  std::vector<std::uint32_t> session_offsets{};
  std::vector<std::string> session_flow{};
  std::vector<std::string> session_persona{};
  std::vector<int> session_step_attempted{};
  std::vector<int> session_timeout_ms{};
  PackedEvents flat{};
  session_offsets.reserve(n + 1);
  session_flow.reserve(n);
  session_persona.reserve(n);
  session_step_attempted.reserve(n);
  session_timeout_ms.reserve(n);
  session_offsets.push_back(0);
  {
    py::gil_scoped_release release;
    for (std::size_t i = 0; i < n; ++i) {
      const std::string& flow_name = flow_names[i];
      auto itf = spec.flow_index.find(flow_name);
      if (itf == spec.flow_index.end()) {
        session_flow.emplace_back(flow_name);
        session_persona.emplace_back("");
        session_step_attempted.push_back(0);
        session_timeout_ms.push_back(0);
        session_offsets.push_back(static_cast<std::uint32_t>(flat.event_kind.size()));
        continue;
      }
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
  }
  py::dict out;
  out["packed_soa"] = py::bool_(true);
  out["session_offsets"] = py::cast(session_offsets);
  out["session_flow"] = py::cast(session_flow);
  out["session_persona"] = py::cast(session_persona);
  out["session_step_attempted"] = py::cast(session_step_attempted);
  out["session_timeout_ms"] = py::cast(session_timeout_ms);
  out["event_kind"] = py::cast(flat.event_kind);
  out["request_kind"] = py::cast(flat.request_kind);
  out["method"] = py::cast(flat.method);
  out["path"] = py::cast(flat.path);
  out["body_template"] = py::cast(flat.body_template);
  out["headers_idx"] = py::cast(flat.headers_idx);
  out["cookies_idx"] = py::cast(flat.cookies_idx);
  out["headers_pool"] = py::cast(flat.headers_pool);
  out["cookies_pool"] = py::cast(flat.cookies_pool);
  out["device_profile"] = py::cast(flat.device_profile);
  out["timeout_ms"] = py::cast(flat.timeout_ms);
  out["retry_count"] = py::cast(flat.retry_count);
  out["on_failure"] = py::cast(flat.on_failure);
  out["think_min_ms"] = py::cast(flat.think_min_ms);
  out["think_max_ms"] = py::cast(flat.think_max_ms);
  out["think_distribution"] = py::cast(flat.think_distribution);
  out["think_mean_ms"] = py::cast(flat.think_mean_ms);
  out["think_stddev_ms"] = py::cast(flat.think_stddev_ms);
  out["tcp_dst_port"] = py::cast(flat.tcp_dst_port);
  out["tcp_payload"] = py::cast(flat.tcp_payload);
  out["tcp_expect_condition"] = py::cast(flat.tcp_expect_condition);
  out["tcp_expect_timeout_ms"] = py::cast(flat.tcp_expect_timeout_ms);
  return out;
}

}  // namespace ddos_samurai::scenario_native
