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
        if (st.contains("flow")) step.flow = py::str(st["flow"]).cast<std::string>();
        if (st.contains("repeat")) step.repeat = std::max(1, static_cast<int>(py::int_(st["repeat"])));
        if (st.contains("probability")) step.probability = std::clamp(static_cast<double>(py::float_(st["probability"])), 0.0, 1.0);
        if (st.contains("think_time")) {
          py::dict tt = py::reinterpret_borrow<py::dict>(st["think_time"]);
          if (tt.contains("min_ms")) step.think_time.min_ms = std::max(0, static_cast<int>(py::int_(tt["min_ms"])));
          if (tt.contains("max_ms")) step.think_time.max_ms = std::max(step.think_time.min_ms, static_cast<int>(py::int_(tt["max_ms"])));
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
        events.append(ev);
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

}  // namespace ddos_samurai::scenario_native
