#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <algorithm>
#include <cstdint>
#include <random>
#include <string>
#include <vector>
#include <numeric>

namespace py = pybind11;

struct CompileContext {
    py::dict spec;
    std::mt19937_64* rng;
    std::string backend;
    int max_depth{8};
    int max_events{200000};
    int emitted_events{0};
    int attempted_steps{0};
};

static void compile_flow_into(
    CompileContext& ctx,
    const std::string& flow_name,
    int depth,
    py::list& events
) {
    if (depth > ctx.max_depth) {
        return;
    }
    if (ctx.emitted_events >= ctx.max_events) {
        return;
    }
    py::dict flows = py::reinterpret_borrow<py::dict>(ctx.spec["flows"]);
    if (!flows.contains(py::str(flow_name))) {
        return;
    }
    py::dict flow = py::reinterpret_borrow<py::dict>(flows[py::str(flow_name)]);
    std::string persona_name = flow.contains("persona") ? py::str(flow["persona"]).cast<std::string>() : std::string();
    py::dict personas = py::reinterpret_borrow<py::dict>(ctx.spec["personas"]);
    py::dict persona = personas.contains(py::str(persona_name))
        ? py::reinterpret_borrow<py::dict>(personas[py::str(persona_name)])
        : py::dict();
    py::list steps = py::reinterpret_borrow<py::list>(flow["steps"]);
    std::uniform_real_distribution<double> uni(0.0, 1.0);

    for (auto obj : steps) {
        if (ctx.emitted_events >= ctx.max_events) {
            break;
        }
        py::dict step = py::reinterpret_borrow<py::dict>(obj);
        std::string type = py::str(step["type"]);
        if (type == "end_session") {
            break;
        }
        if (type == "pause") {
            py::dict ev;
            ev["event_type"] = py::str("think_time");
            int min_ms = 0;
            int max_ms = 0;
            if (step.contains("think_time")) {
                py::dict tt = py::reinterpret_borrow<py::dict>(step["think_time"]);
                if (tt.contains("min_ms")) {
                    min_ms = static_cast<int>(py::int_(tt["min_ms"]));
                }
                if (tt.contains("max_ms")) {
                    max_ms = static_cast<int>(py::int_(tt["max_ms"]));
                }
            }
            ev["min_ms"] = py::int_(std::max(0, min_ms));
            ev["max_ms"] = py::int_(std::max(std::max(0, min_ms), max_ms));
            events.append(ev);
            ctx.emitted_events += 1;
            continue;
        }
        if (type == "assert") {
            ctx.attempted_steps += 1;
            continue;
        }
        if (type == "branch") {
            double prob = 1.0;
            if (step.contains("probability")) {
                prob = static_cast<double>(py::float_(step["probability"]));
            }
            prob = std::clamp(prob, 0.0, 1.0);
            if (uni(*ctx.rng) <= prob) {
                std::string ref_flow = step.contains("flow") ? py::str(step["flow"]).cast<std::string>() : std::string();
                if (!ref_flow.empty()) {
                    compile_flow_into(ctx, ref_flow, depth + 1, events);
                }
            }
            continue;
        }
        if (type == "loop") {
            int repeat = step.contains("repeat")
                ? static_cast<int>(py::int_(step["repeat"]))
                : 1;
            repeat = std::max(1, repeat);
            std::string ref_flow = step.contains("flow") ? py::str(step["flow"]).cast<std::string>() : flow_name;
            if (ref_flow.empty()) {
                ref_flow = flow_name;
            }
            for (int i = 0; i < repeat; ++i) {
                compile_flow_into(ctx, ref_flow, depth + 1, events);
                if (ctx.emitted_events >= ctx.max_events) {
                    break;
                }
            }
            continue;
        }
        if (type == "request") {
            ctx.attempted_steps += 1;
            py::dict ev;
            ev["event_type"] = (ctx.backend == "http2") ? py::str("http2_headers") : py::str("http_request");
            ev["method"] = step.contains("method") ? step["method"] : py::str("GET");
            ev["path"] = step.contains("path") ? step["path"] : py::str("/");
            ev["headers"] = persona.contains("headers") ? persona["headers"] : py::dict();
            ev["cookies"] = persona.contains("cookies") ? persona["cookies"] : py::dict();
            ev["device_profile"] = persona.contains("device_profile") ? persona["device_profile"] : py::str("web");
            py::dict timeout_policy = persona.contains("timeout_policy")
                ? py::reinterpret_borrow<py::dict>(persona["timeout_policy"])
                : py::dict();
            py::dict retry_policy = persona.contains("retry_policy")
                ? py::reinterpret_borrow<py::dict>(persona["retry_policy"])
                : py::dict();
            ev["timeout_ms"] = timeout_policy.contains("request_timeout_ms")
                ? timeout_policy["request_timeout_ms"] : py::int_(5000);
            ev["retry_count"] = retry_policy.contains("max_retries")
                ? retry_policy["max_retries"] : py::int_(0);
            events.append(ev);
            ctx.emitted_events += 1;
        }
    }
}

static py::dict compile_session_plan(
    const py::dict& spec,
    const std::string& flow_name,
    std::uint64_t seed
) {
    py::dict flows = py::reinterpret_borrow<py::dict>(spec["flows"]);
    if (!flows.contains(py::str(flow_name))) {
        throw std::runtime_error("flow not found: " + flow_name);
    }
    std::mt19937_64 rng(seed);
    std::string backend = "http";
    if (spec.contains("load_model")) {
        py::dict load_model = py::reinterpret_borrow<py::dict>(spec["load_model"]);
        if (load_model.contains("backend")) {
            backend = py::str(load_model["backend"]);
        }
    }
    py::list events;
    CompileContext ctx{spec, &rng, backend, 8, 200000, 0, 0};
    compile_flow_into(ctx, flow_name, 0, events);

    py::dict out;
    out["flow"] = flow_name;
    py::dict flow = py::reinterpret_borrow<py::dict>(flows[py::str(flow_name)]);
    out["persona"] = flow.contains("persona") ? flow["persona"] : py::str("");
    out["events"] = events;
    out["step_attempted"] = ctx.attempted_steps;
    return out;
}

static py::tuple build_worker_session_plans(
    const py::dict& spec,
    const std::vector<int>& worker_counts,
    std::uint64_t seed
) {
    py::dict flows = py::reinterpret_borrow<py::dict>(spec["flows"]);
    py::dict personas = py::reinterpret_borrow<py::dict>(spec["personas"]);
    std::vector<std::string> flow_names;
    std::vector<double> flow_weights;
    for (auto item : flows) {
        std::string flow_name = py::str(item.first);
        py::dict flow = py::reinterpret_borrow<py::dict>(item.second);
        std::string persona_name;
        if (flow.contains("persona")) {
            persona_name = py::str(flow["persona"]);
        } else {
            persona_name = std::string();
        }
        double weight = 1.0;
        if (!persona_name.empty() && personas.contains(py::str(persona_name))) {
            py::dict persona = py::reinterpret_borrow<py::dict>(personas[py::str(persona_name)]);
            if (persona.contains("weight")) {
                weight = std::max(0.000001, static_cast<double>(py::float_(persona["weight"])));
            }
        }
        flow_names.emplace_back(flow_name);
        flow_weights.emplace_back(weight);
    }
    std::mt19937_64 rng(seed);
    std::discrete_distribution<std::size_t> flow_dist(flow_weights.begin(), flow_weights.end());
    py::list plans_by_worker;
    std::uint64_t sessions_started = 0;
    std::uint64_t step_attempted = 0;
    if (flow_names.empty()) {
        for (std::size_t i = 0; i < worker_counts.size(); ++i) {
            plans_by_worker.append(py::list());
        }
    } else {
        for (std::size_t wi = 0; wi < worker_counts.size(); ++wi) {
            py::list worker_plans;
            int wc = std::max(0, worker_counts[wi]);
            for (int i = 0; i < wc; ++i) {
                const auto idx = flow_dist(rng);
                std::uint64_t local_seed = rng();
                py::dict plan = compile_session_plan(spec, flow_names[idx], local_seed);
                worker_plans.append(plan);
                sessions_started += 1;
                step_attempted += static_cast<std::uint64_t>(py::int_(plan["step_attempted"]));
            }
            plans_by_worker.append(worker_plans);
        }
    }

    py::dict metrics;
    metrics["sessions_started"] = py::int_(sessions_started);
    metrics["step_attempted"] = py::int_(step_attempted);
    py::dict load_model = spec.contains("load_model")
        ? py::reinterpret_borrow<py::dict>(spec["load_model"])
        : py::dict();
    metrics["scenario_backend"] = load_model.contains("backend") ? load_model["backend"] : py::str("http");
    metrics["scenario_vus_target"] = load_model.contains("concurrent_vus") ? load_model["concurrent_vus"] : py::int_(0);
    metrics["scenario_ramp_seconds"] = load_model.contains("ramp_seconds") ? load_model["ramp_seconds"] : py::int_(0);
    return py::make_tuple(plans_by_worker, metrics);
}

static py::tuple evaluate_sla(
    const py::dict& sla,
    int sessions_started,
    int sessions_completed,
    int step_attempted,
    int step_failed,
    py::object latency_p95_ms
) {
    const int started = std::max(0, sessions_started);
    const int completed = std::max(0, sessions_completed);
    const int attempted = std::max(0, step_attempted);
    const int failed = std::max(0, step_failed);
    const double completion_rate = static_cast<double>(completed) / static_cast<double>(std::max(1, started));
    const double step_fail_ratio = static_cast<double>(failed) / static_cast<double>(std::max(1, attempted));
    const double min_completion_rate = sla.contains("min_completion_rate")
        ? static_cast<double>(py::float_(sla["min_completion_rate"]))
        : 0.95;
    const double max_step_fail_ratio = sla.contains("max_step_fail_ratio")
        ? static_cast<double>(py::float_(sla["max_step_fail_ratio"]))
        : 0.05;

    bool latency_ok = true;
    py::object max_latency_obj = py::none();
    if (sla.contains("max_latency_p95_ms")) {
        max_latency_obj = sla["max_latency_p95_ms"];
    }
    if (!max_latency_obj.is_none() && !latency_p95_ms.is_none()) {
        latency_ok = py::float_(latency_p95_ms) <= py::float_(max_latency_obj);
    }
    const bool ok = completion_rate >= min_completion_rate &&
                    step_fail_ratio <= max_step_fail_ratio &&
                    latency_ok;

    py::dict detail;
    detail["session_completion_rate"] = completion_rate;
    detail["l7_step_fail_ratio"] = step_fail_ratio;
    detail["sla_min_completion_rate"] = min_completion_rate;
    detail["sla_max_step_fail_ratio"] = max_step_fail_ratio;
    detail["sla_max_latency_p95_ms"] = max_latency_obj;
    detail["sla_latency_p95_ms"] = latency_p95_ms;
    detail["sla_passed"] = py::int_(ok ? 1 : 0);
    return py::make_tuple(ok, detail);
}

PYBIND11_MODULE(_scenario_native, m) {
    m.doc() = "Scenario engine native kernels";
    m.def("compile_session_plan", &compile_session_plan, py::arg("spec"), py::arg("flow_name"), py::arg("seed"));
    m.def("build_worker_session_plans", &build_worker_session_plans, py::arg("spec"), py::arg("worker_counts"), py::arg("seed"));
    m.def("evaluate_sla", &evaluate_sla, py::arg("sla"), py::arg("sessions_started"), py::arg("sessions_completed"), py::arg("step_attempted"), py::arg("step_failed"), py::arg("latency_p95_ms") = py::none());
}
