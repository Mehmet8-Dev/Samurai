#include "sut_probe.hpp"

#include <cstdio>

#include "http_client.hpp"

namespace samurai::control {

namespace {

namespace json = samurai::core::json;
namespace http = samurai::core::http;

// Percent-encode everything outside the unreserved set so a PromQL expression
// survives as a single query-string value.
std::string UrlEncode(const std::string& s) {
  static const char* hex = "0123456789ABCDEF";
  std::string out;
  out.reserve(s.size() * 3);
  for (unsigned char c : s) {
    const bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~';
    if (unreserved) {
      out.push_back(static_cast<char>(c));
    } else {
      out.push_back('%');
      out.push_back(hex[c >> 4]);
      out.push_back(hex[c & 0x0F]);
    }
  }
  return out;
}

// A Prometheus value is [<unix_ts>, "<string number>"]; pull the numeric string.
bool ValuePairToDouble(const json::Value& value_pair, double& out) {
  if (!value_pair.is_array() || value_pair.elements().size() < 2) return false;
  const json::Value& v = value_pair.elements()[1];
  // The sample value is a stringified number ("42.5", "+Inf", "NaN").
  const std::string sv = v.as_string("");
  if (sv.empty()) {
    // Some encoders may hand back a bare number; accept that too.
    out = v.as_double(0.0);
    return v.is_number();
  }
  try {
    out = std::stod(sv);
    return true;
  } catch (...) {
    return false;
  }
}

}  // namespace

bool ParsePromInstantScalar(const std::string& json_body, double& out, std::string& err) {
  auto pr = json::Parse(json_body);
  if (!pr.ok || !pr.value.is_object()) {
    err = "prometheus: unparseable response";
    return false;
  }
  const json::Value& root = pr.value;
  const json::Value* status = root.find("status");
  if (status && status->as_string("") != "success") {
    const json::Value* e = root.find("error");
    err = "prometheus: query status " + status->as_string("") +
          (e ? (" (" + e->as_string("") + ")") : "");
    return false;
  }
  const json::Value* data = root.find("data");
  if (!data || !data->is_object()) {
    err = "prometheus: missing data";
    return false;
  }
  const json::Value* rtype = data->find("resultType");
  const json::Value* result = data->find("result");
  const std::string type = rtype ? rtype->as_string("") : "";

  if (type == "scalar" && result) {
    // scalar: result itself is [ts, "val"].
    if (ValuePairToDouble(*result, out)) return true;
    err = "prometheus: scalar result not numeric";
    return false;
  }
  // vector / matrix: result is an array of series; take the first series' value.
  if (result && result->is_array()) {
    if (result->elements().empty()) {
      err = "prometheus: empty result (query matched no series)";
      return false;
    }
    const json::Value& first = result->elements()[0];
    const json::Value* value_pair = first.is_object() ? first.find("value") : nullptr;
    if (value_pair && ValuePairToDouble(*value_pair, out)) return true;
    // matrix results carry "values":[[ts,"v"],...]; take the last point.
    const json::Value* values = first.is_object() ? first.find("values") : nullptr;
    if (values && values->is_array() && !values->elements().empty()) {
      if (ValuePairToDouble(values->elements().back(), out)) return true;
    }
    err = "prometheus: result value not numeric";
    return false;
  }
  err = "prometheus: unsupported resultType '" + type + "'";
  return false;
}

std::string BuildPromQueryUrl(const std::string& base, const std::string& promql) {
  std::string b = base;
  while (!b.empty() && b.back() == '/') b.pop_back();
  return b + "/api/v1/query?query=" + UrlEncode(promql);
}

SutSample SutProbe::Scrape() const {
  SutSample s;
  if (!enabled()) {
    s.error = "sut probe disabled";
    return s;
  }

  auto run_one = [&](const std::string& promql, double& out) -> bool {
    http::HttpOptions o;
    o.insecure = cfg_.insecure;
    o.timeout_s = cfg_.timeout_s;
    const http::HttpResponse resp = http::Request(BuildPromQueryUrl(cfg_.prometheus_url, promql), o);
    if (!resp.ok || resp.status / 100 != 2) {
      if (s.error.empty()) {
        s.error = resp.error.empty() ? ("prometheus http status " + std::to_string(resp.status))
                                     : resp.error;
      }
      return false;
    }
    std::string perr;
    if (!ParsePromInstantScalar(resp.body, out, perr)) {
      if (s.error.empty()) s.error = perr;
      return false;
    }
    return true;
  };

  if (!cfg_.latency_p99_query.empty()) {
    double v = 0.0;
    if (run_one(cfg_.latency_p99_query, v)) {
      s.latency_p99_ms = v;
      s.metrics["latency_p99_ms"] = v;
      s.ok = true;
    }
  }
  for (const auto& q : cfg_.extra) {
    double v = 0.0;
    if (run_one(q.promql, v)) {
      s.metrics[q.name] = v;
      s.ok = true;
    }
  }
  return s;
}

json::Value SutProbe::SampleJson(const SutSample& s) {
  json::Value o = json::Value::Object();
  o.set("ok", json::Value::Bool(s.ok));
  o.set("latency_p99_ms", json::Value::Double(s.latency_p99_ms));
  json::Value m = json::Value::Object();
  for (const auto& kv : s.metrics) m.set(kv.first, json::Value::Double(kv.second));
  o.set("metrics", std::move(m));
  if (!s.error.empty()) o.set("error", json::Value::Str(s.error));
  return o;
}

}  // namespace samurai::control
