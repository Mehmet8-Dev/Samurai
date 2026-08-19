#include "client.hpp"

#include <string>

#include "http_client.hpp"
#include "json.hpp"

namespace samurai::licensing {

namespace {
using samurai::core::json::Value;

LicenseResult ParseLicense(const std::string& body) {
  LicenseResult r;
  const auto parsed = samurai::core::json::Parse(body);
  if (!parsed.ok || !parsed.value.is_object()) {
    r.valid = false;
    r.reason = "invalid server response";
    return r;
  }
  const Value& p = parsed.value;
  r.valid = p.find("valid") && p.find("valid")->as_bool();
  r.tier = TierFromName(p.find("tier") ? p.find("tier")->as_string("community") : "community");
  if (const Value* fs = p.find("features"); fs && fs->is_array()) {
    for (const auto& e : fs->elements()) r.features.push_back(e.as_string(""));
  }
  if (const Value* lm = p.find("limits"); lm && lm->is_object()) {
    r.limits.has_value = true;
    r.limits.max_workers = static_cast<int>(lm->find("max_workers") ? lm->find("max_workers")->as_int(0) : 0);
    r.limits.max_pps = static_cast<int>(lm->find("max_pps") ? lm->find("max_pps")->as_int(0) : 0);
    r.limits.max_duration_s = static_cast<int>(lm->find("max_duration_s") ? lm->find("max_duration_s")->as_int(0) : 0);
    r.limits.max_devices = static_cast<int>(lm->find("max_devices") ? lm->find("max_devices")->as_int(1) : 1);
  }
  r.expires = p.find("expires") ? p.find("expires")->as_string("") : "";
  r.customer_email = p.find("customer_email") ? p.find("customer_email")->as_string("") : "";
  r.session_id = p.find("session_id") ? p.find("session_id")->as_string("") : "";
  r.reason = p.find("reason") ? p.find("reason")->as_string("") : "";
  r.offline = false;
  return r;
}
}  // namespace

LicenseResult HttpLicenseClient::Validate(const std::string& license_key,
                                          const std::string& hardware_id) {
  Value body = Value::Object();
  body.set("license_key", Value::Str(license_key));
  body.set("hardware_id", Value::Str(hardware_id));
  const HttpResponse resp = HttpPostJson(server_url_ + kValidateEndpoint, body.dump(), timeout_s_);
  if (!resp.ok) {
    LicenseResult r;
    r.valid = false;
    r.reason = "license server unreachable: " + resp.error;
    return r;
  }
  if (resp.status != 200) {
    LicenseResult r;
    r.valid = false;
    r.reason = "license server http " + std::to_string(resp.status);
    return r;
  }
  return ParseLicense(resp.body);
}

ExecGrantResult HttpLicenseClient::RequestGrant(const std::string& license_key,
                                                const std::string& hardware_id,
                                                const std::string& session_id,
                                                const std::string& attack_vector,
                                                const std::string& compute_backend,
                                                const std::string& role,
                                                const std::vector<std::string>& required_features) {
  Value body = Value::Object();
  body.set("license_key", Value::Str(license_key));
  body.set("hardware_id", Value::Str(hardware_id));
  body.set("session_id", Value::Str(session_id));
  body.set("attack_vector", Value::Str(attack_vector));
  body.set("compute_backend", Value::Str(compute_backend));
  body.set("role", Value::Str(role));
  Value feats = Value::Array();
  for (const auto& f : required_features) feats.push_back(Value::Str(f));
  body.set("required_features", std::move(feats));

  ExecGrantResult out;
  const HttpResponse resp = HttpPostJson(server_url_ + kExecGrantEndpoint, body.dump(), timeout_s_);
  if (!resp.ok) {
    out.reason = "grant endpoint unreachable: " + resp.error;
    return out;
  }
  if (resp.status != 200) {
    out.reason = "grant http " + std::to_string(resp.status);
    return out;
  }
  const auto parsed = samurai::core::json::Parse(resp.body);
  if (!parsed.ok || !parsed.value.is_object()) {
    out.reason = "invalid grant response";
    return out;
  }
  const Value& p = parsed.value;
  out.ok = p.find("granted") && p.find("granted")->as_bool();
  out.reason = p.find("reason") ? p.find("reason")->as_string("") : (out.ok ? "" : "denied");
  out.grant_token = p.find("grant_token") ? p.find("grant_token")->as_string("") : "";
  out.expires_at = p.find("expires_at") ? p.find("expires_at")->as_string("") : "";
  return out;
}

}  // namespace samurai::licensing
