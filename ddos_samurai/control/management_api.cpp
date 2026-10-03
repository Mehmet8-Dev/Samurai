#include "management_api.hpp"

#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <fstream>
#include <mutex>
#include <unordered_map>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "jwt.hpp"
#include "worker_registry.hpp"  // orchestrator::kWorkerTable / IsBundleWorkerName

namespace samurai::control {

struct RateLimiter::Impl {
  std::mutex mu;
  std::unordered_map<std::string, std::pair<int, std::int64_t>> clients;
};

RateLimiter::RateLimiter(int max_per_sec)
    : max_per_sec_(max_per_sec), impl_(std::make_shared<Impl>()) {}

bool RateLimiter::Allow(const std::string& client_key) {
  if (max_per_sec_ <= 0) return true;
  std::lock_guard<std::mutex> lock(impl_->mu);
  const auto now_sec = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::steady_clock::now().time_since_epoch())
                           .count();
  if (impl_->clients.size() > 2048) {
    for (auto it = impl_->clients.begin(); it != impl_->clients.end(); ) {
      if (it->second.second < now_sec - 2) {
        it = impl_->clients.erase(it);
      } else {
        ++it;
      }
    }
  }
  auto& entry = impl_->clients[client_key];
  if (entry.second != now_sec) {
    entry.first = 1;
    entry.second = now_sec;
    return true;
  }
  if (entry.first < max_per_sec_) {
    entry.first++;
    return true;
  }
  return false;
}

namespace {

using samurai::core::json::Value;

std::string Lower(std::string s) {
  for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}
std::string Strip(const std::string& s) {
  const auto first = s.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) return "";
  const auto last = s.find_last_not_of(" \t\r\n");
  return s.substr(first, last - first + 1);
}

std::string UrlDecode(const std::string& s) {
  std::string out;
  out.reserve(s.size());
  for (std::size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '%' && i + 2 < s.size()) {
      auto hex = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
      };
      const int hi = hex(s[i + 1]), lo = hex(s[i + 2]);
      if (hi >= 0 && lo >= 0) {
        out.push_back(static_cast<char>((hi << 4) | lo));
        i += 2;
        continue;
      }
    }
    out.push_back(s[i] == '+' ? ' ' : s[i]);
  }
  return out;
}

std::string ExtractBearer(const std::string& header) {
  std::string raw = Strip(header);
  if (raw.empty()) return "";
  if (raw.size() >= 7 && Lower(raw.substr(0, 7)) == "bearer ") return Strip(raw.substr(7));
  return raw;
}

std::string HeaderOr(const std::map<std::string, std::string>& h, const std::string& key) {
  auto it = h.find(key);
  return it == h.end() ? "" : it->second;
}

HttpResponse JsonResp(int status, const std::string& reason, const Value& body) {
  HttpResponse r;
  r.status = status;
  r.reason = reason;
  r.content_type = "application/json";
  r.body = body.dump();
  return r;
}
HttpResponse ErrResp(int status, const std::string& reason, const std::string& detail) {
  Value b = Value::Object();
  b.set("detail", Value::Str(detail));
  return JsonResp(status, reason, b);
}

// --- Self-bootstrapping agent helpers --------------------------------------

std::string HexOf(const unsigned char* p, std::size_t n) {
  static const char* kHex = "0123456789abcdef";
  std::string out;
  out.reserve(n * 2);
  for (std::size_t i = 0; i < n; ++i) {
    out.push_back(kHex[p[i] >> 4]);
    out.push_back(kHex[p[i] & 0x0F]);
  }
  return out;
}
std::string Sha256Hex(const std::string& data) {
  unsigned char md[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), md);
  return HexOf(md, SHA256_DIGEST_LENGTH);
}
std::string HmacSha256Hex(const std::string& data, const std::string& key) {
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int len = 0;
  HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
       reinterpret_cast<const unsigned char*>(data.data()), data.size(), md, &len);
  return HexOf(md, len);
}
bool ReadFileBytes(const std::string& path, std::string& out) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return false;
  std::ostringstream ss;
  ss << f.rdbuf();
  out = ss.str();
  return static_cast<bool>(f) || f.eof();
}
bool ConstTimeEq(const std::string& a, const std::string& b) {
  if (a.size() != b.size() || a.empty()) return false;
  unsigned char diff = 0;
  for (std::size_t i = 0; i < a.size(); ++i) {
    diff |= static_cast<unsigned char>(a[i] ^ b[i]);
  }
  return diff == 0;
}
bool SafeBlobName(const std::string& n) {
  if (n.size() < 9 || n.size() > 64) return false;   // "samurai_" + >=1
  if (n.rfind("samurai_", 0) != 0) return false;
  for (char c : n) {
    if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_')) return false;
  }
  return true;
}
std::string SanitizeHost(const std::string& h) {
  std::string out;
  for (char c : h) {
    if (std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == ':' || c == '-') {
      out.push_back(c);
    }
  }
  return out.empty() ? std::string("127.0.0.1") : out;
}

// The POSIX-sh installer served at /v1/agent/install. It fetches the HMAC-signed
// manifest (key = the join token the operator embedded in the curl URL), verifies
// the signature and every binary's SHA-256, then execs the slave in reverse mode.
std::string BuildInstallScript(const std::string& base, const std::string& token,
                               bool tls_skip_verify) {
  // `-k` skips cert verification: needed only for the self-signed TLS mode (the
  // manifest HMAC still authenticates the payload). Real certs verify normally.
  const char* curl = tls_skip_verify ? "curl -fsSLk" : "curl -fsSL";
  std::ostringstream s;
  s << "#!/bin/sh\n"
       "set -eu\n"
       "BASE=\"" << base << "\"\n"
       "TOKEN=\"" << token << "\"\n"
       "TMP=\"$(mktemp -d)\"\n"
       "trap 'rm -rf \"$TMP\"' EXIT INT TERM HUP\n"
    << curl << " \"$BASE/v1/agent/manifest?token=$TOKEN\" -o \"$TMP/manifest\"\n"
       "SIG=\"$(head -n1 \"$TMP/manifest\" | awk '{print $2}')\"\n"
       "tail -n +2 \"$TMP/manifest\" > \"$TMP/body\"\n"
       "CALC=\"$(openssl dgst -sha256 -hmac \"$TOKEN\" \"$TMP/body\" | awk '{print $NF}')\"\n"
       "[ \"$SIG\" = \"$CALC\" ] || { echo 'samurai-agent: manifest HMAC mismatch' >&2; exit 1; }\n"
       "CE=''; DM='reverse'; WK='cpu'; CP=''; CS=''\n"
       "while read -r k v w; do\n"
       "  case \"$k\" in\n"
       "    control_endpoint) CE=\"$v\" ;;\n"
       "    dispatch_mode) DM=\"$v\" ;;\n"
       "    worker) WK=\"$v\" ;;\n"
       "    cluster_secret) CS=\"$v\" ;;\n"
       "    curve_server_public) CP=\"$v\" ;;\n"
       "    blob)\n"
    << "      " << curl << " \"$BASE/v1/agent/blob?token=$TOKEN&name=$v\" -o \"$TMP/$v\"\n"
       "      echo \"$w  $TMP/$v\" | sha256sum -c - >/dev/null || "
       "{ echo \"samurai-agent: $v sha256 mismatch\" >&2; exit 1; }\n"
       "      chmod +x \"$TMP/$v\" ;;\n"
       "  esac\n"
       "done < \"$TMP/body\"\n"
       "[ -n \"$CE\" ] || { echo 'samurai-agent: no control_endpoint' >&2; exit 1; }\n"
       "echo \"samurai-agent: verified; joining $CE (mode=$DM worker=$WK)\" >&2\n"
       "set -- --control-endpoints \"$CE\" --dispatch-mode \"$DM\" --worker \"$WK\" --worker-dir \"$TMP\"\n"
       "if [ -n \"$CS\" ]; then set -- \"$@\" --cluster-secret \"$CS\"; fi\n"
       "if [ -n \"$CP\" ]; then set -- \"$@\" --curve-server-public \"$CP\"; fi\n"
       "\"$TMP/samurai_slave\" \"$@\"\n"
       "EXIT_CODE=$?\n"
       "exit $EXIT_CODE\n";
  return s.str();
}

// Handles /v1/agent/* (install/manifest/blob). Returns nullopt when the feature
// is disabled or the path is not an agent path, so Handle continues its routing.
std::optional<HttpResponse> MaybeHandleAgent(const ManagementConfig& cfg,
                                            const HttpRequest& req,
                                            std::unordered_map<std::string, std::string>& blob_cache,
                                            std::mutex& blob_cache_mu) {
  if (cfg.agent_join_token.empty()) return std::nullopt;       // feature disabled
  if (req.method != "GET" || req.path.rfind("/v1/agent/", 0) != 0) return std::nullopt;

  std::string token;
  auto tit = req.query.find("token");
  if (tit != req.query.end()) token = tit->second;
  if (!ConstTimeEq(token, cfg.agent_join_token)) {
    return ErrResp(401, "Unauthorized", "agent_unauthorized");
  }

  const std::string worker = cfg.agent_worker.empty() ? std::string("cpu") : cfg.agent_worker;
  const std::string slave_bin = "samurai_slave";
  const std::string art = cfg.agent_artifact_dir;
  const bool bundle = samurai::orchestrator::IsBundleWorkerName(worker);

  // Cached file reader to eliminate redundant disk reads for static worker/slave binaries
  auto read_file_cached = [&](const std::string& path, const std::string& name, std::string& out_bytes) -> bool {
    {
      std::lock_guard<std::mutex> lock(blob_cache_mu);
      auto it = blob_cache.find(name);
      if (it != blob_cache.end()) {
        out_bytes = it->second;
        return true;
      }
    }
    if (!ReadFileBytes(path, out_bytes)) {
      return false;
    }
    {
      std::lock_guard<std::mutex> lock(blob_cache_mu);
      blob_cache[name] = out_bytes;
    }
    return true;
  };

  // The worker binaries this agent join serves. Bundle ships every catalog binary
  // present in the artifact dir (per-shard resolution on the slave); a fixed kind
  // ships exactly one. Used by both the manifest (blob list) and the blob gate.
  auto served_worker_bins = [&]() {
    std::vector<std::string> bins;
    if (bundle) {
      for (const auto& e : samurai::orchestrator::kWorkerTable) {
        std::string bytes;
        if (read_file_cached(art + "/" + e.binary, e.binary, bytes)) bins.emplace_back(e.binary);
      }
    } else {
      bins.push_back("samurai_" + worker + "_worker");
    }
    return bins;
  };

  if (req.path == "/v1/agent/manifest") {
    std::string slave_bytes;
    if (art.empty() || !read_file_cached(art + "/" + slave_bin, slave_bin, slave_bytes)) {
      return ErrResp(500, "Internal Server Error", "agent_artifacts_unavailable");
    }
    const std::vector<std::string> worker_bins = served_worker_bins();
    if (worker_bins.empty()) {
      return ErrResp(500, "Internal Server Error", "agent_artifacts_unavailable");
    }
    // Whitespace-delimited "key value" lines so the installer can parse them with
    // a single `read -r k v w` + `case "$k"` (same shape as the `blob` lines).
    std::ostringstream body;
    body << "control_endpoint " << cfg.agent_advertise_endpoint << "\n"
         << "dispatch_mode " << cfg.agent_dispatch_mode << "\n"
         << "worker " << worker << "\n";
    if (!cfg.agent_cluster_secret.empty()) {
      body << "cluster_secret " << cfg.agent_cluster_secret << "\n";
    }
    if (!cfg.agent_curve_public.empty()) {
      body << "curve_server_public " << cfg.agent_curve_public << "\n";
    }
    body << "blob " << slave_bin << " " << Sha256Hex(slave_bytes) << "\n";
    for (const std::string& wb : worker_bins) {
      std::string wbytes;
      if (!read_file_cached(art + "/" + wb, wb, wbytes)) {
        return ErrResp(500, "Internal Server Error", "agent_artifacts_unavailable");
      }
      body << "blob " << wb << " " << Sha256Hex(wbytes) << "\n";
    }
    const std::string b = body.str();
    HttpResponse r;
    r.status = 200;
    r.reason = "OK";
    r.content_type = "text/plain";
    r.body = "#hmac " + HmacSha256Hex(b, cfg.agent_join_token) + "\n" + b;
    return r;
  }

  if (req.path == "/v1/agent/blob") {
    std::string name;
    auto nit = req.query.find("name");
    if (nit != req.query.end()) name = nit->second;
    bool allowed = name == slave_bin;
    if (!allowed) {
      for (const std::string& wb : served_worker_bins()) {
        if (name == wb) { allowed = true; break; }
      }
    }
    if (!SafeBlobName(name) || !allowed) {
      return ErrResp(400, "Bad Request", "agent_bad_blob");
    }
    std::string bytes;
    if (art.empty() || !read_file_cached(art + "/" + name, name, bytes)) {
      return ErrResp(404, "Not Found", "agent_blob_missing");
    }
    HttpResponse r;
    r.status = 200;
    r.reason = "OK";
    r.content_type = "application/octet-stream";
    r.body = std::move(bytes);
    return r;
  }

  if (req.path == "/v1/agent/install") {
    const std::string scheme = cfg.agent_public_scheme.empty() ? "http" : cfg.agent_public_scheme;
    const std::string base = scheme + "://" + SanitizeHost(HeaderOr(req.headers, "host"));
    HttpResponse r;
    r.status = 200;
    r.reason = "OK";
    r.content_type = "text/x-shellscript";
    r.body = BuildInstallScript(base, cfg.agent_join_token, cfg.agent_tls_skip_verify);
    return r;
  }

  return std::nullopt;
}

bool MatchTenant(const Value& item, const std::string& tenant) {
  if (tenant.empty()) return true;
  const Value* t = item.find("tenant_namespace");
  return t && Strip(t->as_string("")) == tenant;
}

Value FilterArrayByTenant(const Value& arr, const std::string& tenant) {
  Value out = Value::Array();
  if (arr.is_array()) {
    for (const auto& e : arr.elements()) {
      if (MatchTenant(e, tenant)) out.push_back(e);
    }
  }
  return out;
}

const Value* Field(const Value& o, const char* k) { return o.is_object() ? o.find(k) : nullptr; }

Value ObjOr(const Value& o, const char* k) {
  const Value* v = Field(o, k);
  return (v && v->is_object()) ? *v : Value::Object();
}
Value ArrOr(const Value& o, const char* k) {
  const Value* v = Field(o, k);
  return (v && v->is_array()) ? *v : Value::Array();
}

}  // namespace

bool ParseHttpRequest(const std::string& raw, HttpRequest& out) {
  const auto line_end = raw.find("\r\n");
  const std::string request_line = raw.substr(0, line_end == std::string::npos ? raw.size() : line_end);
  std::istringstream ls(request_line);
  std::string target, version;
  if (!(ls >> out.method >> target >> version)) return false;

  // Split target into path + query.
  const auto qpos = target.find('?');
  out.path = qpos == std::string::npos ? target : target.substr(0, qpos);
  if (qpos != std::string::npos) {
    std::string qs = target.substr(qpos + 1);
    std::stringstream qss(qs);
    std::string pair;
    while (std::getline(qss, pair, '&')) {
      const auto eq = pair.find('=');
      if (eq == std::string::npos) {
        out.query[UrlDecode(pair)] = "";
      } else {
        out.query[UrlDecode(pair.substr(0, eq))] = UrlDecode(pair.substr(eq + 1));
      }
    }
  }

  // Headers.
  std::size_t pos = (line_end == std::string::npos) ? raw.size() : line_end + 2;
  while (pos < raw.size()) {
    const auto next = raw.find("\r\n", pos);
    const std::string header = raw.substr(pos, next == std::string::npos ? std::string::npos : next - pos);
    if (header.empty()) break;
    const auto colon = header.find(':');
    if (colon != std::string::npos) {
      out.headers[Lower(Strip(header.substr(0, colon)))] = Strip(header.substr(colon + 1));
    }
    if (next == std::string::npos) break;
    pos = next + 2;
  }
  return true;
}

ManagementApi::ManagementApi(const ManagementConfig& cfg, ManagementProviders providers)
    : cfg_(cfg), providers_(std::move(providers)), rate_limiter_(cfg.rate_limit_per_sec) {
  cfg_.tenant_namespace = Strip(cfg_.tenant_namespace);
  cfg_.jwt_secret = Strip(cfg_.jwt_secret);
  if (cfg_.jwt_role_claim.empty()) cfg_.jwt_role_claim = "role";
  if (cfg_.jwt_tenant_claim.empty()) cfg_.jwt_tenant_claim = "tenant_namespace";
  cfg_.trusted_secret_header = Lower(Strip(cfg_.trusted_secret_header));
  cfg_.trusted_role_header = Lower(Strip(cfg_.trusted_role_header));
  cfg_.trusted_tenant_header = Lower(Strip(cfg_.trusted_tenant_header));
  // Legacy token grants all three roles if not otherwise mapped.
  const std::string legacy = Strip(cfg_.auth_token);
  if (!legacy.empty()) {
    for (const char* r : {"admin", "operator", "viewer"}) {
      if (cfg_.role_tokens.find(r) == cfg_.role_tokens.end()) cfg_.role_tokens[r] = legacy;
    }
  }
}

void ManagementApi::ClearBlobCache() const {
  std::lock_guard<std::mutex> lock(blob_cache_mu_);
  blob_cache_.clear();
}

std::string ManagementApi::ResolveRole(const std::string& authorization,
                                       const std::map<std::string, std::string>& headers) const {
  // Trusted identity proxy header.
  const std::string trusted_secret = Strip(cfg_.trusted_identity_secret);
  if (!trusted_secret.empty() &&
      Strip(HeaderOr(headers, cfg_.trusted_secret_header)) == trusted_secret) {
    const std::string role = Lower(Strip(HeaderOr(headers, cfg_.trusted_role_header)));
    if (!role.empty()) return role;
  }

  const std::string token = ExtractBearer(authorization);
  if (cfg_.role_tokens.empty()) {
    if (!cfg_.jwt_secret.empty()) {
      const auto dec = DecodeJwtHs256(token, cfg_.jwt_secret);
      if (dec.ok) {
        const Value* c = dec.payload.find(cfg_.jwt_role_claim);
        const std::string role = c ? Lower(Strip(c->as_string(""))) : "";
        if (!role.empty()) return role;
      }
    }
    return "admin";  // no tokens + no usable jwt -> open (admin)
  }
  for (const char* role : {"admin", "operator", "viewer"}) {
    auto it = cfg_.role_tokens.find(role);
    if (it != cfg_.role_tokens.end() && !Strip(it->second).empty() && token == Strip(it->second)) {
      return role;
    }
  }
  if (!cfg_.jwt_secret.empty()) {
    const auto dec = DecodeJwtHs256(token, cfg_.jwt_secret);
    if (dec.ok) {
      const Value* c = dec.payload.find(cfg_.jwt_role_claim);
      return c ? Lower(Strip(c->as_string(""))) : "";
    }
    return "";
  }
  return "";
}

HttpResponse ManagementApi::Handle(const HttpRequest& req) const {
  // Rate limiter check across all endpoints (/healthz, /v1/agent/*, and API routes)
  std::string client_key = req.client_ip;
  if (client_key.empty()) {
    auto xff = req.headers.find("x-forwarded-for");
    if (xff != req.headers.end() && !xff->second.empty()) {
      client_key = xff->second;
    } else {
      auto auth = req.headers.find("authorization");
      if (auth != req.headers.end() && !auth->second.empty()) {
        client_key = auth->second;
      } else {
        auto tok = req.query.find("token");
        if (tok != req.query.end() && !tok->second.empty()) {
          client_key = tok->second;
        } else {
          client_key = "anonymous";
        }
      }
    }
  } else {
    // Only trust X-Forwarded-For if request comes with verified trusted proxy secret
    const std::string trusted_secret = Strip(cfg_.trusted_identity_secret);
    if (!trusted_secret.empty() &&
        Strip(HeaderOr(req.headers, cfg_.trusted_secret_header)) == trusted_secret) {
      auto xff = req.headers.find("x-forwarded-for");
      if (xff != req.headers.end() && !xff->second.empty()) {
        client_key = xff->second;
      }
    }
  }
  if (!rate_limiter_.Allow(client_key)) {
    return ErrResp(429, "Too Many Requests", "rate_limited");
  }

  const std::string authz = HeaderOr(req.headers, "authorization");

  // /healthz is unauthenticated.
  if (req.method == "GET" && req.path == "/healthz") {
    Value b = Value::Object();
    b.set("status", Value::Str("ok"));
    return JsonResp(200, "OK", b);
  }

  // Self-bootstrapping agent join (/v1/agent/*) uses its own join-token auth.
  if (auto agent = MaybeHandleAgent(cfg_, req, blob_cache_, blob_cache_mu_)) return *agent;

  auto guard = [&](std::initializer_list<const char*> allowed) -> std::optional<HttpResponse> {
    const std::string role = ResolveRole(authz, req.headers);
    if (role.empty()) return ErrResp(401, "Unauthorized", "unauthorized");
    for (const char* a : allowed) {
      if (role == a) return std::nullopt;
    }
    return ErrResp(403, "Forbidden", "forbidden");
  };

  // Effective tenant: app tenant wins; a conflicting query/claim tenant -> 403.
  auto effective_tenant = [&](std::string* out) -> std::optional<HttpResponse> {
    std::string qt;
    auto qit = req.query.find("tenant_namespace");
    if (qit != req.query.end()) qt = Strip(qit->second);
    if (!cfg_.tenant_namespace.empty() && !qt.empty() && qt != cfg_.tenant_namespace) {
      return ErrResp(403, "Forbidden", "forbidden_tenant");
    }
    std::string tenant = !cfg_.tenant_namespace.empty() ? cfg_.tenant_namespace : qt;
    // JWT tenant claim conflict check.
    std::string claim_tenant;
    if (!cfg_.jwt_secret.empty()) {
      const std::string token = ExtractBearer(authz);
      if (!token.empty()) {
        const auto dec = DecodeJwtHs256(token, cfg_.jwt_secret);
        if (dec.ok) {
          const Value* c = dec.payload.find(cfg_.jwt_tenant_claim);
          if (c) claim_tenant = Strip(c->as_string(""));
        }
      }
    }
    if (!tenant.empty() && !claim_tenant.empty() && tenant != claim_tenant) {
      return ErrResp(403, "Forbidden", "forbidden_tenant_claim");
    }
    *out = tenant.empty() ? claim_tenant : tenant;
    return std::nullopt;
  };

  const bool is_get = req.method == "GET";
  const bool is_post = req.method == "POST";

  if (is_get && req.path == "/metrics") {
    if (auto e = guard({"admin", "operator", "viewer"})) return *e;
    HttpResponse r;
    r.status = 200;
    r.reason = "OK";
    r.content_type = "text/plain; version=0.0.4";
    r.body = providers_.metrics_provider ? providers_.metrics_provider() : "";
    return r;
  }

  if (is_post && req.path == "/v1/jobs/abort") {
    if (auto e = guard({"admin", "operator"})) return *e;
    std::string tenant;
    if (auto e = effective_tenant(&tenant)) return *e;
    Value res = providers_.abort_callback ? providers_.abort_callback() : Value::Object();
    if (!res.is_object()) {
      res = Value::Object();
      res.set("aborted", Value::Bool(false));
    }
    return JsonResp(200, "OK", res);
  }

  // Read endpoints (viewer+).
  if (is_get && (req.path == "/v1/cluster/summary" || req.path == "/v1/cluster/workers" ||
                 req.path == "/v1/cluster/shards" || req.path == "/v1/cluster/events")) {
    if (auto e = guard({"admin", "operator", "viewer"})) return *e;
    std::string tenant;
    if (auto e = effective_tenant(&tenant)) return *e;
    const Value st = providers_.state_provider ? providers_.state_provider() : Value::Object();

    if (req.path == "/v1/cluster/workers") {
      Value b = Value::Object();
      b.set("tenant_namespace", Value::Str(tenant));
      b.set("workers", FilterArrayByTenant(ArrOr(st, "workers"), tenant));
      return JsonResp(200, "OK", b);
    }
    if (req.path == "/v1/cluster/shards") {
      Value b = Value::Object();
      b.set("tenant_namespace", Value::Str(tenant));
      b.set("shards", FilterArrayByTenant(ArrOr(st, "shards"), tenant));
      return JsonResp(200, "OK", b);
    }
    if (req.path == "/v1/cluster/events") {
      Value b = Value::Object();
      b.set("tenant_namespace", Value::Str(tenant));
      b.set("events", FilterArrayByTenant(ArrOr(st, "events"), tenant));
      return JsonResp(200, "OK", b);
    }
    // summary
    Value workers = FilterArrayByTenant(ArrOr(st, "workers"), tenant);
    Value shards = FilterArrayByTenant(ArrOr(st, "shards"), tenant);
    Value current_job = ObjOr(st, "current_job");
    if (!tenant.empty()) {
      const Value* ct = current_job.find("tenant_namespace");
      if (!ct || Strip(ct->as_string("")) != tenant) {
        current_job = Value::Object();
        current_job.set("state", Value::Str("idle"));
        current_job.set("job_id", Value::Str(""));
        current_job.set("tenant_namespace", Value::Str(tenant));
      }
    }
    Value b = Value::Object();
    b.set("status", Value::Str("ok"));
    b.set("tenant_namespace", Value::Str(tenant));
    b.set("current_job", std::move(current_job));
    b.set("latest_snapshot", ObjOr(st, "latest_snapshot"));
    b.set("ha", ObjOr(st, "ha"));
    b.set("multi_master", ObjOr(st, "multi_master"));
    b.set("multi_master_regions", ArrOr(st, "multi_master_regions"));
    b.set("multi_master_latest", ArrOr(st, "multi_master_latest"));
    b.set("autoscale", ObjOr(st, "autoscale"));
    b.set("closed_loop", ObjOr(st, "closed_loop"));
    b.set("workers_count", Value::Int(static_cast<std::int64_t>(workers.elements().size())));
    b.set("shards_reported_count", Value::Int(static_cast<std::int64_t>(shards.elements().size())));
    return JsonResp(200, "OK", b);
  }

  return ErrResp(404, "Not Found", "not found");
}

// --- ManagementApiServer ---------------------------------------------------

ManagementApiServer::ManagementApiServer(const std::string& listen_addr,
                                         const ManagementConfig& cfg,
                                         ManagementProviders providers,
                                         ManagementTlsConfig tls)
    : listen_addr_(Strip(listen_addr)),
      api_(cfg, std::move(providers)),
      tls_(std::move(tls)) {}

ManagementApiServer::~ManagementApiServer() {
  Stop();
  if (ssl_ctx_) {
    SSL_CTX_free(static_cast<SSL_CTX*>(ssl_ctx_));
    ssl_ctx_ = nullptr;
  }
}

// Generate an ephemeral RSA-2048 self-signed cert (CN=localhost, 1y) and install
// it on `ctx`. Returns false on any OpenSSL failure. Used when TLS is enabled
// without explicit cert/key files (zero-config secure transport for tests).
static bool InstallSelfSignedCert(SSL_CTX* ctx) {
  EVP_PKEY* pkey = nullptr;
  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
  bool ok = pctx && EVP_PKEY_keygen_init(pctx) > 0 &&
            EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) > 0 &&
            EVP_PKEY_keygen(pctx, &pkey) > 0;
  if (pctx) EVP_PKEY_CTX_free(pctx);
  if (!ok || !pkey) {
    if (pkey) EVP_PKEY_free(pkey);
    return false;
  }
  X509* x = X509_new();
  ok = x != nullptr;
  if (ok) {
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 60L * 60 * 24 * 365);
    X509_set_pubkey(x, pkey);
    X509_NAME* name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0);
    X509_set_issuer_name(x, name);  // self-signed: issuer == subject
    ok = X509_sign(x, pkey, EVP_sha256()) > 0 &&
         SSL_CTX_use_certificate(ctx, x) == 1 &&
         SSL_CTX_use_PrivateKey(ctx, pkey) == 1;
  }
  if (x) X509_free(x);
  EVP_PKEY_free(pkey);
  return ok;
}

bool ManagementApiServer::InitTls() {
  const SSL_METHOD* method = TLS_server_method();
  SSL_CTX* ctx = SSL_CTX_new(method);
  if (!ctx) return false;
  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
  bool ok = false;
  if (!tls_.cert_path.empty() && !tls_.key_path.empty()) {
    ok = SSL_CTX_use_certificate_chain_file(ctx, tls_.cert_path.c_str()) == 1 &&
         SSL_CTX_use_PrivateKey_file(ctx, tls_.key_path.c_str(), SSL_FILETYPE_PEM) == 1 &&
         SSL_CTX_check_private_key(ctx) == 1;
  } else {
    ok = InstallSelfSignedCert(ctx);  // ephemeral self-signed
  }
  if (!ok) {
    SSL_CTX_free(ctx);
    return false;
  }
  ssl_ctx_ = ctx;
  return true;
}

bool ManagementApiServer::Start() {
  if (running_.load()) return true;
  if (tls_.enabled && !ssl_ctx_ && !InitTls()) return false;  // cert load/gen failed
  std::string host = "127.0.0.1";
  int port = 0;
  const auto colon = listen_addr_.rfind(':');
  if (colon != std::string::npos) {
    host = listen_addr_.substr(0, colon);
    port = std::atoi(listen_addr_.substr(colon + 1).c_str());
  }
  if (host.empty() || host == "0.0.0.0") host = "0.0.0.0";

  listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
  if (listen_fd_ < 0) return false;
  int one = 1;
  ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  timeval tv{0, 200 * 1000};  // 200ms accept timeout so Loop sees the stop flag
  ::setsockopt(listen_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<uint16_t>(port));
  if (host == "0.0.0.0") {
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
  } else if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
    ::close(listen_fd_);
    listen_fd_ = -1;
    return false;
  }
  if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
      ::listen(listen_fd_, 16) != 0) {
    ::close(listen_fd_);
    listen_fd_ = -1;
    return false;
  }
  sockaddr_in bound{};
  socklen_t blen = sizeof(bound);
  if (::getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&bound), &blen) == 0) {
    char ip[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &bound.sin_addr, ip, sizeof(ip));
    endpoint_ = std::string(ip) + ":" + std::to_string(ntohs(bound.sin_port));
  } else {
    endpoint_ = listen_addr_;
  }
  running_.store(true);
  thread_ = std::thread(&ManagementApiServer::Loop, this);
  return true;
}

void ManagementApiServer::Stop() {
  running_.store(false);
  if (thread_.joinable()) thread_.join();
  if (listen_fd_ >= 0) {
    ::close(listen_fd_);
    listen_fd_ = -1;
  }
}

void ManagementApiServer::Loop() {
  while (running_.load()) {
    sockaddr_in peer{};
    socklen_t plen = sizeof(peer);
    int conn = ::accept(listen_fd_, reinterpret_cast<sockaddr*>(&peer), &plen);
    if (conn < 0) continue;  // timeout/interrupt -> re-check running_

    timeval tv{2, 0};
    ::setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Optional TLS: wrap the accepted fd. A failed handshake drops the conn.
    SSL* ssl = nullptr;
    if (ssl_ctx_) {
      ssl = SSL_new(static_cast<SSL_CTX*>(ssl_ctx_));
      if (!ssl || SSL_set_fd(ssl, conn) != 1 || SSL_accept(ssl) != 1) {
        if (ssl) SSL_free(ssl);
        ::close(conn);
        continue;
      }
    }
    auto readb = [&](char* p, int n) -> ssize_t {
      return ssl ? SSL_read(ssl, p, n) : ::recv(conn, p, n, 0);
    };
    auto writeb = [&](const char* p, std::size_t n) {
      if (ssl) SSL_write(ssl, p, static_cast<int>(n));
      else ::send(conn, p, n, 0);
    };

    // Read the request head (until CRLFCRLF), capped.
    std::string buf;
    char chunk[4096];
    while (buf.find("\r\n\r\n") == std::string::npos && buf.size() < 64 * 1024) {
      const ssize_t n = readb(chunk, sizeof(chunk));
      if (n <= 0) break;
      buf.append(chunk, static_cast<std::size_t>(n));
    }

    HttpRequest req;
    HttpResponse resp;
    if (ParseHttpRequest(buf, req)) {
      char ip_str[INET_ADDRSTRLEN] = {0};
      if (inet_ntop(AF_INET, &peer.sin_addr, ip_str, sizeof(ip_str))) {
        req.client_ip = ip_str;
      }
      resp = api_.Handle(req);
    } else {
      resp.status = 400;
      resp.reason = "Bad Request";
      resp.body = "{\"detail\":\"bad request\"}";
    }

    std::ostringstream os;
    os << "HTTP/1.1 " << resp.status << " " << resp.reason << "\r\n"
       << "Content-Type: " << resp.content_type << "\r\n"
       << "Content-Length: " << resp.body.size() << "\r\n"
       << "Access-Control-Allow-Origin: *\r\n"
       << "X-Frame-Options: DENY\r\n"
       << "X-Content-Type-Options: nosniff\r\n"
       << "Connection: close\r\n\r\n"
       << resp.body;
    const std::string out = os.str();
    writeb(out.data(), out.size());
    if (ssl) {
      SSL_shutdown(ssl);
      SSL_free(ssl);
    }
    ::close(conn);
  }
}

}  // namespace samurai::control
