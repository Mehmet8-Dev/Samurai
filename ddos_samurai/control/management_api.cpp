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

#include "jwt.hpp"

namespace samurai::control {

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
    : cfg_(cfg), providers_(std::move(providers)) {
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
  const std::string authz = HeaderOr(req.headers, "authorization");

  // /healthz is unauthenticated.
  if (req.method == "GET" && req.path == "/healthz") {
    Value b = Value::Object();
    b.set("status", Value::Str("ok"));
    return JsonResp(200, "OK", b);
  }

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
    b.set("workers_count", Value::Int(static_cast<std::int64_t>(workers.elements().size())));
    b.set("shards_reported_count", Value::Int(static_cast<std::int64_t>(shards.elements().size())));
    return JsonResp(200, "OK", b);
  }

  return ErrResp(404, "Not Found", "not found");
}

// --- ManagementApiServer ---------------------------------------------------

ManagementApiServer::ManagementApiServer(const std::string& listen_addr,
                                         const ManagementConfig& cfg,
                                         ManagementProviders providers)
    : listen_addr_(Strip(listen_addr)), api_(cfg, std::move(providers)) {}

ManagementApiServer::~ManagementApiServer() { Stop(); }

bool ManagementApiServer::Start() {
  if (running_.load()) return true;
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

    // Read the request head (until CRLFCRLF), capped.
    std::string buf;
    char chunk[4096];
    while (buf.find("\r\n\r\n") == std::string::npos && buf.size() < 64 * 1024) {
      const ssize_t n = ::recv(conn, chunk, sizeof(chunk), 0);
      if (n <= 0) break;
      buf.append(chunk, static_cast<std::size_t>(n));
    }

    HttpRequest req;
    HttpResponse resp;
    if (ParseHttpRequest(buf, req)) {
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
       << "Connection: close\r\n\r\n"
       << resp.body;
    const std::string out = os.str();
    ::send(conn, out.data(), out.size(), 0);
    ::close(conn);
  }
}

}  // namespace samurai::control
