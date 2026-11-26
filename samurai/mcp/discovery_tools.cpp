#include "discovery_tools.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "runtime_tools.hpp"

namespace samurai::mcp {

namespace {

using samurai::core::json::Parse;
using samurai::core::json::Value;

constexpr std::size_t kMaxHttpReadBytes = 512 * 1024;
constexpr std::size_t kBodyPreviewBytes = 512;

std::string LowerCopy(std::string s) {
  for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

std::string UpperCopy(std::string s) {
  for (char& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  return s;
}

std::string TrimCopy(const std::string& s) {
  std::size_t a = 0;
  while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
  std::size_t b = s.size();
  while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
  return s.substr(a, b - a);
}

bool ContainsInsensitive(const std::string& haystack, const std::string& needle) {
  if (needle.empty()) return true;
  return LowerCopy(haystack).find(LowerCopy(needle)) != std::string::npos;
}

std::string OptStr(const Value& obj, const char* key, const std::string& def = "") {
  if (const Value* v = obj.find(key); v && v->is_string()) return v->as_string(def);
  return def;
}

std::int64_t OptInt(const Value& obj, const char* key, std::int64_t def) {
  if (const Value* v = obj.find(key); v && v->is_number()) return v->as_int(def);
  return def;
}

bool OptBool(const Value& obj, const char* key, bool def) {
  if (const Value* v = obj.find(key); v && v->is_bool()) return v->as_bool(def);
  return def;
}

// Sanitizes arbitrary HTTP response payloads to safe printable ASCII for previews.
std::string SanitizePreview(const std::string& raw, std::size_t max_len = kBodyPreviewBytes) {
  std::string out;
  out.reserve(std::min(raw.size(), max_len));
  for (unsigned char c : raw) {
    if (out.size() >= max_len) break;
    if (c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c <= 0x7E)) {
      out.push_back(static_cast<char>(c));
    } else {
      out.push_back('.');
    }
  }
  return out;
}

struct TcpConnectOutcome {
  bool ok = false;
  double latency_ms = 0.0;
  std::string error;
};

int ConnectWithTimeout(int fd, const sockaddr* addr, socklen_t addrlen, int timeout_ms, std::string& err_out) {
  const int flags = ::fcntl(fd, F_GETFL, 0);
  if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    err_out = std::string("fcntl(O_NONBLOCK) failed: ") + std::strerror(errno);
    return -1;
  }

  const int rc = ::connect(fd, addr, addrlen);
  if (rc == 0) {
    ::fcntl(fd, F_SETFL, flags);
    return 0;
  }
  if (errno != EINPROGRESS) {
    err_out = std::strerror(errno);
    return -1;
  }

  pollfd pfd{};
  pfd.fd = fd;
  pfd.events = POLLOUT;
  const int pr = ::poll(&pfd, 1, timeout_ms);
  if (pr == 0) {
    err_out = "connect timed out";
    return -1;
  }
  if (pr < 0) {
    err_out = std::string("poll failed: ") + std::strerror(errno);
    return -1;
  }

  int so_err = 0;
  socklen_t slen = sizeof(so_err);
  if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &slen) != 0) {
    err_out = std::string("getsockopt(SO_ERROR) failed: ") + std::strerror(errno);
    return -1;
  }
  if (so_err != 0) {
    err_out = std::strerror(so_err);
    return -1;
  }

  ::fcntl(fd, F_SETFL, flags);
  return 0;
}

TcpConnectOutcome TcpCheck(const std::string& ip, int port, int connect_timeout_ms) {
  TcpConnectOutcome res;
  const auto t0 = std::chrono::steady_clock::now();

  const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    res.error = std::string("socket() failed: ") + std::strerror(errno);
    return res;
  }

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<std::uint16_t>(port));
  if (::inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
    ::close(fd);
    res.error = "Invalid IPv4 address: " + ip;
    return res;
  }

  std::string err;
  const int ok = ConnectWithTimeout(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr),
                                    connect_timeout_ms, err);
  const auto t1 = std::chrono::steady_clock::now();
  res.latency_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
  ::close(fd);

  res.ok = (ok == 0);
  res.error = err;
  return res;
}

std::string DecodeChunkedBody(const std::string& raw) {
  std::string out;
  std::size_t pos = 0;
  while (pos < raw.size()) {
    const std::size_t line_end = raw.find("\r\n", pos);
    if (line_end == std::string::npos) break;
    std::string size_str = raw.substr(pos, line_end - pos);
    const std::size_t semi = size_str.find(';');
    if (semi != std::string::npos) size_str = size_str.substr(0, semi);
    size_str = TrimCopy(size_str);
    if (size_str.empty()) break;

    char* endp = nullptr;
    const unsigned long long chunk_len = std::strtoull(size_str.c_str(), &endp, 16);
    if (endp == size_str.c_str() || *endp != '\0') break;
    pos = line_end + 2;
    if (chunk_len == 0) break;
    if (pos + chunk_len > raw.size()) {
      out.append(raw, pos, raw.size() - pos);
      break;
    }
    out.append(raw, pos, static_cast<std::size_t>(chunk_len));
    pos += static_cast<std::size_t>(chunk_len);
    if (pos + 2 <= raw.size() && raw[pos] == '\r' && raw[pos + 1] == '\n') {
      pos += 2;
    }
  }
  return out;
}

struct HttpProbeOutcome {
  bool ok = false;
  int http_status = 0;
  double latency_ms = 0.0;
  std::map<std::string, std::string> headers;
  std::string body;
  std::string error;
};

HttpProbeOutcome ExecuteHttpOnConnectedFd(int fd,
                                          const std::string& wire_request,
                                          int request_timeout_ms) {
  HttpProbeOutcome out;
  const auto t0 = std::chrono::steady_clock::now();

  std::size_t sent = 0;
  while (sent < wire_request.size()) {
    const ssize_t n = ::send(fd, wire_request.data() + sent, wire_request.size() - sent, MSG_NOSIGNAL);
    if (n <= 0) {
      out.error = std::string("send failed: ") + std::strerror(errno);
      return out;
    }
    sent += static_cast<std::size_t>(n);
  }

  std::string raw;
  char buf[8192];
  const auto deadline = t0 + std::chrono::milliseconds(request_timeout_ms);
  while (raw.size() < kMaxHttpReadBytes) {
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
      if (raw.empty()) {
        out.error = "HTTP read timed out";
        return out;
      }
      break;
    }
    const int rem_ms = static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
    pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLIN;
    const int pr = ::poll(&pfd, 1, std::max(1, rem_ms));
    if (pr <= 0) {
      if (raw.empty()) {
        out.error = pr == 0 ? "HTTP read timed out" : (std::string("poll failed: ") + std::strerror(errno));
        return out;
      }
      break;
    }
    const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) break;
    raw.append(buf, static_cast<std::size_t>(n));
  }

  const auto t1 = std::chrono::steady_clock::now();
  out.latency_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

  const std::size_t sep = raw.find("\r\n\r\n");
  if (sep == std::string::npos) {
    out.error = raw.empty() ? "Empty HTTP response" : "Malformed HTTP response (no header terminator)";
    return out;
  }

  const std::string header_block = raw.substr(0, sep);
  std::string body_raw = raw.substr(sep + 4);

  std::istringstream hss(header_block);
  std::string status_line;
  std::getline(hss, status_line);
  if (!status_line.empty() && status_line.back() == '\r') status_line.pop_back();
  const std::size_t sp1 = status_line.find(' ');
  if (sp1 == std::string::npos || status_line.rfind("HTTP/", 0) != 0) {
    out.error = "Non-HTTP response: " + SanitizePreview(status_line, 80);
    return out;
  }
  out.http_status = std::atoi(status_line.c_str() + sp1 + 1);

  std::string hline;
  while (std::getline(hss, hline)) {
    if (!hline.empty() && hline.back() == '\r') hline.pop_back();
    const std::size_t colon = hline.find(':');
    if (colon == std::string::npos) continue;
    const std::string key = LowerCopy(TrimCopy(hline.substr(0, colon)));
    const std::string val = TrimCopy(hline.substr(colon + 1));
    out.headers[key] = val;
  }

  const auto te_it = out.headers.find("transfer-encoding");
  if (te_it != out.headers.end() && ContainsInsensitive(te_it->second, "chunked")) {
    out.body = DecodeChunkedBody(body_raw);
  } else {
    out.body = std::move(body_raw);
  }

  out.ok = out.http_status > 0;
  return out;
}

HttpProbeOutcome HttpProbeTcp(const std::string& ip,
                              int port,
                              const std::string& path,
                              const std::string& host_header,
                              const std::string& bearer_token,
                              int connect_timeout_ms,
                              int request_timeout_ms) {
  HttpProbeOutcome out;
  const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    out.error = std::string("socket() failed: ") + std::strerror(errno);
    return out;
  }

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<std::uint16_t>(port));
  if (::inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
    ::close(fd);
    out.error = "Invalid IPv4 address: " + ip;
    return out;
  }

  std::string conn_err;
  if (ConnectWithTimeout(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr),
                         connect_timeout_ms, conn_err) != 0) {
    ::close(fd);
    out.error = "connect failed: " + conn_err;
    return out;
  }

  const std::string norm_path = (!path.empty() && path[0] == '/') ? path : ("/" + path);
  const std::string host_val = !host_header.empty() ? host_header : (ip + ":" + std::to_string(port));

  std::ostringstream req;
  req << "GET " << norm_path << " HTTP/1.1\r\n"
      << "Host: " << host_val << "\r\n"
      << "User-Agent: SamuraiDiscovery/3.4\r\n"
      << "Accept: application/json, text/plain, */*\r\n"
      << "Connection: close\r\n";
  if (!bearer_token.empty()) {
    req << "Authorization: Bearer " << bearer_token << "\r\n";
  }
  req << "\r\n";

  out = ExecuteHttpOnConnectedFd(fd, req.str(), request_timeout_ms);
  ::close(fd);
  return out;
}

HttpProbeOutcome QueryDockerUnixSocket(const std::string& socket_path,
                                       const std::string& path,
                                       int timeout_ms) {
  HttpProbeOutcome out;
  const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    out.error = std::string("AF_UNIX socket() failed: ") + std::strerror(errno);
    return out;
  }

  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  if (socket_path.size() >= sizeof(addr.sun_path)) {
    ::close(fd);
    out.error = "Docker socket path exceeds sockaddr_un limit";
    return out;
  }
  std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path.c_str());

  std::string conn_err;
  if (ConnectWithTimeout(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr),
                         timeout_ms, conn_err) != 0) {
    ::close(fd);
    out.error = "Docker socket connect failed (" + socket_path + "): " + conn_err;
    return out;
  }

  std::ostringstream req;
  req << "GET " << path << " HTTP/1.0\r\n"
      << "Host: localhost\r\n"
      << "Accept: application/json\r\n\r\n";

  out = ExecuteHttpOnConnectedFd(fd, req.str(), timeout_ms);
  ::close(fd);
  return out;
}

std::string KnownNonHttpPortHint(int port) {
  switch (port) {
    case 5432: return "postgres";
    case 6379: return "redis";
    case 3306: return "mysql";
    case 27017: return "mongodb";
    case 5672: return "amqp";
    case 9042: return "cassandra";
    case 22: return "ssh";
    default: return "";
  }
}

struct OpenApiSummary {
  bool found = false;
  std::string spec_path;
  std::string spec_version;
  std::string title;
  std::string api_version;
  std::vector<std::string> get_paths;
  Value endpoints = Value::Array();
};

OpenApiSummary TryExtractOpenApi(const std::string& path, const std::string& body) {
  OpenApiSummary out;
  const auto parsed = Parse(body);
  if (!parsed.ok || !parsed.value.is_object()) return out;
  const Value& doc = parsed.value;
  const Value* paths = doc.find("paths");
  if (!paths || !paths->is_object()) return out;

  out.found = true;
  out.spec_path = path;
  if (const Value* oa = doc.find("openapi"); oa && oa->is_string()) {
    out.spec_version = "openapi " + oa->as_string();
  } else if (const Value* sw = doc.find("swagger"); sw && sw->is_string()) {
    out.spec_version = "swagger " + sw->as_string();
  }
  if (const Value* info = doc.find("info"); info && info->is_object()) {
    out.title = OptStr(*info, "title", "");
    out.api_version = OptStr(*info, "version", "");
  }

  static const std::set<std::string> kHttpMethods = {
      "get", "post", "put", "patch", "delete", "options", "head"};

  for (const auto& path_kv : paths->members()) {
    if (!path_kv.second.is_object()) continue;
    for (const auto& op_kv : path_kv.second.members()) {
      const std::string m_low = LowerCopy(op_kv.first);
      if (kHttpMethods.find(m_low) == kHttpMethods.end()) continue;
      if (!op_kv.second.is_object()) continue;

      Value ep = Value::Object();
      ep.set("method", Value::Str(UpperCopy(m_low)));
      ep.set("path", Value::Str(path_kv.first));
      if (const std::string sum = OptStr(op_kv.second, "summary", ""); !sum.empty()) {
        ep.set("summary", Value::Str(sum));
      }
      if (const std::string opid = OptStr(op_kv.second, "operationId", ""); !opid.empty()) {
        ep.set("operation_id", Value::Str(opid));
      }
      out.endpoints.push_back(std::move(ep));

      if (m_low == "get" && path_kv.first.find('{') == std::string::npos &&
          out.get_paths.size() < 12) {
        out.get_paths.push_back(path_kv.first);
      }
    }
  }
  return out;
}

struct ProbeFingerprintSample {
  std::string path;
  int http_status = 0;
  std::string server;
  std::string body_sample;
  std::map<std::string, std::string> headers;
};

std::string InferFingerprint(const std::vector<ProbeFingerprintSample>& probe_records, const OpenApiSummary& oa) {
  if (oa.found && !oa.title.empty()) {
    return "OpenAPI (" + oa.title + ")";
  }

  bool tls_plain_rejected = false;
  bool has_minio_server = false;
  bool has_minio_health_200 = false;
  bool has_minio_xml_error = false;
  bool has_non_200_root = false;
  bool has_osrm_server = false;
  bool has_osrm_signature = false;
  bool has_echo_whoami = false;
  bool has_anubis = false;
  std::string first_server;

  for (const auto& rec : probe_records) {
    const std::string& raw_srv = rec.server;
    const std::string srv = LowerCopy(raw_srv);
    const std::string& p = rec.path;
    const std::string body = rec.body_sample.substr(0, 1024);
    const std::string body_low = LowerCopy(body);
    const int st = rec.http_status;

    if (first_server.empty() && !raw_srv.empty()) first_server = raw_srv;

    if (body_low.find("client sent an http request to an https server") != std::string::npos ||
        body_low.find("plain http request was sent to https") != std::string::npos) {
      tls_plain_rejected = true;
    }

    if (srv.find("minio") != std::string::npos ||
        body_low.find("<meta content=\"minio console\"") != std::string::npos ||
        body_low.find("<title>minio console</title>") != std::string::npos) {
      has_minio_server = true;
    }
    if (p.rfind("/minio/health/", 0) == 0 && st == 200) {
      has_minio_health_200 = true;
    }
    if (body_low.find("<error><code>") != std::string::npos &&
        body_low.find("<requestid>") != std::string::npos) {
      has_minio_xml_error = true;
    }
    if (p == "/" && st > 0 && st != 200) {
      has_non_200_root = true;
    }

    if (srv.find("osrm") != std::string::npos) {
      has_osrm_server = true;
    }
    if ((p.rfind("/nearest/", 0) == 0 || p.rfind("/route/", 0) == 0) &&
        (st == 200 || st == 400) &&
        (body.find("\"waypoints\"") != std::string::npos ||
         body.find("\"InvalidUrl\"") != std::string::npos ||
         body.find("\"code\":\"Ok\"") != std::string::npos)) {
      has_osrm_signature = true;
    }

    if (body.find("Hostname: ") != std::string::npos &&
        body.find("RemoteAddr: ") != std::string::npos) {
      has_echo_whoami = true;
    }
    if (body_low.find("x-anubis-action") != std::string::npos ||
        body_low.find("x-anubis-rule") != std::string::npos ||
        rec.headers.find("x-anubis-action") != rec.headers.end()) {
      has_anubis = true;
    }
  }

  if (tls_plain_rejected) return "HTTPS/TLS Service (plain HTTP rejected)";
  if (has_minio_server || (has_minio_health_200 && (has_minio_xml_error || has_non_200_root) && !has_echo_whoami)) {
    return "MinIO Object Storage API";
  }
  if (has_osrm_server || has_osrm_signature) {
    return "OSRM Routing API";
  }
  if (has_anubis) return "Anubis Bot-Protection Proxy";
  if (has_echo_whoami && first_server.empty()) return "HTTP Echo / whoami Service";
  if (!first_server.empty()) return "HTTP (" + first_server + ")";
  return "HTTP/1.1 Service";
}

Value BuildRecommendedScenario(const std::vector<std::string>& candidate_paths) {
  Value steps = Value::Array();
  std::set<std::string> seen;
  for (const auto& p : candidate_paths) {
    if (p.empty() || !seen.insert(p).second) continue;
    Value step = Value::Object();
    step.set("kind", Value::Str("request"));
    step.set("method", Value::Str("GET"));
    step.set("path", Value::Str(p));
    steps.push_back(std::move(step));
    if (steps.elements().size() >= 8) break;
  }
  if (steps.elements().empty()) {
    Value step = Value::Object();
    step.set("kind", Value::Str("request"));
    step.set("method", Value::Str("GET"));
    step.set("path", Value::Str("/"));
    steps.push_back(std::move(step));
  }

  Value headers = Value::Object();
  headers.set("Accept", Value::Str("application/json"));
  headers.set("User-Agent", Value::Str("SamuraiScenario/3.4"));

  Value timeout_policy = Value::Object();
  timeout_policy.set("request_timeout_ms", Value::Int(3000));

  Value persona = Value::Object();
  persona.set("device_profile", Value::Str("web"));
  persona.set("headers", std::move(headers));
  persona.set("weight", Value::Double(1.0));
  persona.set("timeout_policy", std::move(timeout_policy));

  Value personas = Value::Object();
  personas.set("discovered_client", std::move(persona));

  Value flow = Value::Object();
  flow.set("persona", Value::Str("discovered_client"));
  flow.set("steps", std::move(steps));

  Value flows = Value::Object();
  flows.set("discovered_journey", std::move(flow));

  Value load_model = Value::Object();
  load_model.set("backend", Value::Str("l7"));
  load_model.set("concurrent_vus", Value::Int(10));
  load_model.set("ramp_seconds", Value::Int(1));

  Value sla = Value::Object();
  sla.set("min_completion_rate", Value::Double(0.95));
  sla.set("max_step_fail_ratio", Value::Double(0.05));
  sla.set("max_latency_p95_ms", Value::Double(500.0));
  sla.set("max_connect_timeout_ratio", Value::Double(0.02));
  sla.set("max_retransmit_ratio", Value::Double(0.02));

  Value sc = Value::Object();
  sc.set("schema_version", Value::Int(1));
  sc.set("protocol", Value::Str("http1"));
  sc.set("personas", std::move(personas));
  sc.set("flows", std::move(flows));
  sc.set("load_model", std::move(load_model));
  sc.set("sla", std::move(sla));
  return sc;
}

struct TargetEndpoint {
  std::string ip;
  int port = 80;
  std::string source;  // "explicit" | "docker"
  std::string container_name;
  std::string image;
  std::string network_name;
  std::string container_status;
  int host_port = 0;
};

struct ProbeOptions {
  bool probe_http = true;
  bool probe_openapi = true;
  bool probe_non_http_ports = false;
  bool include_body_preview = true;
  bool generate_scenario = true;
  int connect_timeout_ms = 400;
  int request_timeout_ms = 1500;
  std::string host_header;
  std::string bearer_token;
  std::vector<std::string> probe_paths;
};

Value ProbeTargetEndpoint(const TargetEndpoint& ep, const ProbeOptions& opts) {
  Value item = Value::Object();
  item.set("ip", Value::Str(ep.ip));
  item.set("port", Value::Int(ep.port));
  item.set("source", Value::Str(ep.source));
  if (!ep.container_name.empty()) item.set("container", Value::Str(ep.container_name));
  if (!ep.image.empty()) item.set("image", Value::Str(ep.image));
  if (!ep.network_name.empty()) item.set("network", Value::Str(ep.network_name));
  if (!ep.container_status.empty()) item.set("container_status", Value::Str(ep.container_status));
  if (ep.host_port > 0) item.set("host_port", Value::Int(ep.host_port));

  const TcpConnectOutcome tcp = TcpCheck(ep.ip, ep.port, opts.connect_timeout_ms);
  item.set("tcp_open", Value::Bool(tcp.ok));
  item.set("connect_latency_ms", Value::Double(tcp.latency_ms));
  if (!tcp.ok) {
    item.set("connect_error", Value::Str(tcp.error));
    return item;
  }

  const std::string non_http_hint = KnownNonHttpPortHint(ep.port);
  if (!non_http_hint.empty() && !opts.probe_non_http_ports) {
    item.set("protocol_hint", Value::Str("non-http (" + non_http_hint + ")"));
    item.set("http_probed", Value::Bool(false));
    return item;
  }

  if (!opts.probe_http) {
    item.set("http_probed", Value::Bool(false));
    return item;
  }

  item.set("http_probed", Value::Bool(true));

  OpenApiSummary oa;
  if (opts.probe_openapi) {
    static const char* kOpenApiPaths[] = {
        "/openapi.json", "/swagger.json", "/v3/api-docs", "/v2/api-docs",
        "/api-docs", "/api/openapi.json", "/api/swagger.json", "/docs/openapi.json",
    };
    for (const char* oa_path : kOpenApiPaths) {
      const HttpProbeOutcome r = HttpProbeTcp(ep.ip, ep.port, oa_path, opts.host_header,
                                              opts.bearer_token, opts.connect_timeout_ms,
                                              opts.request_timeout_ms);
      if (r.ok && r.http_status >= 200 && r.http_status < 300) {
        oa = TryExtractOpenApi(oa_path, r.body);
        if (oa.found) break;
      }
    }
  }

  std::vector<ProbeFingerprintSample> probe_records;
  std::vector<std::string> live_get_paths;
  for (const auto& oa_get : oa.get_paths) {
    live_get_paths.push_back(oa_get);
  }

  Value probes_arr = Value::Array();
  for (const auto& p : opts.probe_paths) {
    const HttpProbeOutcome r = HttpProbeTcp(ep.ip, ep.port, p, opts.host_header,
                                            opts.bearer_token, opts.connect_timeout_ms,
                                            opts.request_timeout_ms);
    Value prec = Value::Object();
    prec.set("path", Value::Str(p));
    prec.set("ok", Value::Bool(r.ok));
    if (r.ok) {
      prec.set("http_status", Value::Int(r.http_status));
      prec.set("latency_ms", Value::Double(r.latency_ms));
      if (auto it = r.headers.find("content-type"); it != r.headers.end()) {
        prec.set("content_type", Value::Str(it->second));
      }
      if (auto it = r.headers.find("server"); it != r.headers.end()) {
        prec.set("server", Value::Str(it->second));
      }
      if (auto it = r.headers.find("location"); it != r.headers.end()) {
        prec.set("location", Value::Str(it->second));
      }
      if (opts.include_body_preview && !r.body.empty()) {
        prec.set("body_preview", Value::Str(SanitizePreview(r.body)));
      }
      const auto parsed_body = Parse(r.body);
      if (parsed_body.ok && parsed_body.value.is_object()) {
        Value keys = Value::Array();
        for (const auto& kv : parsed_body.value.members()) {
          keys.push_back(Value::Str(kv.first));
          if (keys.elements().size() >= 16) break;
        }
        prec.set("json_keys", std::move(keys));
      }
      if (r.http_status > 0 && r.http_status != 404 && r.http_status < 500) {
        live_get_paths.push_back(p);
      }
      ProbeFingerprintSample sample;
      sample.path = p;
      sample.http_status = r.http_status;
      if (auto it = r.headers.find("server"); it != r.headers.end()) {
        sample.server = it->second;
      }
      sample.body_sample = r.body;
      sample.headers = r.headers;
      probe_records.push_back(std::move(sample));
    } else {
      prec.set("error", Value::Str(r.error));
    }
    probes_arr.push_back(std::move(prec));
  }

  if (oa.found) {
    Value oa_obj = Value::Object();
    oa_obj.set("spec_path", Value::Str(oa.spec_path));
    if (!oa.spec_version.empty()) oa_obj.set("spec_version", Value::Str(oa.spec_version));
    if (!oa.title.empty()) oa_obj.set("title", Value::Str(oa.title));
    if (!oa.api_version.empty()) oa_obj.set("api_version", Value::Str(oa.api_version));
    oa_obj.set("endpoint_count", Value::Int(static_cast<std::int64_t>(oa.endpoints.elements().size())));
    oa_obj.set("endpoints", oa.endpoints);
    item.set("openapi", std::move(oa_obj));
  }

  item.set("service_fingerprint", Value::Str(InferFingerprint(probe_records, oa)));
  item.set("probed_paths", std::move(probes_arr));
  if (opts.generate_scenario) {
    item.set("recommended_scenario", BuildRecommendedScenario(live_get_paths));
  }
  return item;
}

std::vector<int> DefaultDiscoveryPorts() {
  return {80, 443, 3000, 3001, 4000, 5000, 8000, 8080, 8081, 8089, 8443, 9000, 9001};
}

std::vector<std::string> BuildProbePaths(const Value& args) {
  std::vector<std::string> defaults = {
      "/", "/health", "/healthz", "/ready", "/live", "/status",
      "/metrics", "/api", "/api/health", "/api/v1/health",
      "/minio/health/live", "/minio/health/ready", "/nearest/v1/driving/28.9784,41.0082",
  };
  const bool replace_defaults = OptBool(args, "replace_default_paths", false);
  std::vector<std::string> out;
  std::set<std::string> seen;

  auto add_path = [&](std::string p) {
    p = TrimCopy(p);
    if (p.empty()) return;
    if (p[0] != '/') p.insert(p.begin(), '/');
    if (seen.insert(p).second) out.push_back(std::move(p));
  };

  if (!replace_defaults) {
    for (const auto& d : defaults) add_path(d);
  }
  if (const Value* pp = args.find("probe_paths"); pp && pp->is_array()) {
    for (const auto& el : pp->elements()) {
      if (el.is_string()) add_path(el.as_string());
    }
  }
  if (out.empty()) add_path("/");
  return out;
}

}  // namespace

ToolResult HandleDiscoverApis(const Value& args, const SafetyConfig& safety) {
  std::string safety_err;
  const SafetyConfig eff_safety = EffectiveSafetyConfig(args, safety, &safety_err);
  if (!safety_err.empty()) {
    return MakeToolError("Invalid target authorization parameter: " + safety_err);
  }

  // 1. Gather explicit targets (if any) and validate fail-closed immediately.
  std::vector<std::string> explicit_ips;
  std::set<std::string> seen_explicit;
  std::unordered_map<std::string, std::string> resolved_hostname_by_ip;
  auto push_explicit = [&](const std::string& raw) -> std::string {
    const std::string trimmed = TrimCopy(raw);
    if (trimmed.empty()) return "";
    std::string resolved;
    const auto chk = ResolveMcpTarget(trimmed, eff_safety, resolved);
    if (!chk.ok) {
      return "Target blocked by fail-closed MCP safety gate ('" + trimmed + "'): " + chk.reason;
    }
    if (resolved != trimmed && resolved_hostname_by_ip.find(resolved) == resolved_hostname_by_ip.end()) {
      resolved_hostname_by_ip.emplace(resolved, trimmed);
    }
    if (seen_explicit.insert(resolved).second) explicit_ips.push_back(resolved);
    return "";
  };

  if (const std::string single = OptStr(args, "target", ""); !single.empty()) {
    if (const std::string err = push_explicit(single); !err.empty()) return MakeToolError(err);
  }
  if (const Value* arr = args.find("targets"); arr && arr->is_array()) {
    for (const auto& el : arr->elements()) {
      if (!el.is_string()) continue;
      if (const std::string err = push_explicit(el.as_string()); !err.empty()) return MakeToolError(err);
    }
  }

  std::vector<int> explicit_ports;
  if (const Value* p_arr = args.find("ports"); p_arr && p_arr->is_array()) {
    for (const auto& el : p_arr->elements()) {
      if (!el.is_number()) continue;
      const int p = static_cast<int>(el.as_int(0));
      if (p < 1 || p > 65535) {
        return MakeToolError("All ports must be between 1 and 65535");
      }
      explicit_ports.push_back(p);
    }
  }
  if (explicit_ports.empty()) explicit_ports = DefaultDiscoveryPorts();

  const bool discover_docker = OptBool(args, "discover_docker", explicit_ips.empty());
  const std::string docker_socket = OptStr(args, "docker_socket", "/var/run/docker.sock");
  const std::string name_filter = OptStr(args, "name_filter", "");
  const std::string network_filter = OptStr(args, "network_filter", "");

  ProbeOptions opts;
  opts.probe_http = OptBool(args, "probe_http", true);
  opts.probe_openapi = OptBool(args, "probe_openapi", true);
  opts.probe_non_http_ports = OptBool(args, "probe_non_http_ports", false);
  opts.include_body_preview = OptBool(args, "include_body_preview", true);
  opts.generate_scenario = OptBool(args, "generate_scenario", true);
  opts.connect_timeout_ms = static_cast<int>(
      std::clamp<std::int64_t>(OptInt(args, "connect_timeout_ms", 400), 50, 5000));
  opts.request_timeout_ms = static_cast<int>(
      std::clamp<std::int64_t>(OptInt(args, "request_timeout_ms", 1500), 100, 10000));
  opts.host_header = OptStr(args, "host_header", "");
  opts.bearer_token = OptStr(args, "auth_token", "");
  opts.probe_paths = BuildProbePaths(args);

  std::vector<TargetEndpoint> targets_to_probe;
  std::set<std::pair<std::string, int>> seen_ip_port;

  for (const auto& ip : explicit_ips) {
    for (int port : explicit_ports) {
      if (seen_ip_port.insert({ip, port}).second) {
        TargetEndpoint ep;
        ep.ip = ip;
        ep.port = port;
        ep.source = "explicit";
        targets_to_probe.push_back(std::move(ep));
      }
    }
  }

  Value docker_info = Value::Object();
  docker_info.set("enabled", Value::Bool(discover_docker));
  if (discover_docker) {
    docker_info.set("socket", Value::Str(docker_socket));
    const HttpProbeOutcome dr = QueryDockerUnixSocket(docker_socket, "/containers/json", 2000);
    if (!dr.ok || dr.http_status >= 400) {
      docker_info.set("available", Value::Bool(false));
      docker_info.set("error", Value::Str(dr.ok ? ("HTTP " + std::to_string(dr.http_status)) : dr.error));
      if (explicit_ips.empty()) {
        return MakeToolError("Docker API discovery failed and no explicit target/targets provided: " +
                             OptStr(docker_info, "error", "unknown error"));
      }
    } else {
      const auto parsed = Parse(dr.body);
      if (!parsed.ok || !parsed.value.is_array()) {
        docker_info.set("available", Value::Bool(false));
        docker_info.set("error", Value::Str("Invalid JSON from Docker Engine /containers/json"));
      } else {
        docker_info.set("available", Value::Bool(true));
        std::int64_t matched_containers = 0;
        std::int64_t blocked_ips = 0;
        for (const auto& c : parsed.value.elements()) {
          if (!c.is_object()) continue;
          std::string cname;
          if (const Value* names = c.find("Names"); names && names->is_array() && !names->elements().empty()) {
            cname = names->elements()[0].as_string();
            if (!cname.empty() && cname[0] == '/') cname.erase(0, 1);
          }
          const std::string image = OptStr(c, "Image", "");
          const std::string status = OptStr(c, "Status", "");
          if (!name_filter.empty() && !ContainsInsensitive(cname, name_filter) &&
              !ContainsInsensitive(image, name_filter)) {
            continue;
          }

          // Collect distinct TCP container ports (falling back to user ports only if none declared).
          std::map<int, int> tcp_ports;  // private_port -> public_port
          if (const Value* ports = c.find("Ports"); ports && ports->is_array()) {
            for (const auto& p : ports->elements()) {
              if (!p.is_object()) continue;
              if (LowerCopy(OptStr(p, "Type", "tcp")) != "tcp") continue;
              const int priv = static_cast<int>(OptInt(p, "PrivatePort", 0));
              const int pub = static_cast<int>(OptInt(p, "PublicPort", 0));
              if (priv > 0 && tcp_ports.find(priv) == tcp_ports.end()) {
                tcp_ports[priv] = pub;
              }
            }
          }

          const Value* net_settings = c.find("NetworkSettings");
          const Value* nets = net_settings ? net_settings->find("Networks") : nullptr;
          if (!nets || !nets->is_object()) continue;

          bool container_counted = false;
          for (const auto& nkv : nets->members()) {
            if (!network_filter.empty() && !ContainsInsensitive(nkv.first, network_filter)) {
              continue;
            }
            if (!nkv.second.is_object()) continue;
            const std::string ip = OptStr(nkv.second, "IPAddress", "");
            if (ip.empty()) continue;
            if (!ValidateMcpTarget(ip, eff_safety).ok) {
              ++blocked_ips;
              continue;
            }
            if (!container_counted) {
              ++matched_containers;
              container_counted = true;
            }
            for (const auto& port_kv : tcp_ports) {
              if (seen_ip_port.insert({ip, port_kv.first}).second) {
                TargetEndpoint ep;
                ep.ip = ip;
                ep.port = port_kv.first;
                ep.host_port = port_kv.second;
                ep.source = "docker";
                ep.container_name = cname;
                ep.image = image;
                ep.network_name = nkv.first;
                ep.container_status = status;
                targets_to_probe.push_back(std::move(ep));
              }
            }
          }
        }
        docker_info.set("matched_containers", Value::Int(matched_containers));
        docker_info.set("safety_skipped_ips", Value::Int(blocked_ips));
      }
    }
  }

  Value results = Value::Array();
  std::int64_t open_count = 0;
  std::int64_t http_service_count = 0;
  for (const auto& ep : targets_to_probe) {
    ProbeOptions eff_opts = opts;
    if (eff_opts.host_header.empty()) {
      auto hit = resolved_hostname_by_ip.find(ep.ip);
      if (hit != resolved_hostname_by_ip.end()) {
        eff_opts.host_header = hit->second;
      }
    }
    Value probed = ProbeTargetEndpoint(ep, eff_opts);
    if (OptBool(probed, "tcp_open", false)) ++open_count;
    if (OptBool(probed, "http_probed", false)) ++http_service_count;
    results.push_back(std::move(probed));
  }

  Value out = Value::Object();
  out.set("host", HostMetadataJson());
  out.set("docker_discovery", std::move(docker_info));
  out.set("endpoints_checked", Value::Int(static_cast<std::int64_t>(targets_to_probe.size())));
  out.set("tcp_open_count", Value::Int(open_count));
  out.set("http_services_count", Value::Int(http_service_count));
  out.set("services", std::move(results));
  return MakeToolSuccess(std::move(out));
}

}  // namespace samurai::mcp
