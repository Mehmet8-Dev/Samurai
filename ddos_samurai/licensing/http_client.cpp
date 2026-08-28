#include "http_client.hpp"

#include <cstring>
#include <sstream>
#include <string>

#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

namespace samurai::licensing {

namespace {

struct Url {
  bool https = false;
  std::string host;
  std::string port;
  std::string path;
};

bool ParseUrl(const std::string& url, Url& out) {
  const auto scheme_end = url.find("://");
  if (scheme_end == std::string::npos) return false;
  const std::string scheme = url.substr(0, scheme_end);
  out.https = (scheme == "https");
  if (scheme != "http" && scheme != "https") return false;
  std::string rest = url.substr(scheme_end + 3);
  const auto slash = rest.find('/');
  std::string host_port = slash == std::string::npos ? rest : rest.substr(0, slash);
  out.path = slash == std::string::npos ? "/" : rest.substr(slash);
  const auto colon = host_port.find(':');
  if (colon == std::string::npos) {
    out.host = host_port;
    out.port = out.https ? "443" : "80";
  } else {
    out.host = host_port.substr(0, colon);
    out.port = host_port.substr(colon + 1);
  }
  return !out.host.empty();
}

int ConnectTcp(const std::string& host, const std::string& port, int timeout_s) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* res = nullptr;
  if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0 || !res) return -1;
  int fd = -1;
  for (addrinfo* p = res; p; p = p->ai_next) {
    fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (fd < 0) continue;
    timeval tv{timeout_s > 0 ? timeout_s : 10, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (::connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
    ::close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  return fd;
}

std::string BuildRequest(const Url& u, const std::string& body, const std::string& bearer) {
  std::ostringstream os;
  os << "POST " << u.path << " HTTP/1.1\r\n"
     << "Host: " << u.host << "\r\n"
     << "Content-Type: application/json\r\n"
     << "Accept: application/json\r\n";
  if (!bearer.empty()) os << "Authorization: Bearer " << bearer << "\r\n";
  os << "Content-Length: " << body.size() << "\r\n"
     << "Connection: close\r\n\r\n"
     << body;
  return os.str();
}

// Parse an HTTP response: status code + body (after CRLFCRLF).
HttpResponse ParseResponse(const std::string& raw) {
  HttpResponse r;
  if (raw.empty()) {
    r.error = "empty response";
    return r;
  }
  const auto line_end = raw.find("\r\n");
  const std::string status_line = raw.substr(0, line_end);
  // "HTTP/1.1 200 OK"
  const auto sp1 = status_line.find(' ');
  if (sp1 != std::string::npos) {
    try {
      r.status = std::stoi(status_line.substr(sp1 + 1, 4));
    } catch (...) {
      r.status = 0;
    }
  }
  const auto hdr_end = raw.find("\r\n\r\n");
  r.body = hdr_end == std::string::npos ? "" : raw.substr(hdr_end + 4);
  r.ok = r.status > 0;
  if (!r.ok) r.error = "malformed response";
  return r;
}

}  // namespace

HttpResponse HttpPostJson(const std::string& url, const std::string& json_body, int timeout_s,
                          const std::string& bearer_token) {
  HttpResponse r;
  Url u;
  if (!ParseUrl(url, u)) {
    r.error = "invalid url: " + url;
    return r;
  }
  const int fd = ConnectTcp(u.host, u.port, timeout_s);
  if (fd < 0) {
    r.error = "connect failed: " + u.host + ":" + u.port;
    return r;
  }
  const std::string request = BuildRequest(u, json_body, bearer_token);
  std::string raw;

  if (u.https) {
    static bool ssl_inited = [] {
      SSL_library_init();
      SSL_load_error_strings();
      return true;
    }();
    (void)ssl_inited;
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
      ::close(fd);
      r.error = "ssl ctx failed";
      return r;
    }
    SSL_CTX_set_default_verify_paths(ctx);
    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
      SSL_CTX_free(ctx);
      ::close(fd);
      r.error = "ssl new failed";
      return r;
    }
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, u.host.c_str());  // SNI
    if (SSL_connect(ssl) != 1) {
      SSL_free(ssl);
      SSL_CTX_free(ctx);
      ::close(fd);
      r.error = "tls handshake failed";
      return r;
    }
    SSL_write(ssl, request.data(), static_cast<int>(request.size()));
    char buf[4096];
    int n;
    while ((n = SSL_read(ssl, buf, sizeof(buf))) > 0) raw.append(buf, static_cast<std::size_t>(n));
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
  } else {
    ::send(fd, request.data(), request.size(), 0);
    char buf[4096];
    ssize_t n;
    while ((n = ::recv(fd, buf, sizeof(buf), 0)) > 0) raw.append(buf, static_cast<std::size_t>(n));
  }
  ::close(fd);

  if (raw.empty()) {
    r.error = "no response / timeout";
    return r;
  }
  return ParseResponse(raw);
}

}  // namespace samurai::licensing
