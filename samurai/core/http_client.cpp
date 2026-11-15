#include "http_client.hpp"

#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cctype>
#include <cstddef>
#include <sstream>

#include <openssl/ssl.h>
#include <openssl/x509.h>

namespace samurai::core::http {

namespace {

struct Url {
  bool https = false;
  std::string host;
  std::string port;
  std::string path;  // path + query, e.g. "/api/v1/query?query=up"
};

// Split "http(s)://host[:port]/path?query" into parts. The path (with query) is
// everything from the first '/' after the authority; defaults to "/".
bool ParseUrl(const std::string& url, Url& out) {
  const auto scheme_end = url.find("://");
  if (scheme_end == std::string::npos) return false;
  const std::string scheme = url.substr(0, scheme_end);
  if (scheme != "http" && scheme != "https") return false;
  out.https = (scheme == "https");
  const std::string rest = url.substr(scheme_end + 3);
  std::string authority = rest;
  std::string path = "/";
  const auto slash = rest.find('/');
  if (slash != std::string::npos) {
    authority = rest.substr(0, slash);
    path = rest.substr(slash);
  }
  std::string host = authority;
  std::string port = out.https ? "443" : "80";
  if (!authority.empty() && authority.front() == '[') {  // [ipv6]:port
    const auto rb = authority.find(']');
    if (rb == std::string::npos) return false;
    host = authority.substr(1, rb - 1);
    if (rb + 1 < authority.size() && authority[rb + 1] == ':') port = authority.substr(rb + 2);
  } else {
    const auto colon = authority.rfind(':');
    if (colon != std::string::npos) {
      host = authority.substr(0, colon);
      port = authority.substr(colon + 1);
    }
  }
  if (host.empty()) return false;
  out.host = host;
  out.port = port;
  out.path = path;
  return true;
}

int ConnectTcp(const std::string& host, const std::string& port, int timeout_s) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* res = nullptr;
  if (::getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0) return -1;
  int fd = -1;
  for (addrinfo* p = res; p; p = p->ai_next) {
    fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (fd < 0) continue;
    timeval tv{timeout_s, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (::connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
    ::close(fd);
    fd = -1;
  }
  ::freeaddrinfo(res);
  return fd;
}

std::string BuildRequest(const Url& u, const HttpOptions& opts) {
  std::ostringstream os;
  os << opts.method << " " << u.path << " HTTP/1.1\r\n"
     << "Host: " << u.host << "\r\n"
     << "Accept: " << (opts.accept.empty() ? "*/*" : opts.accept) << "\r\n";
  if (!opts.bearer.empty()) os << "Authorization: Bearer " << opts.bearer << "\r\n";
  if (!opts.body.empty() || opts.method == "PATCH" || opts.method == "POST" ||
      opts.method == "PUT") {
    os << "Content-Type: " << opts.content_type << "\r\n"
       << "Content-Length: " << opts.body.size() << "\r\n";
  }
  os << "Connection: close\r\n\r\n";
  if (!opts.body.empty()) os << opts.body;
  return os.str();
}

std::string HeaderValue(const std::string& headers, const std::string& name) {
  std::string lh = headers, ln = name;
  for (char& c : lh) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  for (char& c : ln) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  auto pos = lh.find("\r\n" + ln + ":");
  if (pos == std::string::npos) return "";
  pos += 2 + ln.size() + 1;
  auto end = lh.find("\r\n", pos);
  std::string v = headers.substr(pos, (end == std::string::npos ? headers.size() : end) - pos);
  const auto a = v.find_first_not_of(" \t");
  const auto b = v.find_last_not_of(" \t");
  return a == std::string::npos ? "" : v.substr(a, b - a + 1);
}

bool ResponseComplete(const std::string& raw) {
  const auto hdr_end = raw.find("\r\n\r\n");
  if (hdr_end == std::string::npos) return false;
  const std::string headers = raw.substr(0, hdr_end);
  const std::size_t body_len = raw.size() - (hdr_end + 4);
  const std::string te = HeaderValue(headers, "Transfer-Encoding");
  if (!te.empty() && te.find("chunked") != std::string::npos) {
    return raw.size() >= hdr_end + 4 + 5 && raw.compare(raw.size() - 5, 5, "0\r\n\r\n") == 0;
  }
  const std::string cl = HeaderValue(headers, "Content-Length");
  if (!cl.empty()) {
    try {
      return body_len >= static_cast<std::size_t>(std::stoul(cl));
    } catch (...) {
      return false;
    }
  }
  return true;
}

// De-chunk a Transfer-Encoding: chunked body; returns the body verbatim when it
// is not chunked.
std::string MaybeDechunk(const std::string& headers, const std::string& body) {
  const std::string te = HeaderValue(headers, "Transfer-Encoding");
  if (te.empty() || te.find("chunked") == std::string::npos) return body;
  std::string out;
  std::size_t pos = 0;
  while (pos < body.size()) {
    const auto crlf = body.find("\r\n", pos);
    if (crlf == std::string::npos) break;
    std::size_t chunk_len = 0;
    try {
      chunk_len = static_cast<std::size_t>(std::stoul(body.substr(pos, crlf - pos), nullptr, 16));
    } catch (...) {
      break;
    }
    if (chunk_len == 0) break;  // last chunk
    const std::size_t data = crlf + 2;
    if (data + chunk_len > body.size()) break;
    out.append(body, data, chunk_len);
    pos = data + chunk_len + 2;  // skip data + trailing CRLF
  }
  return out;
}

HttpResponse ParseResponse(const std::string& raw) {
  HttpResponse r;
  if (raw.empty()) {
    r.error = "empty response";
    return r;
  }
  const auto line_end = raw.find("\r\n");
  const std::string status_line = raw.substr(0, line_end);
  const auto sp1 = status_line.find(' ');
  if (sp1 != std::string::npos) {
    try {
      r.status = std::stoi(status_line.substr(sp1 + 1, 4));
    } catch (...) {
      r.status = 0;
    }
  }
  const auto hdr_end = raw.find("\r\n\r\n");
  const std::string headers = hdr_end == std::string::npos ? "" : raw.substr(0, hdr_end);
  const std::string body = hdr_end == std::string::npos ? "" : raw.substr(hdr_end + 4);
  r.body = MaybeDechunk(headers, body);
  r.ok = r.status > 0;
  if (!r.ok) r.error = "malformed response";
  return r;
}

}  // namespace

std::string JoinUrl(const std::string& base, const std::string& path) {
  const auto scheme_end = base.find("://");
  if (scheme_end == std::string::npos) return base + path;
  const std::string scheme = base.substr(0, scheme_end);
  std::string rest = base.substr(scheme_end + 3);
  const auto slash = rest.find('/');
  const std::string authority = slash == std::string::npos ? rest : rest.substr(0, slash);
  return scheme + "://" + authority + path;
}

HttpResponse Request(const std::string& url, const HttpOptions& opts) {
  HttpResponse r;
  Url u;
  if (!ParseUrl(url, u)) {
    r.error = "invalid url: " + url;
    return r;
  }
  const int fd = ConnectTcp(u.host, u.port, opts.timeout_s);
  if (fd < 0) {
    r.error = "connect failed: " + u.host + ":" + u.port;
    return r;
  }
  const std::string request = BuildRequest(u, opts);
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
    if (!opts.insecure) {
      if (!opts.ca_file.empty()) {
        SSL_CTX_load_verify_locations(ctx, opts.ca_file.c_str(), nullptr);
      } else {
        SSL_CTX_set_default_verify_paths(ctx);
      }
      SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    }
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
    if (!opts.insecure && SSL_get_verify_result(ssl) != X509_V_OK) {
      SSL_shutdown(ssl);
      SSL_free(ssl);
      SSL_CTX_free(ctx);
      ::close(fd);
      r.error = "tls certificate verification failed";
      return r;
    }
    SSL_write(ssl, request.data(), static_cast<int>(request.size()));
    char buf[4096];
    int n;
    while ((n = SSL_read(ssl, buf, sizeof(buf))) > 0) {
      raw.append(buf, static_cast<std::size_t>(n));
      if (ResponseComplete(raw)) break;
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
  } else {
    ::send(fd, request.data(), request.size(), 0);
    char buf[4096];
    ssize_t n;
    while ((n = ::recv(fd, buf, sizeof(buf), 0)) > 0) {
      raw.append(buf, static_cast<std::size_t>(n));
      if (ResponseComplete(raw)) break;
    }
  }
  ::close(fd);
  if (raw.empty()) {
    r.error = "no response / timeout";
    return r;
  }
  return ParseResponse(raw);
}

bool ResponseCompleteForTest(const std::string& raw) { return ResponseComplete(raw); }

}  // namespace samurai::core::http
