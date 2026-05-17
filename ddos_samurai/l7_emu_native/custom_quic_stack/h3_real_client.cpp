#include "h3_real_client.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace ddos_samurai::l7_emu_native::custom_quic_stack {
namespace {

struct RequestSpec {
  std::string method{"GET"};
  std::string path{"/"};
  std::vector<unsigned char> body{};
};

struct Expectations {
  int status_min{100};
  int status_max{599};
  bool has_header_expect{false};
  std::string header_name{};
  std::string header_value_contains{};
  bool has_body_expect{false};
  std::string body_substring{};
};

std::string shell_quote(const std::string& src) {
  std::string out;
  out.reserve(src.size() + 2);
  out.push_back('\'');
  for (char ch : src) {
    if (ch == '\'') {
      out += "'\"'\"'";
    } else {
      out.push_back(ch);
    }
  }
  out.push_back('\'');
  return out;
}

bool read_text_file(const std::string& path, std::string* out) {
  if (out == nullptr) {
    return false;
  }
  std::ifstream in(path, std::ios::in | std::ios::binary);
  if (!in.is_open()) {
    return false;
  }
  std::string data(
      (std::istreambuf_iterator<char>(in)),
      std::istreambuf_iterator<char>());
  *out = std::move(data);
  return true;
}

std::size_t file_size_bytes(const std::string& path) {
  struct stat st {};
  if (::stat(path.c_str(), &st) != 0 || st.st_size <= 0) {
    return 0;
  }
  return static_cast<std::size_t>(st.st_size);
}

std::string make_temp_path(const char* prefix) {
  if (prefix == nullptr || *prefix == '\0') {
    return {};
  }
  std::array<char, 128> tpl{};
  std::snprintf(tpl.data(), tpl.size(), "/tmp/%s-XXXXXX", prefix);
  const int fd = ::mkstemp(tpl.data());
  if (fd < 0) {
    return {};
  }
  (void)::close(fd);
  return std::string(tpl.data());
}

void remove_if_exists(const std::string& path) {
  if (!path.empty()) {
    (void)::unlink(path.c_str());
  }
}

RequestSpec derive_request_spec(const Profile& profile) {
  RequestSpec out;
  for (const auto& op : profile.ops) {
    if (op.opcode == "SEND_HEADERS") {
      if (!op.method.empty()) {
        out.method = op.method;
      }
      if (!op.path.empty()) {
        out.path = op.path;
      }
      break;
    }
  }
  for (const auto& op : profile.ops) {
    if (op.opcode == "SEND_BODY" && !op.body.empty()) {
      out.body = op.body;
      break;
    }
  }
  if (out.path.empty()) {
    out.path = "/";
  }
  if (out.path.front() != '/') {
    out.path.insert(out.path.begin(), '/');
  }
  return out;
}

Expectations derive_expectations(const Profile& profile) {
  Expectations exp{};
  for (const auto& op : profile.ops) {
    if (op.opcode == "EXPECT_STATUS" && op.has_expect) {
      exp.status_min = std::max(100, op.expect.status_min);
      exp.status_max = std::max(exp.status_min, std::min(599, op.expect.status_max));
      continue;
    }
    if (op.opcode == "EXPECT_HEADER" && op.has_expect) {
      exp.has_header_expect = true;
      exp.header_name = op.expect.name;
      exp.header_value_contains = op.expect.value;
      continue;
    }
    if (op.opcode == "EXPECT_BODY_SUBSTRING" && op.has_expect) {
      exp.has_body_expect = true;
      exp.body_substring = op.expect.value;
      continue;
    }
  }
  return exp;
}

bool has_command(const char* cmd) {
  if (cmd == nullptr || *cmd == '\0') {
    return false;
  }
  std::string check = std::string("command -v ") + cmd + " >/dev/null 2>&1";
  const int rc = std::system(check.c_str());
  return rc == 0;
}

int parse_status_code(const std::string& text) {
  int code = 0;
  for (char ch : text) {
    if (ch >= '0' && ch <= '9') {
      code = code * 10 + static_cast<int>(ch - '0');
      if (code > 9999) {
        break;
      }
    } else if (code > 0) {
      break;
    }
  }
  return code;
}

bool header_expect_ok(
    const std::string& headers,
    const std::string& name,
    const std::string& value_contains) {
  if (name.empty()) {
    return true;
  }
  std::string key = name;
  std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  std::string lines = headers;
  std::transform(lines.begin(), lines.end(), lines.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  const std::string needle = key + ":";
  std::size_t pos = lines.find(needle);
  if (pos == std::string::npos) {
    return false;
  }
  if (value_contains.empty()) {
    return true;
  }
  std::string v = value_contains;
  std::transform(v.begin(), v.end(), v.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  const std::size_t line_end = lines.find('\n', pos);
  const std::string segment = line_end == std::string::npos ? lines.substr(pos) : lines.substr(pos, line_end - pos);
  return segment.find(v) != std::string::npos;
}

bool body_expect_ok(const std::string& body, const std::string& substr) {
  if (substr.empty()) {
    return true;
  }
  return body.find(substr) != std::string::npos;
}

struct CurlRunResult {
  int exit_code{127};
  int http_status{0};
  bool timeout{false};
  std::size_t tx_bytes{0};
  std::size_t rx_bytes{0};
  bool headers_ok{false};
  bool body_ok{false};
  bool expected_header_ok{false};
  bool expected_body_ok{false};
  bool response_valid{false};
};

CurlRunResult run_curl_http3_once(
    const Profile& profile,
    const RequestSpec& req,
    const Expectations& exp) {
  CurlRunResult out{};
  const std::string body_path = make_temp_path("samurai-quic-body");
  const std::string hdr_path = make_temp_path("samurai-quic-hdr");
  const std::string status_path = make_temp_path("samurai-quic-status");
  const std::string req_body_path = make_temp_path("samurai-quic-req");
  if (body_path.empty() || hdr_path.empty() || status_path.empty() || req_body_path.empty()) {
    return out;
  }

  if (!req.body.empty()) {
    std::ofstream out_body(req_body_path, std::ios::out | std::ios::binary | std::ios::trunc);
    if (out_body.is_open()) {
      out_body.write(reinterpret_cast<const char*>(req.body.data()), static_cast<std::streamsize>(req.body.size()));
    }
    out.tx_bytes = req.body.size();
  }

  const std::string scheme = "https://";
  const std::string url =
      scheme + profile.target_ip + ":" + std::to_string(std::max(1, profile.target_port)) + req.path;
  const int timeout_sec = std::max(1, profile.timeout_ms / 1000);

  std::string cmd = "curl --http3-only --silent --show-error";
  if (profile.verify == 0) {
    cmd += " --insecure";
  }
  cmd += " --max-time " + std::to_string(timeout_sec);
  cmd += " --request " + shell_quote(req.method.empty() ? "GET" : req.method);
  cmd += " --url " + shell_quote(url);
  cmd += " --output " + shell_quote(body_path);
  cmd += " --dump-header " + shell_quote(hdr_path);
  cmd += " --write-out " + shell_quote("%{http_code}\\n");
  if (!req.body.empty()) {
    cmd += " --data-binary @" + shell_quote(req_body_path);
  }
  cmd += " >" + shell_quote(status_path) + " 2>/dev/null";

  const int rc = std::system(cmd.c_str());
  if (WIFEXITED(rc)) {
    out.exit_code = WEXITSTATUS(rc);
  } else {
    out.exit_code = 127;
  }

  std::string status_text;
  std::string hdr_text;
  std::string body_text;
  (void)read_text_file(status_path, &status_text);
  (void)read_text_file(hdr_path, &hdr_text);
  (void)read_text_file(body_path, &body_text);
  out.http_status = parse_status_code(status_text);

  out.rx_bytes = file_size_bytes(body_path) + file_size_bytes(hdr_path);
  if (out.http_status >= 100 && out.http_status <= 599) {
    out.headers_ok = true;
  }
  out.body_ok = !body_text.empty();
  out.expected_header_ok = !exp.has_header_expect || header_expect_ok(hdr_text, exp.header_name, exp.header_value_contains);
  out.expected_body_ok = !exp.has_body_expect || body_expect_ok(body_text, exp.body_substring);
  out.response_valid =
      out.http_status >= exp.status_min &&
      out.http_status <= exp.status_max &&
      out.expected_header_ok &&
      out.expected_body_ok;

  // curl exit code 28 is timeout, keep this explicit for metrics.
  if (out.exit_code == 28) {
    out.timeout = true;
  }

  remove_if_exists(req_body_path);
  remove_if_exists(status_path);
  remove_if_exists(hdr_path);
  remove_if_exists(body_path);
  return out;
}

}  // namespace

bool run_h3_real_client(
    const Profile& profile,
    const RuntimeConfig& cfg,
    UdpProbeCounters* out) {
  if (out == nullptr) {
    return false;
  }
  *out = UdpProbeCounters{};
  (void)cfg;
  const int attempted = std::max(0, profile.flow_attempted);
  if (attempted <= 0) {
    return true;
  }
  if (!has_command("curl")) {
    out->errors = attempted;
    out->connect_fail = attempted;
    out->handshake_fail = attempted;
    out->timeouts = attempted;
    out->conn_attempted = attempted;
    out->response_validation_fail = attempted;
    return false;
  }

  const RequestSpec req = derive_request_spec(profile);
  const Expectations exp = derive_expectations(profile);
  for (int i = 0; i < attempted; ++i) {
    out->conn_attempted += 1;
    const CurlRunResult res = run_curl_http3_once(profile, req, exp);
    out->tx_bytes += res.tx_bytes;
    out->rx_bytes += res.rx_bytes;

    if (res.exit_code == 0) {
      out->conn_established += 1;
      out->responses += 1;
      if (res.headers_ok) {
        out->response_headers_ok += 1;
      }
      if (res.body_ok) {
        out->response_body_ok += 1;
      }
      if (res.expected_header_ok) {
        out->response_expected_header_ok += 1;
      }
      if (res.expected_body_ok) {
        out->response_expected_body_match_ok += 1;
      }
      if (!res.response_valid) {
        out->response_validation_fail += 1;
        out->errors += 1;
      } else {
        out->send_ok += 1;
      }
      continue;
    }

    out->errors += 1;
    out->response_validation_fail += 1;
    if (res.timeout) {
      out->timeouts += 1;
    }
    if (res.exit_code == 7) {
      out->connect_fail += 1;
    } else {
      out->handshake_fail += 1;
    }
  }

  out->errors = std::max(out->errors, attempted - out->send_ok);
  return true;
}

}  // namespace ddos_samurai::l7_emu_native::custom_quic_stack
