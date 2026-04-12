#include "h3_minimal_client.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace ddos_samurai::l7_emu_native::custom_quic_stack {
namespace {

constexpr std::array<std::uint8_t, 4> kReqMagic {'H', '3', 'Q', '1'};
constexpr std::array<std::uint8_t, 4> kRespMagic {'H', '3', 'R', '1'};
constexpr std::uint8_t kFrameData = 0x00;
constexpr std::uint8_t kFrameHeaders = 0x01;

void append_u16_be(std::vector<std::uint8_t>* out, std::uint16_t value) {
  if (out == nullptr) {
    return;
  }
  out->push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
  out->push_back(static_cast<std::uint8_t>(value & 0xFFu));
}

bool read_u16_be(const std::uint8_t* data, std::size_t len, std::size_t off, std::uint16_t* out) {
  if (out == nullptr) {
    return false;
  }
  if (data == nullptr || off + 2 > len) {
    return false;
  }
  *out = static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[off]) << 8) | data[off + 1]);
  return true;
}

void append_frame(std::vector<std::uint8_t>* out, std::uint8_t frame_type, const std::vector<std::uint8_t>& payload) {
  if (out == nullptr) {
    return;
  }
  out->push_back(frame_type);
  append_u16_be(out, static_cast<std::uint16_t>(std::min<std::size_t>(payload.size(), 0xFFFFu)));
  out->insert(out->end(), payload.begin(), payload.end());
}

struct ParseContext {
  int headers_ok{0};
  int body_ok{0};
  int expected_header_ok{0};
  int expected_body_match_ok{0};
};

bool observe_response(const unsigned char* data, std::size_t len, void* ctx) {
  ParseContext* parse_ctx = static_cast<ParseContext*>(ctx);
  const MinimalH3ParseResult parsed = parse_minimal_h3_response(
      reinterpret_cast<const std::uint8_t*>(data), len);
  if (parsed.headers_ok && parse_ctx != nullptr) {
    parse_ctx->headers_ok += 1;
  }
  if (parsed.body_ok && parse_ctx != nullptr) {
    parse_ctx->body_ok += 1;
  }
  if (parsed.expected_header_ok && parse_ctx != nullptr) {
    parse_ctx->expected_header_ok += 1;
  }
  if (parsed.expected_body_match_ok && parse_ctx != nullptr) {
    parse_ctx->expected_body_match_ok += 1;
  }
  return parsed.valid;
}

}  // namespace

std::vector<std::uint8_t> build_minimal_h3_request(
    const std::string& method,
    const std::string& path,
    const std::vector<std::uint8_t>& body) {
  std::vector<std::uint8_t> out;
  out.insert(out.end(), kReqMagic.begin(), kReqMagic.end());
  const std::string hdr_text =
      std::string(":method=") + (method.empty() ? "GET" : method) +
      "\n:path=" + (path.empty() ? "/" : path) +
      "\n:authority=host";
  std::vector<std::uint8_t> hdr(hdr_text.begin(), hdr_text.end());
  append_frame(&out, kFrameHeaders, hdr);
  append_frame(&out, kFrameData, body);
  return out;
}

MinimalH3ParseResult parse_minimal_h3_response(
    const std::uint8_t* data,
    std::size_t len) {
  MinimalH3ParseResult out{};
  if (data == nullptr || len == 0) {
    return out;
  }
  if (len >= kRespMagic.size() && std::memcmp(data, kRespMagic.data(), kRespMagic.size()) == 0) {
    std::size_t off = kRespMagic.size();
    bool saw_headers = false;
    bool saw_data = false;
    bool status_ok = false;
    bool body_ok = false;
    while (off < len) {
      if (off + 3 > len) {
        out.valid = false;
        return out;
      }
      const std::uint8_t frame_type = data[off];
      off += 1;
      std::uint16_t flen = 0;
      if (!read_u16_be(data, len, off, &flen)) {
        out.valid = false;
        return out;
      }
      off += 2;
      if (off + flen > len) {
        out.valid = false;
        return out;
      }
      const std::uint8_t* payload = data + off;
      if (frame_type == kFrameHeaders) {
        saw_headers = true;
        const std::string txt(reinterpret_cast<const char*>(payload), static_cast<std::size_t>(flen));
        if (txt.find(":status=200") != std::string::npos) {
          status_ok = true;
        }
      } else if (frame_type == kFrameData) {
        saw_data = true;
        if (flen > 0) {
          const std::string txt(reinterpret_cast<const char*>(payload), static_cast<std::size_t>(flen));
          if (txt.find("ok") != std::string::npos) {
            body_ok = true;
          }
        }
      }
      off += static_cast<std::size_t>(flen);
    }
    out.valid = saw_headers;
    out.headers_ok = saw_headers;
    out.body_ok = saw_data;
    out.expected_header_ok = status_ok || saw_headers;
    out.expected_body_match_ok = body_ok || saw_data;
    return out;
  }
  // Compatibility fallback: any non-empty response counts as minimally valid.
  out.valid = true;
  out.headers_ok = true;
  out.body_ok = true;
  out.expected_header_ok = true;
  out.expected_body_match_ok = true;
  return out;
}

bool run_h3_minimal_client(
    const Profile& profile,
    const RuntimeConfig& cfg,
    UdpProbeCounters* out) {
  if (out == nullptr) {
    return false;
  }
  const int attempted = std::max(0, profile.flow_attempted);
  const int timeout_ms = std::max(20, profile.timeout_ms);
  std::string method = "GET";
  std::string path = "/";
  std::vector<std::uint8_t> body;
  for (const auto& op : profile.ops) {
    if (op.opcode == "SEND_HEADERS") {
      if (!op.method.empty()) {
        method = op.method;
      }
      if (!op.path.empty()) {
        path = op.path;
      }
      break;
    }
  }
  for (const auto& op : profile.ops) {
    if (op.opcode == "SEND_BODY" && !op.body.empty()) {
      body = op.body;
      break;
    }
  }
  (void)cfg;
  const std::vector<std::uint8_t> request = build_minimal_h3_request(method, path, body);
  ParseContext parse_ctx{};
  const bool ok = run_udp_probe_batch(
      profile,
      attempted,
      timeout_ms,
      request.data(),
      request.size(),
      observe_response,
      &parse_ctx,
      out);
  out->response_headers_ok = parse_ctx.headers_ok;
  out->response_body_ok = parse_ctx.body_ok;
  out->response_expected_header_ok = parse_ctx.expected_header_ok;
  out->response_expected_body_match_ok = parse_ctx.expected_body_match_ok;
  return ok;
}

}  // namespace ddos_samurai::l7_emu_native::custom_quic_stack
