#include "engine_internal.hpp"
#include "dns_client_engine.hpp"
#include "l2l3_stack/dhcp_state_machine.hpp"
#include "l2l3_stack/igmp_engine.hpp"
#include "l2l3_stack/nd_engine.hpp"
#include "l2l3_stack/arp_engine.hpp"

namespace samurai::l7_emu_native {

const std::string* find_scenario_header(
    const std::map<std::string, std::string>& headers,
    const char* needle) {
  if (needle == nullptr) {
    return nullptr;
  }
  auto to_lower_ascii = [](std::string s) {
    for (char& c : s) {
      if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
  };
  const std::string wanted = to_lower_ascii(std::string(needle));
  for (const auto& [k, v] : headers) {
    if (to_lower_ascii(k) == wanted) {
      return &v;
    }
  }
  return nullptr;
}

const std::string* find_header_value(
    const std::vector<std::pair<std::string, std::string>>& headers,
    const std::string& key) {
  for (const auto& [header_key, header_value] : headers) {
    if (header_key == key) {
      return &header_value;
    }
  }
  return nullptr;
}

CompiledCaptureTemplate compile_capture_template(const std::string& input) {
  CompiledCaptureTemplate compiled;
  std::size_t pos = 0;
  while (pos < input.size()) {
    const std::size_t start = input.find("{{", pos);
    if (start == std::string::npos) {
      if (pos < input.size()) {
        CompiledCaptureChunk chunk;
        chunk.value = input.substr(pos);
        compiled.static_bytes += chunk.value.size();
        compiled.chunks.push_back(std::move(chunk));
      }
      break;
    }
    if (start > pos) {
      CompiledCaptureChunk literal;
      literal.value = input.substr(pos, start - pos);
      compiled.static_bytes += literal.value.size();
      compiled.chunks.push_back(std::move(literal));
    }
    const std::size_t end = input.find("}}", start + 2);
    if (end == std::string::npos) {
      CompiledCaptureChunk literal;
      literal.value = input.substr(start);
      compiled.static_bytes += literal.value.size();
      compiled.chunks.push_back(std::move(literal));
      break;
    }
    std::string token = input.substr(start + 2, end - (start + 2));
    const std::string capture_prefix = "capture:";
    const std::string header_prefix = "header:";
    const std::string cookie_prefix = "cookie:";
    if (token.rfind(capture_prefix, 0) == 0) {
      token.erase(0, capture_prefix.size());
    } else if (token.rfind(header_prefix, 0) == 0) {
      token.erase(0, header_prefix.size());
    } else if (token.rfind(cookie_prefix, 0) == 0) {
      token.erase(0, cookie_prefix.size());
    }
    CompiledCaptureChunk capture;
    capture.is_capture = true;
    capture.value = std::move(token);
    compiled.has_captures = true;
    compiled.chunks.push_back(std::move(capture));
    pos = end + 2;
  }
  return compiled;
}

void render_capture_template_into(
    const CompiledCaptureTemplate& compiled,
    const std::map<std::string, std::string>& captures,
    std::string& out) {
  if (!compiled.has_captures) {
    out.clear();
    ensure_reusable_string_capacity(out, compiled.static_bytes);
    for (const auto& chunk : compiled.chunks) {
      out.append(chunk.value);
    }
    return;
  }
  std::size_t reserve_bytes = compiled.static_bytes;
  for (const auto& chunk : compiled.chunks) {
    if (!chunk.is_capture) {
      continue;
    }
    const auto it = captures.find(chunk.value);
    if (it != captures.end()) {
      reserve_bytes += it->second.size();
    }
  }
  out.clear();
  ensure_reusable_string_capacity(out, reserve_bytes);
  for (const auto& chunk : compiled.chunks) {
    if (!chunk.is_capture) {
      out.append(chunk.value);
      continue;
    }
    const auto it = captures.find(chunk.value);
    if (it != captures.end()) {
      out.append(it->second);
    }
  }
}

void build_http1_request_into(
    std::string& out,
    LaneStringArena& arena,
    const Profile& profile,
    const H1RequestSpec& request,
    const std::map<std::string, std::string>& captures) {
  out.clear();
  auto method_lease = arena_acquire_string(arena, std::max<std::size_t>(request.method_template.static_bytes, 16));
  auto path_lease = arena_acquire_string(arena, std::max<std::size_t>(request.path_template.static_bytes, 64));
  std::string& method = arena_string_or_throw(method_lease, "http1 method");
  std::string& path = arena_string_or_throw(path_lease, "http1 path");
  render_capture_template_into(request.method_template, captures, method);
  render_capture_template_into(request.path_template, captures, path);
  std::size_t reserve_bytes = method.size() + path.size() + 64 +
      (profile.host_header.empty() ? profile.target_ip.size() : profile.host_header.size());
  for (const auto& [key, compiled_value] : request.compiled_header_values) {
    reserve_bytes += key.size() + compiled_value.static_bytes + 4;
  }
  if (request.body_template.has_value()) {
    reserve_bytes += request.body_template->static_bytes + 32;
  }
  ensure_reusable_string_capacity(out, std::max<std::size_t>(reserve_bytes, kH1SlabWriteBytes));
  out.append(method);
  out.append(" ");
  out.append(path);
  out.append(" HTTP/1.1\r\n");
  out.append("Host: ");
  out.append(profile.host_header.empty() ? profile.target_ip : profile.host_header);
  out.append("\r\nConnection: ");
  out.append(profile.keepalive ? "keep-alive" : "close");
  out.append("\r\n");
  bool has_content_length = false;
  for (const auto& [key, compiled_value] : request.compiled_header_values) {
    if (key == "Content-Length" || key == "content-length") {
      has_content_length = true;
    }
    out.append(key);
    out.append(": ");
    auto value_lease = arena_acquire_string(
        arena,
        std::max<std::size_t>(compiled_value.static_bytes, kArenaBucketSmallBytes));
    std::string& header_value = arena_string_or_throw(value_lease, "http1 header value");
    render_capture_template_into(compiled_value, captures, header_value);
    out.append(header_value);
    out.append("\r\n");
  }
  auto body_lease = request.body_template.has_value()
      ? arena_acquire_string(
            arena,
            std::max<std::size_t>(request.body_template->static_bytes, kArenaBucketBodyBytes))
      : ArenaStringLease{};
  if (request.body_template.has_value()) {
    std::string& body = arena_string_or_throw(body_lease, "http1 body");
    render_capture_template_into(*request.body_template, captures, body);
    if (!body.empty() && !has_content_length) {
      out.append("Content-Length: ");
      out.append(std::to_string(body.size()));
      out.append("\r\n");
    }
    out.append("\r\n");
    if (!body.empty()) {
      out.append(body);
    }
  } else {
    out.append("\r\n");
  }
  if (out.empty()) {
    std::string method_plain;
    std::string path_plain;
    std::string body_plain;
    render_capture_template_into(request.method_template, captures, method_plain);
    render_capture_template_into(request.path_template, captures, path_plain);
    if (request.body_template.has_value()) {
      render_capture_template_into(*request.body_template, captures, body_plain);
    }
    out.append(method_plain.empty() ? "GET" : method_plain);
    out.append(" ");
    out.append(path_plain.empty() ? "/" : path_plain);
    out.append(" HTTP/1.1\r\n");
    out.append("Host: ");
    out.append(profile.host_header.empty() ? profile.target_ip : profile.host_header);
    out.append("\r\nConnection: ");
    out.append(profile.keepalive ? "keep-alive" : "close");
    out.append("\r\n");
    bool emitted_content_length = false;
    for (const auto& [key, compiled_value] : request.compiled_header_values) {
      std::string value_plain;
      render_capture_template_into(compiled_value, captures, value_plain);
      out.append(key);
      out.append(": ");
      out.append(value_plain);
      out.append("\r\n");
      if (key == "Content-Length" || key == "content-length") {
        emitted_content_length = true;
      }
    }
    if (!body_plain.empty() && !emitted_content_length) {
      out.append("Content-Length: ");
      out.append(std::to_string(body_plain.size()));
      out.append("\r\n");
    }
    out.append("\r\n");
    out.append(body_plain);
  }
  perf_alloc(out.size());
}

std::vector<H1RequestSpec> build_h1_requests(const Profile& profile) {
  std::vector<H1RequestSpec> requests;
  requests.reserve(profile.ops.size());
  for (std::size_t idx = 0; idx < profile.ops.size(); ++idx) {
    const FlowOp& op = profile.ops[idx];
    if (op.opcode != "SEND_HEADERS") {
      continue;
    }
    H1RequestSpec spec;
    spec.send_headers = op;
    spec.method_template = compile_capture_template(op.method.empty() ? "GET" : op.method);
    spec.path_template = compile_capture_template(op.path.empty() ? "/" : op.path);
    spec.header_fields.reserve(op.headers.size());
    spec.compiled_header_values.reserve(op.headers.size());
    for (const auto& [key, value] : op.headers) {
      spec.header_bytes += key.size() + value.size() + 4;
      spec.header_fields.emplace_back(key, value);
      spec.compiled_header_values.emplace_back(key, compile_capture_template(value));
    }
    if (const std::string* f = find_scenario_header(op.headers, "x-scenario-flow")) {
      spec.scenario_flow = *f;
    }
    if (const std::string* v = find_scenario_header(op.headers, "x-scenario-vu-id")) {
      spec.scenario_vu_id = *v;
    }
    if (const std::string* of = find_scenario_header(op.headers, "x-scenario-on-failure")) {
      spec.scenario_on_failure = *of;
    }
    std::size_t j = idx + 1;
    if (j < profile.ops.size() && profile.ops[j].opcode == "SEND_BODY") {
      spec.body_op = profile.ops[j];
      spec.body_template = compile_capture_template(
          std::string(reinterpret_cast<const char*>(profile.ops[j].body.data()), profile.ops[j].body.size()));
      ++j;
    } else if (!op.body.empty()) {
      spec.body_op = op;
      spec.body_template = compile_capture_template(
          std::string(reinterpret_cast<const char*>(op.body.data()), op.body.size()));
    }
    while (j < profile.ops.size()) {
      const FlowOp& follow = profile.ops[j];
      if (follow.opcode == "SEND_HEADERS" || follow.opcode == "CONNECT" || follow.opcode == "CLOSE") {
        break;
      }
      spec.follow_ops.push_back(follow);
      ++j;
    }
    requests.push_back(std::move(spec));
  }
  return requests;
}

std::vector<std::vector<H1RequestSpec>> bucket_h1_requests_by_shard(
    const std::vector<H1RequestSpec>& requests,
    std::size_t shard_count) {
  const std::size_t count = std::max<std::size_t>(1, shard_count);
  std::vector<std::vector<H1RequestSpec>> buckets(count);
  for (std::size_t b = 0; b < count; ++b) {
    buckets[b].reserve(requests.size() / count + 1);
  }
  static const std::hash<std::string> vu_hash{};
  for (std::size_t i = 0; i < requests.size(); ++i) {
    const std::string& vu = requests[i].scenario_vu_id;
    const std::size_t bucket = vu.empty() ? (i % count) : (vu_hash(vu) % count);
    buckets[bucket].push_back(requests[i]);
  }
  return buckets;
}

std::vector<H2RequestSpec> build_h2_requests(const Profile& profile) {
  std::vector<H2RequestSpec> requests;
  for (const H1RequestSpec& h1_spec : build_h1_requests(profile)) {
    H2RequestSpec spec;
    spec.method = h1_spec.send_headers.method.empty() ? "GET" : h1_spec.send_headers.method;
    spec.path = h1_spec.send_headers.path.empty() ? "/" : h1_spec.send_headers.path;
    spec.method_template = h1_spec.method_template;
    spec.path_template = h1_spec.path_template;
    spec.headers = h1_spec.header_fields;
    spec.compiled_headers = h1_spec.compiled_header_values;
    if (h1_spec.body_op.has_value()) {
      spec.body.assign(
          reinterpret_cast<const char*>(h1_spec.body_op->body.data()),
          h1_spec.body_op->body.size());
    }
    spec.body_template = h1_spec.body_template;
    spec.follow_ops = h1_spec.follow_ops;
    spec.scenario_flow = h1_spec.scenario_flow;
    spec.scenario_vu_id = h1_spec.scenario_vu_id;
    spec.scenario_on_failure = h1_spec.scenario_on_failure;
    requests.push_back(std::move(spec));
  }
  return requests;
}

std::vector<std::vector<H2RequestSpec>> bucket_h2_requests_by_shard(
    const std::vector<H2RequestSpec>& requests,
    std::size_t shard_count) {
  const std::size_t count = std::max<std::size_t>(1, shard_count);
  std::vector<std::vector<H2RequestSpec>> buckets(count);
  for (std::size_t i = 0; i < requests.size(); ++i) {
    buckets[i % count].push_back(requests[i]);
  }
  return buckets;
}

void capture_cookie(
    const std::string& cookie_line,
    const std::string& capture_name,
    std::map<std::string, std::string>& captures) {
  const std::size_t sep = cookie_line.find(';');
  const std::string cookie = cookie_line.substr(0, sep);
  const std::size_t eq = cookie.find('=');
  if (eq != std::string::npos) {
    captures[cookie.substr(0, eq)] = cookie.substr(eq + 1);
  } else if (!capture_name.empty()) {
    captures[capture_name] = cookie;
  } else {
    captures["set-cookie"] = cookie;
  }
}

bool extract_json_field(const std::string& body, const std::string& path, std::string* out) {
  std::size_t cursor = 0;
  std::size_t start = 0;
  const std::size_t n = path.size();
  bool matched_any = false;
  while (start <= n) {
    std::size_t dot = path.find('.', start);
    const std::string key = path.substr(start, dot == std::string::npos ? std::string::npos : dot - start);
    if (key.empty()) {
      break;
    }
    const std::string needle = "\"" + key + "\"";
    const std::size_t at = body.find(needle, cursor);
    if (at == std::string::npos) {
      return false;
    }
    std::size_t colon = body.find(':', at + needle.size());
    if (colon == std::string::npos) {
      return false;
    }
    cursor = colon + 1;
    matched_any = true;
    if (dot == std::string::npos) {
      break;
    }
    start = dot + 1;
  }
  if (!matched_any) {
    return false;
  }
  while (cursor < body.size() &&
         (body[cursor] == ' ' || body[cursor] == '\t' || body[cursor] == '\n' || body[cursor] == '\r')) {
    ++cursor;
  }
  if (cursor >= body.size()) {
    return false;
  }
  if (body[cursor] == '"') {
    ++cursor;
    std::string value;
    while (cursor < body.size()) {
      const char c = body[cursor];
      if (c == '\\' && cursor + 1 < body.size()) {
        const char esc = body[cursor + 1];
        if (esc == '"' || esc == '\\' || esc == '/') {
          value.push_back(esc);
        } else if (esc == 'n') {
          value.push_back('\n');
        } else if (esc == 't') {
          value.push_back('\t');
        } else {
          value.push_back(esc);
        }
        cursor += 2;
        continue;
      }
      if (c == '"') {
        break;
      }
      value.push_back(c);
      ++cursor;
    }
    if (out != nullptr) {
      *out = std::move(value);
    }
    return true;
  }
  std::size_t end = cursor;
  while (end < body.size()) {
    const char c = body[end];
    if (c == ',' || c == '}' || c == ']' || c == ' ' || c == '\t' || c == '\n' || c == '\r') {
      break;
    }
    ++end;
  }
  if (out != nullptr) {
    *out = body.substr(cursor, end - cursor);
  }
  return end > cursor;
}

void capture_body_json(
    const FlowOp& follow,
    const std::string& body,
    std::map<std::string, std::string>& captures) {
  const std::string path = follow.capture_source.empty() ? follow.capture_name : follow.capture_source;
  if (path.empty()) {
    return;
  }
  std::string value;
  if (extract_json_field(body, path, &value)) {
    captures[follow.capture_name.empty() ? path : follow.capture_name] = value;
  }
}

void evaluate_response_ops(
    const std::vector<FlowOp>& follow_ops,
    int status_code,
    const std::vector<std::pair<std::string, std::string>>& header_fields,
    const std::map<std::string, std::string>& headers,
    const std::string& body,
    std::map<std::string, std::string>& captures,
    int& expectation_failures,
    int& think_time_total_ms) {
  for (const FlowOp& follow : follow_ops) {
    if (follow.opcode == "EXPECT_STATUS" && follow.has_expect) {
      if (status_code < follow.expect.status_min || status_code > follow.expect.status_max) {
        expectation_failures += 1;
      }
      continue;
    }
    if (follow.opcode == "EXPECT_HEADER" && follow.has_expect) {
      const std::string key = lower_copy(follow.expect.name);
      const std::string* header_value = find_header_value(header_fields, key);
      if ((header_value == nullptr || header_value->find(follow.expect.value) == std::string::npos) &&
          (headers.empty() || headers.find(key) == headers.end() ||
           headers.at(key).find(follow.expect.value) == std::string::npos)) {
        expectation_failures += 1;
      }
      continue;
    }
    if (follow.opcode == "EXPECT_BODY_SUBSTRING" && follow.has_expect) {
      if (body.find(follow.expect.value) == std::string::npos) {
        expectation_failures += 1;
      }
      continue;
    }
    if (follow.opcode == "CAPTURE_HEADER") {
      const std::string source = lower_copy(
          follow.capture_source.empty() ? follow.capture_name : follow.capture_source);
      const std::string* header_value = find_header_value(header_fields, source);
      if (header_value != nullptr) {
        captures[follow.capture_name.empty() ? source : follow.capture_name] = *header_value;
      } else {
        const auto it = headers.find(source);
        if (it != headers.end()) {
          captures[follow.capture_name.empty() ? source : follow.capture_name] = it->second;
        }
      }
      continue;
    }
    if (follow.opcode == "CAPTURE_COOKIE") {
      const std::string* cookie_value = find_header_value(header_fields, "set-cookie");
      if (cookie_value != nullptr) {
        capture_cookie(*cookie_value, follow.capture_name, captures);
      } else {
        const auto it = headers.find("set-cookie");
        if (it != headers.end()) {
          capture_cookie(it->second, follow.capture_name, captures);
        }
      }
      continue;
    }
    if (follow.opcode == "CAPTURE_BODY_JSON") {
      capture_body_json(follow, body, captures);
      continue;
    }
    if (follow.opcode == "THINK_TIME") {
      think_time_total_ms += std::max(0, follow.think_time_ms);
      continue;
    }
    if (follow.opcode == "RESOLVE_DNS") {
      dns::DnsClientEngine dns_engine;
      dns_engine.resolve(
          follow.dns_hostname.empty() ? "example.com" : follow.dns_hostname,
          follow.dns_protocol.empty() ? "udp" : follow.dns_protocol,
          follow.dns_qtype.empty() ? "A" : follow.dns_qtype,
          follow.dns_edns0,
          follow.dns_ecs_subnet);
      continue;
    }
    if (follow.opcode == "DHCP_DISCOVER" || follow.opcode == "DHCP_REQUEST") {
      l2l3::DhcpStateMachine dhcp;
      l2l3::DhcpConfig cfg;
      cfg.client_mac = follow.dhcp_client_mac.empty() ? "00:11:22:33:44:55" : follow.dhcp_client_mac;
      dhcp.start(cfg);
      if (follow.opcode == "DHCP_REQUEST") {
        dhcp.process_offer();
        dhcp.process_ack();
      }
      continue;
    }
    if (follow.opcode == "IGMP_JOIN" || follow.opcode == "IGMP_LEAVE") {
      l2l3::IgmpEngine igmp;
      const std::string group = follow.igmp_group_ip.empty() ? "224.1.1.1" : follow.igmp_group_ip;
      if (follow.opcode == "IGMP_JOIN") {
        igmp.join_group(group, follow.igmp_version);
      } else {
        igmp.leave_group(group, follow.igmp_version);
      }
      continue;
    }
    if (follow.opcode == "ND_SOLICIT") {
      l2l3::NdEngine nd;
      nd.send_neighbor_solicitation(follow.nd_target_ip.empty() ? "fe80::1" : follow.nd_target_ip);
      continue;
    }
    if (follow.opcode == "ARP_REQUEST") {
      l2l3::ArpEngine arp;
      arp.send_arp_request("192.168.1.1");
      continue;
    }
  }
}

}  // namespace samurai::l7_emu_native
