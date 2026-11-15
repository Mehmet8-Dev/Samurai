#include "shard.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <numeric>
#include <string>
#include <vector>

namespace samurai::control {

namespace {

using samurai::core::json::Value;

std::string Trim(const std::string& s) {
  const auto first = s.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) return "";
  const auto last = s.find_last_not_of(" \t\r\n");
  return s.substr(first, last - first + 1);
}

std::string Lower(const std::string& s) {
  std::string out = Trim(s);
  for (char& c : out) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return out;
}

std::string MacroRegion(const std::string& r) {
  const auto pos = r.find_first_of("-_");
  return pos == std::string::npos ? r : r.substr(0, pos);
}

bool ParseAsnString(const std::string& raw, std::uint32_t& out_asn) {
  std::string s = Lower(raw);
  if (s.size() >= 2 && s[0] == 'a' && s[1] == 's') {
    s = Trim(s.substr(2));
  }
  if (s.empty()) return false;
  for (unsigned char c : s) {
    if (!std::isdigit(c)) return false;
  }
  char* end = nullptr;
  const unsigned long long v = std::strtoull(s.c_str(), &end, 10);
  if (end == s.c_str() || *end != '\0' || v == 0 || v > 0xFFFFFFFFull) return false;
  out_asn = static_cast<std::uint32_t>(v);
  return true;
}

bool ParseIpv4HostOrder(const std::string& text, std::uint32_t& out_host) {
  in_addr addr{};
  if (inet_pton(AF_INET, Trim(text).c_str(), &addr) != 1) return false;
  out_host = ntohl(addr.s_addr);
  return true;
}

std::string FormatIpv4HostOrder(std::uint32_t host_ip) {
  in_addr addr{};
  addr.s_addr = htonl(host_ip);
  char buf[INET_ADDRSTRLEN] = {};
  if (!inet_ntop(AF_INET, &addr, buf, sizeof(buf))) return "0.0.0.0";
  return std::string(buf);
}

bool BoolFromCap(const std::string& v) {
  const std::string l = Lower(v);
  return l == "1" || l == "true" || l == "yes";
}

// Mirrors shard._worker_weight: base 1, +2 for GPU, +1 for XDP; an explicit
// capacity_score (>= 1) overrides the derived weight. Result is always >= 1.
int WorkerWeight(const WorkerCapabilities& caps) {
  int weight = 1;
  if (caps.gpu_available) weight += 2;
  if (caps.xdp_available) weight += 1;
  if (caps.capacity_score >= 1) weight = caps.capacity_score;
  return weight < 1 ? 1 : weight;
}

// Largest-remainder distribution: floor(total*w / sum_w) per worker, then hand
// out the leftover one-by-one round-robin — matches the Python arithmetic
// exactly (including the "counts[i % n] += 1" leftover pass).
std::vector<std::uint64_t> WeightedCounts(std::uint64_t total,
                                          const std::vector<int>& weights) {
  const std::uint64_t total_weight =
      std::max<std::uint64_t>(1, std::accumulate(weights.begin(), weights.end(), 0ull,
                                                 [](std::uint64_t a, int w) { return a + static_cast<std::uint64_t>(w); }));
  std::vector<std::uint64_t> counts(weights.size(), 0);
  std::uint64_t used = 0;
  for (std::size_t i = 0; i < weights.size(); ++i) {
    counts[i] = (total * static_cast<std::uint64_t>(weights[i])) / total_weight;
    used += counts[i];
  }
  const std::uint64_t rem = total > used ? total - used : 0;
  for (std::uint64_t i = 0; i < rem && !counts.empty(); ++i) {
    counts[i % counts.size()] += 1;
  }
  return counts;
}

std::vector<Shard> Emit(const std::vector<std::string>& workers,
                        const std::vector<std::uint64_t>& counts) {
  std::vector<Shard> out;
  out.reserve(workers.size());
  for (std::size_t idx = 0; idx < workers.size(); ++idx) {
    out.push_back(Shard{"shard-" + std::to_string(idx + 1), workers[idx], counts[idx]});
  }
  return out;
}

const WorkerCapabilities& CapsFor(const std::map<std::string, WorkerCapabilities>& caps_map,
                                  const std::string& wid) {
  static const WorkerCapabilities kEmpty{};
  auto it = caps_map.find(wid);
  return it == caps_map.end() ? kEmpty : it->second;
}

std::vector<std::string> FilterWorkers(const std::vector<std::string>& worker_ids) {
  std::vector<std::string> workers;
  workers.reserve(worker_ids.size());
  for (const auto& w : worker_ids) {
    if (!Trim(w).empty()) workers.push_back(w);
  }
  return workers;
}

std::vector<int> ComputeWorkerWeights(
    const std::vector<std::string>& workers,
    const std::string& strategy,
    const std::map<std::string, WorkerCapabilities>& worker_capabilities,
    const std::string& target_region,
    const RegionTopology* topology) {
  const RegionTopology default_topo;
  const RegionTopology& topo = topology ? *topology : default_topo;
  const std::string mode = Lower(strategy.empty() ? "equal" : strategy);
  const std::string tr = topo.ResolveRegion(0, target_region);

  std::vector<int> weights;
  weights.reserve(workers.size());
  for (const auto& wid : workers) {
    if (mode == "equal") {
      weights.push_back(1);
      continue;
    }
    const WorkerCapabilities& caps = CapsFor(worker_capabilities, wid);
    int base = WorkerWeight(caps);
    if (mode == "region") {
      base = std::max(1, base + topo.AffinityDelta(caps.region, tr));
    }
    weights.push_back(base);
  }
  return weights;
}

std::uint32_t ClampPrefixLen(std::uint8_t plen) noexcept {
  return std::clamp<std::uint32_t>(plen, 8u, 30u);
}

std::uint32_t AlignUpHostIp(std::uint32_t ip, std::uint64_t block_size) noexcept {
  if (block_size <= 1) return ip;
  const std::uint64_t rem = static_cast<std::uint64_t>(ip) % block_size;
  return rem == 0 ? ip : static_cast<std::uint32_t>(static_cast<std::uint64_t>(ip) + (block_size - rem));
}

bool ValidateAndPackBuckets(const std::vector<TelcoPoolBucket>& raw,
                            std::uint32_t cursor_start,
                            bool pack_sequential,
                            std::vector<TelcoPoolBucket>& out,
                            std::string& err) {
  out.clear();
  std::uint64_t cursor = cursor_start;
  for (std::size_t i = 0; i < raw.size(); ++i) {
    TelcoPoolBucket b = raw[i];
    if (b.prefix_len < 8 || b.prefix_len > 30) {
      err = "invalid telco pool prefix_len at bucket " + std::to_string(i);
      return false;
    }
    if (b.subnet_count == 0 || b.subnet_count > 65536u) {
      err = "invalid telco pool subnet_count at bucket " + std::to_string(i);
      return false;
    }
    const std::uint64_t block_size = 1ull << (32u - b.prefix_len);
    const std::uint32_t mask = static_cast<std::uint32_t>(~(block_size - 1ull));
    if (pack_sequential) {
      const std::uint32_t aligned = AlignUpHostIp(static_cast<std::uint32_t>(cursor), block_size);
      b.base_ip = aligned;
      cursor = static_cast<std::uint64_t>(aligned) +
               block_size * static_cast<std::uint64_t>(b.subnet_count);
      if (cursor > 0xFFFFFFFFull) {
        err = "packed telco lab pool overflow";
        return false;
      }
    } else {
      b.base_ip &= mask;
    }
    for (std::uint32_t s = 0; s < b.subnet_count; ++s) {
      const std::uint64_t net64 =
          static_cast<std::uint64_t>(b.base_ip) + static_cast<std::uint64_t>(s) * block_size;
      if (net64 > 0xFFFFFFFFull ||
          !IsSafeTelcoLabSubnet(static_cast<std::uint32_t>(net64), b.prefix_len)) {
        err = "telco lab pool base_ip outside RFC1918/6598/2544 lab safety bounds: " +
              FormatIpv4HostOrder(b.base_ip) + "/" + std::to_string(b.prefix_len);
        return false;
      }
    }
    out.push_back(b);
  }
  return true;
}

}  // namespace

WorkerCapabilities CapabilitiesFromStrings(const std::map<std::string, std::string>& caps) {
  WorkerCapabilities out;
  if (auto it = caps.find("gpu_available"); it != caps.end()) out.gpu_available = BoolFromCap(it->second);
  if (auto it = caps.find("xdp_available"); it != caps.end()) out.xdp_available = BoolFromCap(it->second);
  if (auto it = caps.find("region"); it != caps.end()) out.region = Trim(it->second);
  if (auto it = caps.find("capacity_score"); it != caps.end()) {
    try {
      const long v = std::stol(it->second);
      if (v > 0) out.capacity_score = static_cast<int>(v);
    } catch (...) {
    }
  }
  return out;
}

std::string RegionTopology::CanonicalRegion(const std::string& raw) const {
  std::string norm = Lower(raw);
  if (norm.empty()) return "";
  auto it = region_aliases.find(norm);
  if (it != region_aliases.end()) {
    norm = Lower(it->second);
  } else {
    for (const auto& kv : region_aliases) {
      if (Lower(kv.first) == norm) {
        norm = Lower(kv.second);
        break;
      }
    }
  }
  return norm;
}

std::string RegionTopology::ResolveRegion(std::uint32_t target_asn,
                                          const std::string& explicit_region) const {
  const std::string ex = CanonicalRegion(explicit_region);
  if (!ex.empty()) return ex;
  if (target_asn != 0) {
    auto it = asn_to_region.find(target_asn);
    if (it != asn_to_region.end()) return CanonicalRegion(it->second);
  }
  return "";
}

int RegionTopology::AffinityDelta(const std::string& worker_region,
                                  const std::string& target_region) const {
  const std::string wr = CanonicalRegion(worker_region);
  const std::string tr = CanonicalRegion(target_region);
  if (wr.empty() || tr.empty()) return 0;
  if (wr == tr) return 5;
  if (MacroRegion(wr) == MacroRegion(tr)) return 2;
  return -1;
}

Value RegionTopology::ToJson() const {
  Value root = Value::Object();
  Value asns = Value::Object();
  for (const auto& kv : asn_to_region) {
    asns.set(std::to_string(kv.first), Value::Str(kv.second));
  }
  Value aliases = Value::Object();
  for (const auto& kv : region_aliases) {
    aliases.set(kv.first, Value::Str(kv.second));
  }
  root.set("asn_to_region", std::move(asns));
  root.set("region_aliases", std::move(aliases));
  return root;
}

bool RegionTopology::FromJson(const Value& val, RegionTopology& out, std::string& err) {
  if (!val.is_object()) {
    err = "region topology JSON must be an object";
    return false;
  }
  RegionTopology parsed;
  const Value* asn_obj = val.find("asn_to_region");
  const Value* alias_obj = val.find("region_aliases");
  if (asn_obj || alias_obj) {
    if (asn_obj) {
      if (!asn_obj->is_object()) {
        err = "asn_to_region must be a JSON object";
        return false;
      }
      for (const auto& kv : asn_obj->members()) {
        std::uint32_t asn = 0;
        if (!ParseAsnString(kv.first, asn) || !kv.second.is_string()) {
          err = "invalid ASN entry in asn_to_region: " + kv.first;
          return false;
        }
        parsed.asn_to_region[asn] = Lower(kv.second.as_string(""));
      }
    }
    if (alias_obj) {
      if (!alias_obj->is_object()) {
        err = "region_aliases must be a JSON object";
        return false;
      }
      for (const auto& kv : alias_obj->members()) {
        if (kv.second.is_string()) {
          parsed.region_aliases[Lower(kv.first)] = Lower(kv.second.as_string(""));
        }
      }
    }
  } else {
    // Shorthand flat map: { "9121": "tr-ist", "AS15897": "tr-ank" }
    for (const auto& kv : val.members()) {
      std::uint32_t asn = 0;
      if (!ParseAsnString(kv.first, asn) || !kv.second.is_string()) {
        err = "invalid shorthand ASN->region entry: " + kv.first;
        return false;
      }
      parsed.asn_to_region[asn] = Lower(kv.second.as_string(""));
    }
  }
  out = std::move(parsed);
  return true;
}

std::vector<Shard> SplitJobToShards(std::uint64_t total_count,
                                    const std::vector<std::string>& worker_ids,
                                    const std::string& strategy,
                                    const std::map<std::string, WorkerCapabilities>& worker_capabilities,
                                    const std::string& target_region,
                                    const RegionTopology* topology) {
  const std::vector<std::string> workers = FilterWorkers(worker_ids);
  if (workers.empty()) return {};

  const std::string mode = Lower(strategy.empty() ? "equal" : strategy);
  if (mode == "capability" || mode == "region") {
    const auto weights =
        ComputeWorkerWeights(workers, mode, worker_capabilities, target_region, topology);
    return Emit(workers, WeightedCounts(total_count, weights));
  }

  // "equal": floor split + first-`rem` workers get one extra.
  const std::uint64_t base = total_count / workers.size();
  const std::uint64_t rem = total_count % workers.size();
  std::vector<std::uint64_t> counts(workers.size());
  for (std::size_t idx = 0; idx < workers.size(); ++idx) {
    counts[idx] = base + (idx < rem ? 1 : 0);
  }
  return Emit(workers, counts);
}

bool IsSafeTelcoLabIpv4(std::uint32_t host_ip) noexcept {
  if ((host_ip & 0xFF000000u) == 0x0A000000u) return true;  // 10.0.0.0/8 (RFC 1918)
  if ((host_ip & 0xFFF00000u) == 0xAC100000u) return true;  // 172.16.0.0/12 (RFC 1918)
  if ((host_ip & 0xFFFF0000u) == 0xC0A80000u) return true;  // 192.168.0.0/16 (RFC 1918)
  if ((host_ip & 0xFFC00000u) == 0x64400000u) return true;  // 100.64.0.0/10 (RFC 6598 CGNAT)
  if ((host_ip & 0xFFFE0000u) == 0xC6120000u) return true;  // 198.18.0.0/15 (RFC 2544 bench)
  if ((host_ip & 0xFF000000u) == 0x7F000000u) return true;  // 127.0.0.0/8 (loopback)
  return false;
}

bool IsSafeTelcoLabSubnet(std::uint32_t network_ip, std::uint8_t prefix_len) noexcept {
  if (prefix_len < 8 || prefix_len > 30) return false;
  const std::uint64_t host_span = (1ull << (32u - prefix_len)) - 1ull;
  const std::uint32_t net_start = network_ip & static_cast<std::uint32_t>(~host_span);
  const std::uint32_t net_end = net_start | static_cast<std::uint32_t>(host_span);
  return IsSafeTelcoLabIpv4(net_start) && IsSafeTelcoLabIpv4(net_end);
}

std::uint32_t TelcoPoolBucket::HostsPerSubnet() const noexcept {
  const std::uint32_t plen = ClampPrefixLen(prefix_len);
  const std::uint64_t block = 1ull << (32u - plen);
  const std::uint32_t max_usable = block > 2 ? static_cast<std::uint32_t>(block - 2) : 1u;
  if (hosts_per_subnet == 0) return max_usable;
  return std::min(hosts_per_subnet, max_usable);
}

std::uint64_t TelcoPoolBucket::TotalCapacity() const noexcept {
  return static_cast<std::uint64_t>(std::max<std::uint32_t>(1, subnet_count)) *
         static_cast<std::uint64_t>(HostsPerSubnet());
}

std::uint32_t TelcoPoolBucket::Ipv4ForOffset(std::uint64_t local_idx) const noexcept {
  const std::uint32_t plen = ClampPrefixLen(prefix_len);
  const std::uint64_t block_size = 1ull << (32u - plen);
  const std::uint32_t mask = static_cast<std::uint32_t>(~(block_size - 1ull));
  const std::uint32_t net_base = base_ip & mask;
  const std::uint32_t cap = std::max<std::uint32_t>(1, HostsPerSubnet());
  const std::uint32_t subs = std::max<std::uint32_t>(1, subnet_count);
  const std::uint32_t s_idx = static_cast<std::uint32_t>((local_idx / cap) % subs);
  const std::uint32_t h_idx = static_cast<std::uint32_t>(local_idx % cap);
  return net_base + static_cast<std::uint32_t>(s_idx * block_size) + 1u + h_idx;
}

std::uint32_t TelcoLabSizingProfile::RouteCount() const noexcept {
  if (buckets.empty()) return 1u;
  std::uint64_t total = 0;
  for (const auto& b : buckets) total += std::max<std::uint32_t>(1, b.subnet_count);
  return static_cast<std::uint32_t>(std::min<std::uint64_t>(total, 0xFFFFFFFFull));
}

std::uint64_t TelcoLabSizingProfile::TotalCapacity() const noexcept {
  std::uint64_t total = 0;
  for (const auto& b : buckets) total += b.TotalCapacity();
  return total;
}

std::uint32_t TelcoLabSizingProfile::Ipv4ForIndex(std::uint32_t sub_idx,
                                                  std::uint32_t fallback_base_ip) const noexcept {
  if (buckets.empty()) return fallback_base_ip + sub_idx;
  const std::uint64_t cap = std::max<std::uint64_t>(1, TotalCapacity());
  std::uint64_t rem = static_cast<std::uint64_t>(sub_idx) % cap;
  for (const auto& b : buckets) {
    const std::uint64_t bc = b.TotalCapacity();
    if (rem < bc) return b.Ipv4ForOffset(rem);
    rem -= bc;
  }
  return buckets.front().Ipv4ForOffset(0);
}

TelcoLabSizingProfile TelcoLabSizingProfile::Preset(const std::string& profile_name) {
  const std::string p = Lower(profile_name);
  TelcoLabSizingProfile out;
  if (p.empty() || p == "linear") {
    out.name = "linear";
    return out;
  }
  std::vector<TelcoPoolBucket> raw;
  if (p == "regional-bng") {
    out.name = "regional-bng";
    // Disjoint /20 + /22 + /24 lab buckets inside RFC 6598 100.64.0.0/10 (52 prefixes, ~40.9k IPs).
    raw = {
        TelcoPoolBucket{0x64400000u, 20, 4, 0},
        TelcoPoolBucket{0x64400000u, 22, 16, 0},
        TelcoPoolBucket{0x64400000u, 24, 32, 0},
    };
  } else if (p == "national-cgnat") {
    out.name = "national-cgnat";
    // Disjoint /18 + /20 + /22 + /24 lab buckets inside RFC 6598 100.64.0.0/10 (232 prefixes, ~359k IPs).
    raw = {
        TelcoPoolBucket{0x64400000u, 18, 8, 0},
        TelcoPoolBucket{0x64400000u, 20, 32, 0},
        TelcoPoolBucket{0x64400000u, 22, 64, 0},
        TelcoPoolBucket{0x64400000u, 24, 128, 0},
    };
  } else {
    out.name = p;
    return out;
  }
  std::string ignored_err;
  ValidateAndPackBuckets(raw, 0x64400000u, true, out.buckets, ignored_err);
  return out;
}

bool TelcoLabSizingProfile::FromJson(const Value& val, TelcoLabSizingProfile& out, std::string& err) {
  if (!val.is_object()) {
    err = "telco sizing profile JSON must be an object";
    return false;
  }
  if (const Value* pname = val.find("preset"); pname && pname->is_string()) {
    TelcoLabSizingProfile preset = Preset(pname->as_string(""));
    if (!preset.buckets.empty() || Lower(pname->as_string("")) == "linear") {
      out = std::move(preset);
      return true;
    }
    err = "unknown telco pool preset: " + pname->as_string("");
    return false;
  }

  std::uint32_t lab_base = 0x64400000u;  // 100.64.0.0
  bool has_explicit_bucket_bases = false;
  if (const Value* lb = val.find("lab_base_ip")) {
    if (lb->is_string()) {
      if (!ParseIpv4HostOrder(lb->as_string(""), lab_base)) {
        err = "invalid lab_base_ip: " + lb->as_string("");
        return false;
      }
    } else if (lb->is_int()) {
      lab_base = static_cast<std::uint32_t>(lb->as_int(0));
    }
    if (!IsSafeTelcoLabIpv4(lab_base)) {
      err = "lab_base_ip must be within RFC1918/6598/2544 lab address space";
      return false;
    }
  }

  std::vector<TelcoPoolBucket> raw;
  if (const Value* barr = val.find("buckets")) {
    if (!barr->is_array()) {
      err = "buckets must be a JSON array";
      return false;
    }
    for (const auto& item : barr->elements()) {
      if (!item.is_object()) {
        err = "each bucket entry must be a JSON object";
        return false;
      }
      TelcoPoolBucket b;
      b.base_ip = lab_base;
      if (const Value* bip = item.find("base_ip")) {
        has_explicit_bucket_bases = true;
        if (bip->is_string()) {
          if (!ParseIpv4HostOrder(bip->as_string(""), b.base_ip)) {
            err = "invalid bucket base_ip: " + bip->as_string("");
            return false;
          }
        } else if (bip->is_int()) {
          b.base_ip = static_cast<std::uint32_t>(bip->as_int(0));
        }
      }
      const Value* pl = item.find("prefix_len");
      const Value* sc = item.find("subnet_count");
      const Value* hps = item.find("hosts_per_subnet");
      b.prefix_len = static_cast<std::uint8_t>(pl ? pl->as_int(22) : 22);
      b.subnet_count = static_cast<std::uint32_t>(sc ? sc->as_int(1) : 1);
      b.hosts_per_subnet = static_cast<std::uint32_t>(hps ? std::max<std::int64_t>(0, hps->as_int(0)) : 0);
      raw.push_back(b);
    }
  } else if (const Value* pc = val.find("prefix_counts")) {
    if (!pc->is_object()) {
      err = "prefix_counts must be a JSON object";
      return false;
    }
    // Sort keys largest blocks first (/16 before /24) so alignment packing stays tight.
    std::vector<std::pair<std::uint8_t, std::uint32_t>> sorted;
    for (const auto& kv : pc->members()) {
      std::string k = Trim(kv.first);
      if (!k.empty() && k[0] == '/') k = k.substr(1);
      char* end = nullptr;
      const long plen = std::strtol(k.c_str(), &end, 10);
      const std::int64_t cnt = kv.second.as_int(0);
      if (end == k.c_str() || *end != '\0' || plen < 8 || plen > 30 || cnt <= 0) {
        err = "invalid prefix_counts entry: " + kv.first;
        return false;
      }
      sorted.emplace_back(static_cast<std::uint8_t>(plen), static_cast<std::uint32_t>(cnt));
    }
    std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
    for (const auto& p : sorted) {
      raw.push_back(TelcoPoolBucket{lab_base, p.first, p.second, 0});
    }
  } else {
    err = "telco sizing profile requires buckets, prefix_counts, or preset";
    return false;
  }

  TelcoLabSizingProfile parsed;
  parsed.name = val.find("name") ? val.find("name")->as_string("custom") : "custom";
  if (!ValidateAndPackBuckets(raw, lab_base, !has_explicit_bucket_bases, parsed.buckets, err)) {
    return false;
  }
  out = std::move(parsed);
  return true;
}

Value TelcoLabSizingProfile::ToJson() const {
  Value root = Value::Object();
  root.set("name", Value::Str(name));
  root.set("route_count", Value::Int(RouteCount()));
  root.set("total_capacity", Value::Int(static_cast<std::int64_t>(TotalCapacity())));
  Value barr = Value::Array();
  for (const auto& b : buckets) {
    Value bo = Value::Object();
    bo.set("base_ip", Value::Int(b.base_ip));
    bo.set("base_ip_str", Value::Str(FormatIpv4HostOrder(b.base_ip)));
    bo.set("prefix_len", Value::Int(b.prefix_len));
    bo.set("subnet_count", Value::Int(b.subnet_count));
    bo.set("hosts_per_subnet", Value::Int(b.hosts_per_subnet));
    barr.push_back(std::move(bo));
  }
  root.set("buckets", std::move(barr));
  return root;
}

std::uint32_t SubscriberRange::GetIpFor(std::uint32_t sub_idx) const noexcept {
  if (pools.empty()) return base_ip + sub_idx;
  std::uint64_t total_cap = 0;
  for (const auto& b : pools) total_cap += b.TotalCapacity();
  if (total_cap == 0) return base_ip + sub_idx;
  std::uint64_t rem = static_cast<std::uint64_t>(sub_idx) % total_cap;
  for (const auto& b : pools) {
    const std::uint64_t bc = b.TotalCapacity();
    if (rem < bc) return b.Ipv4ForOffset(rem);
    rem -= bc;
  }
  return pools.front().Ipv4ForOffset(0);
}

std::uint32_t SubscriberRange::PoolRouteCount() const noexcept {
  if (pools.empty()) return 1u;
  std::uint64_t routes = 0;
  for (const auto& b : pools) routes += std::max<std::uint32_t>(1, b.subnet_count);
  return static_cast<std::uint32_t>(std::min<std::uint64_t>(routes, 0xFFFFFFFFull));
}

std::uint64_t SubscriberRange::EstimatedNatTableEntries(std::uint16_t ports_per_subscriber) const noexcept {
  return static_cast<std::uint64_t>(count) * static_cast<std::uint64_t>(ports_per_subscriber);
}

Value TelcoShardSpec::ToJson() const {
  auto val = Value::Object();
  val.set("shard_id", Value::Str(shard_id));
  val.set("worker_id", Value::Str(worker_id));
  val.set("protocol", Value::Str(protocol));
  val.set("target_cps", Value::Int(target_cps));
  val.set("max_retries", Value::Int(max_retries));
  val.set("timeout_ms", Value::Int(timeout_ms));
  val.set("db_port", Value::Int(db_port));

  auto r = Value::Object();
  r.set("start_idx", Value::Int(range.start_idx));
  r.set("count", Value::Int(range.count));
  r.set("base_vlan_s", Value::Int(range.base_vlan_s));
  r.set("base_vlan_c", Value::Int(range.base_vlan_c));
  r.set("vlan_step", Value::Int(range.vlan_step));
  r.set("base_ip", Value::Int(range.base_ip));
  r.set("gateway_ip", Value::Int(range.gateway_ip));

  char mac_buf[32];
  std::snprintf(mac_buf, sizeof(mac_buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                range.base_mac[0], range.base_mac[1], range.base_mac[2],
                range.base_mac[3], range.base_mac[4], range.base_mac[5]);
  r.set("base_mac", Value::Str(mac_buf));
  if (!range.pools.empty()) {
    Value parr = Value::Array();
    for (const auto& b : range.pools) {
      Value bo = Value::Object();
      bo.set("base_ip", Value::Int(b.base_ip));
      bo.set("prefix_len", Value::Int(b.prefix_len));
      bo.set("subnet_count", Value::Int(b.subnet_count));
      bo.set("hosts_per_subnet", Value::Int(b.hosts_per_subnet));
      parr.push_back(std::move(bo));
    }
    r.set("pools", std::move(parr));
  }
  val.set("range", std::move(r));
  return val;
}

TelcoShardSpec TelcoShardSpec::FromJson(const Value& val) {
  TelcoShardSpec spec;
  if (!val.is_object()) return spec;

  spec.shard_id = val.find("shard_id") ? val.find("shard_id")->as_string("") : "";
  spec.worker_id = val.find("worker_id") ? val.find("worker_id")->as_string("") : "";
  spec.protocol = val.find("protocol") ? val.find("protocol")->as_string("pppoe") : "pppoe";
  spec.target_cps = static_cast<std::uint32_t>(val.find("target_cps") ? val.find("target_cps")->as_int(5000) : 5000);
  spec.max_retries = static_cast<std::uint32_t>(val.find("max_retries") ? val.find("max_retries")->as_int(3) : 3);
  spec.timeout_ms = static_cast<std::uint32_t>(val.find("timeout_ms") ? val.find("timeout_ms")->as_int(500) : 500);
  spec.db_port = static_cast<int>(val.find("db_port") ? val.find("db_port")->as_int(5099) : 5099);

  const auto* r = val.find("range");
  if (r && r->is_object()) {
    spec.range.start_idx = static_cast<std::uint32_t>(r->find("start_idx") ? r->find("start_idx")->as_int(0) : 0);
    spec.range.count = static_cast<std::uint32_t>(r->find("count") ? r->find("count")->as_int(0) : 0);
    spec.range.base_vlan_s = static_cast<std::uint16_t>(r->find("base_vlan_s") ? r->find("base_vlan_s")->as_int(100) : 100);
    spec.range.base_vlan_c = static_cast<std::uint16_t>(r->find("base_vlan_c") ? r->find("base_vlan_c")->as_int(10) : 10);
    spec.range.vlan_step = static_cast<std::uint16_t>(r->find("vlan_step") ? r->find("vlan_step")->as_int(1) : 1);
    spec.range.base_ip = static_cast<std::uint32_t>(r->find("base_ip") ? r->find("base_ip")->as_int(0x0A000001) : 0x0A000001);
    spec.range.gateway_ip = static_cast<std::uint32_t>(r->find("gateway_ip") ? r->find("gateway_ip")->as_int(0x0A0000FE) : 0x0A0000FE);

    const auto* mac_val = r->find("base_mac");
    if (mac_val && mac_val->is_string()) {
      unsigned int m[6];
      if (std::sscanf(mac_val->as_string().c_str(), "%x:%x:%x:%x:%x:%x",
                      &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
        for (int i = 0; i < 6; ++i) spec.range.base_mac[i] = static_cast<std::uint8_t>(m[i]);
      }
    }
    if (const auto* parr = r->find("pools"); parr && parr->is_array()) {
      std::vector<TelcoPoolBucket> candidate;
      for (const auto& item : parr->elements()) {
        if (!item.is_object()) continue;
        TelcoPoolBucket b;
        b.base_ip = static_cast<std::uint32_t>(item.find("base_ip") ? item.find("base_ip")->as_int(0x64400000) : 0x64400000);
        b.prefix_len = static_cast<std::uint8_t>(item.find("prefix_len") ? item.find("prefix_len")->as_int(22) : 22);
        b.subnet_count = static_cast<std::uint32_t>(item.find("subnet_count") ? item.find("subnet_count")->as_int(1) : 1);
        b.hosts_per_subnet = static_cast<std::uint32_t>(item.find("hosts_per_subnet") ? item.find("hosts_per_subnet")->as_int(0) : 0);
        candidate.push_back(b);
      }
      std::string ignored_err;
      ValidateAndPackBuckets(candidate, 0x64400000u, false, spec.range.pools, ignored_err);
    }
  }
  return spec;
}

std::vector<TelcoShardSpec> SplitTelcoSubscribers(
    std::uint32_t total_subscribers,
    const std::vector<std::string>& worker_ids,
    const std::map<std::string, WorkerCapabilities>& worker_capabilities,
    const std::string& target_region,
    const std::string& strategy,
    const std::string& protocol,
    std::uint32_t target_cps,
    std::uint16_t base_vlan_s,
    std::uint16_t base_vlan_c,
    const std::uint8_t base_mac[6],
    std::uint32_t base_ip,
    std::uint32_t gateway_ip,
    const TelcoLabSizingProfile* pool_profile,
    const RegionTopology* topology) {
  const std::vector<std::string> workers = FilterWorkers(worker_ids);
  if (workers.empty() || total_subscribers == 0) return {};

  const std::vector<int> weights =
      ComputeWorkerWeights(workers, strategy, worker_capabilities, target_region, topology);
  const std::vector<std::uint64_t> counts = WeightedCounts(total_subscribers, weights);
  const std::uint64_t sum_weights = std::max<std::uint64_t>(
      1, std::accumulate(weights.begin(), weights.end(), 0ull,
                         [](std::uint64_t a, int w) { return a + static_cast<std::uint64_t>(w); }));

  const bool use_pool = pool_profile != nullptr && !pool_profile->buckets.empty();
  const std::uint32_t effective_base_ip =
      use_pool ? pool_profile->buckets.front().base_ip : base_ip;

  std::uint32_t curr_start = 0;
  std::vector<TelcoShardSpec> out;
  out.reserve(workers.size());

  for (std::size_t i = 0; i < workers.size(); ++i) {
    const std::uint32_t count = static_cast<std::uint32_t>(counts[i]);
    TelcoShardSpec spec;
    spec.shard_id = "telco-shard-" + std::to_string(i + 1);
    spec.worker_id = workers[i];
    spec.protocol = protocol.empty() ? "pppoe" : protocol;
    const std::uint64_t scaled_cps =
        (static_cast<std::uint64_t>(target_cps) * static_cast<std::uint64_t>(weights[i])) / sum_weights;
    spec.target_cps = static_cast<std::uint32_t>(std::max<std::uint64_t>(1, scaled_cps));
    spec.db_port = 5099;

    spec.range.start_idx = curr_start;
    spec.range.count = count;
    spec.range.base_vlan_s = base_vlan_s;
    spec.range.base_vlan_c = base_vlan_c;
    spec.range.base_ip = effective_base_ip;
    spec.range.gateway_ip = gateway_ip;
    if (use_pool) {
      spec.range.pools = pool_profile->buckets;
    }
    if (base_mac) {
      std::memcpy(spec.range.base_mac, base_mac, 6);
    }

    curr_start += count;
    out.push_back(std::move(spec));
  }
  return out;
}

std::vector<TelcoShardSpec> SplitTelcoSubscribers(
    std::uint32_t total_subscribers,
    const std::vector<std::string>& worker_ids,
    const std::string& protocol,
    std::uint32_t target_cps,
    std::uint16_t base_vlan_s,
    std::uint16_t base_vlan_c,
    const std::uint8_t base_mac[6],
    std::uint32_t base_ip,
    std::uint32_t gateway_ip) {
  return SplitTelcoSubscribers(total_subscribers, worker_ids, {}, "", "equal", protocol,
                               target_cps, base_vlan_s, base_vlan_c, base_mac, base_ip,
                               gateway_ip, nullptr, nullptr);
}

}  // namespace samurai::control

