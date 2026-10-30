#include "shard.hpp"

#include <algorithm>
#include <cstdint>
#include <numeric>
#include <string>
#include <vector>

namespace samurai::control {

namespace {

std::string Lower(const std::string& s) {
  std::string out = s;
  for (char& c : out) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return out;
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

}  // namespace

std::vector<Shard> SplitJobToShards(std::uint64_t total_count,
                                    const std::vector<std::string>& worker_ids,
                                    const std::string& strategy,
                                    const std::map<std::string, WorkerCapabilities>& worker_capabilities,
                                    const std::string& target_region) {
  std::vector<std::string> workers;
  for (const auto& w : worker_ids) {
    // strip(): drop blank ids
    const auto first = w.find_first_not_of(" \t\r\n");
    if (first != std::string::npos) workers.push_back(w);
  }
  if (workers.empty()) return {};

  const std::uint64_t total = total_count;
  const std::string mode = Lower(strategy.empty() ? "equal" : strategy);

  if (mode == "capability") {
    std::vector<int> weights;
    weights.reserve(workers.size());
    for (const auto& wid : workers) weights.push_back(WorkerWeight(CapsFor(worker_capabilities, wid)));
    return Emit(workers, WeightedCounts(total, weights));
  }

  if (mode == "region") {
    const std::string tr = Lower(target_region);
    std::vector<int> weights;
    weights.reserve(workers.size());
    for (const auto& wid : workers) {
      const WorkerCapabilities& caps = CapsFor(worker_capabilities, wid);
      const std::string wr = Lower(caps.region);
      int base = WorkerWeight(caps);
      if (!tr.empty() && wr == tr) {
        base += 5;
      } else if (!tr.empty() && !wr.empty() && wr != tr) {
        base = std::max(1, base - 1);
      }
      weights.push_back(base);
    }
    return Emit(workers, WeightedCounts(total, weights));
  }

  // "equal": floor split + first-`rem` workers get one extra.
  const std::uint64_t base = total / workers.size();
  const std::uint64_t rem = total % workers.size();
  std::vector<std::uint64_t> counts(workers.size());
  for (std::size_t idx = 0; idx < workers.size(); ++idx) {
    counts[idx] = base + (idx < rem ? 1 : 0);
  }
  return Emit(workers, counts);
}

samurai::core::json::Value TelcoShardSpec::ToJson() const {
  auto val = samurai::core::json::Value::Object();
  val.set("shard_id", samurai::core::json::Value::Str(shard_id));
  val.set("worker_id", samurai::core::json::Value::Str(worker_id));
  val.set("protocol", samurai::core::json::Value::Str(protocol));
  val.set("target_cps", samurai::core::json::Value::Int(target_cps));
  val.set("max_retries", samurai::core::json::Value::Int(max_retries));
  val.set("timeout_ms", samurai::core::json::Value::Int(timeout_ms));
  val.set("db_port", samurai::core::json::Value::Int(db_port));

  auto r = samurai::core::json::Value::Object();
  r.set("start_idx", samurai::core::json::Value::Int(range.start_idx));
  r.set("count", samurai::core::json::Value::Int(range.count));
  r.set("base_vlan_s", samurai::core::json::Value::Int(range.base_vlan_s));
  r.set("base_vlan_c", samurai::core::json::Value::Int(range.base_vlan_c));
  r.set("vlan_step", samurai::core::json::Value::Int(range.vlan_step));
  r.set("base_ip", samurai::core::json::Value::Int(range.base_ip));
  r.set("gateway_ip", samurai::core::json::Value::Int(range.gateway_ip));

  char mac_buf[32];
  std::snprintf(mac_buf, sizeof(mac_buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                range.base_mac[0], range.base_mac[1], range.base_mac[2],
                range.base_mac[3], range.base_mac[4], range.base_mac[5]);
  r.set("base_mac", samurai::core::json::Value::Str(mac_buf));
  val.set("range", std::move(r));
  return val;
}

TelcoShardSpec TelcoShardSpec::FromJson(const samurai::core::json::Value& val) {
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
  }
  return spec;
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
  std::vector<std::string> workers;
  for (const auto& w : worker_ids) {
    const auto first = w.find_first_not_of(" \t\r\n");
    if (first != std::string::npos) workers.push_back(w);
  }
  if (workers.empty() || total_subscribers == 0) return {};

  const std::uint32_t n = static_cast<std::uint32_t>(workers.size());
  const std::uint32_t base_chunk = total_subscribers / n;
  const std::uint32_t rem = total_subscribers % n;
  std::uint32_t curr_start = 0;

  std::vector<TelcoShardSpec> out;
  out.reserve(n);

  for (std::uint32_t i = 0; i < n; ++i) {
    const std::uint32_t count = base_chunk + (i < rem ? 1 : 0);
    TelcoShardSpec spec;
    spec.shard_id = "telco-shard-" + std::to_string(i + 1);
    spec.worker_id = workers[i];
    spec.protocol = protocol.empty() ? "pppoe" : protocol;
    spec.target_cps = target_cps;
    spec.db_port = 5099;

    spec.range.start_idx = curr_start;
    spec.range.count = count;
    spec.range.base_vlan_s = base_vlan_s;
    spec.range.base_vlan_c = base_vlan_c;
    spec.range.base_ip = base_ip;
    spec.range.gateway_ip = gateway_ip;

    if (base_mac) {
      std::memcpy(spec.range.base_mac, base_mac, 6);
    }

    curr_start += count;
    out.push_back(std::move(spec));
  }

  return out;
}

}  // namespace samurai::control

