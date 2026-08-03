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

}  // namespace samurai::control
