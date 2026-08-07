#include "ha.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <ctime>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <unistd.h>

#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>

namespace samurai::control {

namespace {

using samurai::core::json::Value;

std::string Strip(const std::string& s) {
  const auto first = s.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) return "";
  const auto last = s.find_last_not_of(" \t\r\n");
  return s.substr(first, last - first + 1);
}

std::vector<std::string> ParsePeers(const std::string& raw) {
  std::vector<std::string> out;
  std::stringstream ss(raw);
  std::string tok;
  while (std::getline(ss, tok, ',')) {
    const std::string t = Strip(tok);
    if (!t.empty()) out.push_back(t);
  }
  return out;
}

std::string Hostname() {
  char buf[256] = {0};
  if (::gethostname(buf, sizeof(buf) - 1) == 0 && buf[0]) return std::string(buf);
  return "localhost";
}

double NowSec() {
  using namespace std::chrono;
  return duration_cast<duration<double>>(system_clock::now().time_since_epoch()).count();
}

// RAII exclusive flock on a lock file (fcntl LOCK_EX), mirroring _meta_lock.
class FileLock {
 public:
  explicit FileLock(const std::string& lock_path) {
    fd_ = ::open(lock_path.c_str(), O_CREAT | O_RDWR, 0644);
    if (fd_ >= 0) locked_ = (::flock(fd_, LOCK_EX) == 0);
  }
  ~FileLock() {
    if (fd_ >= 0) {
      if (locked_) ::flock(fd_, LOCK_UN);
      ::close(fd_);
    }
  }
  bool ok() const { return fd_ >= 0 && locked_; }

 private:
  int fd_ = -1;
  bool locked_ = false;
};

}  // namespace

// --- StaticLeaderElector ---------------------------------------------------

StaticLeaderElector::StaticLeaderElector(const std::string& node_id, const std::string& peers_csv) {
  node_id_ = Strip(node_id);
  if (node_id_.empty()) node_id_ = Hostname();
  peers_ = ParsePeers(peers_csv);
  std::set<std::string> uniq(peers_.begin(), peers_.end());
  uniq.insert(node_id_);
  candidates_.assign(uniq.begin(), uniq.end());  // std::set -> sorted
  leader_id_ = candidates_.empty() ? node_id_ : candidates_.front();
}

Value StaticLeaderElector::Snapshot() const {
  Value o = Value::Object();
  o.set("mode", Value::Str("static"));
  o.set("node_id", Value::Str(node_id_));
  o.set("leader_id", Value::Str(leader_id_));
  o.set("is_leader", Value::Int(IsLeader() ? 1 : 0));
  Value cand = Value::Array();
  for (const auto& c : candidates_) cand.push_back(Value::Str(c));
  o.set("candidates", std::move(cand));
  return o;
}

// --- FileLeaseLeaderElector ------------------------------------------------

FileLeaseLeaderElector::FileLeaseLeaderElector(const std::string& node_id,
                                               const std::string& lease_path, double lease_seconds)
    : lease_path_(Strip(lease_path)), lease_seconds_(std::max(1.0, lease_seconds)) {
  node_id_ = Strip(node_id);
  if (node_id_.empty()) node_id_ = Hostname();
}

FileLeaseLeaderElector::~FileLeaseLeaderElector() { Stop(); }

bool FileLeaseLeaderElector::ReadLease(std::string& owner, double& expires_at) const {
  owner.clear();
  expires_at = 0.0;
  std::ifstream f(lease_path_, std::ios::binary);
  if (!f) return false;
  std::stringstream ss;
  ss << f.rdbuf();
  const auto parsed = samurai::core::json::Parse(ss.str());
  if (!parsed.ok || !parsed.value.is_object()) return false;
  if (const Value* o = parsed.value.find("owner")) owner = o->as_string("");
  if (const Value* e = parsed.value.find("expires_at")) expires_at = e->as_double(0.0);
  return true;
}

bool FileLeaseLeaderElector::WriteLease(const std::string& owner, double expires_at) const {
  const std::string tmp = lease_path_ + ".tmp." + std::to_string(::getpid());
  {
    std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    Value o = Value::Object();
    o.set("owner", Value::Str(owner));
    o.set("expires_at", Value::Double(expires_at));
    f << o.dump();
    if (!f) return false;
  }
  return ::rename(tmp.c_str(), lease_path_.c_str()) == 0;
}

bool FileLeaseLeaderElector::TryAcquire() {
  const double now = NowSec();
  FileLock lk(lease_path_ + ".lock");
  std::string owner;
  double exp = 0.0;
  ReadLease(owner, exp);
  if (owner == node_id_) {
    WriteLease(node_id_, now + lease_seconds_);
    leader_.store(true);
    return true;
  }
  if (!owner.empty() && exp > now) {
    leader_.store(false);
    return false;
  }
  WriteLease(node_id_, now + lease_seconds_);
  leader_.store(true);
  return true;
}

bool FileLeaseLeaderElector::RenewOnce() {
  const double now = NowSec();
  FileLock lk(lease_path_ + ".lock");
  std::string owner;
  double exp = 0.0;
  ReadLease(owner, exp);
  if (owner != node_id_ || exp <= now) {
    leader_.store(false);
    return false;
  }
  WriteLease(node_id_, now + lease_seconds_);
  leader_.store(true);
  return true;
}

void FileLeaseLeaderElector::Release() {
  FileLock lk(lease_path_ + ".lock");
  std::string owner;
  double exp = 0.0;
  ReadLease(owner, exp);
  if (owner == node_id_) ::remove(lease_path_.c_str());
  leader_.store(false);
}

void FileLeaseLeaderElector::StartRenewLoop(double interval_s) {
  const double iv = std::max(0.2, interval_s);
  stop_.store(false);
  renew_thread_ = std::thread([this, iv]() {
    while (!stop_.load()) {
      std::unique_lock<std::mutex> lk(cv_mu_);
      if (cv_.wait_for(lk, std::chrono::duration<double>(iv), [this]() { return stop_.load(); })) {
        break;  // stop requested
      }
      lk.unlock();
      if (!RenewOnce()) break;
    }
  });
}

void FileLeaseLeaderElector::Stop() {
  stop_.store(true);
  cv_.notify_all();
  if (renew_thread_.joinable()) renew_thread_.join();
  Release();
}

Value FileLeaseLeaderElector::Snapshot() const {
  std::string owner;
  double exp = 0.0;
  ReadLease(owner, exp);
  Value o = Value::Object();
  o.set("mode", Value::Str("file-lock"));
  o.set("node_id", Value::Str(node_id_));
  o.set("leader_id", Value::Str(owner));
  o.set("is_leader", Value::Int(IsLeader() ? 1 : 0));
  o.set("lease_path", Value::Str(lease_path_));
  o.set("lease_seconds", Value::Double(lease_seconds_));
  o.set("lease_expires_at", Value::Double(exp));
  return o;
}

}  // namespace samurai::control
