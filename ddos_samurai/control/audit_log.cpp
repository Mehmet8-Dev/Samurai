#include "audit_log.hpp"

#include <cstdio>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <sys/stat.h>

#include <openssl/sha.h>

namespace samurai::control {

namespace {

using samurai::core::json::Value;

constexpr const char* kSchema = "samurai.rbac.audit.v1";

std::string Sha256Hex(const std::string& data) {
  unsigned char digest[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), digest);
  static const char* kHex = "0123456789abcdef";
  std::string out;
  out.reserve(SHA256_DIGEST_LENGTH * 2);
  for (unsigned char b : digest) {
    out.push_back(kHex[b >> 4]);
    out.push_back(kHex[b & 0x0F]);
  }
  return out;
}

std::string Strip(const std::string& s) {
  const auto first = s.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) return "";
  const auto last = s.find_last_not_of(" \t\r\n");
  return s.substr(first, last - first + 1);
}

// Copy of `row` with the entry_hash member removed.
Value WithoutEntryHash(const Value& row) {
  Value out = Value::Object();
  for (const auto& kv : row.members()) {
    if (kv.first == "entry_hash") continue;
    out.set(kv.first, kv.second);
  }
  return out;
}

bool FileExists(const std::string& path) {
  struct stat st{};
  return ::stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

}  // namespace

RbacAuditLog::RbacAuditLog(const std::string& path) : path_(Strip(path)) {
  if (path_.empty() || !FileExists(path_)) return;
  // Load the last entry's hash to continue the chain.
  std::ifstream f(path_, std::ios::binary);
  std::string line, last;
  while (std::getline(f, line)) {
    if (!Strip(line).empty()) last = line;
  }
  if (last.empty()) return;
  const auto parsed = samurai::core::json::Parse(last);
  if (parsed.ok && parsed.value.is_object()) {
    if (const Value* h = parsed.value.find("entry_hash")) prev_hash_ = h->as_string("");
  }
}

bool RbacAuditLog::Append(const Value& item) {
  if (path_.empty()) return true;  // disabled
  std::lock_guard<std::mutex> lk(mu_);

  Value row = Value::Object();
  if (item.is_object()) {
    for (const auto& kv : item.members()) row.set(kv.first, kv.second);
  }
  row.set("schema", Value::Str(kSchema));
  row.set("prev_hash", Value::Str(prev_hash_));
  // Hash over the sorted-key JSON of the row without entry_hash.
  const std::string entry_hash = Sha256Hex(WithoutEntryHash(row).dump(/*sort_keys=*/true));
  row.set("entry_hash", Value::Str(entry_hash));

  std::ofstream f(path_, std::ios::binary | std::ios::app);
  if (!f) return false;
  f << row.dump() << "\n";
  if (!f) return false;
  prev_hash_ = entry_hash;
  return true;
}

AuditVerifyResult RbacAuditLog::Verify(const std::string& path) {
  const std::string p = Strip(path);
  if (p.empty()) return {false, "empty path"};
  if (!FileExists(p)) return {false, "file not found"};

  std::ifstream f(p, std::ios::binary);
  std::string line;
  std::string prev;
  int lineno = 0;
  while (std::getline(f, line)) {
    ++lineno;
    const std::string txt = Strip(line);
    if (txt.empty()) continue;
    const auto parsed = samurai::core::json::Parse(txt);
    if (!parsed.ok || !parsed.value.is_object()) {
      return {false, "line " + std::to_string(lineno) + ": invalid json object"};
    }
    const Value& rec = parsed.value;
    const Value* prev_h = rec.find("prev_hash");
    const std::string got_prev = prev_h ? prev_h->as_string("") : "";
    if (got_prev != prev) {
      return {false, "line " + std::to_string(lineno) + ": prev_hash mismatch"};
    }
    const Value* eh = rec.find("entry_hash");
    const std::string got_hash = eh ? eh->as_string("") : "";
    if (got_hash.empty()) {
      return {false, "line " + std::to_string(lineno) + ": missing entry_hash"};
    }
    const std::string calc = Sha256Hex(WithoutEntryHash(rec).dump(/*sort_keys=*/true));
    if (calc != got_hash) {
      return {false, "line " + std::to_string(lineno) + ": entry_hash mismatch"};
    }
    prev = got_hash;
  }
  return {true, "ok"};
}

}  // namespace samurai::control
