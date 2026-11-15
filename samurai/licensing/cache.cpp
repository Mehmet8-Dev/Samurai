#include "cache.hpp"

#include <chrono>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "constants.hpp"
#include "json.hpp"

namespace samurai::licensing {

namespace {

using samurai::core::json::Value;

constexpr int kNonceLen = 12;
constexpr int kTagLen = 16;

double NowSec() {
  using namespace std::chrono;
  return duration_cast<duration<double>>(system_clock::now().time_since_epoch()).count();
}

// 32-byte AES key = SHA256("samurai-cache-" + hwid).
void DeriveKey(const std::string& hwid, unsigned char key[32]) {
  const std::string material = "samurai-cache-" + hwid;
  SHA256(reinterpret_cast<const unsigned char*>(material.data()), material.size(), key);
}

bool AesGcmEncrypt(const unsigned char key[32], const std::string& plaintext, std::string& out) {
  unsigned char nonce[kNonceLen];
  if (RAND_bytes(nonce, kNonceLen) != 1) return false;
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return false;
  bool ok = false;
  std::string ct(plaintext.size(), '\0');
  unsigned char tag[kTagLen];
  int len = 0, total = 0;
  do {
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kNonceLen, nullptr) != 1) break;
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) break;
    if (!plaintext.empty() &&
        EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&ct[0]), &len,
                          reinterpret_cast<const unsigned char*>(plaintext.data()),
                          static_cast<int>(plaintext.size())) != 1)
      break;
    total = len;
    if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&ct[0]) + total, &len) != 1) break;
    total += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kTagLen, tag) != 1) break;
    ok = true;
  } while (false);
  EVP_CIPHER_CTX_free(ctx);
  if (!ok) return false;
  ct.resize(static_cast<std::size_t>(total));
  out.assign(reinterpret_cast<char*>(nonce), kNonceLen);
  out.append(ct);
  out.append(reinterpret_cast<char*>(tag), kTagLen);
  return true;
}

bool AesGcmDecrypt(const unsigned char key[32], const std::string& blob, std::string& out) {
  if (blob.size() < static_cast<std::size_t>(kNonceLen + kTagLen)) return false;
  const unsigned char* nonce = reinterpret_cast<const unsigned char*>(blob.data());
  const std::size_t ct_len = blob.size() - kNonceLen - kTagLen;
  const unsigned char* ct = reinterpret_cast<const unsigned char*>(blob.data()) + kNonceLen;
  const unsigned char* tag = reinterpret_cast<const unsigned char*>(blob.data()) + kNonceLen + ct_len;

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return false;
  bool ok = false;
  std::string pt(ct_len, '\0');
  int len = 0, total = 0;
  do {
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kNonceLen, nullptr) != 1) break;
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) break;
    if (ct_len > 0 &&
        EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&pt[0]), &len, ct,
                          static_cast<int>(ct_len)) != 1)
      break;
    total = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kTagLen,
                            const_cast<unsigned char*>(tag)) != 1)
      break;
    if (EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&pt[0]) + total, &len) != 1)
      break;  // authentication failed
    total += len;
    ok = true;
  } while (false);
  EVP_CIPHER_CTX_free(ctx);
  if (!ok) return false;
  pt.resize(static_cast<std::size_t>(total));
  out.swap(pt);
  return true;
}

bool FileExists(const std::string& path) {
  struct stat st{};
  return ::stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

}  // namespace

bool SaveCache(const LicenseResult& result, const std::string& hwid) {
  ::mkdir(CacheDir().c_str(), 0700);

  Value payload = Value::Object();
  payload.set("valid", Value::Bool(result.valid));
  payload.set("tier", Value::Str(TierName(result.tier)));
  Value features = Value::Array();
  for (const auto& f : result.features) features.push_back(Value::Str(f));
  payload.set("features", std::move(features));
  payload.set("expires", Value::Str(result.expires));
  payload.set("customer_email", Value::Str(result.customer_email));
  payload.set("session_id", Value::Str(result.session_id));
  payload.set("cached_at", Value::Double(NowSec()));
  if (result.limits.has_value) {
    Value lm = Value::Object();
    lm.set("max_workers", Value::Int(result.limits.max_workers));
    lm.set("max_pps", Value::Int(result.limits.max_pps));
    lm.set("max_duration_s", Value::Int(result.limits.max_duration_s));
    lm.set("max_devices", Value::Int(result.limits.max_devices));
    payload.set("limits", std::move(lm));
  } else {
    payload.set("limits", Value::Null());
  }

  unsigned char key[32];
  DeriveKey(hwid, key);
  std::string blob;
  if (!AesGcmEncrypt(key, payload.dump(), blob)) return false;

  const std::string path = CacheFile();
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  if (!f) return false;
  f.write(blob.data(), static_cast<std::streamsize>(blob.size()));
  if (!f) return false;
  f.close();
  ::chmod(path.c_str(), 0600);
  return true;
}

bool LoadCache(const std::string& hwid, LicenseResult& out) {
  const std::string path = CacheFile();
  if (!FileExists(path)) return false;

  std::ifstream f(path, std::ios::binary);
  std::stringstream ss;
  ss << f.rdbuf();
  const std::string blob = ss.str();

  unsigned char key[32];
  DeriveKey(hwid, key);
  std::string plaintext;
  if (!AesGcmDecrypt(key, blob, plaintext)) {
    ::remove(path.c_str());
    return false;
  }
  const auto parsed = samurai::core::json::Parse(plaintext);
  if (!parsed.ok || !parsed.value.is_object()) {
    ::remove(path.c_str());
    return false;
  }
  const Value& p = parsed.value;
  const Value* cached_at = p.find("cached_at");
  const double age = NowSec() - (cached_at ? cached_at->as_double(0.0) : 0.0);
  if (age > static_cast<double>(OfflineGracePeriodS())) {
    ::remove(path.c_str());
    return false;  // grace period elapsed
  }

  LicenseResult r;
  r.valid = p.find("valid") && p.find("valid")->as_bool();
  r.tier = TierFromName(p.find("tier") ? p.find("tier")->as_string("community") : "community");
  if (const Value* fs = p.find("features")) {
    if (fs->is_array()) {
      for (const auto& e : fs->elements()) r.features.push_back(e.as_string(""));
    }
  }
  if (const Value* lm = p.find("limits")) {
    if (lm->is_object()) {
      r.limits.has_value = true;
      r.limits.max_workers = static_cast<int>(lm->find("max_workers") ? lm->find("max_workers")->as_int(0) : 0);
      r.limits.max_pps = static_cast<int>(lm->find("max_pps") ? lm->find("max_pps")->as_int(0) : 0);
      r.limits.max_duration_s = static_cast<int>(lm->find("max_duration_s") ? lm->find("max_duration_s")->as_int(0) : 0);
      r.limits.max_devices = static_cast<int>(lm->find("max_devices") ? lm->find("max_devices")->as_int(1) : 1);
    }
  }
  r.expires = p.find("expires") ? p.find("expires")->as_string("") : "";
  r.customer_email = p.find("customer_email") ? p.find("customer_email")->as_string("") : "";
  r.session_id = p.find("session_id") ? p.find("session_id")->as_string("") : "";
  r.reason = "offline_cache";
  r.offline = true;
  out = std::move(r);
  return true;
}

void ClearCache() {
  const std::string path = CacheFile();
  if (FileExists(path)) ::remove(path.c_str());
}

}  // namespace samurai::licensing
