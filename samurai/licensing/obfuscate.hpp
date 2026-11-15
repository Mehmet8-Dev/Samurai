#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace samurai::licensing {

// Compile-time XOR string obfuscation to prevent plain-text sensitive strings
// (license URLs, endpoints, keys) from showing up in .rodata / IDA / Ghidra.
template <size_t N, uint8_t Key>
class XorString {
 public:
  constexpr explicit XorString(const char (&str)[N]) {
    for (size_t i = 0; i < N; ++i) {
      data_[i] = static_cast<char>(str[i] ^ (Key + (static_cast<uint8_t>(i) * 7U)));
    }
  }

  std::string decrypt() const {
    std::string s;
    if (N <= 1) return s;
    s.resize(N - 1);
    for (size_t i = 0; i < N - 1; ++i) {
      s[i] = static_cast<char>(data_[i] ^ (Key + (static_cast<uint8_t>(i) * 7U)));
    }
    return s;
  }

 private:
  char data_[N]{};
};

#define SAMURAI_OBFUSCATE_KEY(seed) static_cast<uint8_t>((((seed) * 167U) + 13U) & 0xFFU)

#define SAMURAI_OBFUSCATE(str) \
  ([]() -> std::string { \
    static constexpr auto obfuscated = \
        ::samurai::licensing::XorString<sizeof(str), SAMURAI_OBFUSCATE_KEY(__LINE__)>(str); \
    return obfuscated.decrypt(); \
  }())

}  // namespace samurai::licensing
