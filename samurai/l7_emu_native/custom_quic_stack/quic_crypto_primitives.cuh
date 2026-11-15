#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "quic_cuda_crypto.hpp"

#ifndef __CUDACC__
#ifndef __host__
#define __host__
#endif
#ifndef __device__
#define __device__
#endif
#ifndef __forceinline__
#define __forceinline__ inline
#endif
#endif

namespace samurai::l7_emu_native::custom_quic_stack::primitives {

// ============================================================================
// 1. SHA-256 & HMAC-SHA256 & TLS 1.3 HKDF-Expand-Label (RFC 9001 Section 5.2)
// ============================================================================

__host__ __device__ __forceinline__ uint32_t rotr32(uint32_t x, uint32_t n) {
  return (x >> n) | (x << (32u - n));
}

__host__ __device__ __forceinline__ uint32_t rotl32(uint32_t x, uint32_t n) {
  return (x << n) | (x >> (32u - n));
}

__host__ __device__ __forceinline__ uint32_t load_be32(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) |
         (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) |
         static_cast<uint32_t>(p[3]);
}

__host__ __device__ __forceinline__ void store_be32(uint8_t* p, uint32_t v) {
  p[0] = static_cast<uint8_t>((v >> 24) & 0xffu);
  p[1] = static_cast<uint8_t>((v >> 16) & 0xffu);
  p[2] = static_cast<uint8_t>((v >> 8) & 0xffu);
  p[3] = static_cast<uint8_t>(v & 0xffu);
}

__host__ __device__ __forceinline__ uint32_t load_le32(const uint8_t* p) {
  return static_cast<uint32_t>(p[0]) |
         (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) |
         (static_cast<uint32_t>(p[3]) << 24);
}

__host__ __device__ __forceinline__ void store_le32(uint8_t* p, uint32_t v) {
  p[0] = static_cast<uint8_t>(v & 0xffu);
  p[1] = static_cast<uint8_t>((v >> 8) & 0xffu);
  p[2] = static_cast<uint8_t>((v >> 16) & 0xffu);
  p[3] = static_cast<uint8_t>((v >> 24) & 0xffu);
}

__host__ __device__ inline void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
  static constexpr uint32_t K[64] = {
      0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
      0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
      0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
      0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
      0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcU, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
      0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
      0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
      0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffaU, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

  uint32_t w[64];
  for (int i = 0; i < 16; ++i) {
    w[i] = load_be32(block + i * 4);
  }
  for (int i = 16; i < 64; ++i) {
    const uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
    const uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
  uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

  for (int i = 0; i < 64; ++i) {
    const uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
    const uint32_t ch = (e & f) ^ ((~e) & g);
    const uint32_t temp1 = h + S1 + ch + K[i] + w[i];
    const uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
    const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    const uint32_t temp2 = S0 + maj;

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;
}

// Compute SHA-256 over a two-part message (part1 || part2), total len <= 119 bytes
__host__ __device__ inline void sha256_two_parts(
    const uint8_t* p1, std::size_t len1,
    const uint8_t* p2, std::size_t len2,
    uint8_t out[32]) {
  uint32_t state[8] = {
      0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
      0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};

  uint8_t buf[128];
  for (int i = 0; i < 128; ++i) buf[i] = 0;
  for (std::size_t i = 0; i < len1; ++i) buf[i] = p1[i];
  for (std::size_t i = 0; i < len2; ++i) buf[len1 + i] = p2[i];

  const std::size_t total = len1 + len2;
  buf[total] = 0x80u;
  const uint64_t bit_len = static_cast<uint64_t>(total) * 8ull;

  if (total + 1 + 8 <= 64) {
    store_be32(buf + 56, static_cast<uint32_t>(bit_len >> 32));
    store_be32(buf + 60, static_cast<uint32_t>(bit_len & 0xffffffffu));
    sha256_transform(state, buf);
  } else {
    store_be32(buf + 120, static_cast<uint32_t>(bit_len >> 32));
    store_be32(buf + 124, static_cast<uint32_t>(bit_len & 0xffffffffu));
    sha256_transform(state, buf);
    sha256_transform(state, buf + 64);
  }

  for (int i = 0; i < 8; ++i) {
    store_be32(out + i * 4, state[i]);
  }
}

// Compute HMAC-SHA256 where key_len <= 64 and msg_len <= 55
__host__ __device__ inline void hmac_sha256(
    const uint8_t* key, std::size_t key_len,
    const uint8_t* msg, std::size_t msg_len,
    uint8_t out[32]) {
  uint8_t k_ipad[64];
  uint8_t k_opad[64];
  for (std::size_t i = 0; i < 64; ++i) {
    const uint8_t kb = (i < key_len) ? key[i] : 0u;
    k_ipad[i] = kb ^ 0x36u;
    k_opad[i] = kb ^ 0x5cu;
  }
  uint8_t inner_hash[32];
  sha256_two_parts(k_ipad, 64, msg, msg_len, inner_hash);
  sha256_two_parts(k_opad, 64, inner_hash, 32, out);
}

// TLS 1.3 / QUIC HKDF-Expand-Label (for out_len <= 32, empty context)
// label is without "tls13 " prefix (e.g. "client in", "quic key", "quic iv", "quic hp")
__host__ __device__ inline void hkdf_expand_label_sha256(
    const uint8_t secret[32],
    const char* label,
    std::size_t label_len,
    uint8_t* out,
    std::size_t out_len) {
  uint8_t info[32];
  info[0] = 0u;
  info[1] = static_cast<uint8_t>(out_len);
  const std::size_t full_label_len = 6u + label_len;
  info[2] = static_cast<uint8_t>(full_label_len);
  info[3] = 't';
  info[4] = 'l';
  info[5] = 's';
  info[6] = '1';
  info[7] = '3';
  info[8] = ' ';
  for (std::size_t i = 0; i < label_len; ++i) {
    info[9 + i] = static_cast<uint8_t>(label[i]);
  }
  info[9 + label_len] = 0u;      // context length = 0
  info[9 + label_len + 1] = 1u;  // HKDF-Expand iteration counter = 0x01

  uint8_t digest[32];
  hmac_sha256(secret, 32, info, 9 + label_len + 2, digest);
  for (std::size_t i = 0; i < out_len; ++i) {
    out[i] = digest[i];
  }
}

// Full RFC 9001 Section 5.2 QUIC v1 Initial Key Derivation from 8-byte DCID
__host__ __device__ inline void derive_quic_v1_initial_keys_8b(
    const uint8_t dcid[8],
    const uint8_t scid[8],
    QuicInitialKeyMaterial* out) {
  // RFC 9001 Section 5.2 QUIC v1 initial_salt
  static constexpr uint8_t kQuicV1InitialSalt[20] = {
      0x38u, 0x76u, 0x2cu, 0xf7u, 0xf5u, 0x59u, 0x34u, 0xb3u, 0x4du, 0x17u,
      0x9au, 0xe6u, 0xa4u, 0xc8u, 0x0cu, 0xadu, 0xccu, 0xbbu, 0x7fu, 0x0au};

  for (int i = 0; i < 8; ++i) {
    out->dcid[i] = dcid[i];
    out->scid[i] = (scid != nullptr) ? scid[i] : 0u;
  }
  out->reserved = 0u;

  // 1. initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
  hmac_sha256(kQuicV1InitialSalt, 20, dcid, 8, out->initial_secret);

  // 2. client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
  hkdf_expand_label_sha256(out->initial_secret, "client in", 9, out->client_initial_secret, 32);

  // 3. quic_key (16B), quic_iv (12B), quic_hp (16B)
  hkdf_expand_label_sha256(out->client_initial_secret, "quic key", 8, out->quic_key, 16);
  hkdf_expand_label_sha256(out->client_initial_secret, "quic iv", 7, out->quic_iv, 12);
  hkdf_expand_label_sha256(out->client_initial_secret, "quic hp", 7, out->quic_hp, 16);
}

// ============================================================================
// 2. AES-128 Key Schedule, ECB Header Protection, CTR & GCM (RFC 9001 Sec 5.3/5.4.3)
// ============================================================================

__host__ __device__ inline uint8_t aes_sbox(uint8_t x) {
  static constexpr uint8_t kSbox[256] = {
      0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
      0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
      0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
      0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
      0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
      0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
      0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
      0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
      0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
      0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
      0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
      0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
      0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
      0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
      0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
      0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};
  return kSbox[x];
}

__host__ __device__ __forceinline__ uint8_t gf256_xtime(uint8_t x) {
  return static_cast<uint8_t>((x << 1) ^ ((x & 0x80u) ? 0x1bu : 0x00u));
}

__host__ __device__ inline void aes128_expand_key(const uint8_t key[16], uint8_t round_keys[176]) {
  static constexpr uint8_t kRcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
  for (int i = 0; i < 16; ++i) {
    round_keys[i] = key[i];
  }
  uint8_t temp[4];
  for (int i = 4; i < 44; ++i) {
    for (int j = 0; j < 4; ++j) {
      temp[j] = round_keys[(i - 1) * 4 + j];
    }
    if (i % 4 == 0) {
      const uint8_t t = temp[0];
      temp[0] = aes_sbox(temp[1]) ^ kRcon[(i / 4) - 1];
      temp[1] = aes_sbox(temp[2]);
      temp[2] = aes_sbox(temp[3]);
      temp[3] = aes_sbox(t);
    }
    for (int j = 0; j < 4; ++j) {
      round_keys[i * 4 + j] = round_keys[(i - 4) * 4 + j] ^ temp[j];
    }
  }
}

__host__ __device__ inline void aes128_encrypt_block(
    const uint8_t round_keys[176],
    const uint8_t in[16],
    uint8_t out[16]) {
  uint8_t s[16];
  for (int i = 0; i < 16; ++i) {
    s[i] = in[i] ^ round_keys[i];
  }

  for (int round = 1; round <= 10; ++round) {
    // SubBytes
    for (int i = 0; i < 16; ++i) {
      s[i] = aes_sbox(s[i]);
    }
    // ShiftRows
    uint8_t t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
    t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;

    // MixColumns (rounds 1..9)
    if (round < 10) {
      for (int c = 0; c < 4; ++c) {
        const int idx = c * 4;
        const uint8_t a0 = s[idx + 0];
        const uint8_t a1 = s[idx + 1];
        const uint8_t a2 = s[idx + 2];
        const uint8_t a3 = s[idx + 3];
        const uint8_t all = a0 ^ a1 ^ a2 ^ a3;
        s[idx + 0] ^= all ^ gf256_xtime(a0 ^ a1);
        s[idx + 1] ^= all ^ gf256_xtime(a1 ^ a2);
        s[idx + 2] ^= all ^ gf256_xtime(a2 ^ a3);
        s[idx + 3] ^= all ^ gf256_xtime(a3 ^ a0);
      }
    }

    // AddRoundKey
    const uint8_t* rk = round_keys + round * 16;
    for (int i = 0; i < 16; ++i) {
      s[i] ^= rk[i];
    }
  }

  for (int i = 0; i < 16; ++i) {
    out[i] = s[i];
  }
}

// GHASH multiplication in GF(2^128) (NIST SP 800-38D)
__host__ __device__ inline void ghash_mul(uint8_t X[16], const uint8_t H[16]) {
  uint8_t Z[16] = {0};
  uint8_t V[16];
  for (int i = 0; i < 16; ++i) V[i] = H[i];

  for (int i = 0; i < 16; ++i) {
    uint8_t xb = X[i];
    for (int bit = 7; bit >= 0; --bit) {
      if ((xb >> bit) & 1u) {
        for (int k = 0; k < 16; ++k) Z[k] ^= V[k];
      }
      const uint8_t lsb = V[15] & 1u;
      for (int k = 15; k > 0; --k) {
        V[k] = static_cast<uint8_t>((V[k] >> 1) | ((V[k - 1] & 1u) << 7));
      }
      V[0] >>= 1;
      if (lsb) {
        V[0] ^= 0xe1u;
      }
    }
  }
  for (int i = 0; i < 16; ++i) X[i] = Z[i];
}

// Full AES-128-GCM AEAD + RFC 9001 Section 5.4.3 AES-128-ECB Header Protection
__host__ __device__ inline void quic_aes128_gcm_encrypt_and_hp(
    QuicAeadBatchItem* item,
    uint8_t* pkt_buf) {
  uint8_t rk_aead[176];
  aes128_expand_key(item->key, rk_aead);

  // 1. Compute GHASH subkey H = AES_K(0^128)
  const uint8_t zero_block[16] = {0};
  uint8_t H[16];
  aes128_encrypt_block(rk_aead, zero_block, H);

  // 2. Construct 96-bit nonce = iv ^ pkt_num, and J0 = nonce || 0x00000001
  uint8_t j0[16];
  for (int i = 0; i < 12; ++i) {
    j0[i] = item->iv[i];
  }
  uint64_t pn = item->pkt_num;
  for (int i = 0; i < 8; ++i) {
    j0[11 - i] ^= static_cast<uint8_t>(pn & 0xffu);
    pn >>= 8;
  }
  j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;

  // 3. Encrypt payload with AES-128-CTR starting at counter = J0 + 1
  uint8_t ctr[16];
  for (int i = 0; i < 16; ++i) ctr[i] = j0[i];
  uint32_t counter_val = 1u;

  uint8_t* payload = pkt_buf + item->aad_len;
  const uint32_t pt_len = item->plaintext_len;
  for (uint32_t off = 0; off < pt_len; off += 16u) {
    ++counter_val;
    store_be32(ctr + 12, counter_val);
    uint8_t ks[16];
    aes128_encrypt_block(rk_aead, ctr, ks);
    const uint32_t chunk = (pt_len - off < 16u) ? (pt_len - off) : 16u;
    for (uint32_t j = 0; j < chunk; ++j) {
      payload[off + j] ^= ks[j];
    }
  }

  // 4. Compute GHASH over AAD, Ciphertext, and 64-bit bit-lengths
  uint8_t ghash_state[16] = {0};
  const uint32_t aad_len = item->aad_len;
  for (uint32_t off = 0; off < aad_len; off += 16u) {
    const uint32_t chunk = (aad_len - off < 16u) ? (aad_len - off) : 16u;
    for (uint32_t j = 0; j < chunk; ++j) {
      ghash_state[j] ^= pkt_buf[off + j];
    }
    ghash_mul(ghash_state, H);
  }
  for (uint32_t off = 0; off < pt_len; off += 16u) {
    const uint32_t chunk = (pt_len - off < 16u) ? (pt_len - off) : 16u;
    for (uint32_t j = 0; j < chunk; ++j) {
      ghash_state[j] ^= payload[off + j];
    }
    ghash_mul(ghash_state, H);
  }
  uint8_t len_block[16] = {0};
  const uint64_t aad_bits = static_cast<uint64_t>(aad_len) * 8ull;
  const uint64_t ct_bits = static_cast<uint64_t>(pt_len) * 8ull;
  store_be32(len_block + 0, static_cast<uint32_t>(aad_bits >> 32));
  store_be32(len_block + 4, static_cast<uint32_t>(aad_bits & 0xffffffffu));
  store_be32(len_block + 8, static_cast<uint32_t>(ct_bits >> 32));
  store_be32(len_block + 12, static_cast<uint32_t>(ct_bits & 0xffffffffu));
  for (int i = 0; i < 16; ++i) {
    ghash_state[i] ^= len_block[i];
  }
  ghash_mul(ghash_state, H);

  uint8_t tag_mask[16];
  aes128_encrypt_block(rk_aead, j0, tag_mask);
  uint8_t* tag_dst = payload + pt_len;
  for (int i = 0; i < 16; ++i) {
    const uint8_t t = ghash_state[i] ^ tag_mask[i];
    tag_dst[i] = t;
    item->tag_out[i] = t;
  }

  // 5. RFC 9001 Section 5.4.3 Header Protection (sample at pn_offset + 4)
  if (item->pn_offset + 4u + 16u <= aad_len + pt_len + 16u) {
    uint8_t rk_hp[176];
    aes128_expand_key(item->hp_key, rk_hp);
    uint8_t hp_block[16];
    aes128_encrypt_block(rk_hp, pkt_buf + item->pn_offset + 4u, hp_block);
    for (int i = 0; i < 5; ++i) {
      item->hp_mask_out[i] = hp_block[i];
    }
    if ((pkt_buf[0] & 0x80u) != 0u) {
      pkt_buf[0] ^= (hp_block[0] & 0x0fu);
    } else {
      pkt_buf[0] ^= (hp_block[0] & 0x1fu);
    }
    const uint32_t pn_len = (item->pn_length >= 1u && item->pn_length <= 4u) ? item->pn_length : 4u;
    for (uint32_t i = 0; i < pn_len; ++i) {
      pkt_buf[item->pn_offset + i] ^= hp_block[1u + i];
    }
  }
}

// ============================================================================
// 3. ChaCha20-Poly1305 AEAD & ChaCha20 Header Protection (RFC 8439 / RFC 9001)
// ============================================================================

#define SAMURAI_CHACHA_QR(a, b, c, d) \
  do {                                \
    a += b; d ^= a; d = rotl32(d, 16);\
    c += d; b ^= c; b = rotl32(b, 12);\
    a += b; d ^= a; d = rotl32(d, 8); \
    c += d; b ^= c; b = rotl32(b, 7); \
  } while (0)

__host__ __device__ inline void chacha20_block(
    const uint8_t key[32],
    uint32_t counter,
    const uint8_t nonce[12],
    uint8_t out[64]) {
  uint32_t state[16] = {
      0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u,
      load_le32(key + 0),  load_le32(key + 4),  load_le32(key + 8),  load_le32(key + 12),
      load_le32(key + 16), load_le32(key + 20), load_le32(key + 24), load_le32(key + 28),
      counter,
      load_le32(nonce + 0), load_le32(nonce + 4), load_le32(nonce + 8)};

  uint32_t x[16];
  for (int i = 0; i < 16; ++i) x[i] = state[i];

  for (int i = 0; i < 10; ++i) {
    SAMURAI_CHACHA_QR(x[0], x[4], x[8],  x[12]);
    SAMURAI_CHACHA_QR(x[1], x[5], x[9],  x[13]);
    SAMURAI_CHACHA_QR(x[2], x[6], x[10], x[14]);
    SAMURAI_CHACHA_QR(x[3], x[7], x[11], x[15]);
    SAMURAI_CHACHA_QR(x[0], x[5], x[10], x[15]);
    SAMURAI_CHACHA_QR(x[1], x[6], x[11], x[12]);
    SAMURAI_CHACHA_QR(x[2], x[7], x[8],  x[13]);
    SAMURAI_CHACHA_QR(x[3], x[4], x[9],  x[14]);
  }

  for (int i = 0; i < 16; ++i) {
    store_le32(out + i * 4, x[i] + state[i]);
  }
}

#undef SAMURAI_CHACHA_QR

// Poly1305 26-bit limb accumulator (RFC 8439 Section 2.5)
struct Poly1305State {
  uint32_t r[5];
  uint32_t s[4];
  uint32_t h[5];
};

__host__ __device__ inline void poly1305_init(Poly1305State* st, const uint8_t key[32]) {
  const uint32_t t0 = load_le32(key + 0);
  const uint32_t t1 = load_le32(key + 4);
  const uint32_t t2 = load_le32(key + 8);
  const uint32_t t3 = load_le32(key + 12);

  st->r[0] = t0 & 0x3ffffffu;
  st->r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03u;
  st->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ffu;
  st->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fffu;
  st->r[4] = (t3 >> 8) & 0x00fffffu;

  st->s[0] = load_le32(key + 16);
  st->s[1] = load_le32(key + 20);
  st->s[2] = load_le32(key + 24);
  st->s[3] = load_le32(key + 28);

  for (int i = 0; i < 5; ++i) st->h[i] = 0;
}

__host__ __device__ inline void poly1305_block(Poly1305State* st, const uint8_t block[16], uint32_t hibit) {
  const uint32_t t0 = load_le32(block + 0);
  const uint32_t t1 = load_le32(block + 4);
  const uint32_t t2 = load_le32(block + 8);
  const uint32_t t3 = load_le32(block + 12);

  uint32_t h0 = st->h[0] + (t0 & 0x3ffffffu);
  uint32_t h1 = st->h[1] + (((t0 >> 26) | (t1 << 6)) & 0x3ffffffu);
  uint32_t h2 = st->h[2] + (((t1 >> 20) | (t2 << 12)) & 0x3ffffffu);
  uint32_t h3 = st->h[3] + (((t2 >> 14) | (t3 << 18)) & 0x3ffffffu);
  uint32_t h4 = st->h[4] + (t3 >> 8) + (hibit << 24);

  const uint32_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2], r3 = st->r[3], r4 = st->r[4];
  const uint32_t s1 = r1 * 5u, s2 = r2 * 5u, s3 = r3 * 5u, s4 = r4 * 5u;

  uint64_t d0 = static_cast<uint64_t>(h0) * r0 + static_cast<uint64_t>(h1) * s4 +
                static_cast<uint64_t>(h2) * s3 + static_cast<uint64_t>(h3) * s2 +
                static_cast<uint64_t>(h4) * s1;
  uint64_t d1 = static_cast<uint64_t>(h0) * r1 + static_cast<uint64_t>(h1) * r0 +
                static_cast<uint64_t>(h2) * s4 + static_cast<uint64_t>(h3) * s3 +
                static_cast<uint64_t>(h4) * s2;
  uint64_t d2 = static_cast<uint64_t>(h0) * r2 + static_cast<uint64_t>(h1) * r1 +
                static_cast<uint64_t>(h2) * r0 + static_cast<uint64_t>(h3) * s4 +
                static_cast<uint64_t>(h4) * s3;
  uint64_t d3 = static_cast<uint64_t>(h0) * r3 + static_cast<uint64_t>(h1) * r2 +
                static_cast<uint64_t>(h2) * r1 + static_cast<uint64_t>(h3) * r0 +
                static_cast<uint64_t>(h4) * s4;
  uint64_t d4 = static_cast<uint64_t>(h0) * r4 + static_cast<uint64_t>(h1) * r3 +
                static_cast<uint64_t>(h2) * r2 + static_cast<uint64_t>(h3) * r1 +
                static_cast<uint64_t>(h4) * r0;

  uint32_t c = static_cast<uint32_t>(d0 >> 26); h0 = static_cast<uint32_t>(d0) & 0x3ffffffu;
  d1 += c; c = static_cast<uint32_t>(d1 >> 26); h1 = static_cast<uint32_t>(d1) & 0x3ffffffu;
  d2 += c; c = static_cast<uint32_t>(d2 >> 26); h2 = static_cast<uint32_t>(d2) & 0x3ffffffu;
  d3 += c; c = static_cast<uint32_t>(d3 >> 26); h3 = static_cast<uint32_t>(d3) & 0x3ffffffu;
  d4 += c; c = static_cast<uint32_t>(d4 >> 26); h4 = static_cast<uint32_t>(d4) & 0x3ffffffu;
  h0 += c * 5u; c = h0 >> 26; h0 &= 0x3ffffffu;
  h1 += c;

  st->h[0] = h0; st->h[1] = h1; st->h[2] = h2; st->h[3] = h3; st->h[4] = h4;
}

__host__ __device__ inline void poly1305_finish(Poly1305State* st, uint8_t mac[16]) {
  uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];
  uint32_t c = h1 >> 26; h1 &= 0x3ffffffu;
  h2 += c; c = h2 >> 26; h2 &= 0x3ffffffu;
  h3 += c; c = h3 >> 26; h3 &= 0x3ffffffu;
  h4 += c; c = h4 >> 26; h4 &= 0x3ffffffu;
  h0 += c * 5u; c = h0 >> 26; h0 &= 0x3ffffffu;
  h1 += c;

  uint32_t g0 = h0 + 5u; c = g0 >> 26; g0 &= 0x3ffffffu;
  uint32_t g1 = h1 + c;  c = g1 >> 26; g1 &= 0x3ffffffu;
  uint32_t g2 = h2 + c;  c = g2 >> 26; g2 &= 0x3ffffffu;
  uint32_t g3 = h3 + c;  c = g3 >> 26; g3 &= 0x3ffffffu;
  uint32_t g4 = h4 + c - (1u << 26);

  uint32_t mask = (g4 >> 31) - 1u;
  g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
  mask = ~mask;
  h0 = (h0 & mask) | g0;
  h1 = (h1 & mask) | g1;
  h2 = (h2 & mask) | g2;
  h3 = (h3 & mask) | g3;
  h4 = (h4 & mask) | g4;

  const uint64_t f0 = static_cast<uint64_t>(h0 | (h1 << 26)) + st->s[0];
  const uint64_t f1 = static_cast<uint64_t>((h1 >> 6) | (h2 << 20)) + st->s[1] + (f0 >> 32);
  const uint64_t f2 = static_cast<uint64_t>((h2 >> 12) | (h3 << 14)) + st->s[2] + (f1 >> 32);
  const uint64_t f3 = static_cast<uint64_t>((h3 >> 18) | (h4 << 8)) + st->s[3] + (f2 >> 32);

  store_le32(mac + 0,  static_cast<uint32_t>(f0));
  store_le32(mac + 4,  static_cast<uint32_t>(f1));
  store_le32(mac + 8,  static_cast<uint32_t>(f2));
  store_le32(mac + 12, static_cast<uint32_t>(f3));
}

__host__ __device__ inline void quic_chacha20_poly1305_encrypt_and_hp(
    QuicAeadBatchItem* item,
    uint8_t* pkt_buf) {
  uint8_t nonce[12];
  for (int i = 0; i < 12; ++i) nonce[i] = item->iv[i];
  uint64_t pn = item->pkt_num;
  for (int i = 0; i < 8; ++i) {
    nonce[11 - i] ^= static_cast<uint8_t>(pn & 0xffu);
    pn >>= 8;
  }

  // 1. Block 0 -> Poly1305 one-time key
  uint8_t otk_block[64];
  chacha20_block(item->key, 0u, nonce, otk_block);
  Poly1305State poly;
  poly1305_init(&poly, otk_block);

  // 2. Encrypt payload starting at counter = 1
  uint8_t* payload = pkt_buf + item->aad_len;
  const uint32_t pt_len = item->plaintext_len;
  uint32_t block_counter = 1u;
  for (uint32_t off = 0; off < pt_len; off += 64u, ++block_counter) {
    uint8_t ks[64];
    chacha20_block(item->key, block_counter, nonce, ks);
    const uint32_t chunk = (pt_len - off < 64u) ? (pt_len - off) : 64u;
    for (uint32_t j = 0; j < chunk; ++j) {
      payload[off + j] ^= ks[j];
    }
  }

  // 3. Poly1305 over padded AAD, padded Ciphertext, and 64-bit LE lengths
  const uint32_t aad_len = item->aad_len;
  for (uint32_t off = 0; off < aad_len; off += 16u) {
    uint8_t b[16] = {0};
    const uint32_t chunk = (aad_len - off < 16u) ? (aad_len - off) : 16u;
    for (uint32_t j = 0; j < chunk; ++j) b[j] = pkt_buf[off + j];
    poly1305_block(&poly, b, 1u);
  }
  for (uint32_t off = 0; off < pt_len; off += 16u) {
    uint8_t b[16] = {0};
    const uint32_t chunk = (pt_len - off < 16u) ? (pt_len - off) : 16u;
    for (uint32_t j = 0; j < chunk; ++j) b[j] = payload[off + j];
    poly1305_block(&poly, b, 1u);
  }
  uint8_t len_b[16] = {0};
  store_le32(len_b + 0, aad_len);
  store_le32(len_b + 8, pt_len);
  poly1305_block(&poly, len_b, 1u);

  uint8_t* tag_dst = payload + pt_len;
  poly1305_finish(&poly, item->tag_out);
  for (int i = 0; i < 16; ++i) tag_dst[i] = item->tag_out[i];

  // 4. RFC 9001 Section 5.4.4 ChaCha20 Header Protection
  if (item->pn_offset + 4u + 16u <= aad_len + pt_len + 16u) {
    const uint8_t* sample = pkt_buf + item->pn_offset + 4u;
    const uint32_t hp_counter = load_le32(sample);
    uint8_t hp_block[64];
    chacha20_block(item->hp_key, hp_counter, sample + 4, hp_block);
    for (int i = 0; i < 5; ++i) item->hp_mask_out[i] = hp_block[i];
    if ((pkt_buf[0] & 0x80u) != 0u) {
      pkt_buf[0] ^= (hp_block[0] & 0x0fu);
    } else {
      pkt_buf[0] ^= (hp_block[0] & 0x1fu);
    }
    const uint32_t pn_len = (item->pn_length >= 1u && item->pn_length <= 4u) ? item->pn_length : 4u;
    for (uint32_t i = 0; i < pn_len; ++i) {
      pkt_buf[item->pn_offset + i] ^= hp_block[1u + i];
    }
  }
}

}  // namespace samurai::l7_emu_native::custom_quic_stack::primitives
