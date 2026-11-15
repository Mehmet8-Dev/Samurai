#include "quic_cuda_crypto.hpp"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>

#include "quic_crypto_primitives.cuh"

namespace samurai::l7_emu_native::custom_quic_stack {

#if defined(SAMURAI_WITH_QUIC_CUDA_CRYPTO)
extern "C" bool samurai_quic_cuda_probe_device(int* device_id_out);
extern "C" bool samurai_quic_cuda_derive_initial_keys(
    const uint8_t* dcids_8b,
    const uint8_t* scids_8b,
    std::size_t count,
    QuicInitialKeyMaterial* out_materials);
extern "C" bool samurai_quic_cuda_aes128_hp_mask(
    const uint8_t* hp_keys_16b,
    const uint8_t* samples_16b,
    std::size_t count,
    uint8_t* masks_5b_out);
extern "C" bool samurai_quic_cuda_aead_encrypt(
    QuicAeadBatchItem* items,
    uint8_t* packet_buffers,
    std::size_t packet_stride,
    std::size_t count,
    bool use_chacha20);
#endif

namespace {

std::atomic<uint64_t> g_cuda_launches{0};
std::atomic<uint64_t> g_cuda_initial_keys{0};
std::atomic<uint64_t> g_cuda_aead_packets{0};
std::atomic<uint64_t> g_cuda_hp_masks{0};
std::atomic<uint64_t> g_cuda_gpu_ns{0};

bool env_disabled() {
  const char* env = std::getenv("SAMURAI_QUIC_CUDA_DISABLE");
  return env != nullptr && std::strcmp(env, "1") == 0;
}

uint64_t steady_now_ns() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
}

}  // namespace

bool quic_cuda_crypto_available() {
  if (env_disabled()) {
    return false;
  }
#if defined(SAMURAI_WITH_QUIC_CUDA_CRYPTO)
  int dev = -1;
  return samurai_quic_cuda_probe_device(&dev);
#else
  return false;
#endif
}

bool quic_cuda_derive_initial_keys_batch(
    const uint8_t* dcids_8b,
    const uint8_t* scids_8b,
    std::size_t count,
    QuicInitialKeyMaterial* out_materials,
    uint64_t* elapsed_ns_out) {
  if (dcids_8b == nullptr || out_materials == nullptr || count == 0) {
    return false;
  }
  const uint64_t t0 = steady_now_ns();
  bool used_gpu = false;
#if defined(SAMURAI_WITH_QUIC_CUDA_CRYPTO)
  if (!env_disabled()) {
    used_gpu = samurai_quic_cuda_derive_initial_keys(dcids_8b, scids_8b, count, out_materials);
  }
#endif
  if (!used_gpu) {
    for (std::size_t i = 0; i < count; ++i) {
      const uint8_t* dcid = dcids_8b + i * 8u;
      const uint8_t* scid = (scids_8b != nullptr) ? (scids_8b + i * 8u) : nullptr;
      primitives::derive_quic_v1_initial_keys_8b(dcid, scid, &out_materials[i]);
    }
  }
  const uint64_t dt = steady_now_ns() - t0;
  if (used_gpu) {
    g_cuda_launches.fetch_add(1, std::memory_order_relaxed);
    g_cuda_initial_keys.fetch_add(count, std::memory_order_relaxed);
    g_cuda_gpu_ns.fetch_add(dt, std::memory_order_relaxed);
  }
  if (elapsed_ns_out != nullptr) {
    *elapsed_ns_out = dt;
  }
  return true;
}

bool quic_cuda_aes128_hp_mask_batch(
    const uint8_t* hp_keys_16b,
    const uint8_t* samples_16b,
    std::size_t count,
    uint8_t* masks_5b_out,
    uint64_t* elapsed_ns_out) {
  if (hp_keys_16b == nullptr || samples_16b == nullptr || masks_5b_out == nullptr || count == 0) {
    return false;
  }
  const uint64_t t0 = steady_now_ns();
  bool used_gpu = false;
#if defined(SAMURAI_WITH_QUIC_CUDA_CRYPTO)
  if (!env_disabled()) {
    used_gpu = samurai_quic_cuda_aes128_hp_mask(hp_keys_16b, samples_16b, count, masks_5b_out);
  }
#endif
  if (!used_gpu) {
    for (std::size_t i = 0; i < count; ++i) {
      uint8_t rk[176];
      primitives::aes128_expand_key(hp_keys_16b + i * 16u, rk);
      uint8_t block[16];
      primitives::aes128_encrypt_block(rk, samples_16b + i * 16u, block);
      std::memcpy(masks_5b_out + i * 5u, block, 5u);
    }
  }
  const uint64_t dt = steady_now_ns() - t0;
  if (used_gpu) {
    g_cuda_launches.fetch_add(1, std::memory_order_relaxed);
    g_cuda_hp_masks.fetch_add(count, std::memory_order_relaxed);
    g_cuda_gpu_ns.fetch_add(dt, std::memory_order_relaxed);
  }
  if (elapsed_ns_out != nullptr) {
    *elapsed_ns_out = dt;
  }
  return true;
}

bool quic_cuda_chacha20_poly1305_encrypt_batch(
    QuicAeadBatchItem* items,
    uint8_t* packet_buffers,
    std::size_t packet_stride,
    std::size_t count,
    uint64_t* elapsed_ns_out) {
  if (items == nullptr || packet_buffers == nullptr || packet_stride == 0 || count == 0) {
    return false;
  }
  const uint64_t t0 = steady_now_ns();
  bool used_gpu = false;
#if defined(SAMURAI_WITH_QUIC_CUDA_CRYPTO)
  if (!env_disabled()) {
    used_gpu = samurai_quic_cuda_aead_encrypt(items, packet_buffers, packet_stride, count, true);
  }
#endif
  if (!used_gpu) {
    for (std::size_t i = 0; i < count; ++i) {
      primitives::quic_chacha20_poly1305_encrypt_and_hp(&items[i], packet_buffers + i * packet_stride);
    }
  }
  const uint64_t dt = steady_now_ns() - t0;
  if (used_gpu) {
    g_cuda_launches.fetch_add(1, std::memory_order_relaxed);
    g_cuda_aead_packets.fetch_add(count, std::memory_order_relaxed);
    g_cuda_gpu_ns.fetch_add(dt, std::memory_order_relaxed);
  }
  if (elapsed_ns_out != nullptr) {
    *elapsed_ns_out = dt;
  }
  return true;
}

bool quic_cuda_aes128_gcm_encrypt_batch(
    QuicAeadBatchItem* items,
    uint8_t* packet_buffers,
    std::size_t packet_stride,
    std::size_t count,
    uint64_t* elapsed_ns_out) {
  if (items == nullptr || packet_buffers == nullptr || packet_stride == 0 || count == 0) {
    return false;
  }
  const uint64_t t0 = steady_now_ns();
  bool used_gpu = false;
#if defined(SAMURAI_WITH_QUIC_CUDA_CRYPTO)
  if (!env_disabled()) {
    used_gpu = samurai_quic_cuda_aead_encrypt(items, packet_buffers, packet_stride, count, false);
  }
#endif
  if (!used_gpu) {
    for (std::size_t i = 0; i < count; ++i) {
      primitives::quic_aes128_gcm_encrypt_and_hp(&items[i], packet_buffers + i * packet_stride);
    }
  }
  const uint64_t dt = steady_now_ns() - t0;
  if (used_gpu) {
    g_cuda_launches.fetch_add(1, std::memory_order_relaxed);
    g_cuda_aead_packets.fetch_add(count, std::memory_order_relaxed);
    g_cuda_gpu_ns.fetch_add(dt, std::memory_order_relaxed);
  }
  if (elapsed_ns_out != nullptr) {
    *elapsed_ns_out = dt;
  }
  return true;
}

bool quic_cuda_crypto_selftest() {
  // Official IETF RFC 9001 Appendix A.1 Test Vector:
  // client_dst_connection_id = 0x8394c8f03e515708
  static constexpr uint8_t kTestDcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  static constexpr uint8_t kExpectedKey[16] = {
      0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46,
      0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d};
  static constexpr uint8_t kExpectedIv[12] = {
      0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c};
  static constexpr uint8_t kExpectedHp[16] = {
      0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
      0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2};
  static constexpr uint8_t kTestSample[16] = {
      0xd1, 0xb1, 0xc9, 0x8d, 0xd7, 0x68, 0x9f, 0xb8,
      0xec, 0x11, 0xd2, 0x42, 0xb1, 0x23, 0xdc, 0x9b};
  static constexpr uint8_t kExpectedMask[5] = {0x43, 0x7b, 0x9a, 0xec, 0x36};

  QuicInitialKeyMaterial mat{};
  if (!quic_cuda_derive_initial_keys_batch(kTestDcid, nullptr, 1, &mat)) {
    return false;
  }
  if (std::memcmp(mat.quic_key, kExpectedKey, 16) != 0 ||
      std::memcmp(mat.quic_iv, kExpectedIv, 12) != 0 ||
      std::memcmp(mat.quic_hp, kExpectedHp, 16) != 0) {
    return false;
  }

  uint8_t mask[5]{};
  if (!quic_cuda_aes128_hp_mask_batch(mat.quic_hp, kTestSample, 1, mask)) {
    return false;
  }
  return std::memcmp(mask, kExpectedMask, 5) == 0;
}

QuicCudaCryptoTelemetry quic_cuda_crypto_get_telemetry() {
  QuicCudaCryptoTelemetry t{};
#if defined(SAMURAI_WITH_QUIC_CUDA_CRYPTO)
  if (!env_disabled()) {
    t.gpu_available = samurai_quic_cuda_probe_device(&t.device_id);
  }
#endif
  t.kernel_launches = g_cuda_launches.load(std::memory_order_relaxed);
  t.initial_keys_derived = g_cuda_initial_keys.load(std::memory_order_relaxed);
  t.aead_packets_processed = g_cuda_aead_packets.load(std::memory_order_relaxed);
  t.hp_masks_generated = g_cuda_hp_masks.load(std::memory_order_relaxed);
  t.total_gpu_ns = g_cuda_gpu_ns.load(std::memory_order_relaxed);
  return t;
}

}  // namespace samurai::l7_emu_native::custom_quic_stack
