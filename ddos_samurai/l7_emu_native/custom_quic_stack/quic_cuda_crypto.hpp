#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace ddos_samurai::l7_emu_native::custom_quic_stack {

// RFC 9001 Section 5.2 derived Initial Secrets & AEAD/HP keys for a single QUIC connection
struct alignas(16) QuicInitialKeyMaterial {
  uint8_t dcid[8];
  uint8_t scid[8];
  uint8_t initial_secret[32];
  uint8_t client_initial_secret[32];
  uint8_t quic_key[16];
  uint8_t quic_iv[12];
  uint8_t quic_hp[16];
  uint32_t reserved;
};

// Descriptor for a single packet in a batch AEAD + Header Protection operation
struct alignas(16) QuicAeadBatchItem {
  uint8_t key[32];         // 16B for AES-128-GCM, 32B for ChaCha20-Poly1305
  uint8_t iv[12];          // 12B base IV
  uint8_t hp_key[32];      // 16B for AES-128-ECB HP, 32B for ChaCha20 HP
  uint64_t pkt_num;        // 64-bit packet number (XORed with iv)
  uint32_t aad_len;        // Unencrypted QUIC header length (AAD)
  uint32_t plaintext_len;  // Payload length to encrypt
  uint32_t pn_offset;      // Offset of packet number field in header for HP masking
  uint32_t pn_length;      // Packet number length (1..4 bytes)
  uint8_t hp_mask_out[5];  // Computed 5-byte RFC 9001 Header Protection mask
  uint8_t tag_out[16];     // Computed 16-byte AEAD authentication tag
  uint8_t pad[3];
};

struct QuicCudaCryptoTelemetry {
  bool gpu_available{false};
  int device_id{-1};
  uint64_t kernel_launches{0};
  uint64_t initial_keys_derived{0};
  uint64_t aead_packets_processed{0};
  uint64_t hp_masks_generated{0};
  uint64_t total_gpu_ns{0};
};

// Returns true if CUDA runtime and a capable NVIDIA GPU are available for QUIC crypto offload
bool quic_cuda_crypto_available();

// Derives RFC 9001 Section 5.2 QUIC v1 Initial secrets (HKDF-Extract + HKDF-Expand-Label over SHA-256)
// for a batch of 8-byte Destination Connection IDs (DCIDs).
// Runs on CUDA GPU when available, otherwise falls back to deterministic CPU execution.
bool quic_cuda_derive_initial_keys_batch(
    const uint8_t* dcids_8b,
    const uint8_t* scids_8b,
    std::size_t count,
    QuicInitialKeyMaterial* out_materials,
    uint64_t* elapsed_ns_out = nullptr);

// Computes RFC 9001 Section 5.4.3 AES-128-ECB 5-byte Header Protection masks for a batch of
// 16-byte ciphertext samples and 16-byte HP keys on the GPU (or CPU fallback).
bool quic_cuda_aes128_hp_mask_batch(
    const uint8_t* hp_keys_16b,
    const uint8_t* samples_16b,
    std::size_t count,
    uint8_t* masks_5b_out,
    uint64_t* elapsed_ns_out = nullptr);

// Performs batch ChaCha20-Poly1305 AEAD encryption + ChaCha20 Header Protection (RFC 8439 / RFC 9001)
// across a contiguous packet buffer (each packet stride = packet_stride bytes).
bool quic_cuda_chacha20_poly1305_encrypt_batch(
    QuicAeadBatchItem* items,
    uint8_t* packet_buffers,
    std::size_t packet_stride,
    std::size_t count,
    uint64_t* elapsed_ns_out = nullptr);

// Performs batch AES-128-GCM AEAD encryption + AES-128-ECB Header Protection (RFC 9001 Section 5.3/5.4.3)
// across a contiguous packet buffer (each packet stride = packet_stride bytes).
bool quic_cuda_aes128_gcm_encrypt_batch(
    QuicAeadBatchItem* items,
    uint8_t* packet_buffers,
    std::size_t packet_stride,
    std::size_t count,
    uint64_t* elapsed_ns_out = nullptr);

// Self-test against IETF RFC 9001 Appendix A.1 test vectors (verifies byte-exact HKDF + AES-128-ECB HP)
bool quic_cuda_crypto_selftest();

// Read cumulative telemetry for QUIC CUDA crypto offload
QuicCudaCryptoTelemetry quic_cuda_crypto_get_telemetry();

}  // namespace ddos_samurai::l7_emu_native::custom_quic_stack
