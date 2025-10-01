#pragma once

#include <sodium.h>

#include <array>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace cjj365 {
namespace cryptutil {

inline void sodium_init_or_throw() {
  if (sodium_init() < 0) throw std::runtime_error("sodium_init failed");
}

// Wrapper for crypto_box keypair (X25519 after libsodium scalar mult transform)
struct BoxKeyPair {
  std::array<unsigned char, crypto_box_PUBLICKEYBYTES> public_key{};
  std::array<unsigned char, crypto_box_SECRETKEYBYTES> secret_key{};
};

inline BoxKeyPair generate_box_keypair() {
  BoxKeyPair kp;
  if (crypto_box_keypair(kp.public_key.data(), kp.secret_key.data()) != 0)
    throw std::runtime_error("crypto_box_keypair failed");
  return kp;
}

// Ed25519 key pair (signing) if needed
struct SignKeyPair {
  std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> public_key{};
  std::array<unsigned char, crypto_sign_SECRETKEYBYTES> secret_key{};
};

inline SignKeyPair generate_sign_keypair() {
  SignKeyPair kp;
  if (crypto_sign_keypair(kp.public_key.data(), kp.secret_key.data()) != 0)
    throw std::runtime_error("crypto_sign_keypair failed");
  return kp;
}

// Encrypt arbitrary data for recipient's X25519 (crypto_box) public key via
// seal.
inline std::vector<unsigned char> seal_for_user(
    const unsigned char user_pub[crypto_box_PUBLICKEYBYTES],
    const unsigned char* data, size_t len) {
  std::vector<unsigned char> ct(len + crypto_box_SEALBYTES);
  if (crypto_box_seal(ct.data(), data, len, user_pub) != 0) {
    throw std::runtime_error("crypto_box_seal failed");
  }
  return ct;
}

inline std::vector<unsigned char> seal_for_user(
    const unsigned char user_pub[crypto_box_PUBLICKEYBYTES],
    const std::vector<unsigned char>& data) {
  return seal_for_user(user_pub, data.data(), data.size());
}

inline std::vector<unsigned char> seal_for_user(
    const unsigned char user_pub[crypto_box_PUBLICKEYBYTES],
    const std::string& data) {
  return seal_for_user(user_pub,
                       reinterpret_cast<const unsigned char*>(data.data()),
                       data.size());
}

// Decrypt sealed box for user (needs public + secret key)
inline std::vector<unsigned char> unseal_for_user(
    const unsigned char user_pub[crypto_box_PUBLICKEYBYTES],
    const unsigned char user_sec[crypto_box_SECRETKEYBYTES],
    const unsigned char* ct, size_t ct_len) {
  if (ct_len < crypto_box_SEALBYTES)
    throw std::runtime_error("ciphertext too short");
  std::vector<unsigned char> pt(ct_len - crypto_box_SEALBYTES);
  if (crypto_box_seal_open(pt.data(), ct, ct_len, user_pub, user_sec) != 0) {
    throw std::runtime_error("crypto_box_seal_open failed");
  }
  return pt;
}

inline std::vector<unsigned char> unseal_for_user(
    const unsigned char user_pub[crypto_box_PUBLICKEYBYTES],
    const unsigned char user_sec[crypto_box_SECRETKEYBYTES],
    const std::vector<unsigned char>& ct) {
  return unseal_for_user(user_pub, user_sec, ct.data(), ct.size());
}

// Convenience: convert binary vector to hex
inline std::string to_hex(const unsigned char* data, size_t len) {
  static const char* hex = "0123456789abcdef";
  std::string out;
  out.resize(len * 2);
  for (size_t i = 0; i < len; ++i) {
    out[2 * i] = hex[(data[i] >> 4) & 0xF];
    out[2 * i + 1] = hex[data[i] & 0xF];
  }
  return out;
}

inline std::string to_hex(const std::vector<unsigned char>& v) {
  return to_hex(v.data(), v.size());
}

// ---- Hex decoding helpers ----
inline int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

inline bool from_hex(std::string_view hex, unsigned char* out, size_t out_len) {
  if (hex.size() != out_len * 2) return false;
  for (size_t i = 0; i < out_len; ++i) {
    int hi = hex_nibble(hex[2 * i]);
    int lo = hex_nibble(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = static_cast<unsigned char>((hi << 4) | lo);
  }
  return true;
}

inline std::vector<unsigned char> from_hex(std::string_view hex) {
  if (hex.size() % 2 != 0) throw std::runtime_error("bad hex length");
  std::vector<unsigned char> out(hex.size() / 2);
  if (!from_hex(hex, out.data(), out.size()))
    throw std::runtime_error("invalid hex digit");
  return out;
}

inline std::array<unsigned char, 32> decode_public_key_hex(const std::string& h) {
  std::array<unsigned char, 32> pk{};
  if (!from_hex(h, pk.data(), pk.size())) throw std::runtime_error("bad public key hex");
  return pk;
}
// ---- End hex decoding helpers ----

// Compute 32-byte fingerprint of a public key (default: BLAKE2b via crypto_generichash)
inline std::array<unsigned char, 32> fingerprint_public_key(
    const unsigned char* pub, size_t len = crypto_box_PUBLICKEYBYTES) {
  std::array<unsigned char, 32> out{};
  if (crypto_generichash(out.data(), out.size(), pub, len, nullptr, 0) != 0) {
    throw std::runtime_error("crypto_generichash failed");
  }
  return out;
}

inline std::array<unsigned char, 32> fingerprint_public_key(
    const std::array<unsigned char, crypto_box_PUBLICKEYBYTES>& pk) {
  return fingerprint_public_key(pk.data(), pk.size());
}

// If you specifically need SHA-256: use crypto_hash_sha256
inline std::array<unsigned char, crypto_hash_sha256_BYTES>
fingerprint_public_key_sha256(const unsigned char* pub,
                              size_t len = crypto_box_PUBLICKEYBYTES) {
  std::array<unsigned char, crypto_hash_sha256_BYTES> out{};
  if (crypto_hash_sha256(out.data(), pub, len) != 0) {
    throw std::runtime_error("crypto_hash_sha256 failed");
  }
  return out;
}

// Overload for array
inline std::array<unsigned char, crypto_hash_sha256_BYTES>
fingerprint_public_key_sha256(
    const std::array<unsigned char, crypto_box_PUBLICKEYBYTES>& pk) {
  return fingerprint_public_key_sha256(pk.data(), pk.size());
}

}  // namespace cryptutil
}  // namespace cjj365
