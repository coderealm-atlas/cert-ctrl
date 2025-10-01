#pragma once

#include <sodium.h>
#include <sodium/crypto_box.h>

#include <array>
#include <cstring>  // for std::memcpy
#include <optional>
#include <stdexcept>
#include <string>

#include "base64.h"

namespace cjj365 {
namespace cryptutil {

class KeyPairSo {
 public:
  static constexpr size_t PK_SIZE = crypto_box_PUBLICKEYBYTES;
  static constexpr size_t SK_SIZE = crypto_box_SECRETKEYBYTES;

  std::array<unsigned char, PK_SIZE> pk;
  std::optional<std::array<unsigned char, SK_SIZE>> sk;  // optional!

  KeyPairSo(const std::string& pk_b64,
            const std::optional<std::string>& sk_b64 = std::nullopt) {
    // Decode public key
    auto pk_decoded = base64_decode(pk_b64);
    if (pk_decoded.size() != PK_SIZE)
      throw std::runtime_error("Invalid public key size");
    std::memcpy(pk.data(), pk_decoded.data(), PK_SIZE);

    // Decode secret key if present
    if (sk_b64 && !sk_b64->empty()) {
      auto sk_decoded = base64_decode(*sk_b64);
      if (sk_decoded.size() != SK_SIZE)
        throw std::runtime_error("Invalid secret key size");

      sk.emplace();
      std::memcpy(sk->data(), sk_decoded.data(), SK_SIZE);
    }
  }

  bool has_secret() const { return sk.has_value(); }

  const unsigned char* public_key() const { return pk.data(); }

  const unsigned char* secret_key() const {
    if (!has_secret()) throw std::runtime_error("Secret key not available");
    return sk->data();
  }
};

bool encrypt_hybrid_gcm_sealed(const unsigned char* pk,
                               const std::string& message_plain,
                               std::string& ciphertext, std::string& nonce,
                               std::string& enc_key);

bool decrypt_hybrid_gcm_sealed(const unsigned char* pk, const unsigned char* sk,
                               const std::string& ciphertext,
                               const std::string& nonce,
                               const std::string& enc_key,
                               std::string& message_plain);
}  // namespace cryptutil
}  // namespace cjj365
