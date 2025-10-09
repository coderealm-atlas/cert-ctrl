#include "util/secret_util.hpp"

#include <sodium/crypto_aead_aes256gcm.h>
#include <sodium/randombytes.h>

#include <iostream>
#include <string_view>
#include <vector>

#include <openssl/evp.h>

#include <cstring>

namespace {

constexpr std::size_t kAesGcmTagLen = crypto_aead_aes256gcm_ABYTES;

bool decrypt_aes256gcm_libsodium(const std::string& ciphertext,  // NOLINT
                                 const std::string& nonce,
                                 const unsigned char* sym_key,
                                 std::string_view aad,
                                 std::string& message_plain) {
  if (!crypto_aead_aes256gcm_is_available()) {
    std::cerr << "libsodium AES256-GCM not available" << std::endl;
    return false;
  }

  if (nonce.size() != crypto_aead_aes256gcm_NPUBBYTES) {
    std::cerr << "libsodium AES256-GCM invalid nonce size: "
              << nonce.size() << std::endl;
    return false;
  }
  if (ciphertext.size() < kAesGcmTagLen) {
    std::cerr << "libsodium AES256-GCM ciphertext too short: "
              << ciphertext.size() << std::endl;
    return false;
  }

  const auto* ciphertext_data =
      reinterpret_cast<const unsigned char*>(ciphertext.data());
  const auto* nonce_data =
      reinterpret_cast<const unsigned char*>(nonce.data());

  unsigned long long decrypted_len = 0;
  std::vector<unsigned char> decrypted_buf(ciphertext.size());

  const unsigned char* aad_ptr = aad.empty()
                                     ? nullptr
                                     : reinterpret_cast<const unsigned char*>(
                                           aad.data());

  if (crypto_aead_aes256gcm_decrypt(
          decrypted_buf.data(), &decrypted_len, nullptr, ciphertext_data,
          ciphertext.size(), aad_ptr,
          static_cast<unsigned long long>(aad.size()), nonce_data, sym_key) !=
      0) {
    std::cerr << "libsodium AES256-GCM decrypt failed" << std::endl;
    return false;
  }

  message_plain.assign(reinterpret_cast<char*>(decrypted_buf.data()),
                       decrypted_len);
  return true;
}

bool decrypt_aes256gcm_openssl(const std::string& ciphertext,  // NOLINT
                               const std::string& nonce,
                               const unsigned char* sym_key,
                               std::string_view aad,
                               std::string& message_plain) {
  if (ciphertext.size() < kAesGcmTagLen || sym_key == nullptr) {
    std::cerr << "OpenSSL AES256-GCM invalid input: ct=" << ciphertext.size()
              << " taglen=" << kAesGcmTagLen
              << " sym=" << (sym_key ? 32 : 0) << std::endl;
    return false;
  }

  const std::size_t tag_offset = ciphertext.size() - kAesGcmTagLen;
  const auto* ct_data =
      reinterpret_cast<const unsigned char*>(ciphertext.data());
  const auto* nonce_data =
      reinterpret_cast<const unsigned char*>(nonce.data());

  std::vector<unsigned char> tag_buf(kAesGcmTagLen);
  std::memcpy(tag_buf.data(), ct_data + tag_offset, kAesGcmTagLen);

  std::vector<unsigned char> plaintext(tag_offset);

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr) {
    std::cerr << "OpenSSL AES256-GCM failed to create context" << std::endl;
    return false;
  }

  bool success = false;
  do {
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr,
                           nullptr) != 1) {
      std::cerr << "OpenSSL AES256-GCM EVP_DecryptInit_ex failed" << std::endl;
      break;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                             static_cast<int>(nonce.size()),
                             nullptr) != 1) {
      std::cerr << "OpenSSL AES256-GCM set IV len failed" << std::endl;
      break;
    }

    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, sym_key, nonce_data) != 1) {
      std::cerr << "OpenSSL AES256-GCM set key/nonce failed" << std::endl;
      break;
    }

    if (!aad.empty()) {
      const auto* aad_data =
          reinterpret_cast<const unsigned char*>(aad.data());
      int aad_len = 0;
      if (EVP_DecryptUpdate(ctx, nullptr, &aad_len, aad_data,
                            static_cast<int>(aad.size())) != 1) {
        std::cerr << "OpenSSL AES256-GCM AAD update failed" << std::endl;
        break;
      }
    }

    int out_len = 0;
    if (tag_offset > 0) {
      if (EVP_DecryptUpdate(ctx, plaintext.data(), &out_len, ct_data,
                            static_cast<int>(tag_offset)) != 1) {
        std::cerr << "OpenSSL AES256-GCM decrypt update failed" << std::endl;
        break;
      }
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                             static_cast<int>(tag_buf.size()),
                             tag_buf.data()) != 1) {
      std::cerr << "OpenSSL AES256-GCM set tag failed" << std::endl;
      break;
    }

    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &final_len) !=
        1) {
      std::cerr << "OpenSSL AES256-GCM final failed" << std::endl;
      break;
    }

    message_plain.assign(reinterpret_cast<char*>(plaintext.data()),
                         out_len + final_len);
    success = true;
  } while (false);

  EVP_CIPHER_CTX_free(ctx);
  return success;
}

}  // namespace

namespace cjj365 {
namespace cryptutil {

bool encrypt_hybrid_gcm_sealed(const unsigned char* pk,
                               const std::string& message_plain,  //
                               std::string& ciphertext,           //
                               std::string& nonce,                //
                               std::string& enc_key) {
  // Generate symmetric key
  if (!pk || message_plain.empty()) return false;
  unsigned char sym_key[crypto_aead_aes256gcm_KEYBYTES];
  randombytes_buf(sym_key, sizeof sym_key);

  // Generate nonce
  unsigned char nonce_[crypto_aead_aes256gcm_NPUBBYTES];
  randombytes_buf(nonce_, sizeof nonce_);

  // Encrypt the message with AES-GCM
  unsigned long long ciphertext_len = 0;
  std::vector<unsigned char> ciphertext_buf(message_plain.size() +
                                            crypto_aead_aes256gcm_ABYTES);

  if (crypto_aead_aes256gcm_encrypt(
          ciphertext_buf.data(), &ciphertext_len,
          reinterpret_cast<const unsigned char*>(message_plain.data()),
          message_plain.size(), nullptr, 0,  // Optional AAD
          nullptr, nonce_, sym_key) != 0) {
    std::cerr << "Failed to encrypt message" << std::endl;
    return false;
  }

  // Encrypt symmetric key with recipient's public key
  std::vector<unsigned char> enc_key_buf(crypto_box_SEALBYTES + sizeof sym_key);
  if (crypto_box_seal(enc_key_buf.data(), sym_key, sizeof sym_key, pk) != 0) {
    std::cerr << "Failed to encrypt symmetric key" << std::endl;
    return false;
  }
  // Store results as std::string
  ciphertext = std::string(reinterpret_cast<char*>(ciphertext_buf.data()),
                           ciphertext_len);
  nonce = std::string(reinterpret_cast<char*>(nonce_), sizeof nonce_);
  enc_key = std::string(reinterpret_cast<char*>(enc_key_buf.data()),
                        enc_key_buf.size());
  return true;
}

bool decrypt_hybrid_gcm_sealed(const unsigned char* pk,        //
                               const unsigned char* sk,        //
                               const std::string& ciphertext,  //
                               const std::string& nonce,       //
                               const std::string& enc_key,     //
                               std::string& message_plain,
                               std::string_view aad) {
  // Decrypt sym_key
  unsigned char sym_key[crypto_aead_aes256gcm_KEYBYTES];
  const unsigned char* enc_key_data =
      reinterpret_cast<const unsigned char*>(enc_key.data());

  if (crypto_box_seal_open(sym_key, enc_key_data, enc_key.size(), pk, sk) !=
      0) {
    std::cerr << "Failed to decrypt symmetric key" << std::endl;
    return false;
  }

  if (decrypt_aes256gcm_libsodium(ciphertext, nonce, sym_key, aad,
                                  message_plain)) {
    return true;
  }

  if (decrypt_aes256gcm_openssl(ciphertext, nonce, sym_key, aad,
                                message_plain)) {
    return true;
  }

  std::cerr << "Failed to decrypt message" << std::endl;
  return false;
}

}  // namespace cryptutil
}  // namespace cjj365
