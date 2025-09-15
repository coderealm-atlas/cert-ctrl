#pragma once

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <stdexcept>
#include <vector>

#include "my_error_codes.hpp"
#include "result_monad.hpp"

namespace cjj365 {
namespace cryptutil {

struct AesGcmCiphertext {
  std::vector<unsigned char> nonce;       // 12 bytes
  std::vector<unsigned char> tag;         // 16 bytes
  std::vector<unsigned char> ciphertext;  // encrypted private key
};

// AES-256-GCM encrypt (key must be 32 bytes). Generates random 12-byte nonce.
inline monad::MyResult<AesGcmCiphertext> encrypt_privkey_aes256_gcm(
    const unsigned char* key, size_t key_len, const unsigned char* plaintext,
    size_t plaintext_len, const unsigned char* aad = nullptr,
    size_t aad_len = 0) {
  if (key_len != 32)
    return monad::MyResult<AesGcmCiphertext>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "key size must be 32"});
  AesGcmCiphertext out;
  out.nonce.resize(12);
  if (RAND_bytes(out.nonce.data(), (int)out.nonce.size()) != 1)
    return monad::MyResult<AesGcmCiphertext>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "RAND_bytes failed"});
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    return monad::MyResult<AesGcmCiphertext>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "EVP_CIPHER_CTX_new failed"});
  int len = 0;
  out.ciphertext.resize(plaintext_len);
  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) !=
      1)
    return monad::MyResult<AesGcmCiphertext>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "EncryptInit failed"});
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)out.nonce.size(),
                          nullptr) != 1)
    return monad::MyResult<AesGcmCiphertext>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "SET_IVLEN failed"});
  if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, out.nonce.data()) != 1)
    return monad::MyResult<AesGcmCiphertext>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "EncryptInit key/iv failed"});
  if (aad && aad_len > 0) {
    if (EVP_EncryptUpdate(ctx, nullptr, &len, aad, (int)aad_len) != 1)
      return monad::MyResult<AesGcmCiphertext>::Err(
          monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                       .what = "AAD update failed"});
  }
  if (EVP_EncryptUpdate(ctx, out.ciphertext.data(), &len, plaintext,
                        (int)plaintext_len) != 1)
    return monad::MyResult<AesGcmCiphertext>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "EncryptUpdate failed"});
  int ct_len = len;
  if (EVP_EncryptFinal_ex(ctx, out.ciphertext.data() + len, &len) != 1)
    return monad::MyResult<AesGcmCiphertext>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "EncryptFinal failed"});
  ct_len += len;
  out.ciphertext.resize(ct_len);
  out.tag.resize(16);
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out.tag.data()) != 1)
    return monad::MyResult<AesGcmCiphertext>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "GET_TAG failed"});
  EVP_CIPHER_CTX_free(ctx);
  return monad::MyResult<AesGcmCiphertext>::Ok(std::move(out));
}

inline monad::MyResult<std::vector<unsigned char>> decrypt_privkey_aes256_gcm(
    const unsigned char* key, size_t key_len, const unsigned char* nonce,
    size_t nonce_len, const unsigned char* tag, size_t tag_len,
    const unsigned char* ciphertext, size_t ciphertext_len,
    const unsigned char* aad = nullptr, size_t aad_len = 0) {
  if (key_len != 32)
    return monad::MyResult<std::vector<unsigned char>>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "key size must be 32"});
  if (nonce_len != 12)
    return monad::MyResult<std::vector<unsigned char>>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "nonce size must be 12"});
  if (tag_len != 16)
    return monad::MyResult<std::vector<unsigned char>>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "tag size must be 16"});
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    return monad::MyResult<std::vector<unsigned char>>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "EVP_CIPHER_CTX_new failed"});
  }
  int len = 0;
  std::vector<unsigned char> plaintext(ciphertext_len);
  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) !=
      1)
    return monad::MyResult<std::vector<unsigned char>>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "DecryptInit failed"});
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce_len,
                          nullptr) != 1)
    return monad::MyResult<std::vector<unsigned char>>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "SET_IVLEN failed"});
  if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1)
    return monad::MyResult<std::vector<unsigned char>>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "DecryptInit key/iv failed"});
  if (aad && aad_len > 0) {
    if (EVP_DecryptUpdate(ctx, nullptr, &len, aad, (int)aad_len) != 1)
      return monad::MyResult<std::vector<unsigned char>>::Err(
          monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                       .what = "AAD update failed"});
  }
  if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext,
                        (int)ciphertext_len) != 1)
    return monad::MyResult<std::vector<unsigned char>>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "DecryptUpdate failed"});
  int pt_len = len;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_len,
                          (void*)tag) != 1)
    return monad::MyResult<std::vector<unsigned char>>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "SET_TAG failed"});
  if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return monad::MyResult<std::vector<unsigned char>>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "DecryptFinal (auth) failed"});
  }
  pt_len += len;
  plaintext.resize(pt_len);
  EVP_CIPHER_CTX_free(ctx);
  return monad::MyResult<std::vector<unsigned char>>::Ok(std::move(plaintext));
}

}  // namespace cryptutil
}  // namespace cjj365
