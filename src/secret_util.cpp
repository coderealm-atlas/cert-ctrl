#include "util/secret_util.hpp"

#include <sodium/crypto_aead_aes256gcm.h>
#include <sodium/randombytes.h>

#include <iostream>
#include <vector>

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
                               std::string& message_plain) {
  // Decrypt sym_key
  unsigned char sym_key[crypto_aead_aes256gcm_KEYBYTES];
  const unsigned char* enc_key_data =
      reinterpret_cast<const unsigned char*>(enc_key.data());

  if (crypto_box_seal_open(sym_key, enc_key_data, enc_key.size(), pk, sk) !=
      0) {
    std::cerr << "Failed to decrypt symmetric key" << std::endl;
    return false;
  }

  // Prepare buffers
  const unsigned char* ciphertext_data =
      reinterpret_cast<const unsigned char*>(ciphertext.data());
  const unsigned char* nonce_data =
      reinterpret_cast<const unsigned char*>(nonce.data());

  unsigned long long decrypted_len = 0;
  std::vector<unsigned char> decrypted_buf(ciphertext.size());  // large enough

  if (crypto_aead_aes256gcm_decrypt(decrypted_buf.data(), &decrypted_len,
                                    nullptr, ciphertext_data, ciphertext.size(),
                                    nullptr, 0,  // AAD
                                    nonce_data, sym_key) != 0) {
    std::cerr << "Failed to decrypt message" << std::endl;
    return false;
  }

  message_plain =
      std::string(reinterpret_cast<char*>(decrypted_buf.data()), decrypted_len);
  return true;
}

}  // namespace cryptutil
}  // namespace cjj365
