#include "openssl/crypt_util.hpp"

#include <fmt/base.h>
#include <fmt/format.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/types.h>

#include <fstream>
#include <iostream>
#include <stdexcept>

#include "base64.h"
#include "openssl/openssl_raii.hpp"

namespace cjj365 {
namespace cryptutil {

// Versioned PBKDF2 hash format:
// pbkdf2$sha256$v=<version>$i=<iterations>$s=<salt_b64>$h=<hash_b64>
std::string hash_password_openssl(const std::string& password) {
  std::vector<unsigned char> salt(PASSWORD_SALT_LENGTH);
  if (RAND_bytes(salt.data(), PASSWORD_SALT_LENGTH) != 1) {
    throw std::runtime_error("Random salt generation failed");
  }
  std::vector<unsigned char> hash(PASSWORD_HASH_LENGTH);
  if (!PKCS5_PBKDF2_HMAC(password.c_str(), password.size(), salt.data(),
                         PASSWORD_SALT_LENGTH, PASSWORD_PBKDF2_ITERATIONS,
                         EVP_sha256(), PASSWORD_HASH_LENGTH, hash.data())) {
    throw std::runtime_error("Password hashing failed");
  }
  std::string salt_b64 =
      base64_encode(salt.data(), static_cast<int>(salt.size()));
  std::string hash_b64 =
      base64_encode(hash.data(), static_cast<int>(hash.size()));
  return fmt::format("pbkdf2$sha256$v={}$i={}$s={}$h={}", PASSWORD_HASH_VERSION,
                     PASSWORD_PBKDF2_ITERATIONS, salt_b64, hash_b64);
}

static bool parse_param(std::string_view token, std::string_view prefix,
                        std::string_view& out) {
  if (token.rfind(prefix, 0) == 0) {
    out = token.substr(prefix.size());
    return true;
  }
  return false;
}

PasswordVerifyResult verify_password_openssl_ex(std::string_view stored,
                                                std::string_view password) {
  PasswordVerifyResult vr{};
  if (stored.rfind("pbkdf2$sha256$", 0) == 0) {
    // New format
    // Split by '$'
    std::vector<std::string_view> parts;
    size_t start = 0;
    while (start < stored.size()) {
      size_t pos = stored.find('$', start);
      if (pos == std::string_view::npos) {
        parts.push_back(stored.substr(start));
        break;
      }
      parts.push_back(stored.substr(start, pos - start));
      start = pos + 1;
    }
    if (parts.size() < 6) {
      return vr;
    }
    // parts: pbkdf2 sha256 v=... i=... s=... h=...
    int version = 0;
    int iterations = 0;
    std::string_view salt_b64;
    std::string_view hash_b64;
    for (auto p : parts) {
      if (p.rfind("v=", 0) == 0)
        version = std::atoi(std::string(p.substr(2)).c_str());
      else if (p.rfind("i=", 0) == 0)
        iterations = std::atoi(std::string(p.substr(2)).c_str());
      else if (p.rfind("s=", 0) == 0)
        salt_b64 = p.substr(2);
      else if (p.rfind("h=", 0) == 0)
        hash_b64 = p.substr(2);
    }
    if (!iterations || salt_b64.empty() || hash_b64.empty()) return vr;
    auto salt_bin = base64_decode(std::string(salt_b64));
    auto hash_bin = base64_decode(std::string(hash_b64));
    if (salt_bin.size() != PASSWORD_SALT_LENGTH ||
        hash_bin.size() != PASSWORD_HASH_LENGTH)
      return vr;
    std::vector<unsigned char> computed(PASSWORD_HASH_LENGTH);
    if (!PKCS5_PBKDF2_HMAC(
            password.data(), password.size(),
            reinterpret_cast<const unsigned char*>(salt_bin.data()),
            PASSWORD_SALT_LENGTH, iterations, EVP_sha256(),
            PASSWORD_HASH_LENGTH, computed.data())) {
      return vr;
    }
    vr.ok = (CRYPTO_memcmp(hash_bin.data(), computed.data(),
                           PASSWORD_HASH_LENGTH) == 0);
    vr.need_rehash = vr.ok && (version < PASSWORD_HASH_VERSION ||
                               iterations < PASSWORD_PBKDF2_ITERATIONS);
    return vr;
  }
  // Legacy raw binary (salt||hash) fallback
  if (stored.size() == 16 + 32) {
    const unsigned char* salt =
        reinterpret_cast<const unsigned char*>(stored.data());
    const unsigned char* hash =
        reinterpret_cast<const unsigned char*>(stored.data() + 16);
    std::vector<unsigned char> computed(32);
    if (!PKCS5_PBKDF2_HMAC(password.data(), password.size(), salt, 16, 10000,
                           EVP_sha256(), 32, computed.data())) {
      return vr;
    }
    vr.ok = (CRYPTO_memcmp(hash, computed.data(), 32) == 0);
    vr.need_rehash = vr.ok;  // legacy always rehash
    return vr;
  }
  return vr;  // invalid format
}

bool verify_password_openssl(std::string_view stored,
                             std::string_view password) {
  return verify_password_openssl_ex(stored, password).ok;
}

std::string base64_to_base64url(const std::string& base64) {
  std::string base64url = base64;
  std::replace(base64url.begin(), base64url.end(), '+', '-');
  std::replace(base64url.begin(), base64url.end(), '/', '_');
  base64url.erase(std::remove(base64url.begin(), base64url.end(), '='),
                  base64url.end());
  return base64url;
}

// Specialized helper functions for different use cases

std::string generateRandomPassword(int length) {
  const std::string uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const std::string lowercase = "abcdefghijklmnopqrstuvwxyz";
  const std::string digits = "0123456789";
  const std::string special = "!@#$%^&*()-_=+[]{}|;:,.<>?";

  const std::string all_characters = uppercase + lowercase + digits + special;

  if (length <= 0) return {};
  std::string password;
  password.resize(static_cast<size_t>(length));

  auto rnd_index = [](int n) -> int {
    // Unbiased selection in [0, n)
    unsigned char b = 0;
    const int maxMultiple = (256 / n) * n;  // highest multiple of n below 256
    do {
      if (RAND_bytes(&b, 1) != 1) {
        throw std::runtime_error("RAND_bytes failed generating password");
      }
    } while (b >= maxMultiple);
    return b % n;
  };

  // If length >= 4, ensure at least one from each category
  int pos = 0;
  if (length >= 4) {
    password[pos++] = uppercase[static_cast<size_t>(
        rnd_index(static_cast<int>(uppercase.size())))];
    password[pos++] = lowercase[static_cast<size_t>(
        rnd_index(static_cast<int>(lowercase.size())))];
    password[pos++] =
        digits[static_cast<size_t>(rnd_index(static_cast<int>(digits.size())))];
    password[pos++] = special[static_cast<size_t>(
        rnd_index(static_cast<int>(special.size())))];
  }

  // Fill remaining with all characters
  for (; pos < length; ++pos) {
    password[static_cast<size_t>(pos)] = all_characters[static_cast<size_t>(
        rnd_index(static_cast<int>(all_characters.size())))];
  }

  // Secure Fisher–Yates shuffle
  for (int i = length - 1; i > 0; --i) {
    int j = rnd_index(i + 1);  // 0..i
    std::swap(password[static_cast<size_t>(i)],
              password[static_cast<size_t>(j)]);
  }

  return password;
}

std::string generateApiSecret(int length) {
  if (length <= 0) return {};
  static constexpr char kAlphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";  // 64
  std::string out;
  out.resize(length);
  std::vector<unsigned char> rnd(static_cast<size_t>(length));
  if (RAND_bytes(rnd.data(), static_cast<int>(rnd.size())) != 1) {
    throw std::runtime_error("RAND_bytes failed generating API secret");
  }
  for (int i = 0; i < length; ++i) {
    out[static_cast<size_t>(i)] = kAlphabet[rnd[static_cast<size_t>(i)] & 0x3F];
  }
  return out;
}

std::string hmac_sha1_base64(const std::string& txt, const std::string& key,
                             bool url_safe) {
  unsigned char hash[SHA_DIGEST_LENGTH];  // Buffer for the hash
  unsigned int hash_len = 0;              // Length of the hash

  // Compute the HMAC using SHA1
  HMAC(EVP_sha1(), key.data(), key.size(),
    reinterpret_cast<const unsigned char*>(txt.data()), txt.size(), hash,
    &hash_len);
  return base64_encode(hash, hash_len, url_safe);
}
std::string sha1_hex(const std::string& txt) {
  unsigned char hash[SHA_DIGEST_LENGTH];  // Buffer for the hash
  SHA1(reinterpret_cast<const unsigned char*>(txt.data()), txt.size(), hash);
  std::string_view hash_view{reinterpret_cast<const char*>(hash),
                             SHA_DIGEST_LENGTH};
  // Convert the hash to a hex string
  std::string hex_str;
  hex_str.reserve(SHA_DIGEST_LENGTH * 2);
  for (unsigned int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
    hex_str += fmt::format("{:02x}", hash[i]);
  }
  return hex_str;
}

std::string file_sha(const std::string& file_path) {
  // Open the file
  std::ifstream file(file_path, std::ios::binary);
  if (!file.is_open()) {
    throw std::runtime_error("Failed to open file: " + file_path);
  }

  // Create a SHA256 context using the EVP API
  // EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  // if (mdctx == nullptr) {
  //   throw std::runtime_error("Failed to create EVP_MD_CTX.");
  // }

  // opensslutil::EVP_MD_CTX_raii context{EVP_MD_CTX_new()};
  EVP_MD_CTX_ptr context{EVP_MD_CTX_new(), &EVP_MD_CTX_free};

  if (!context) throw std::runtime_error("Failed to create context");

  const EVP_MD* sha256 = EVP_sha256();  // Get the SHA256 algorithm
  if (EVP_DigestInit_ex(context.get(), sha256, nullptr) != 1) {
    throw std::runtime_error("Failed to initialize SHA256 digest.");
  }

  // Read the file in chunks and update the hash
  char buffer[4096];
  while (file.read(buffer, sizeof(buffer))) {
    EVP_DigestUpdate(context.get(), buffer, file.gcount());
  }

  // Handle any remaining bytes
  if (file.gcount() > 0) {
    EVP_DigestUpdate(context.get(), buffer, file.gcount());
  }

  // Finalize the hash
  unsigned char hash[EVP_MAX_MD_SIZE];  // Maximum size for any hash
  unsigned int hash_len = 0;
  if (EVP_DigestFinal_ex(context.get(), hash, &hash_len) != 1) {
    throw std::runtime_error("Failed to finalize the SHA256 hash.");
  }

  // Convert the hash to a hex string
  std::string result;
  for (unsigned int i = 0; i < hash_len; ++i) {
    result += fmt::format("{:02x}", hash[i]);
  }

  return result;
}


namespace aescbc {

std::vector<unsigned char> encrypt_aes256_cbc_openssl(
    const std::string& plaintext, const unsigned char* key,
    const unsigned char* iv) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) throw std::runtime_error("Failed to create encryption context");

  std::vector<unsigned char> ciphertext(plaintext.size() +
                                        EVP_MAX_BLOCK_LENGTH);
  int len = 0, ciphertext_len = 0;

  EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
  EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                    (unsigned char*)plaintext.data(), plaintext.size());
  ciphertext_len = len;
  EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
  ciphertext_len += len;

  EVP_CIPHER_CTX_free(ctx);
  ciphertext.resize(ciphertext_len);
  return ciphertext;
}

std::string decrypt_aes256_cbc_openssl(
    const std::vector<unsigned char>& ciphertext, const unsigned char* key,
    const unsigned char* iv) {
  EVP_CIPHER_CTX_ptr ctx{EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free};
  if (!ctx) throw std::runtime_error("Failed to create decryption context");

  std::vector<unsigned char> plaintext(ciphertext.size());
  int len = 0, plaintext_len = 0;

  EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, key, iv);
  EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, ciphertext.data(),
                    ciphertext.size());
  plaintext_len = len;
  EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len);
  plaintext_len += len;

  plaintext.resize(plaintext_len);
  return std::string(plaintext.begin(), plaintext.end());
}
}  // namespace aescbc

}  // namespace cryptutil
}  // namespace cjj365
