#pragma once

#include <fmt/format.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <stddef.h>

#include <algorithm>
#include <boost/json.hpp>
#include <memory>
#include <random>
#include <string>
#include <string_view>
#include <vector>

namespace cjj365 {
namespace cryptutil {

using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using X509_ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using BIO_ptr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using BIGNUM_ptr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using X509_NAME_ptr = std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)>;
using EVP_PKEY_CTX_ptr =
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using X509_EXTENSION_ptr =
    std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)>;
using ASN1_INTEGER_ptr =
    std::unique_ptr<ASN1_INTEGER, decltype(&ASN1_INTEGER_free)>;
// Smart pointer wrappers
using EVP_CIPHER_CTX_ptr =
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
using EVP_MD_CTX_ptr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using PKCS12_ptr = std::unique_ptr<PKCS12, decltype(&PKCS12_free)>;
using BUF_MEM_ptr = std::unique_ptr<BUF_MEM, decltype(&BUF_MEM_free)>;
using X509_NAME_ptr = std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)>;
using X509_EXTENSION_ptr =
    std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)>;
using ASN1_INTEGER_ptr =
    std::unique_ptr<ASN1_INTEGER, decltype(&ASN1_INTEGER_free)>;
using X509_REQ_ptr = std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)>;
using X509_STORE_ptr = std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)>;
using X509_CRL_ptr = std::unique_ptr<X509_CRL, decltype(&X509_CRL_free)>;
// using RSA_ptr = std::unique_ptr<RSA, decltype(&RSA_free)>;
// using EC_KEY_ptr = std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)>;
// using DH_ptr = std::unique_ptr<DH, decltype(&DH_free)>;

namespace aescbc {

inline const int SALT_SIZE = 32;  //
inline const int IV_SIZE = 12;    //
inline const int KEY_SIZE = 16;   // AES-256

inline void generate_random_bytes(unsigned char* buffer, size_t size) {
  RAND_bytes(buffer, size);
}

inline bool derive_key(const std::string& password, const unsigned char* salt,
                       unsigned char* key) {
  return PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt, SALT_SIZE,
                           100000, EVP_sha256(), KEY_SIZE, key);
}

std::vector<unsigned char> encrypt_aes256_cbc_openssl(
  const std::string& plaintext, const unsigned char* key,
  const unsigned char* iv);

std::string decrypt_aes256_cbc_openssl(
  const std::vector<unsigned char>& ciphertext, const unsigned char* key,
  const unsigned char* iv);
}  // namespace aescbc

// Current password hashing parameters (bump to force rehash)
inline constexpr int PASSWORD_HASH_VERSION = 1;
inline constexpr int PASSWORD_PBKDF2_ITERATIONS = 100000;  // raise over time
inline constexpr int PASSWORD_SALT_LENGTH = 16;
inline constexpr int PASSWORD_HASH_LENGTH = 32;

struct PasswordVerifyResult {
  bool ok{false};
  bool need_rehash{false};
};

/**
 * Hash a password using PBKDF2-HMAC-SHA256 with a random salt.
 *
 * Output format (versioned, URL-safe base64 components):
 *   pbkdf2$sha256$v=<version>$i=<iterations>$s=<salt_b64>$h=<hash_b64>
 * Where:
 *   - version: cjj365::cryptutil::PASSWORD_HASH_VERSION (int)
 *   - iterations: cjj365::cryptutil::PASSWORD_PBKDF2_ITERATIONS (int)
 *   - salt_b64: base64(salt), salt size = PASSWORD_SALT_LENGTH (default 16)
 *   - hash_b64: base64(derived hash), size = PASSWORD_HASH_LENGTH (default 32)
 *
 * Usage:
 *   std::string stored = cjj365::cryptutil::hash_password_openssl("secret");
 *   auto vr = cjj365::cryptutil::verify_password_openssl_ex(stored, "secret");
 *   if (vr.ok && vr.need_rehash) {
 *     // Re-hash with the current parameters and store again
 *   }
 */
std::string hash_password_openssl(const std::string& password);

/**
 * Verify a password against a stored hash.
 * - Supports the versioned PBKDF2 format produced by hash_password_openssl.
 * - Also supports a legacy binary format (salt||hash) for backward compatibility.
 *
 * Returns:
 *   PasswordVerifyResult { bool ok; bool need_rehash; }
 *   - ok: true if the password matches.
 *   - need_rehash: true if ok==true but the stored parameters (version/iterations)
 *                  are older than the current constants; callers should re-hash
 *                  and persist a new value.
 *
 * Example:
 *   auto vr = cjj365::cryptutil::verify_password_openssl_ex(stored, input);
 *   if (!vr.ok) {
 *     // reject
 *   }
 *   if (vr.need_rehash) {
 *     stored = cjj365::cryptutil::hash_password_openssl(input);
 *   }
 */
PasswordVerifyResult verify_password_openssl_ex(
  std::string_view hashed_password, std::string_view password);

/**
 * Convenience wrapper that returns only a boolean match result.
 * Prefer verify_password_openssl_ex when you want rehash guidance.
 */
bool verify_password_openssl(std::string_view hashed_password,
               std::string_view password);

std::string base64_to_base64url(const std::string& base64);
std::string hmac_sha1_base64(const std::string& txt, const std::string& key,
                             bool url_safe = true);
std::string sha1_hex(const std::string& txt);
std::string file_sha(const std::string& file_path);

template <typename CharSet>
std::string generateRandomString(int length, CharSet charset) {
  // Initialize random engine
  std::random_device rd;
  std::mt19937 generator(rd());
  std::uniform_int_distribution<> distribution(0, charset.size() - 1);

  // Generate random string
  std::string result;
  for (int i = 0; i < length; ++i) {
    result += charset[distribution(generator)];
  }

  // Shuffle to increase randomness
  std::shuffle(result.begin(), result.end(), generator);
  return result;
}

// Specialized helper functions for different use cases

std::string generateRandomPassword(int length);

std::string generateApiSecret(int length);

}  // namespace cryptutil
}  // namespace cjj365
