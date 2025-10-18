#pragma once
// #include <libssh/libssh.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/buffer.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/safestack.h>
#include <openssl/sha.h>
#include <openssl/types.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stddef.h>

#include <fmt/format.h>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "crypt_util.hpp"
#include "my_error_codes.hpp"
#include "result_monad.hpp"

namespace cjj365 {
namespace opensslutil {

// Struct to hold common CSR subject fields
struct CsrSubject {
  std::string common_name;          // CN - Common Name (required)
  std::string organization;         // O - Organization
  std::string organizational_unit;  // OU - Organizational Unit
  std::string country;              // C - Country (2-letter code)
  std::string state;                // ST - State or Province
  std::string locality;             // L - Locality/City
};

// using X509_raii = std::unique_ptr<X509, decltype(&X509_free)>;
// using PKCS12_raii = std::unique_ptr<PKCS12, decltype(&PKCS12_free)>;

// struct X509Deleter {
//   void operator()(X509* p) const { X509_free(p); }
// };
// struct BIGNUMDeleter {
//   void operator()(BIGNUM* p) const { BN_free(p); }
// };

// struct BIODeleter {
//   void operator()(BIO* p) const { BIO_free(p); }
// };

// struct BUF_MEMDeleter {
//   void operator()(BUF_MEM* p) const { BUF_MEM_free(p); }
// };

// class Bn_raii {
//  public:
//   Bn_raii() : bn_(nullptr) {}
//   ~Bn_raii() {
//     if (bn_) BN_free(bn_);
//   }

//   // Move constructor
//   Bn_raii(Bn_raii&& other) noexcept : bn_(other.bn_) { other.bn_ = nullptr; }

//   // Move assignment
//   Bn_raii& operator=(Bn_raii&& other) noexcept {
//     if (this != &other) {
//       BN_free(bn_);
//       bn_ = other.bn_;
//       other.bn_ = nullptr;
//     }
//     return *this;
//   }

//   // Disable copying
//   Bn_raii(const Bn_raii&) = delete;
//   Bn_raii& operator=(const Bn_raii&) = delete;

//   // Implicit conversion to BIGNUM**
//   BIGNUM** get_pofp() { return &bn_; }

//   // Get raw BIGNUM* without transferring ownership
//   BIGNUM* get() const { return bn_; }

//  private:
//   BIGNUM* bn_;
// };

std::string sha256_hex(const std::string& data);

// Encrypt function
std::vector<unsigned char> encrypt(const std::string& plaintext,
                                   const std::vector<unsigned char>& key,
                                   const std::vector<unsigned char>& iv);

std::string decrypt(const std::string& ciphertext, const std::string& secret);
// Decrypt function
std::string decrypt(const std::vector<unsigned char>& ciphertext,
                    const std::vector<unsigned char>& key,
                    const std::vector<unsigned char>& iv);

inline std::string vectorToHex(const std::vector<unsigned char>& data) {
  std::ostringstream oss;
  for (unsigned char byte : data) {
    oss << std::hex << std::setw(2) << std::setfill('0')
        << static_cast<int>(byte);
  }
  return oss.str();
}

inline std::vector<unsigned char> hexToVector(const std::string& hex) {
  if (hex.size() % 2 != 0) {
    throw std::invalid_argument("Hex string must have an even length.");
  }

  std::vector<unsigned char> data;
  data.reserve(hex.size() / 2);

  for (size_t i = 0; i < hex.size(); i += 2) {
    unsigned int byte;
    std::istringstream iss(hex.substr(i, 2));
    iss >> std::hex >> byte;
    data.push_back(static_cast<unsigned char>(byte));
  }
  return data;
}

std::pair<std::vector<unsigned char>, std::vector<unsigned char>> key_iv();

std::pair<std::vector<unsigned char>, std::vector<unsigned char>> hex_to_key_iv(
    const std::string& hex);
std::string key_iv_to_hex(const std::pair<std::vector<unsigned char>,
                                          std::vector<unsigned char>>& key_iv);
monad::MyResult<cryptutil::EVP_PKEY_ptr> make_ec_p256_key();
monad::MyResult<cryptutil::EVP_PKEY_ptr> make_rsa_key(int bits = 4096);

std::string generate_dh();
monad::MyResult<std::string> evp_pkey_to_der(
    const cryptutil::EVP_PKEY_ptr& pkey, bool is_private = true);
bool convert_pem_string_to_der(const std::string& pem_content,
                               std::vector<unsigned char>& der_data);
std::string get_predefined_dh();

monad::MyResult<std::pair<std::string, std::string>> get_ec_public_key_xy(
    cryptutil::EVP_PKEY_ptr& pkey, bool urlsafe = false);
monad::MyResult<std::pair<std::string, std::string>> get_rsa_public_key_ne(
    cryptutil::EVP_PKEY_ptr& privateKey,  //
    bool urlsafe = false);

// inline std::string get_bn_hex_string(Bn_raii& bn) {
inline std::string get_bn_hex_string(cryptutil::BIGNUM_ptr& bn) {
  char* hex_str = BN_bn2hex(bn.get());
  std::string result(hex_str);
  OPENSSL_free(hex_str);
  return result;
}
// inline std::string get_bn_bin_string(Bn_raii& bn) {
inline std::string get_bn_bin_string(cryptutil::BIGNUM_ptr& bn) {
  size_t len = BN_num_bytes(bn.get());
  std::vector<unsigned char> bin(len);
  BN_bn2bin(bn.get(), bin.data());
  return std::string(bin.begin(), bin.end());
}
std::string key_to_pem(cryptutil::EVP_PKEY_ptr& private_pkey, bool for_private);
cryptutil::EVP_PKEY_ptr load_private_key(const std::string& private_key,
                                         bool der = false);
cryptutil::EVP_PKEY_ptr load_public_key(const std::string& public_key);
std::string generate_csr(const cryptutil::EVP_PKEY_ptr& pkey,  //
                         const CsrSubject& subject,            //
                         const std::vector<std::string>& san_list);

monad::MyResult<std::string> generate_csr_monad(
    const cryptutil::EVP_PKEY_ptr& pkey,  //
    const CsrSubject& subject,            //
    const std::vector<std::string>& san_list);

cryptutil::EVP_PKEY_ptr get_public_key(cryptutil::EVP_PKEY_ptr& private_key);

// std::string self_signed_cert(cryptutil::EVP_PKEY_ptr& pkey,
//                              const std::string& cn = "my.domain.com",
//                              const std::string& o = "My Company",
//                              const std::string& l = "San Francisco",
//                              const std::string& st = "California",
//                              const std::string& c = "US");
// EVP stands for Envelope
monad::MyResult<std::string> sign_message(
    const std::string& payload, const cryptutil::EVP_PKEY_ptr& private_key);

monad::MyResult<void> verify_message(const std::string& payload,
                                     const std::string& signature,
                                     const cryptutil::EVP_PKEY_ptr& public_key);

/**
 * @brief Sign a message with a private key with ES256 algorithm.
 */
monad::MyResult<std::string> sign_message(const std::string& payload,
                                          const std::string& private_key);

monad::MyResult<std::string> sign_message_base64(
    const std::string& payload, const cryptutil::EVP_PKEY_ptr& private_key,
    bool urlsafe = false);

monad::MyResult<std::string> sign_message_hex(
    const std::string& payload, const cryptutil::EVP_PKEY_ptr& private_key);

// Helper function to add extensions to the certificate
void add_extension(X509* cert, int nid, const char* value);

std::string bin_to_hex(const std::string& bin);

std::vector<char> hex_to_vector(std::string_view hex);

std::vector<unsigned char> extract_raw_signature(
    const std::vector<unsigned char>& der_signature);
/**
 * @brief Generate a new RSA key pair
 * token.thumbprint
 */
// std::string get_public_key_thumbprint(EVP_PKEY* pkey) {
std::string get_public_key_thumbprint(cryptutil::EVP_PKEY_ptr& pkey);
/**
 * @brief Generate a new key pair for use with ACME.
 */
inline monad::MyVoidResult add_ext(cryptutil::X509_ptr& cert, int nid,
                                   const std::string& val) {
  X509V3_CTX ctx;
  X509V3_set_ctx(&ctx, cert.get(), cert.get(), nullptr, nullptr, 0);
  auto ex = cjj365::cryptutil::X509_EXTENSION_ptr(
      X509V3_EXT_conf_nid(nullptr, &ctx, nid, (char*)val.c_str()),
      &X509_EXTENSION_free);
  if (!ex)
    return monad::MyVoidResult::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "X509V3_EXT_conf_nid failed"});
  if (X509_add_ext(cert.get(), ex.get(), -1) != 1) {
    return monad::MyVoidResult::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "X509_add_ext failed"});
  }
  return monad::MyVoidResult::Ok();
}

// Helper function to issue a certificate using an existing RSA CA
inline monad::MyVoidResult write_pem_key_and_cert(
    const cryptutil::EVP_PKEY_ptr& key, const cryptutil::X509_ptr& cert,
    const std::string& key_path, const std::string& crt_path) {
  // Write private key
  {
    cryptutil::BIO_ptr bio(BIO_new_file(key_path.c_str(), "w"), &BIO_free);
    if (!bio)
      return monad::MyVoidResult::Err(
          monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                       .what = "BIO_new_file key failed"});
    if (PEM_write_bio_PrivateKey(bio.get(), key.get(), nullptr, nullptr, 0,
                                 nullptr, nullptr) != 1)
      return monad::MyVoidResult::Err(
          monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                       .what = "PEM_write_bio_PrivateKey failed"});
  }
  // Write certificate
  {
    cryptutil::BIO_ptr bio(BIO_new_file(crt_path.c_str(), "w"), &BIO_free);
    if (!bio)
      return monad::MyVoidResult::Err(
          monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                       .what = "BIO_new_file cert failed"});
    if (PEM_write_bio_X509(bio.get(), cert.get()) != 1)
      return monad::MyVoidResult::Err(
          monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                       .what = "PEM_write_bio_X509 failed"});
  }
  return monad::MyVoidResult::Ok();
}

monad::MyResult<std::pair<std::string, std::string>> generate_es256_key_pair();

monad::MyResult<cryptutil::X509_ptr> make_self_signed_ca(
    const cryptutil::EVP_PKEY_ptr& pkey,  //
    const std::string& C,                 //
    const std::string& O,                 //
    const std::string& CN,                //
    int days = 3650);

inline monad::MyVoidResult set_name_fields(cryptutil::X509_NAME_ptr& name,
                                           const std::string& C,
                                           const std::string& O,
                                           const std::string& CN) {
  // Add fields; return result for error handling.
  if (!name)
    return monad::MyVoidResult::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "X509_NAME is null"});

  if (X509_NAME_add_entry_by_txt(name.get(), "C", MBSTRING_ASC,
                                 (const unsigned char*)C.c_str(), -1, -1,
                                 0) != 1)
    return monad::MyVoidResult::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = fmt::format("Add C failed, C is: {}", C)});

  if (X509_NAME_add_entry_by_txt(name.get(), "O", MBSTRING_ASC,
                                 (const unsigned char*)O.c_str(), -1, -1,
                                 0) != 1)
    return monad::MyVoidResult::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = fmt::format("Add O failed, O is: {}", O)});

  if (X509_NAME_add_entry_by_txt(name.get(), "CN", MBSTRING_ASC,
                                 (const unsigned char*)CN.c_str(), -1, -1,
                                 0) != 1)
    return monad::MyVoidResult::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = fmt::format("Add CN failed, CN is: {}", CN)});

  return monad::MyVoidResult::Ok();
}

monad::MyResult<cryptutil::X509_ptr> issue_certificate(
    const cryptutil::EVP_PKEY_ptr& cert_key, const std::string& subject_C,
    const std::string& subject_O, const std::string& subject_CN,
    const std::vector<std::string>& sans, const cryptutil::EVP_PKEY_ptr& ca_key,
    const cryptutil::X509_ptr& ca_cert, int days = 90);
// Parses multiple PEM certs, returns leaf and intermediate stack
void parse_cert_chain(const std::string& pem_data,
                      cryptutil::X509_ptr& leaf_cert,
                      STACK_OF(X509) * &ca_stack);

// Create PKCS#12 bundle and return binary content as string
std::string create_pkcs12_string(const cryptutil::EVP_PKEY_ptr& pkey,
                                 const std::string& cert_chain_pem,
                                 const std::string& name,
                                 const std::string& password);

}  // namespace opensslutil
}  // namespace cjj365
