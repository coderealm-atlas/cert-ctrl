#include "openssl/openssl_raii.hpp"
#include <fmt/format.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>

#include <algorithm>
#include <exception>
#include <iostream>
#include <utility>

#include "base64.h"
#include "common_macros.hpp"
#include "openssl/crypt_util.hpp"
#include "my_error_codes.hpp"
#include "openssl/crypt_util.hpp"
#include "result_monad.hpp"
#include "util/string_util.hpp"

namespace cjj365 {
namespace opensslutil {

std::string generate_csr(const cryptutil::EVP_PKEY_ptr& pkey,  //
                         const CsrSubject& subject,            //
                         const std::vector<std::string>& san_list) {
  // Create a new X509 request
  cryptutil::X509_REQ_ptr req(X509_REQ_new(), &X509_REQ_free);
  X509_REQ_set_version(req.get(), 1);  // Version 1 (X.509 v3)

  // Set the subject name using all provided fields
  cryptutil::X509_NAME_ptr name(X509_NAME_new(), &X509_NAME_free);

  // Add subject fields (only if they're not empty)
  if (!subject.common_name.empty()) {
    X509_NAME_add_entry_by_txt(
        name.get(), "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>(subject.common_name.c_str()), -1,
        -1, 0);
  }
  if (!subject.organization.empty()) {
    X509_NAME_add_entry_by_txt(
        name.get(), "O", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>(subject.organization.c_str()),
        -1, -1, 0);
  }
  if (!subject.organizational_unit.empty()) {
    X509_NAME_add_entry_by_txt(name.get(), "OU", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(
                                   subject.organizational_unit.c_str()),
                               -1, -1, 0);
  }
  if (!subject.country.empty()) {
    X509_NAME_add_entry_by_txt(
        name.get(), "C", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>(subject.country.c_str()), -1, -1,
        0);
  }
  if (!subject.state.empty()) {
    X509_NAME_add_entry_by_txt(
        name.get(), "ST", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>(subject.state.c_str()), -1, -1,
        0);
  }
  if (!subject.locality.empty()) {
    X509_NAME_add_entry_by_txt(
        name.get(), "L", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>(subject.locality.c_str()), -1,
        -1, 0);
  }

  X509_REQ_set_subject_name(req.get(), name.get());

  // Add Subject Alternative Names (SANs)
  if (!san_list.empty()) {
    // Create the extension structure
    STACK_OF(X509_EXTENSION)* exts = sk_X509_EXTENSION_new_null();

    // Construct the SANs string
    std::string san_value = "DNS:" + san_list[0];
    for (size_t i = 1; i < san_list.size(); ++i) {
      san_value += ",DNS:" + san_list[i];
    }

    // Create the SAN extension
    X509_EXTENSION* san_ext = X509V3_EXT_conf_nid(
        nullptr, nullptr, NID_subject_alt_name, san_value.c_str());
    if (!san_ext) {
      std::cerr << "Failed to create SAN extension." << std::endl;
      sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
      // EVP_PKEY_free(pkey);
      throw std::runtime_error("Failed to create SAN extension.");
    }

    // Add the SAN extension to the extensions stack
    sk_X509_EXTENSION_push(exts, san_ext);

    // Attach the extensions to the request
    X509_REQ_add_extensions(req.get(), exts);

    // Free the extensions stack
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
  }

  // Set the public key for the request
  X509_REQ_set_pubkey(req.get(), pkey.get());

  // Sign the request with the private key
  if (!X509_REQ_sign(req.get(), pkey.get(), EVP_sha256())) {
    std::cerr << "Failed to sign the CSR." << std::endl;
    throw std::runtime_error("Failed to sign the CSR.");
  }

  unsigned char* der_buf = nullptr;
  int der_len = i2d_X509_REQ(req.get(), &der_buf);

  if (der_len < 0) {
    std::cerr << "Failed to convert CSR to DER format." << std::endl;
    throw std::runtime_error("Failed to convert CSR to DER format.");
  } else {
    // der_buf now contains the DER-encoded CSR, and der_len is its length.
    // Use der_buf as needed and free it after use
    std::string der_b64 = base64_encode(der_buf, static_cast<size_t>(der_len), true);
    size_t pos = der_b64.find_last_not_of('.');
    if (pos != std::string::npos) {
      der_b64.erase(pos + 1);
    }
    OPENSSL_free(der_buf);
    return der_b64;
  }
}
monad::MyResult<std::string> generate_csr_monad(
    const cryptutil::EVP_PKEY_ptr& pkey,  //
    const CsrSubject& subject,            //
    const std::vector<std::string>& san_list) {
  using namespace monad;
  try {
    std::string csr = generate_csr(pkey, subject, san_list);
    return MyResult<std::string>::Ok(std::move(csr));
  } catch (const std::exception& e) {
    return MyResult<std::string>::Err(
        Error{.code = 1,
              .what = fmt::format("Failed to generate CSR: {}", e.what())});
  }
}

std::string sha256_hex(const std::string& data) {
  cryptutil::EVP_MD_CTX_ptr context{EVP_MD_CTX_new(), EVP_MD_CTX_free};
  if (!context) throw std::runtime_error("Failed to create context");

  // Initialize the context with SHA-256
  if (1 != EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr)) {
    throw std::runtime_error("Failed to initialize digest");
  }

  // Update the context with the data
  if (1 != EVP_DigestUpdate(context.get(), data.c_str(), data.size())) {
    throw std::runtime_error("Failed to update digest");
  }

  // Finalize and get the hash
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int length = 0;
  if (1 != EVP_DigestFinal_ex(context.get(), hash, &length)) {
    throw std::runtime_error("Failed to finalize digest");
  }

  // Convert the hash to a hexadecimal string
  std::stringstream ss;
  for (unsigned int i = 0; i < length; i++) {
    ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
  }
  return ss.str();
}

// Helper function to handle OpenSSL errors
void handleOpenSSLError() {
  ERR_print_errors_fp(stderr);
  throw std::runtime_error("OpenSSL error occurred");
}

// Helper function to handle OpenSSL errors with detailed logging
void handleOpenSSLErrorWithDetails() {
  unsigned long errCode;
  while ((errCode = ERR_get_error())) {
    char* err = ERR_error_string(errCode, nullptr);
    std::cerr << "OpenSSL error: " << err << std::endl;
  }
  throw std::runtime_error("OpenSSL error occurred");
}

// Encrypt function
std::vector<unsigned char> encrypt(const std::string& plaintext,
                                   const std::vector<unsigned char>& key,
                                   const std::vector<unsigned char>& iv) {
  std::cerr << "Encrypting with key: " << vectorToHex(key) << std::endl;
  std::cerr << "Encrypting with iv: " << vectorToHex(iv) << std::endl;
  std::cerr << "Plaintext size: " << plaintext.size() << std::endl;

  if (key.size() != EVP_CIPHER_key_length(EVP_aes_256_cbc())) {
    std::cerr << "Invalid key size: " << key.size() << std::endl;
    throw std::runtime_error("Invalid key size");
  }

  if (iv.size() != EVP_CIPHER_iv_length(EVP_aes_256_cbc())) {
    std::cerr << "Invalid IV size: " << iv.size() << std::endl;
    throw std::runtime_error("Invalid IV size");
  }

  cryptutil::EVP_CIPHER_CTX_ptr ctx{EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free};
  if (!ctx) handleOpenSSLErrorWithDetails();

  // Initialize encryption context
  if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key.data(),
                         iv.data()) != 1) {
    handleOpenSSLErrorWithDetails();
  }
  // EVP_CIPHER_CTX_set_padding(ctx, 1);

  std::vector<unsigned char> ciphertext(
      plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
  int len = 0, ciphertext_len = 0;

  // Encrypt the plaintext
  if (EVP_EncryptUpdate(
          ctx.get(), ciphertext.data(), &len,
          reinterpret_cast<const unsigned char*>(plaintext.data()),
          plaintext.size()) != 1) {
    handleOpenSSLErrorWithDetails();
  }
  ciphertext_len += len;

  std::cerr << "Ciphertext length after update: " << ciphertext_len
            << std::endl;

  // Finalize encryption
  if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + ciphertext_len,
                          &len) != 1) {
    handleOpenSSLErrorWithDetails();
  }
  ciphertext_len += len;
  ciphertext.resize(ciphertext_len);
  return ciphertext;
}

std::string decrypt(const std::string& ciphertext, const std::string& secret) {
  std::cout << "secret: " << secret << std::endl;
  std::pair<std::vector<unsigned char>, std::vector<unsigned char>> key_iv =
      hex_to_key_iv(secret);
  std::vector<unsigned char> ciphertext_vec{ciphertext.begin(),
                                            ciphertext.end()};
  return decrypt(ciphertext_vec, key_iv.first, key_iv.second);
}

// Decrypt function
std::string decrypt(const std::vector<unsigned char>& ciphertext,
                    const std::vector<unsigned char>& key,
                    const std::vector<unsigned char>& iv) {
  // std::string decrypt(std::vector<unsigned char> ciphertext,
  //                     std::vector<unsigned char> key,
  //                     std::vector<unsigned char> iv) {
  std::cout << "Decrypting with key: " << vectorToHex(key)
            << "size: " << key.size() << std::endl;
  std::cout << "Decrypting with iv: " << vectorToHex(iv)
            << "size: " << iv.size() << std::endl;
  std::cout << "Ciphertext size: " << ciphertext.size() << std::endl;
  // std::cout << "Ciphertext: " << vectorToHex(ciphertext) << std::endl;

  if (key.size() != EVP_CIPHER_key_length(EVP_aes_256_cbc())) {
    std::cerr << "Invalid key size: " << key.size() << std::endl;
    throw std::runtime_error("Invalid key size");
  }

  if (iv.size() != EVP_CIPHER_iv_length(EVP_aes_256_cbc())) {
    std::cerr << "Invalid IV size: " << iv.size() << std::endl;
    throw std::runtime_error("Invalid IV size");
  }

  if (ciphertext.size() % EVP_CIPHER_block_size(EVP_aes_256_cbc()) != 0) {
    std::cerr << "Ciphertext size is not a multiple of the block size"
              << std::endl;
    throw std::runtime_error("Invalid ciphertext size");
  }

  cryptutil::EVP_CIPHER_CTX_ptr ctx{EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free};
  if (!ctx) handleOpenSSLErrorWithDetails();

  // Initialize decryption context
  if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key.data(),
                         iv.data()) != 1) {
    handleOpenSSLErrorWithDetails();
  }

  // Enable padding
  // EVP_CIPHER_CTX_set_padding(ctx, 1);

  std::vector<unsigned char> plaintext(ciphertext.size());
  int len = 0, plaintext_len = 0;

  // Decrypt the ciphertext
  if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, ciphertext.data(),
                        ciphertext.size()) != 1) {
    handleOpenSSLErrorWithDetails();
  }
  plaintext_len += len;

  std::cerr << "Decrypted length after update: " << plaintext_len << std::endl;

  // Finalize decryption
  if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + plaintext_len, &len) !=
      1) {
    std::cerr << "Failed to finalize decryption" << std::endl;
    handleOpenSSLErrorWithDetails();
  }
  plaintext_len += len;
  plaintext.resize(plaintext_len);
  return std::string(plaintext.begin(), plaintext.end());
}

std::pair<std::vector<unsigned char>, std::vector<unsigned char>> key_iv() {
  std::vector<unsigned char> key(EVP_CIPHER_key_length(EVP_aes_256_cbc()));
  std::vector<unsigned char> iv(EVP_CIPHER_iv_length(EVP_aes_256_cbc()));

  if (RAND_bytes(key.data(), key.size()) != 1) handleOpenSSLError();
  if (RAND_bytes(iv.data(), iv.size()) != 1) handleOpenSSLError();

  return {key, iv};
}

std::pair<std::vector<unsigned char>, std::vector<unsigned char>> hex_to_key_iv(
    const std::string& hex) {
  size_t slash = hex.find('/');
  std::string key_hex = hex.substr(0, slash);
  std::string iv_hex = hex.substr(slash + 1);
  return {hexToVector(std::string{key_hex}), hexToVector(iv_hex)};
}

std::string key_iv_to_hex(const std::pair<std::vector<unsigned char>,
                                          std::vector<unsigned char>>& key_iv) {
  return vectorToHex(key_iv.first) + "/" + vectorToHex(key_iv.second);
}

monad::MyResult<cryptutil::EVP_PKEY_ptr> make_rsa_key(int bits) {
  cryptutil::EVP_PKEY_ptr pkey(EVP_PKEY_new(), &EVP_PKEY_free);
  if (!pkey)
    return monad::MyResult<cryptutil::EVP_PKEY_ptr>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "EVP_PKEY_new failed"});

  cryptutil::BIGNUM_ptr e(BN_new(), &BN_free);
  if (!e || BN_set_word(e.get(), RSA_F4) != 1)
    return monad::MyResult<cryptutil::EVP_PKEY_ptr>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "BN_set_word failed"});

  cryptutil::EVP_PKEY_CTX_ptr genctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr),
                                     &EVP_PKEY_CTX_free);
  if (!genctx)
    return monad::MyResult<cryptutil::EVP_PKEY_ptr>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "EVP_PKEY_CTX_new_id failed"});

  if (EVP_PKEY_keygen_init(genctx.get()) != 1) {
    return monad::MyResult<cryptutil::EVP_PKEY_ptr>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "EVP_PKEY_keygen_init failed"});
  }
  if (EVP_PKEY_CTX_set_rsa_keygen_bits(genctx.get(), bits) != 1 ||
      EVP_PKEY_CTX_set1_rsa_keygen_pubexp(genctx.get(), e.get()) != 1) {
    return monad::MyResult<cryptutil::EVP_PKEY_ptr>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "EVP_PKEY_CTX_set_* failed"});
  }

  EVP_PKEY* raw = nullptr;
  if (EVP_PKEY_keygen(genctx.get(), &raw) != 1) {
    return monad::MyResult<cryptutil::EVP_PKEY_ptr>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "EVP_PKEY_keygen failed"});
  }
  pkey.reset(raw);
  return monad::MyResult<cryptutil::EVP_PKEY_ptr>::Ok(std::move(pkey));
}

monad::MyResult<cryptutil::EVP_PKEY_ptr> make_ec_p256_key() {
  // Use the modern EVP_PKEY approach for ECDSA P-256
  auto e = [](const std::string& message) {
    return monad::MyResult<cryptutil::EVP_PKEY_ptr>::Err(monad::Error{
        .code = my_errors::OPENSSL::UNEXPECTED_RESULT, .what = message});
  };
  cjj365::cryptutil::EVP_PKEY_CTX_ptr pctx(
      EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), &EVP_PKEY_CTX_free);
  if (!pctx)
    return monad::MyResult<cryptutil::EVP_PKEY_ptr>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "EVP_PKEY_CTX_new_id failed"});

  if (EVP_PKEY_keygen_init(pctx.get()) <= 0) {
    return monad::MyResult<cryptutil::EVP_PKEY_ptr>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "EVP_PKEY_keygen_init failed"});
  }

  if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx.get(),
                                             NID_X9_62_prime256v1) <= 0) {
    return monad::MyResult<cryptutil::EVP_PKEY_ptr>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed"});
  }

  EVP_PKEY* pkey = nullptr;
  if (EVP_PKEY_keygen(pctx.get(), &pkey) <= 0) {
    return monad::MyResult<cryptutil::EVP_PKEY_ptr>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "EVP_PKEY_keygen failed"});
  }
  return monad::MyResult<cryptutil::EVP_PKEY_ptr>::Ok(
      cryptutil::EVP_PKEY_ptr(pkey, &EVP_PKEY_free));
}

std::string get_predefined_dh() {
  // Use EVP_PKEY API to generate 2048-bit DH parameters (predefined group)
  cryptutil::EVP_PKEY_CTX_ptr pctx_raii{EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL),
                                        &EVP_PKEY_CTX_free};
  if (!pctx_raii) {
    throw std::runtime_error("Failed to create EVP_PKEY_CTX for DH");
  }

  // Initialize the DH parameters generation
  if (EVP_PKEY_paramgen_init(pctx_raii.get()) <= 0) {
    throw std::runtime_error("Failed to initialize DH parameters generation");
  }

  // Set the key size (prime length in bits, 2048 in this case)
  if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(pctx_raii.get(), 2048) <= 0) {
    throw std::runtime_error("Failed to set DH parameter prime length");
  }

  // Generate the DH parameters
  cryptutil::EVP_PKEY_ptr params_ptr(nullptr, &EVP_PKEY_free);
  EVP_PKEY* raw_params = nullptr;
  if (EVP_PKEY_paramgen(pctx_raii.get(), &raw_params) <= 0) {
    throw std::runtime_error("Failed to generate DH parameters");
  }
  params_ptr.reset(raw_params);

  // Create a BIO for writing the PEM output
  // std::unique_ptr<BIO, BIODeleter> bio_ptr();
  cryptutil::BIO_ptr bio_ptr(BIO_new(BIO_s_mem()), &BIO_free);
  if (!bio_ptr) {
    throw std::runtime_error("Failed to create BIO");
  }
  // Write the DH parameters to the BIO in PEM format
  if (PEM_write_bio_Parameters(bio_ptr.get(), params_ptr.get()) <= 0) {
    throw std::runtime_error("Failed to write DH parameters in PEM format");
  }

  // Get the PEM data from the BIO
  char* pem_data;
  long pem_len = BIO_get_mem_data(bio_ptr.get(), &pem_data);
  std::string pem_string(pem_data, pem_len);

  return pem_string;
}

std::string generate_dh() {
  // Create EVP_PKEY_CTX for Diffie-Hellman
  cryptutil::EVP_PKEY_CTX_ptr pctx_raii{EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL),
                                        &EVP_PKEY_CTX_free};

  if (!pctx_raii) {
    std::cerr << "Failed to create EVP_PKEY_CTX for DH" << std::endl;
    throw std::runtime_error("Failed to create EVP_PKEY_CTX for DH");
  }

  // Initialize the DH parameters generation
  if (EVP_PKEY_paramgen_init(pctx_raii.get()) <= 0) {
    std::cerr << "Failed to initialize DH parameters generation" << std::endl;
    throw std::runtime_error("Failed to initialize DH parameters generation");
  }

  // Set the key size (prime length in bits, 2048 in this case)
  if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(pctx_raii.get(), 2048) <= 0) {
    std::cerr << "Failed to set DH parameter prime length" << std::endl;
    throw std::runtime_error("Failed to set DH parameter prime length");
  }

  cryptutil::EVP_PKEY_ptr params_ptr{nullptr, &EVP_PKEY_free};
  // Generate the DH parameters
  EVP_PKEY* raw_params = nullptr;
  if (EVP_PKEY_paramgen(pctx_raii.get(), &raw_params) <= 0 ||
      raw_params == nullptr) {
    std::cerr << "Failed to generate DH parameters" << std::endl;
    throw std::runtime_error("Failed to generate DH parameters");
  }
  params_ptr.reset(raw_params);

  // Create a BIO for writing the PEM output
  cryptutil::BIO_ptr bio_ptr(BIO_new(BIO_s_mem()), &BIO_free);
  if (!bio_ptr) {
    std::cerr << "Failed to create BIO" << std::endl;
    throw std::runtime_error("Failed to create BIO");
  }
  // Write the DH parameters to the BIO in PEM format
  if (PEM_write_bio_Parameters(bio_ptr.get(), params_ptr.get()) <= 0) {
    std::cerr << "Failed to write DH parameters in PEM format" << std::endl;
    throw std::runtime_error("Failed to write DH parameters in PEM format");
  }

  // Get the PEM data from the BIO
  char* pem_data;
  long pem_len = BIO_get_mem_data(bio_ptr.get(), &pem_data);
  std::string pem_string(pem_data, pem_len);

  // Cleanup
  DEBUG_PRINT("DH Parameters in PEM format:\n" << pem_string);
  return pem_string;
}

bool convert_pem_string_to_der(const std::string& pem_content,
                               std::vector<unsigned char>& der_data) {
  // Create a BIO memory buffer and write the PEM content into it
  cryptutil::BIO_ptr bio_ptr(
      BIO_new_mem_buf(pem_content.data(), pem_content.size()), &BIO_free);
  if (!bio_ptr) {
    std::cerr << "Failed to create BIO buffer." << std::endl;
    return false;
  }

  // Read the PEM certificate from BIO
  cryptutil::X509_ptr cert(
      PEM_read_bio_X509(bio_ptr.get(), nullptr, nullptr, nullptr), &X509_free);

  if (!cert) {
    std::cerr << "Failed to read X509 certificate from PEM string."
              << std::endl;
    return false;
  }

  // Convert X509 certificate to DER format
  int len = i2d_X509(cert.get(), nullptr);
  if (len <= 0) {
    std::cerr << "Failed to calculate DER length." << std::endl;
    return false;
  }

  der_data.resize(len);
  unsigned char* p = der_data.data();
  if (i2d_X509(cert.get(), &p) <= 0) {
    std::cerr << "Failed to convert PEM to DER." << std::endl;
    return false;
  }
  return true;
}

// General function to convert EVP_PKEY to DER format (for both private and
// public key)
monad::MyResult<std::string> evp_pkey_to_der(
    const cryptutil::EVP_PKEY_ptr& pkey, bool is_private) {
  cryptutil::BIO_ptr bio_ptr(BIO_new(BIO_s_mem()), &BIO_free);
  if (!bio_ptr) {
    throw std::runtime_error("Failed to create BIO");
    return monad::MyResult<std::string>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "Failed to create BIO"});
  }

  int result;
  if (is_private) {
    // Encode private key to DER
    result = i2d_PrivateKey_bio(bio_ptr.get(), pkey.get());
  } else {
    // Encode public key to DER
    result = i2d_PUBKEY_bio(bio_ptr.get(), pkey.get());
  }

  if (result <= 0) {
    return monad::MyResult<std::string>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "Failed to convert key to DER format"});
  }

  // Extract DER data from BIO as a string
  char* data;
  long len = BIO_get_mem_data(bio_ptr.get(), &data);
  std::string der_key(data, len);
  return monad::MyResult<std::string>::Ok(std::move(der_key));
}

monad::MyResult<std::pair<std::string, std::string>> get_ec_public_key_xy(
    cryptutil::EVP_PKEY_ptr& pkey, bool urlsafe) {
  // BIGNUM *x = nullptr, *y = nullptr;
  // Bn_raii x, y;
  BIGNUM *raw_x = nullptr, *raw_y = nullptr;
  cryptutil::BIGNUM_ptr x(nullptr, &BN_free), y(nullptr, &BN_free);

  // Get the X and Y components of the EC public key
  if (EVP_PKEY_get_bn_param(pkey.get(), OSSL_PKEY_PARAM_EC_PUB_X, &raw_x) !=
      1) {
    return monad::MyResult<std::pair<std::string, std::string>>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "Failed to get EC public key parameters x."});
  }
  x.reset(raw_x);
  if (EVP_PKEY_get_bn_param(pkey.get(), OSSL_PKEY_PARAM_EC_PUB_Y, &raw_y) !=
      1) {
    return monad::MyResult<std::pair<std::string, std::string>>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "Failed to get EC public key parameters y."});
  }
  y.reset(raw_y);

  std::string x_b64 = base64_encode(get_bn_bin_string(x), urlsafe);
  std::string y_b64 = base64_encode(get_bn_bin_string(y), urlsafe);
  cjj365::stringutil::remove_right_paddings(x_b64, urlsafe ? '.' : '=');
  cjj365::stringutil::remove_right_paddings(y_b64, urlsafe ? '.' : '=');
  return monad::MyResult<std::pair<std::string, std::string>>::Ok(
      std::make_pair(std::move(x_b64), std::move(y_b64)));
}

monad::MyResult<std::pair<std::string, std::string>> get_rsa_public_key_ne(
    cryptutil::EVP_PKEY_ptr& privateKey,  //
    bool urlsafe) {
  if (EVP_PKEY_id(privateKey.get()) != EVP_PKEY_RSA) {
    return monad::MyResult<std::pair<std::string, std::string>>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "Provided key is not an RSA key."});
  }
  BIGNUM *n_raw = nullptr, *e_raw = nullptr;
  // Bn_raii n, e;
  cryptutil::BIGNUM_ptr n(nullptr, &BN_free), e(nullptr, &BN_free);

  if (EVP_PKEY_get_bn_param(privateKey.get(), OSSL_PKEY_PARAM_RSA_N, &n_raw) !=
      1) {
    return monad::MyResult<std::pair<std::string, std::string>>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "Failed to get RSA parameters n."});
  }
  n.reset(n_raw);
  if (EVP_PKEY_get_bn_param(privateKey.get(), OSSL_PKEY_PARAM_RSA_E, &e_raw) !=
      1) {
    return monad::MyResult<std::pair<std::string, std::string>>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "Failed to get RSA parameters e."});
  }
  e.reset(e_raw);

  std::string modules = base64_encode(get_bn_bin_string(n), urlsafe);
  std::string exponent = base64_encode(get_bn_bin_string(e), urlsafe);

  cjj365::stringutil::remove_right_paddings(modules, urlsafe ? '.' : '=');
  cjj365::stringutil::remove_right_paddings(exponent, urlsafe ? '.' : '=');
  return monad::MyResult<std::pair<std::string, std::string>>::Ok(
      std::make_pair(std::move(modules), std::move(exponent)));
}

std::string key_to_pem(cryptutil::EVP_PKEY_ptr& private_pkey,
                       bool for_private) {
  // BIO* bio = BIO_new(BIO_s_mem());
  // std::unique_ptr<BIO, BIODeleter> bio_ptr(BIO_new(BIO_s_mem()));
  cryptutil::BIO_ptr bio_ptr(BIO_new(BIO_s_mem()), &BIO_free);
  if (!bio_ptr) {
    throw std::runtime_error("Failed to create BIO");
  }

  // Write the key to the BIO in PEM format
  if (for_private) {
    if (!PEM_write_bio_PrivateKey(bio_ptr.get(), private_pkey.get(), nullptr,
                                  nullptr, 0, nullptr, nullptr)) {
      throw std::runtime_error("Failed to write private key to BIO");
    }
  } else {
    if (!PEM_write_bio_PUBKEY(bio_ptr.get(), private_pkey.get())) {
      // output error message
      ERR_print_errors_fp(stderr);
      throw std::runtime_error("Failed to write public key to BIO");
    }
  }

  // Extract the key data as a string
  char* key_data;
  long len = BIO_get_mem_data(bio_ptr.get(), &key_data);
  std::string key_string(key_data, len);
  return key_string;
}

cryptutil::EVP_PKEY_ptr load_private_key(const std::string& private_key,
                                         bool der) {
  if (private_key.empty()) {
    std::cerr << "Private key is empty." << std::endl;
    return cryptutil::EVP_PKEY_ptr{nullptr, &EVP_PKEY_free};
  }
  if (der) {
    cryptutil::BIO_ptr bio_ptr(
        BIO_new_mem_buf(private_key.data(),
                        static_cast<int>(private_key.size())),
        &BIO_free);
    // std::unique_ptr<BIO, BIODeleter> bio_ptr();
    // EVP_PKEY* pkey = ;
    return cryptutil::EVP_PKEY_ptr(d2i_PrivateKey_bio(bio_ptr.get(), nullptr),
                                   &EVP_PKEY_free);
    // cryptutil::EVP_PKEY_ptr pkey_ptr(pkey, &EVP_PKEY_free);
    // if (!pkey) {
    //   // BIO_free(private_bio);
    //   // throw std::runtime_error(
    //   //     "Failed to read private key from string, key size: " +
    //   //     std::to_string(private_key.size()));
    //   std::cerr << "Failed to read private key from string, key size: "
    //             << private_key.size() << std::endl;
    //   return EVPKey_raii{};
    // }
    // // BIO_free(private_bio);
    // return EVPKey_raii{pkey};
  }

  // BIO* private_bio = BIO_new_mem_buf(private_key.c_str(), -1);
  // std::unique_ptr<BIO, BIODeleter> bio_ptr(
  //     BIO_new_mem_buf(private_key.c_str(), -1), &BIO_free);
  cryptutil::BIO_ptr bio_ptr(BIO_new_mem_buf(private_key.c_str(), -1),
                             &BIO_free);
  return cryptutil::EVP_PKEY_ptr(
      PEM_read_bio_PrivateKey(bio_ptr.get(), nullptr, nullptr, nullptr),
      &EVP_PKEY_free);
  // if (!pkey) {
  //   // BIO_free(private_bio);
  //   throw std::runtime_error("Failed to read private key from string");
  // }
  // // BIO_free(private_bio);
  // return EVPKey_raii{pkey};
}

cryptutil::EVP_PKEY_ptr load_public_key(const std::string& public_key) {
  // BIO* public_bio = BIO_new_mem_buf(public_key.c_str(), -1);
  // std::unique_ptr<BIO, BIODeleter> public_bio(
  //     BIO_new_mem_buf(public_key.c_str(), -1));
  cryptutil::BIO_ptr public_bio(BIO_new_mem_buf(public_key.c_str(), -1),
                                &BIO_free);
  EVP_PKEY* pkey =
      PEM_read_bio_PUBKEY(public_bio.get(), nullptr, nullptr, nullptr);
  if (!pkey) {
    throw std::runtime_error("Failed to read public key from string");
  }
  return cryptutil::EVP_PKEY_ptr(pkey, &EVP_PKEY_free);
}

// std::string convert_openssh_to_pem(const std::string& openssh_key) {
//   ssh_key sshkey = ssh_key_new();
//   if (ssh_pki_import_privkey_base64(openssh_key.c_str(), nullptr, nullptr,
//                                     nullptr, &sshkey) != SSH_OK) {
//     ssh_key_free(sshkey);
//     throw std::runtime_error("Failed to import OpenSSH key");
//   }

//   BIO* bio = BIO_new(BIO_s_mem());
//   if (!bio) {
//     ssh_key_free(sshkey);
//     throw std::runtime_error("Failed to create BIO");
//   }

//   EVP_PKEY* pkey = EVP_PKEY_new();
//   if (!pkey) {
//     BIO_free(bio);
//     ssh_key_free(sshkey);
//     throw std::runtime_error("Failed to create EVP_PKEY");
//   }

//   switch (ssh_key_type(sshkey)) {
//     case SSH_KEYTYPE_RSA: {
//       RSA* rsa = EVP_PKEY_get1_RSA(pkey);
//       if (!rsa) {
//         EVP_PKEY_free(pkey);
//         BIO_free(bio);
//         ssh_key_free(sshkey);
//         throw std::runtime_error("Failed to get RSA key");
//       }
//       EVP_PKEY_assign_RSA(pkey, rsa);
//       break;
//     }
//     case SSH_KEYTYPE_ED25519: {
//       break;
//     }
//     default: {
//       throw std::runtime_error("Unsupported key type");
//     }
//   }
//   if (PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr,
//                                nullptr) != 1) {
//     BIO_free(bio);
//     EVP_PKEY_free(pkey);
//     ssh_key_free(sshkey);
//     throw std::runtime_error("Failed to write PEM key");
//   }

//   char* pem_data;
//   long pem_len = BIO_get_mem_data(bio, &pem_data);
//   std::string pem_key(pem_data, pem_len);

//   BIO_free(bio);
//   EVP_PKEY_free(pkey);
//   ssh_key_free(sshkey);
//   return pem_key;
// }

// std::string convert_pem_to_openssh(const std::string& pem_key) {
//   BIO* bio = BIO_new_mem_buf(pem_key.data(), pem_key.size());
//   if (!bio) {
//     throw std::runtime_error("Failed to create BIO");
//   }

//   EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
//   if (!pkey) {
//     BIO_free(bio);
//     throw std::runtime_error("Failed to read PEM key");
//   }

//   ssh_key sshkey = ssh_key_new();
//   if (EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA) {
//     if (ssh_pki_import_privkey_base64(pem_key.c_str(), nullptr, nullptr,
//                                       nullptr, &sshkey) != SSH_OK) {
//       EVP_PKEY_free(pkey);
//       BIO_free(bio);
//       throw std::runtime_error("Failed to import OpenSSH key");
//     }
//   } else if (EVP_PKEY_base_id(pkey) == EVP_PKEY_ED25519) {
//     if (ssh_pki_import_privkey_base64(pem_key.c_str(), nullptr, nullptr,
//                                       nullptr, &sshkey) != SSH_OK) {
//       EVP_PKEY_free(pkey);
//       BIO_free(bio);
//       throw std::runtime_error("Failed to import OpenSSH key");
//     }
//   } else {
//     EVP_PKEY_free(pkey);
//     BIO_free(bio);
//     throw std::runtime_error("Unsupported key type");
//   }

//   char* openssh_data;
//   if (ssh_pki_export_privkey_base64(sshkey, nullptr, nullptr, nullptr,
//                                     &openssh_data) != SSH_OK) {
//     ssh_key_free(sshkey);
//     EVP_PKEY_free(pkey);
//     BIO_free(bio);
//     throw std::runtime_error("Failed to export OpenSSH key");
//   }

//   std::string openssh_key(openssh_data);
//   ssh_string_free_char(openssh_data);
//   ssh_key_free(sshkey);
//   EVP_PKEY_free(pkey);
//   BIO_free(bio);
//   return openssh_key;
// }

// std::pair<std::string, std::string> generate_ssh_key_pair(
//     const std::string& type) {
//   ssh_key_raii privkey{ssh_key_new()};
//   ssh_key_raii pubkey{ssh_key_new()};
//   enum ssh_keytypes_e key_type;

//   if (type == "rsa") {
//     key_type = SSH_KEYTYPE_RSA;
//   } else if (type == "dsa") {
//     key_type = SSH_KEYTYPE_DSS;
//   } else if (type == "ecdsa") {
//     key_type = SSH_KEYTYPE_ECDSA_P256;  // Default to P-256
//   } else if (type == "ecdsa-sk") {
//     key_type = SSH_KEYTYPE_SK_ECDSA;
//   } else if (type == "ed25519") {
//     key_type = SSH_KEYTYPE_ED25519;
//   } else if (type == "ed25519-sk") {
//     key_type = SSH_KEYTYPE_SK_ED25519;
//   } else {
//     throw std::invalid_argument("Unsupported key type");
//   }
//   if (ssh_pki_generate(key_type, 2048, privkey.get()) != SSH_OK) {
//     // ssh_key_free(privkey);
//     // ssh_key_free(pubkey);
//     throw std::runtime_error("Failed to generate SSH key pair");
//   }

//   char* privkey_base64 = nullptr;
//   char* pubkey_base64 = nullptr;

//   if (ssh_pki_export_privkey_base64(privkey.getKey(), nullptr, nullptr,
//   nullptr,
//                                     &privkey_base64) != SSH_OK) {
//     // ssh_key_free(privkey);
//     // ssh_key_free(pubkey);
//     throw std::runtime_error("Failed to export private key to base64");
//   }

//   if (ssh_pki_export_pubkey_base64(privkey.getKey(), &pubkey_base64) !=
//       SSH_OK) {
//     // ssh_key_free(privkey);
//     // ssh_key_free(pubkey);
//     throw std::runtime_error("Failed to export public key to base64");
//   }

//   std::string privkey_str(privkey_base64);
//   std::string pubkey_str(pubkey_base64);

//   ssh_string_free_char(privkey_base64);
//   ssh_string_free_char(pubkey_base64);
//   // ssh_key_free(privkey);
//   // ssh_key_free(pubkey);

//   return {privkey_str, pubkey_str};
// }

// std::string create_public_key_from_private_key(
//     const std::string& privkey_base64) {
//   ssh_key_raii privkey{ssh_key_new()};
//   ssh_key_raii pubkey{ssh_key_new()};

//   if (ssh_pki_import_privkey_base64(privkey_base64.c_str(), nullptr, nullptr,
//                                     nullptr, privkey.get()) != SSH_OK) {
//     throw std::runtime_error("Failed to import private key");
//   }

//   if (ssh_pki_export_privkey_to_pubkey(privkey.getKey(), pubkey.get()) !=
//       SSH_OK) {
//     throw std::runtime_error("Failed to create public key from private key");
//   }

//   char* pubkey_base64 = nullptr;
//   if (ssh_pki_export_pubkey_base64(pubkey.getKey(), &pubkey_base64) !=
//   SSH_OK) {
//     throw std::runtime_error("Failed to export public key to base64");
//   }
//   std::string pubkey_str(pubkey_base64);
//   ssh_string_free_char(pubkey_base64);
//   return pubkey_str;
// }

cryptutil::EVP_PKEY_ptr get_public_key(cryptutil::EVP_PKEY_ptr& private_key) {
  // BIO* bio = BIO_new(BIO_s_mem());
  // if (!bio) {
  //   throw std::runtime_error("Failed to create BIO");
  // }
  cryptutil::BIO_ptr bio(BIO_new(BIO_s_mem()), &BIO_free);

  // Write the key to the BIO in PEM format
  if (!PEM_write_bio_PUBKEY(bio.get(), private_key.get())) {
    // BIO_free(bio);
    // output error message
    ERR_print_errors_fp(stderr);
    throw std::runtime_error("Failed to write public key to BIO");
  }

  // read public key from BIO
  // EVP_PKEY* public_key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
  return cryptutil::EVP_PKEY_ptr(
      PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr),
      &EVP_PKEY_free);

  // if (!public_key) {
  //   BIO_free(bio);
  //   throw std::runtime_error("Failed to read public key from BIO");
  // }

  // return EVPKey_raii{public_key};
}
monad::MyResult<cryptutil::X509_ptr> issue_certificate(
    const cryptutil::EVP_PKEY_ptr& cert_key, const std::string& subject_C,
    const std::string& subject_O, const std::string& subject_CN,
    const std::vector<std::string>& sans, const cryptutil::EVP_PKEY_ptr& ca_key,
    const cryptutil::X509_ptr& ca_cert, int days) {
  cryptutil::X509_ptr cert(X509_new(), &X509_free);
  if (!cert)
    return monad::MyResult<cryptutil::X509_ptr>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "X509_new failed"});

  // Version = v3 (value 2)
  if (X509_set_version(cert.get(), 2L) != 1)
    return monad::MyResult<cryptutil::X509_ptr>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "X509_set_version failed"});

  // Serial: random 64-bit
  cryptutil::ASN1_INTEGER_ptr asn1_serial(ASN1_INTEGER_new(),
                                          &ASN1_INTEGER_free);
  if (!asn1_serial)
    return monad::MyResult<cryptutil::X509_ptr>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "ASN1_INTEGER_new failed"});
  DEBUG_PRINT("PPPPPPPP1");
  if (ASN1_INTEGER_set_uint64(
          asn1_serial.get(), (uint64_t)std::chrono::high_resolution_clock::now()
                                 .time_since_epoch()
                                 .count()) != 1) {
    return monad::MyResult<cryptutil::X509_ptr>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "ASN1_INTEGER_set failed"});
  }
  DEBUG_PRINT("PPPPPPPP2");
  if (X509_set_serialNumber(cert.get(), asn1_serial.get()) != 1) {
    return monad::MyResult<cryptutil::X509_ptr>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "X509_set_serialNumber failed"});
  }

  DEBUG_PRINT("PPPPPPPP3");
  // Subject
  cryptutil::X509_NAME_ptr subject_name(X509_NAME_new(), &X509_NAME_free);
  if (!subject_name)
    return monad::MyResult<cryptutil::X509_ptr>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "X509_NAME_new failed"});

  DEBUG_PRINT("PPPPPPPP4");
  auto subject_name_result =
      set_name_fields(subject_name, subject_C, subject_O, subject_CN);
  if (subject_name_result.is_err()) {
    DEBUG_PRINT(
        "Failed to set subject name fields: " << subject_name_result.error());
    return monad::MyResult<cryptutil::X509_ptr>::Err(
        std::move(subject_name_result.error()));
  }

  DEBUG_PRINT("PPPPPPPP5");
  if (X509_set_subject_name(cert.get(), subject_name.get()) != 1) {
    return monad::MyResult<cryptutil::X509_ptr>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "X509_set_subject_name failed"});
  }

  DEBUG_PRINT("PPPPPPPP6");
  // Issuer (from CA certificate)
  X509_NAME* issuer_name = X509_get_subject_name(ca_cert.get());
  if (X509_set_issuer_name(cert.get(), issuer_name) != 1)
    return monad::MyResult<cryptutil::X509_ptr>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "X509_set_issuer_name failed"});

  DEBUG_PRINT("PPPPPPPP7");
  // Validity
  if (X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0) == nullptr ||
      X509_gmtime_adj(X509_getm_notAfter(cert.get()), 60L * 60 * 24 * days) ==
          nullptr)
    return monad::MyResult<cryptutil::X509_ptr>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "X509_gmtime_adj failed"});

  DEBUG_PRINT("PPPPPPPP8");
  // Public key
  if (X509_set_pubkey(cert.get(), cert_key.get()) != 1)
    return monad::MyResult<cryptutil::X509_ptr>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "X509_set_pubkey failed"});

  DEBUG_PRINT("PPPPPPPP9");
  // v3 extensions for end-entity certificate
  auto ext_res1 = add_ext(cert, NID_basic_constraints, "CA:FALSE");
  if (ext_res1.is_err())
    return monad::MyResult<cryptutil::X509_ptr>::Err(ext_res1.error());

  auto ext_res2 =
      add_ext(cert, NID_key_usage, "critical,digitalSignature,keyEncipherment");
  if (ext_res2.is_err())
    return monad::MyResult<cryptutil::X509_ptr>::Err(ext_res2.error());

  auto ext_res3 = add_ext(cert, NID_ext_key_usage, "serverAuth,clientAuth");
  if (ext_res3.is_err())
    return monad::MyResult<cryptutil::X509_ptr>::Err(ext_res3.error());

  auto ext_res4 = add_ext(cert, NID_subject_key_identifier, "hash");
  if (ext_res4.is_err())
    return monad::MyResult<cryptutil::X509_ptr>::Err(ext_res4.error());

  auto ext_res5 = add_ext(cert, NID_authority_key_identifier, "keyid,issuer");
  if (ext_res5.is_err())
    return monad::MyResult<cryptutil::X509_ptr>::Err(ext_res5.error());

  // Add SAN (Subject Alternative Names) if provided
  if (!sans.empty()) {
    std::string san_value;
    for (size_t i = 0; i < sans.size(); ++i) {
      if (i > 0) san_value += ",";
      san_value += "DNS:" + sans[i];
    }
    auto ext_res6 = add_ext(cert, NID_subject_alt_name, san_value);
    if (ext_res6.is_err())
      return monad::MyResult<cryptutil::X509_ptr>::Err(ext_res6.error());
  }

  // Sign with CA's private key
  if (X509_sign(cert.get(), ca_key.get(), EVP_sha256()) == 0)
    return monad::MyResult<cryptutil::X509_ptr>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "X509_sign failed"});

  return monad::MyResult<cryptutil::X509_ptr>::Ok(std::move(cert));
}

monad::MyResult<cryptutil::X509_ptr> make_self_signed_ca(
    const cryptutil::EVP_PKEY_ptr& pkey, const std::string& C,
    const std::string& O, const std::string& CN, int days) {
  cjj365::cryptutil::X509_ptr cert =
      cjj365::cryptutil::X509_ptr(X509_new(), &X509_free);
  if (!cert)
    return monad::MyResult<cryptutil::X509_ptr>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "X509_new failed"});

  if (X509_set_version(cert.get(), 2) != 1)
    return monad::MyResult<cryptutil::X509_ptr>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "set version failed"});
  // serial (quick-n-dirty unique-ish)
  cryptutil::ASN1_INTEGER_ptr s(ASN1_INTEGER_new(), &ASN1_INTEGER_free);
  if (!s)
    return monad::MyResult<cryptutil::X509_ptr>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "ASN1_INTEGER_new failed"});
  uint64_t ser = (uint64_t)std::chrono::high_resolution_clock::now()
                     .time_since_epoch()
                     .count();
  ASN1_INTEGER_set_uint64(s.get(), ser);
  X509_set_serialNumber(cert.get(), s.get());

  // subject/issuer
  cryptutil::X509_NAME_ptr name(X509_NAME_new(), &X509_NAME_free);
  if (!name)
    return monad::MyResult<cryptutil::X509_ptr>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "X509_NAME_new failed"});

  auto add = [&](const char* fld, const std::string& v) {
    return X509_NAME_add_entry_by_txt(name.get(), fld, MBSTRING_ASC,
                                      (const unsigned char*)v.c_str(), -1, -1,
                                      0) != 1;
  };

  if (add("C", C) || add("O", O) || add("CN", CN)) {
    DEBUG_PRINT("C: " << C << ", O: " << O << ", CN: " << CN);
    return monad::MyResult<cryptutil::X509_ptr>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "X509_NAME_add_entry_by_txt failed"});
  }
  if (X509_set_subject_name(cert.get(), name.get()) != 1 ||
      X509_set_issuer_name(cert.get(), name.get()) != 1) {
    return monad::MyResult<cryptutil::X509_ptr>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "set name failed"});
  }

  // validity
  if (!X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0) ||
      !X509_gmtime_adj(X509_getm_notAfter(cert.get()), 60L * 60 * 24 * days))
    return monad::MyResult<cryptutil::X509_ptr>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "set time failed"});

  // public key
  if (X509_set_pubkey(cert.get(), pkey.get()) != 1)
    return monad::MyResult<cryptutil::X509_ptr>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "X509_set_pubkey failed"});

  // Mark as CA
  auto ext_res1 =
      add_ext(cert, NID_basic_constraints, "critical,CA:TRUE,pathlen:1");
  if (!ext_res1.is_ok())
    return monad::MyResult<cryptutil::X509_ptr>::Err(ext_res1.error());

  auto ext_res2 = add_ext(cert, NID_key_usage, "critical,keyCertSign,cRLSign");
  if (!ext_res2.is_ok())
    return monad::MyResult<cryptutil::X509_ptr>::Err(ext_res2.error());

  auto ext_res3 = add_ext(cert, NID_subject_key_identifier, "hash");
  if (!ext_res3.is_ok())
    return monad::MyResult<cryptutil::X509_ptr>::Err(ext_res3.error());

  auto ext_res4 =
      add_ext(cert, NID_authority_key_identifier, "keyid:always,issuer");
  if (!ext_res4.is_ok())
    return monad::MyResult<cryptutil::X509_ptr>::Err(ext_res4.error());

  // Self-sign with ECDSA + SHA-256
  if (X509_sign(cert.get(), pkey.get(), EVP_sha256()) == 0)
    return monad::MyResult<cryptutil::X509_ptr>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "X509_sign failed"});
  return monad::MyResult<cryptutil::X509_ptr>::Ok(std::move(cert));
}

// EVP stands for Envelope
monad::MyResult<std::string> sign_message(
    const std::string& payload, const cryptutil::EVP_PKEY_ptr& private_key) {
  if (!private_key) {
    return monad::MyResult<std::string>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "Private key must not be null"});
  }

  try {
    // EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    cryptutil::EVP_MD_CTX_ptr ctx{EVP_MD_CTX_new(), &EVP_MD_CTX_free};
    if (!ctx) {
      throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    // Initialize the signing operation
    if (EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr,
                           private_key.get()) != 1) {
      throw std::runtime_error("Failed to initialize signing operation");
    }

    // Update the context with the payload
    if (EVP_DigestSignUpdate(ctx.get(), payload.data(), payload.size()) != 1) {
      throw std::runtime_error("Failed to update digest with payload");
    }

    // Determine the size of the signature
    size_t len = 0;
    if (EVP_DigestSignFinal(ctx.get(), nullptr, &len) != 1) {
      throw std::runtime_error("Failed to finalize signing operation");
    }
    // DEBUG_PRINT("sig len: " << len);
    // assert(len == 64); // when using ECDSA, the signature length is 64 bytes
    // Allocate memory for the signature
    std::vector<unsigned char> signature(len);  // Pre-fill with null characters
    if (EVP_DigestSignFinal(ctx.get(), signature.data(), &len) != 1) {
      throw std::runtime_error("Failed to obtain the signature");
    }
    std::vector<unsigned char> raw_signature = extract_raw_signature(signature);
    // DEBUG_PRINT("raw signature size: " << raw_signature.size());
    // Resize the signature to the actual length
    // signature.resize(len);
    return monad::MyResult<std::string>::Ok(
        std::string(reinterpret_cast<char*>(raw_signature.data()),
                    raw_signature.size()));  // or base64_signature;
  } catch (std::exception& e) {
  return monad::MyResult<std::string>::Err(
    {.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
     .what = fmt::format("sign_message: {}", e.what())});
  }
}

monad::MyResult<void> verify_message(
    const std::string& payload, const std::string& signature,
    const cryptutil::EVP_PKEY_ptr& public_key) {
  if (!public_key) {
    return monad::MyResult<void>::Err(
        {.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
         .what = "Public key must not be null"});
  }

  // Create a new message digest context
  // EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  cryptutil::EVP_MD_CTX_ptr ctx{EVP_MD_CTX_new(), EVP_MD_CTX_free};
  if (!ctx) {
    return monad::MyResult<void>::Err(
        {.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
         .what = "Failed to create EVP_MD_CTX"});
  }

  // Initialize the verification operation
  if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr,
                           public_key.get()) != 1) {
    return monad::MyResult<void>::Err(
        {.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
         .what = "Failed to initialize verification operation"});
  }

  // Update the context with the payload
  if (EVP_DigestVerifyUpdate(ctx.get(), payload.data(), payload.size()) != 1) {
    return monad::MyResult<void>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "Failed to update digest with payload"});
  }

  // Perform the verification
  int result = EVP_DigestVerifyFinal(
      ctx.get(), reinterpret_cast<const unsigned char*>(signature.data()),
      signature.size());
  if (result == 1) {
    return monad::MyResult<void>::Ok();
  }
  return monad::MyResult<void>::Err(
      monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                   .what = "Signature verification failed"});
}

/**
 * @brief Sign a message with a private key with ES256 algorithm.
 */
monad::MyResult<std::string> sign_message(const std::string& payload,
                                          const std::string& private_key) {
  // Sign payload with the private key using OpenSSL
  auto pkey = load_private_key(private_key);
  if (!pkey) {
    return monad::MyResult<std::string>::Err(monad::Error{
        .code = my_errors::OPENSSL::UNEXPECTED_RESULT,
        .what = fmt::format("Failed to load private key: {}", private_key)});
  }
  return sign_message(payload, pkey);
}

monad::MyResult<std::string> sign_message_base64(
    const std::string& payload, const cryptutil::EVP_PKEY_ptr& private_key,
    bool urlsafe) {
  return sign_message(payload, private_key).map([urlsafe](auto signature) {
    std::string base64_signature = base64_encode(signature, urlsafe);
    size_t pos = base64_signature.find_last_not_of(urlsafe ? '.' : '=');
    if (pos != std::string::npos) {
      base64_signature.erase(pos + 1);
    }
    return base64_signature;
  });
}

monad::MyResult<std::string> sign_message_hex(
    const std::string& payload, const cryptutil::EVP_PKEY_ptr& private_key) {
  return sign_message(payload, private_key).map([](auto signature) {
    return bin_to_hex(signature);
  });
}

// Helper function to add extensions to the certificate
void add_extension(X509* cert, int nid, const char* value) {
  cryptutil::X509_EXTENSION_ptr ext(
      X509V3_EXT_conf_nid(nullptr, nullptr, nid, const_cast<char*>(value)),
      X509_EXTENSION_free);
  X509_add_ext(cert, ext.get(), -1);
}

std::string bin_to_hex(const std::string& bin) {
  std::ostringstream oss;
  for (size_t i = 0; i < bin.size(); ++i) {
    oss << std::hex << std::setw(2) << std::setfill('0')
        << static_cast<int>(static_cast<unsigned char>(bin[i]));
  }
  return oss.str();
}

std::vector<char> hex_to_vector(std::string_view hex) {
  std::vector<char> result;
  // Remove spaces and the "04" prefix if it's present
  std::string cleanedHex{hex};
  cleanedHex.erase(
      0, cleanedHex.find_first_of(
             "0123456789abcdefABCDEF"));  // remove leading non-hex chars

  for (size_t i = 0; i < cleanedHex.length(); i += 2) {
    std::string byteString = cleanedHex.substr(i, 2);
    char byte = static_cast<char>(strtol(byteString.c_str(), nullptr, 16));
    result.push_back(byte);
  }
  return result;
}

std::vector<unsigned char> extract_raw_signature(
    const std::vector<unsigned char>& der_signature) {
  // Parse the DER-encoded signature
  const unsigned char* sig_data = der_signature.data();
  ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &sig_data, der_signature.size());
  if (!sig) {
    throw std::runtime_error("Failed to parse ECDSA signature");
  }

  // Extract the r and s components
  const BIGNUM* r = ECDSA_SIG_get0_r(sig);
  const BIGNUM* s = ECDSA_SIG_get0_s(sig);

  // Convert r and s to raw byte arrays
  std::vector<unsigned char> r_bytes(BN_num_bytes(r));
  std::vector<unsigned char> s_bytes(BN_num_bytes(s));

  BN_bn2bin(r, r_bytes.data());
  BN_bn2bin(s, s_bytes.data());

  // Ensure r and s are both 32 bytes long for P-256
  if (r_bytes.size() < 32) {
    r_bytes.insert(r_bytes.begin(), 32 - r_bytes.size(), 0);
  }
  if (s_bytes.size() < 32) {
    s_bytes.insert(s_bytes.begin(), 32 - s_bytes.size(), 0);
  }

  // Combine r and s into a single 64-byte signature
  std::vector<unsigned char> raw_signature(64);
  std::copy(r_bytes.begin(), r_bytes.end(), raw_signature.begin());
  std::copy(s_bytes.begin(), s_bytes.end(), raw_signature.begin() + 32);

  // Clean up
  ECDSA_SIG_free(sig);

  return raw_signature;
}

/**
 * @brief Generate a new RSA key pair
 * token.thumbprint
 */
std::string get_public_key_thumbprint(const cryptutil::EVP_PKEY_ptr& pkey) {
  // Convert to ASN.1 format
  // i2d means "internal to DER"
  int len = i2d_PublicKey(pkey.get(), nullptr);
  if (len < 0) {
    throw std::runtime_error("Failed to get public key length.");
  }

  std::vector<unsigned char> buffer(len);
  unsigned char* p = buffer.data();
  i2d_PublicKey(pkey.get(), &p);

  // Compute SHA-256 hash
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(buffer.data(), buffer.size(), hash);

  std::string hash_b64 = base64_encode(hash, SHA256_DIGEST_LENGTH, true);
  size_t pos = hash_b64.find_last_not_of('.');
  if (pos != std::string::npos) {
    hash_b64.erase(pos + 1);
  }
  return hash_b64;
}

/**
 * @brief Generate a new key pair for use with ACME.
 */
monad::MyResult<std::pair<std::string, std::string>> generate_es256_key_pair() {
  // Generate the EC key
  // auto pkey = generate_es256_key();
  auto pkey_r = make_ec_p256_key();
  if (pkey_r.is_err()) {
    return monad::MyResult<std::pair<std::string, std::string>>::Err(
        std::move(pkey_r.error()));
  }

  // Write the private key to a memory buffer
  // BIO* bio = BIO_new(BIO_s_mem());
  cryptutil::BIO_ptr bio_ptr(BIO_new(BIO_s_mem()), &BIO_free);
  if (!PEM_write_bio_PrivateKey(bio_ptr.get(), pkey_r.value().get(), nullptr,
                                nullptr, 0, nullptr, nullptr)) {
    return monad::MyResult<std::pair<std::string, std::string>>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "Failed to write private key to BIO"});
  }

  // Extract private key as a string
  char* key_data;
  long len = BIO_get_mem_data(bio_ptr.get(), &key_data);
  std::string private_key(key_data, len);

  // BIO* public_bio = BIO_new(BIO_s_mem());
  // std::unique_ptr<BIO, BIODeleter> public_bio_ptr(BIO_new(BIO_s_mem()));
  cryptutil::BIO_ptr public_bio_ptr(BIO_new(BIO_s_mem()), &BIO_free);
  if (!PEM_write_bio_PUBKEY(public_bio_ptr.get(), pkey_r.value().get())) {
    return monad::MyResult<std::pair<std::string, std::string>>::Err(
        monad::Error{.code = my_errors::OPENSSL::UNEXPECTED_RESULT,
                     .what = "Failed to write public key to BIO"});
  }
  char* public_key_data;
  long public_len = BIO_get_mem_data(public_bio_ptr.get(), &public_key_data);
  std::string public_key(public_key_data, public_len);
  return monad::MyResult<std::pair<std::string, std::string>>::Ok(
      {private_key, public_key});
}

// Parses multiple PEM certs, returns leaf and intermediate stack
void parse_cert_chain(const std::string& pem_data,
                      cryptutil::X509_ptr& leaf_cert,
                      STACK_OF(X509) * &ca_stack) {
  cryptutil::BIO_ptr bio(BIO_new_mem_buf(pem_data.data(), (int)pem_data.size()),
                         BIO_free);
  if (!bio) throw std::runtime_error("Failed to create BIO");

  ca_stack = sk_X509_new_null();
  if (!ca_stack) throw std::runtime_error("Failed to allocate CA stack");

  bool first = true;
  X509* cert = nullptr;
  while ((cert = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr))) {
    if (first) {
      leaf_cert.reset(cert);
      first = false;
    } else {
      sk_X509_push(ca_stack, cert);  // stack owns cert
    }
  }

  if (first) throw std::runtime_error("No certificate found in PEM data");
}

// Create PKCS#12 bundle and return binary content as string
std::string create_pkcs12_string(const cryptutil::EVP_PKEY_ptr& pkey,
                                 const std::string& cert_chain_pem,
                                 const std::string& name,
                                 const std::string& password) {
  cryptutil::X509_ptr leaf_cert(nullptr, X509_free);
  STACK_OF(X509)* ca_stack = nullptr;

  parse_cert_chain(cert_chain_pem, leaf_cert, ca_stack);

  PKCS12* p12 = PKCS12_create(password.c_str(), name.c_str(), pkey.get(),
                              leaf_cert.get(), ca_stack, 0, 0, 0, 0, 0);
  sk_X509_pop_free(ca_stack, X509_free);  // free CA stack

  if (!p12) throw std::runtime_error("Failed to create PKCS#12");

  cryptutil::BIO_ptr bio(BIO_new(BIO_s_mem()), BIO_free);
  if (!bio) {
    PKCS12_free(p12);
    throw std::runtime_error("Failed to allocate memory BIO");
  }

  if (!i2d_PKCS12_bio(bio.get(), p12)) {
    PKCS12_free(p12);
    throw std::runtime_error("Failed to write PKCS#12 to BIO");
  }

  PKCS12_free(p12);

  BUF_MEM* bptr;
  BIO_get_mem_ptr(bio.get(), &bptr);
  return std::string(bptr->data, bptr->length);
}

}  // namespace opensslutil
}  // namespace cjj365