#include <gtest/gtest.h>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <chrono>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "acme/acme_tlsalpn01_server.hpp"

namespace {

namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = net::ip::tcp;

static constexpr const char* kAcmeIdentifierOid = "1.3.6.1.5.5.7.1.31";
static constexpr std::string_view kAlpnProto = "acme-tls/1";

struct KeyCertPem {
  std::string key_pem;
  std::string cert_pem;
};

static std::string bio_to_string(BIO* bio) {
  char* data = nullptr;
  const long len = BIO_get_mem_data(bio, &data);
  if (len <= 0 || data == nullptr) {
    return {};
  }
  return std::string(data, static_cast<std::size_t>(len));
}

static EVP_PKEY* make_ec_p256_key() {
  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
  if (!pctx) {
    return nullptr;
  }

  EVP_PKEY* pkey = nullptr;

  if (EVP_PKEY_keygen_init(pctx) != 1) {
    EVP_PKEY_CTX_free(pctx);
    return nullptr;
  }

  if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) != 1) {
    EVP_PKEY_CTX_free(pctx);
    return nullptr;
  }

  if (EVP_PKEY_keygen(pctx, &pkey) != 1) {
    EVP_PKEY_CTX_free(pctx);
    return nullptr;
  }

  EVP_PKEY_CTX_free(pctx);
  return pkey;
}

static bool add_subject_alt_name(X509* cert, const std::string& domain) {
  X509V3_CTX ctx;
  X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);

  const std::string san_value = "DNS:" + domain;
  X509_EXTENSION* san_ext = X509V3_EXT_conf_nid(
      nullptr, &ctx, NID_subject_alt_name,
      const_cast<char*>(san_value.c_str()));
  if (!san_ext) {
    return false;
  }
  const int ok = X509_add_ext(cert, san_ext, -1);
  X509_EXTENSION_free(san_ext);
  return ok == 1;
}

static bool add_acme_identifier(X509* cert,
                               const std::array<unsigned char, 32>& digest) {
  ASN1_OBJECT* oid = OBJ_txt2obj(kAcmeIdentifierOid, 1);
  if (!oid) {
    return false;
  }

  unsigned char der[2 + 32];
  der[0] = 0x04;
  der[1] = 0x20;
  std::memcpy(&der[2], digest.data(), digest.size());

  ASN1_OCTET_STRING* os = ASN1_OCTET_STRING_new();
  if (!os) {
    ASN1_OBJECT_free(oid);
    return false;
  }
  if (ASN1_OCTET_STRING_set(os, der, static_cast<int>(sizeof(der))) != 1) {
    ASN1_OCTET_STRING_free(os);
    ASN1_OBJECT_free(oid);
    return false;
  }

  X509_EXTENSION* ext =
      X509_EXTENSION_create_by_OBJ(nullptr, oid, 1 /* critical */, os);
  ASN1_OCTET_STRING_free(os);
  ASN1_OBJECT_free(oid);

  if (!ext) {
    return false;
  }

  const int ok = X509_add_ext(cert, ext, -1);
  X509_EXTENSION_free(ext);
  return ok == 1;
}

static KeyCertPem make_tls_alpn01_cert(const std::string& domain,
                                      const std::string& key_authorization) {
  KeyCertPem out;

  std::array<unsigned char, 32> digest{};
  SHA256(reinterpret_cast<const unsigned char*>(key_authorization.data()),
         key_authorization.size(), digest.data());

  EVP_PKEY* pkey_raw = make_ec_p256_key();
  if (!pkey_raw) {
    ADD_FAILURE() << "failed to generate EC P-256 key";
    return {};
  }
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(pkey_raw,
                                                          &EVP_PKEY_free);

  X509* cert_raw = X509_new();
  if (!cert_raw) {
    ADD_FAILURE() << "failed to allocate X509";
    return {};
  }
  std::unique_ptr<X509, decltype(&X509_free)> cert(cert_raw, &X509_free);

  if (X509_set_version(cert.get(), 2L) != 1) {
    ADD_FAILURE() << "X509_set_version failed";
    return {};
  }

  // Serial number: best-effort.
  ASN1_INTEGER* serial = ASN1_INTEGER_new();
  if (!serial) {
    ADD_FAILURE() << "ASN1_INTEGER_new failed";
    return {};
  }
  std::unique_ptr<ASN1_INTEGER, decltype(&ASN1_INTEGER_free)> serial_raii(
      serial, &ASN1_INTEGER_free);
  ASN1_INTEGER_set_uint64(serial, static_cast<uint64_t>(
                                   std::chrono::high_resolution_clock::now()
                                       .time_since_epoch()
                                       .count()));
  if (X509_set_serialNumber(cert.get(), serial) != 1) {
    ADD_FAILURE() << "X509_set_serialNumber failed";
    return {};
  }

  if (X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0) == nullptr) {
    ADD_FAILURE() << "X509_gmtime_adj notBefore failed";
    return {};
  }
  if (X509_gmtime_adj(X509_getm_notAfter(cert.get()), 60L * 60 * 24) == nullptr) {
    ADD_FAILURE() << "X509_gmtime_adj notAfter failed";
    return {};
  }

  if (X509_set_pubkey(cert.get(), pkey.get()) != 1) {
    ADD_FAILURE() << "X509_set_pubkey failed";
    return {};
  }

  X509_NAME* name = X509_NAME_new();
  if (!name) {
    ADD_FAILURE() << "X509_NAME_new failed";
    return {};
  }
  std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)> name_raii(
      name, &X509_NAME_free);

  if (X509_NAME_add_entry_by_txt(
          name, "CN", MBSTRING_ASC,
          reinterpret_cast<const unsigned char*>(domain.c_str()), -1, -1, 0) != 1) {
    ADD_FAILURE() << "X509_NAME_add_entry_by_txt(CN) failed";
    return {};
  }

  if (X509_set_subject_name(cert.get(), name) != 1) {
    ADD_FAILURE() << "X509_set_subject_name failed";
    return {};
  }
  if (X509_set_issuer_name(cert.get(), name) != 1) {
    ADD_FAILURE() << "X509_set_issuer_name failed";
    return {};
  }

  if (!add_subject_alt_name(cert.get(), domain)) {
    ADD_FAILURE() << "failed to add subjectAltName";
    return {};
  }
  if (!add_acme_identifier(cert.get(), digest)) {
    ADD_FAILURE() << "failed to add acmeIdentifier";
    return {};
  }

  if (X509_sign(cert.get(), pkey.get(), EVP_sha256()) == 0) {
    ADD_FAILURE() << "X509_sign failed";
    return {};
  }

  BIO* key_bio_raw = BIO_new(BIO_s_mem());
  if (!key_bio_raw) {
    ADD_FAILURE() << "BIO_new(key) failed";
    return {};
  }
  std::unique_ptr<BIO, decltype(&BIO_free)> key_bio(key_bio_raw, &BIO_free);

  if (PEM_write_bio_PrivateKey(key_bio.get(), pkey.get(), nullptr, nullptr, 0,
                               nullptr, nullptr) != 1) {
    ADD_FAILURE() << "PEM_write_bio_PrivateKey failed";
    return {};
  }

  BIO* cert_bio_raw = BIO_new(BIO_s_mem());
  if (!cert_bio_raw) {
    ADD_FAILURE() << "BIO_new(cert) failed";
    return {};
  }
  std::unique_ptr<BIO, decltype(&BIO_free)> cert_bio(cert_bio_raw, &BIO_free);

  if (PEM_write_bio_X509(cert_bio.get(), cert.get()) != 1) {
    ADD_FAILURE() << "PEM_write_bio_X509 failed";
    return {};
  }

  out.key_pem = bio_to_string(key_bio.get());
  out.cert_pem = bio_to_string(cert_bio.get());

  if (out.key_pem.empty() || out.cert_pem.empty()) {
    ADD_FAILURE() << "generated PEM is empty";
    return {};
  }

  return out;
}

static void set_client_alpn(ssl::context& ctx) {
  std::vector<unsigned char> protos;
  protos.push_back(static_cast<unsigned char>(kAlpnProto.size()));
  protos.insert(protos.end(), kAlpnProto.begin(), kAlpnProto.end());
  const int rc = SSL_CTX_set_alpn_protos(ctx.native_handle(), protos.data(),
                                        static_cast<unsigned int>(protos.size()));
  ASSERT_EQ(rc, 0);
}

static std::array<unsigned char, 32> sha256(std::string_view data) {
  std::array<unsigned char, 32> out{};
  SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(),
         out.data());
  return out;
}

static void assert_peer_acme_identifier(SSL* ssl,
                                       const std::array<unsigned char, 32>& expected) {
  X509* peer = SSL_get_peer_certificate(ssl);
  ASSERT_NE(peer, nullptr);
  std::unique_ptr<X509, decltype(&X509_free)> peer_raii(peer, &X509_free);

  ASN1_OBJECT* oid = OBJ_txt2obj(kAcmeIdentifierOid, 1);
  ASSERT_NE(oid, nullptr);
  std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)> oid_raii(
      oid, &ASN1_OBJECT_free);

  const int idx = X509_get_ext_by_OBJ(peer, oid, -1);
  ASSERT_GE(idx, 0);

  X509_EXTENSION* ext = X509_get_ext(peer, idx);
  ASSERT_NE(ext, nullptr);

  ASN1_OCTET_STRING* data = X509_EXTENSION_get_data(ext);
  ASSERT_NE(data, nullptr);

  const unsigned char* p = ASN1_STRING_get0_data(data);
  const int len = ASN1_STRING_length(data);

  // OpenSSL stores extnValue octets directly. For tls-alpn-01, it should be the
  // DER encoding of Authorization (OCTET STRING size 32) => 0x04 0x20 <32 bytes>.
  ASSERT_EQ(len, 2 + 32);
  ASSERT_EQ(p[0], 0x04);
  ASSERT_EQ(p[1], 0x20);
  ASSERT_EQ(std::memcmp(p + 2, expected.data(), expected.size()), 0);
}

}  // namespace

TEST(AcmeTlsAlpn01Server, HandshakeNegotiatesAlpnAndSniAndPresentsCert) {
  const std::string domain = "example.com";
  const std::string key_auth = "token.thumbprint";
  const auto expected_digest = sha256(key_auth);
  const auto pem = make_tls_alpn01_cert(domain, key_auth);

  auto started = certctrl::acme::AcmeTlsAlpn01Server::start(
      certctrl::acme::AcmeTlsAlpn01Server::ListenConfig{"127.0.0.1", 0},
      certctrl::acme::AcmeTlsAlpn01Server::ChallengeConfig{domain, pem.cert_pem,
                                                           pem.key_pem,
                                                           std::chrono::seconds(5)});
  ASSERT_TRUE(started.is_ok()) << started.error().what;
  auto srv = started.value();
  ASSERT_GT(srv->port(), 0);

  net::io_context ioc;
  ssl::context cctx(ssl::context::tls_client);
  cctx.set_verify_mode(ssl::verify_none);
  set_client_alpn(cctx);

  ssl::stream<tcp::socket> stream(ioc, cctx);

  tcp::resolver resolver(ioc);
  auto eps = resolver.resolve("127.0.0.1", std::to_string(srv->port()));
  net::connect(stream.next_layer(), eps);

  ASSERT_EQ(SSL_set_tlsext_host_name(stream.native_handle(), domain.c_str()), 1);

  stream.handshake(ssl::stream_base::client);

  const unsigned char* sel = nullptr;
  unsigned int sel_len = 0;
  SSL_get0_alpn_selected(stream.native_handle(), &sel, &sel_len);
  ASSERT_EQ(std::string_view(reinterpret_cast<const char*>(sel), sel_len),
            kAlpnProto);

  assert_peer_acme_identifier(stream.native_handle(), expected_digest);

  boost::system::error_code ignored;
  stream.shutdown(ignored);

  srv->stop();
}

TEST(AcmeTlsAlpn01Server, TtlStopsServer) {
  const std::string domain = "example.com";
  const std::string key_auth = "token.thumbprint";
  const auto pem = make_tls_alpn01_cert(domain, key_auth);

  auto started = certctrl::acme::AcmeTlsAlpn01Server::start(
      certctrl::acme::AcmeTlsAlpn01Server::ListenConfig{"127.0.0.1", 0},
      certctrl::acme::AcmeTlsAlpn01Server::ChallengeConfig{domain, pem.cert_pem,
                                                           pem.key_pem,
                                                           std::chrono::seconds(1)});
  ASSERT_TRUE(started.is_ok()) << started.error().what;
  auto srv = started.value();
  const auto port = srv->port();

  std::this_thread::sleep_for(std::chrono::seconds(2));

  // Best-effort: try connecting; should fail if listener stopped.
  net::io_context ioc;
  boost::system::error_code ec;
  tcp::socket sock(ioc);
  sock.connect(tcp::endpoint(net::ip::make_address("127.0.0.1"), port), ec);
  EXPECT_TRUE(ec) << "expected connect to fail after TTL";

  srv->stop();
}
