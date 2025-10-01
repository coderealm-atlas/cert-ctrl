#include "handlers/login_handler.hpp"
#include "base64.h"
#include "customio/spinner.hpp"
#include "handlers/device_auth_types.hpp"
#include "http_client_monad.hpp"
#include "util/device_fingerprint.hpp"
#include "util/user_key_crypto.hpp"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <jwt-cpp/jwt.h>
#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace json = boost::json;

namespace certctrl {

using VoidPureIO = monad::IO<void>;

VoidPureIO LoginHandler::start() {
  using namespace monad;
  using httphandler::deviceauth::StartResp;

  return http_io<PostJsonTag>(device_auth_url_)
      .map([](auto ex) {
        json::value body{{"action", "device_start"},
                         {"scopes", json::array{"openid", "profile", "email"}},
                         {"interval", 5},
                         {"expires_in", 900}};
        ex->setRequestJsonBody(std::move(body));
        return ex;
      })
      .then(http_request_io<PostJsonTag>(http_client_))
      .then([](auto ex) {
        return monad::IO<StartResp>::from_result(
            ex->template parseJsonResponse<StartResp>());
      })
      .then([this](auto start_resp) {
        output_hub_.printer().yellow()
            << "Device Authorization started.\n"
            << "User Code: " << start_resp.user_code << "\n"
            << "Verification URI: " << start_resp.verification_uri << "\n"
            << "Verification URI complete: "
            << start_resp.verification_uri_complete << "\n"
            << "Complete the authorization in your browser." << std::endl;
        start_resp_ = std::move(start_resp);
        return poll();
      });
}

VoidPureIO LoginHandler::poll() {
  using namespace monad;
  using httphandler::deviceauth::PollResp;
  // Build a single poll IO that performs one HTTP request and parses PollResp
  auto poll_once = [this]() {
    return http_io<PostJsonTag>(device_auth_url_)
        .map([this](auto ex) {
          json::value body{{"action", "device_poll"},
                           {"device_code", start_resp_->device_code}};
          ex->setRequestJsonBody(std::move(body));
          return ex;
        })
        .then(http_request_io<PostJsonTag>(http_client_))
        .then([](auto ex) {
          return monad::IO<PollResp>::from_result(
              ex->template parseJsonResponse<PollResp>());
        });
  };

  const int max_retries = start_resp_->expires_in / start_resp_->interval;
  const auto interval = std::chrono::seconds(start_resp_->interval);

  // Spinner to indicate progress while polling
  auto spinner = std::make_shared<customio::Spinner>(
      this->exec_, output_hub_.printer().stream(), std::string{"Polling... "},
      std::chrono::milliseconds(120),
      /*enabled=*/true);
  spinner->start();

  return poll_once()
      .poll_if(max_retries, interval, this->exec_,
               [](const PollResp &r) {
                 return r.status == "approved" || r.status == "denied";
               })
      .then([this, spinner](PollResp resp) {
        spinner->stop("Polling done.");
        output_hub_.printer().yellow()
            << "Device Authorization polling finished.\n"
            << "Final Status: " << resp.status << "\n"
            << "Expires In: " << resp.expires_in << std::endl;
        poll_resp_ = std::move(resp);
        if (poll_resp_->status == "ready") {
          return register_device();
        }
        return VoidPureIO::pure();
      })
      .catch_then([spinner](const monad::Error &e) {
        spinner->stop();
        return monad::IO<void>::fail(e);
      });
}

VoidPureIO LoginHandler::register_device() {
  using namespace monad;
  // We need access_token, user_id, and device info
  if (!poll_resp_ || poll_resp_->access_token.empty()) {
    return IO<void>::fail(
        {.code = my_errors::GENERAL::INVALID_ARGUMENT,
         .what = "No access token available for device registration"});
  }

  // Extract user_id from refresh_token (assumes JWT with sub claim) if present.
  std::string user_id;
  if (!poll_resp_->refresh_token.empty()) {
    try {
      auto decoded = jwt::decode(poll_resp_->refresh_token);
      if (decoded.has_payload_claim("sub")) {
        user_id = decoded.get_payload_claim("sub").as_string();
      }
    } catch (...) {
      // ignore and leave user_id empty
    }
  }

  // Gather device info and fingerprint
  std::string user_agent = "cert-ctrl/1.0";
  auto info = cjj365::device::gather_device_info(user_agent);
  auto fp_hex = cjj365::device::generate_device_fingerprint_hex(info);
  auto device_public_id =
      cjj365::device::device_public_id_from_fingerprint(fp_hex);

  // Initialize libsodium
  try {
    cjj365::cryptutil::sodium_init_or_throw();
  } catch (const std::exception &e) {
    return IO<void>::fail(
        {.code = my_errors::GENERAL::UNEXPECTED_RESULT,
         .what = std::string{"libsodium init failed: "} + e.what()});
  }

  // Determine output directory: last config source path
  std::filesystem::path out_dir;
  try {
    if (!config_sources_.paths_.empty()) {
      out_dir = std::filesystem::path(config_sources_.paths_.back());
    }
  } catch (...) {
    // leave empty, will error later if used
  }

  auto write_file_0600 = [this](const std::filesystem::path &p,
                                const unsigned char *data,
                                size_t len) -> std::optional<std::string> {
    try {
      std::error_code ec;
      if (auto parent = p.parent_path(); !parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec)
          return std::string{"create_directories failed: "} + ec.message();
      }
      // Write binary
      {
        std::ofstream ofs(p, std::ios::binary | std::ios::trunc);
        if (!ofs.is_open())
          return std::string{"open failed for "} + p.string();
        ofs.write(reinterpret_cast<const char *>(data),
                  static_cast<std::streamsize>(len));
        if (!ofs)
          return std::string{"write failed for "} + p.string();
      }
#ifndef _WIN32
      // chmod 600
      ::chmod(p.c_str(), 0600);
#endif
      return std::nullopt;
    } catch (const std::exception &e) {
      return std::string{"write_file_0600 exception: "} + e.what();
    }
  };

  auto write_text_0600 =
      [this](const std::filesystem::path &p,
             const std::string &text) -> std::optional<std::string> {
    try {
      std::error_code ec;
      if (auto parent = p.parent_path(); !parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec)
          return std::string{"create_directories failed: "} + ec.message();
      }
      {
        std::ofstream ofs(p, std::ios::binary | std::ios::trunc);
        if (!ofs.is_open())
          return std::string{"open failed for "} + p.string();
        ofs.write(text.data(), static_cast<std::streamsize>(text.size()));
        if (!ofs)
          return std::string{"write failed for "} + p.string();
      }
#ifndef _WIN32
      ::chmod(p.c_str(), 0600);
#endif
      return std::nullopt;
    } catch (const std::exception &e) {
      return std::string{"write_text_0600 exception: "} + e.what();
    }
  };

  // Load existing keys if present; otherwise generate a new pair
  cjj365::cryptutil::BoxKeyPair box_kp{};
  bool generated_new_keys = false;
  std::filesystem::path pk_path, sk_path;
  if (!out_dir.empty()) {
    pk_path = out_dir / "dev_pk.bin";
    sk_path = out_dir / "dev_sk.bin";
    std::error_code ec;
    bool have_pk =
        std::filesystem::exists(pk_path, ec) &&
        std::filesystem::file_size(pk_path, ec) == crypto_box_PUBLICKEYBYTES;
    bool have_sk =
        std::filesystem::exists(sk_path, ec) &&
        std::filesystem::file_size(sk_path, ec) == crypto_box_SECRETKEYBYTES;
    if (have_pk && have_sk) {
      // Read existing
      std::ifstream ifp(pk_path, std::ios::binary);
      std::ifstream ifs(sk_path, std::ios::binary);
      if (ifp && ifs) {
        ifp.read(reinterpret_cast<char *>(box_kp.public_key.data()),
                 crypto_box_PUBLICKEYBYTES);
        ifs.read(reinterpret_cast<char *>(box_kp.secret_key.data()),
                 crypto_box_SECRETKEYBYTES);
      }
    } else {
      try {
        box_kp = cjj365::cryptutil::generate_box_keypair();
        generated_new_keys = true;
      } catch (const std::exception &e) {
        return IO<void>::fail(
            {.code = my_errors::GENERAL::UNEXPECTED_RESULT,
             .what = std::string{"keypair generation failed: "} + e.what()});
      }
    }
  } else {
    try {
      box_kp = cjj365::cryptutil::generate_box_keypair();
      generated_new_keys = true;
    } catch (const std::exception &e) {
      return IO<void>::fail(
          {.code = my_errors::GENERAL::UNEXPECTED_RESULT,
           .what = std::string{"keypair generation failed: "} + e.what()});
    }
  }

  // Persist keypair and tokens if out_dir is available; only write keys when
  // newly generated
  if (!out_dir.empty() && generated_new_keys) {
    if (auto err = write_file_0600(pk_path, box_kp.public_key.data(),
                                   box_kp.public_key.size())) {
      output_hub_.logger().warning() << *err << std::endl;
    }
    if (auto err = write_file_0600(sk_path, box_kp.secret_key.data(),
                                   box_kp.secret_key.size())) {
      output_hub_.logger().warning() << *err << std::endl;
    }
    // Save tokens as text
    if (!poll_resp_->access_token.empty()) {
      if (auto err = write_text_0600(out_dir / "access_token.txt",
                                     poll_resp_->access_token)) {
        output_hub_.logger().warning() << *err << std::endl;
      }
    }
    if (!poll_resp_->refresh_token.empty()) {
      if (auto err = write_text_0600(out_dir / "refresh_token.txt",
                                     poll_resp_->refresh_token)) {
        output_hub_.logger().warning() << *err << std::endl;
      }
    }
  }

  // Prepare a minimal JSON payload per docs/script (include dev_pk as base64)
  // We reuse http_client's base64 utilities.
  std::string dev_pk_b64 = base64_encode(
      box_kp.public_key.data(), box_kp.public_key.size(), /*url=*/false);
  boost::json::object payload{
      {"device_public_id", device_public_id},
      {"platform", info.platform},
      {"model", info.model},
      {"app_version", "1.0.0"},
      {"name", std::string("CLI Device ") + info.hostname},
      {"ip", "127.0.0.1"},
      {"user_agent", info.user_agent},
      {"dev_pk", dev_pk_b64},
      // dev_pk omitted for now; TODO: generate X25519 and include
  };

  if (user_id.empty()) {
    output_hub_.printer().yellow()
        << "Device ready; access token obtained.\n"
        << "Missing user_id; showing payload to register the device manually:\n"
        << boost::json::serialize(payload) << std::endl;
    return IO<void>::pure();
  }

  // Build devices endpoint and POST with bearer token
  auto devices_url =
      std::format("{}/apiv1/users/{}/devices",
                  certctrl_config_provider_.get().base_url, user_id);

  return http_io<PostJsonTag>(devices_url)
      .map([this, payload = std::move(payload)](auto ex) mutable {
        ex->setRequestJsonBody(std::move(payload));
        ex->request.set("Authorization",
                        std::string("Bearer ") + poll_resp_->access_token);
        return ex;
      })
      .then(http_request_io<PostJsonTag>(http_client_))
      .then([this](auto ex) {
        if (ex->is_2xx()) {
          output_hub_.printer().green()
              << "Device registered successfully" << std::endl;
          return IO<void>::pure();
        }
        return IO<void>::fail(
            {.code = static_cast<int>(ex->response ? ex->response->result_int()
                                                   : 500),
             .what = "Device registration failed"});
      });
}

} // namespace certctrl