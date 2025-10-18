#include "handlers/login_handler.hpp"
#include "base64.h"
#include "customio/spinner.hpp"
#include "data/device_auth_types.hpp"
#include "http_client_monad.hpp"
#include "util/device_fingerprint.hpp"
#include "util/user_key_crypto.hpp"
#include "version.h"
#include <boost/asio/ip/udp.hpp>
#include <boost/log/trivial.hpp>
#include <boost/url.hpp>
#include <boost/system/error_code.hpp>
#include <chrono>
#include <algorithm>
#include <fmt/format.h>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <jwt-cpp/jwt.h>
#include <exception>
#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace json = boost::json;
namespace asio = boost::asio;

namespace certctrl {

using VoidPureIO = monad::IO<void>;

namespace {

std::string determine_device_ip(asio::io_context &ioc,
                                const std::string &base_url) {
  static constexpr std::string_view kFallback = "";

  auto parsed = boost::urls::parse_uri(base_url);
  if (!parsed) {
    return std::string{kFallback};
  }

  boost::urls::url_view url = parsed.value();
  std::string host = std::string(url.host());
  if (host.empty()) {
    return std::string{kFallback};
  }

  std::string service;
  if (url.has_port()) {
    service = std::string(url.port());
  } else if (url.scheme_id() == boost::urls::scheme::https) {
    service = "443";
  } else {
    service = "80";
  }

  boost::system::error_code ec;
  boost::asio::ip::udp::resolver resolver(ioc);
  auto results = resolver.resolve(host, service, ec);
  if (ec || results.empty()) {
    return std::string{kFallback};
  }

  auto endpoint = results.begin()->endpoint();
  boost::asio::ip::udp::socket socket(ioc);
  try {
    if (endpoint.address().is_v6()) {
      socket.open(boost::asio::ip::udp::v6());
    } else {
      socket.open(boost::asio::ip::udp::v4());
    }

    socket.connect(endpoint);
    auto local_endpoint = socket.local_endpoint();
    socket.close();
    return local_endpoint.address().to_string();
  } catch (const std::exception &) {
    if (socket.is_open()) {
      socket.close();
    }
    return std::string{kFallback};
  }
}

} // namespace

std::optional<std::filesystem::path> LoginHandler::resolve_runtime_dir() const {
  try {
    if (!config_sources_.paths_.empty()) {
      return std::filesystem::path(config_sources_.paths_.back());
    }
  } catch (...) {
  }
  return std::nullopt;
}

std::optional<std::string>
LoginHandler::read_text_file_trimmed(const std::filesystem::path &path) {
  std::ifstream ifs(path, std::ios::binary);
  if (!ifs.is_open()) {
    return std::nullopt;
  }
  std::string contents((std::istreambuf_iterator<char>(ifs)), {});
  auto first = contents.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) {
    return std::nullopt;
  }
  auto last = contents.find_last_not_of(" \t\r\n");
  if (last == std::string::npos || last < first) {
    return std::nullopt;
  }
  std::string trimmed = contents.substr(first, last - first + 1);
  if (trimmed.empty()) {
    return std::nullopt;
  }
  return trimmed;
}

bool LoginHandler::is_access_token_valid(const std::string &token,
                                         std::chrono::seconds skew) {
  try {
    auto decoded = jwt::decode(token);
    if (decoded.has_payload_claim("exp")) {
      auto exp_time = decoded.get_payload_claim("exp").as_date();
      auto now = std::chrono::system_clock::now();
      if (exp_time <= now + skew) {
        return false;
      }
    }
    return true;
  } catch (...) {
    return false;
  }
}

monad::IO<bool> LoginHandler::reuse_existing_session_if_possible() {
  using namespace monad;

  auto runtime_dir = resolve_runtime_dir();
  if (!runtime_dir) {
    return IO<bool>::pure(false);
  }

  const auto state_dir = *runtime_dir / "state";
  const auto access_path = state_dir / "access_token.txt";
  const auto refresh_path = state_dir / "refresh_token.txt";

  auto cached_access = read_text_file_trimmed(access_path);
  auto cached_refresh = read_text_file_trimmed(refresh_path);

  const std::chrono::seconds skew(60);
  if (cached_access && is_access_token_valid(*cached_access, skew)) {
    registration_completed_ = true;
    return IO<bool>::pure(true);
  }

  if (cached_refresh && !cached_refresh->empty()) {
    return refresh_session_with_token(*cached_refresh, *runtime_dir)
        .catch_then([this](const monad::Error &e) {
          output_hub_.logger().warning()
              << "Refresh token attempt failed: " << e.what << std::endl;
          return monad::IO<bool>::pure(false);
        });
  }

  return IO<bool>::pure(false);
}

monad::IO<bool>
LoginHandler::refresh_session_with_token(const std::string &refresh_token,
                                         const std::filesystem::path &out_dir) {
  using namespace monad;

  const auto &base_url = certctrl_config_provider_.get().base_url;
  const auto refresh_url = fmt::format("{}/auth/refresh", base_url);
  auto payload_obj = std::make_shared<boost::json::object>(
      boost::json::object{{"refresh_token", refresh_token}});

  auto write_text_0600 = [](const std::filesystem::path &p,
                            const std::string &text)
      -> std::optional<std::string> {
    try {
      std::error_code ec;
      if (auto parent = p.parent_path(); !parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) {
          return std::string{"create_directories failed: "} + ec.message();
        }
      }
      std::ofstream ofs(p, std::ios::binary | std::ios::trunc);
      if (!ofs.is_open()) {
        return std::string{"open failed for "} + p.string();
      }
      ofs.write(text.data(), static_cast<std::streamsize>(text.size()));
      if (!ofs) {
        return std::string{"write failed for "} + p.string();
      }
#ifndef _WIN32
      ::chmod(p.c_str(), 0600);
#endif
      return std::nullopt;
    } catch (const std::exception &ex) {
      return std::string{"write_text_0600 exception: "} + ex.what();
    }
  };

  return http_io<PostJsonTag>(refresh_url)
      .map([payload_obj](auto ex) {
        ex->setRequestJsonBody(*payload_obj);
        return ex;
      })
      .then(http_request_io<PostJsonTag>(http_client_))
      .then([this, out_dir, refresh_url,
             write_text_0600](auto ex) -> IO<bool> {
        if (!ex->is_2xx()) {
          std::string error_msg =
              std::string("Refresh token request failed via ") + refresh_url;
          if (ex->response) {
            error_msg += " (HTTP " +
                         std::to_string(ex->response->result_int()) + ")";
            if (!ex->response->body().empty()) {
              error_msg += ": " + std::string(ex->response->body());
            }
          }
          return IO<bool>::fail({.code = static_cast<int>(
                                    ex->response ? ex->response->result_int()
                                                 : 500),
                                 .what = std::move(error_msg)});
        }

        auto payload_result =
            ex->template parseJsonDataResponse<boost::json::object>();
        if (payload_result.is_err()) {
          auto err = payload_result.error();
          err.what = std::string("Refresh token response parse failed via ") +
                     refresh_url + ": " + err.what;
          return IO<bool>::fail(std::move(err));
        }
        auto response_obj = payload_result.value();
        const boost::json::object *data_ptr = &response_obj;
        if (auto *data = response_obj.if_contains("data");
            data && data->is_object()) {
          data_ptr = &data->as_object();
        }

        auto get_string = [](const boost::json::object &obj,
                             std::string_view key)
            -> std::optional<std::string> {
          if (auto *p = obj.if_contains(key); p && p->is_string()) {
            return boost::json::value_to<std::string>(*p);
          }
          return std::nullopt;
        };

        std::optional<std::string> new_access_token;
        std::optional<std::string> new_refresh_token;
        std::optional<int> new_expires_in;

        if (auto *session_ptr = data_ptr->if_contains("session");
            session_ptr && session_ptr->is_object()) {
          const auto &session_obj = session_ptr->as_object();
          new_access_token = get_string(session_obj, "access_token");
          new_refresh_token = get_string(session_obj, "refresh_token");
          if (auto *p = session_obj.if_contains("expires_in");
              p && p->is_number()) {
            new_expires_in = boost::json::value_to<int>(*p);
          }
        }

        if (!new_access_token || new_access_token->empty() ||
            !new_refresh_token || new_refresh_token->empty()) {
          return IO<bool>::fail({
              .code = my_errors::GENERAL::UNEXPECTED_RESULT,
              .what =
                  "Refresh token response missing required session tokens"});
        }

        const auto state_dir = out_dir / "state";
        if (auto err = write_text_0600(state_dir / "access_token.txt",
                                       *new_access_token)) {
          output_hub_.logger().warning() << *err << std::endl;
        }
        if (auto err = write_text_0600(state_dir / "refresh_token.txt",
                                       *new_refresh_token)) {
          output_hub_.logger().warning() << *err << std::endl;
        }
        if (new_expires_in) {
          output_hub_.printer().yellow()
              << "Refreshed tokens; expires in " << *new_expires_in << "s"
              << std::endl;
        } else {
          output_hub_.printer().yellow()
              << "Refreshed device tokens" << std::endl;
        }
        registration_completed_ = true;
        return IO<bool>::pure(true);
      });
}

VoidPureIO LoginHandler::start() {
  using namespace monad;

  return reuse_existing_session_if_possible().then([this](bool reused) {
    if (reused) {
      output_hub_.printer().green()
          << "Existing device session is still valid; skipping device authorization."
          << std::endl;
      return VoidPureIO::pure();
    }

    return start_device_authorization().then([this](auto start_resp) {
    output_hub_.printer().yellow()
        << "Device Authorization started.\n"
        << "User Code: " << start_resp.user_code << "\n"
        << "Verification URI: " << start_resp.verification_uri << "\n"
        << "Verification URI complete: "
        << start_resp.verification_uri_complete << "\n"
          << "Complete the authorization in your browser." << std::endl;
      return poll();
    });
  });
}

monad::IO<::data::deviceauth::StartResp>
LoginHandler::start_device_authorization() {
  using namespace monad;
  using ::data::deviceauth::StartResp;
  auto self = this->shared_from_this();
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
      .then([self](auto ex) {
        return monad::IO<StartResp>::from_result(
            ex->template parseJsonDataResponse<StartResp>());
      })
      .then([this](StartResp start_resp) {
        start_resp_ = std::move(start_resp);
        return monad::IO<StartResp>::pure(*start_resp_);
      });
}

monad::IO<::data::deviceauth::PollResp> LoginHandler::poll_device_once() {
  using namespace monad;
  using ::data::deviceauth::PollResp;

  if (!start_resp_) {
    return monad::IO<PollResp>::fail(
        {.code = my_errors::GENERAL::INVALID_ARGUMENT,
         .what = "Device authorization has not been started"});
  }

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
            ex->template parseJsonDataResponse<PollResp>());
      })
      .then([this](PollResp resp) {
        poll_resp_ = resp;
        return monad::IO<PollResp>::pure(std::move(resp));
      });
}

VoidPureIO LoginHandler::poll() {
  using namespace monad;
  using ::data::deviceauth::PollResp;

  if (!start_resp_) {
    return IO<void>::fail({.code = my_errors::GENERAL::INVALID_ARGUMENT,
                           .what = "Device authorization has not been started"});
  }

  const int interval_seconds = std::max(1, start_resp_->interval);
  const auto interval = std::chrono::seconds(interval_seconds);
  const int base_attempts =
      start_resp_->expires_in > 0 ? start_resp_->expires_in / interval_seconds : 0;
  const int max_retries = std::max(2, base_attempts + 1);

  auto spinner = std::make_shared<customio::Spinner>(
      this->exec_, output_hub_.printer().stream(), std::string{"Polling... "},
      std::chrono::milliseconds(120),
      /*enabled=*/true);
  spinner->start();

  auto attempt_counter = std::make_shared<int>(0);
  auto poll_once = [this, attempt_counter]() {
    return this->poll_device_once().map([this, attempt_counter](auto resp) {
      ++(*attempt_counter);
      output_hub_.logger().trace()
          << "Device authorization poll attempt " << *attempt_counter
          << " status=" << resp.status << std::endl;
      return resp;
    });
  };

  return poll_once()
      .poll_if(max_retries, interval, this->exec_,
               [](const PollResp &r) {
                 return r.status == "ready" || r.status == "approved" ||
                        r.status == "denied" || r.status == "access_denied" ||
                        r.status == "expired";
               })
      .then([this, spinner](PollResp resp) {
        spinner->stop("Polling done.");
        output_hub_.printer().yellow()
            << "Device Authorization polling finished.\n"
            << "Final Status: " << resp.status << "\n"
            << "Expires In: " << resp.expires_in.value_or(0) << std::endl;
        poll_resp_ = std::move(resp);
        if (poll_resp_->status == "ready" ||
            poll_resp_->status == "approved") {
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

  if (registration_completed_) {
    output_hub_.printer().yellow()
        << "Device already registered; skipping." << std::endl;
    return IO<void>::pure();
  }

  if (!poll_resp_) {
    return IO<void>::fail(
        {.code = my_errors::GENERAL::INVALID_ARGUMENT,
         .what = "Device authorization state unavailable"});
  }

  const std::string status = poll_resp_->status;
  if (status != "ready" && status != "approved") {
    output_hub_.printer().yellow()
        << "Skipping device registration; status=" << status << std::endl;
    return IO<void>::pure();
  }

  const std::string access_token = poll_resp_->access_token.value_or(std::string{});
  const std::string refresh_token = poll_resp_->refresh_token.value_or(std::string{});
  const std::string registration_code =
      poll_resp_->registration_code.value_or(std::string{});
  const bool have_access_token = !access_token.empty();
  const bool have_registration_code = !registration_code.empty();

  if (!have_access_token && !have_registration_code) {
    return IO<void>::fail({
        .code = my_errors::GENERAL::INVALID_ARGUMENT,
        .what = "Device registration requires access_token or registration_code"});
  }

  if (!poll_resp_->user_id || poll_resp_->user_id->empty()) {
    return IO<void>::fail({
        .code = my_errors::GENERAL::UNEXPECTED_RESULT,
        .what =
            "Device authorization poll response missing user_id"});
  }
  const std::string user_id = *poll_resp_->user_id;

  const auto &base_url = certctrl_config_provider_.get().base_url;

  // Gather device info and fingerprint
  std::string user_agent = fmt::format("cert-ctrl/{}", MYAPP_VERSION);
  auto info = cjj365::device::gather_device_info(user_agent);
  auto fp_hex = cjj365::device::generate_device_fingerprint_hex(info);
  auto device_public_id =
      cjj365::device::device_public_id_from_fingerprint(fp_hex);

  auto device_ip = determine_device_ip(ioc_, base_url);

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
  std::filesystem::path key_dir;
  if (!out_dir.empty()) {
    key_dir = out_dir / "keys";
    pk_path = key_dir / "dev_pk.bin";
    sk_path = key_dir / "dev_sk.bin";
    std::error_code ec;
    bool have_pk =
        std::filesystem::exists(pk_path, ec) &&
        std::filesystem::file_size(pk_path, ec) == crypto_box_PUBLICKEYBYTES;
    bool have_sk =
        std::filesystem::exists(sk_path, ec) &&
        std::filesystem::file_size(sk_path, ec) == crypto_box_SECRETKEYBYTES;
    if (have_pk && have_sk) {
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
             .what = std::string{"keypair generation failed: "} +
                         e.what()});
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

  if (!out_dir.empty() && generated_new_keys) {
    if (auto err = write_file_0600(pk_path, box_kp.public_key.data(),
                                   box_kp.public_key.size())) {
      output_hub_.logger().warning() << *err << std::endl;
    }
    if (auto err = write_file_0600(sk_path, box_kp.secret_key.data(),
                                   box_kp.secret_key.size())) {
      output_hub_.logger().warning() << *err << std::endl;
    }
  }

  std::string dev_pk_b64 = base64_encode(
    box_kp.public_key.data(), box_kp.public_key.size(), /*url=*/false);
  std::string ip_for_payload = device_ip.empty() ? std::string{"unknown"}
                         : std::move(device_ip);

  boost::json::object payload{{"device_public_id", device_public_id},
                {"platform", info.platform},
                {"model", info.model},
                {"app_version", MYAPP_VERSION},
                {"name", std::string("CLI Device ") +
                       info.hostname},
                {"ip", ip_for_payload},
                {"user_agent", info.user_agent},
                {"dev_pk", dev_pk_b64}};

  try {
    auto numeric_user_id = std::stoll(user_id);
    payload["user_id"] = numeric_user_id;
  } catch (...) {
    payload["user_id"] = user_id;
  }

  if (have_registration_code) {
    payload["registration_code"] = registration_code;
  } else {
    std::optional<std::string> refresh_for_payload;
    if (!refresh_token.empty()) {
      refresh_for_payload = refresh_token;
    } else if (!out_dir.empty()) {
      if (auto stored_refresh =
              read_text_file_trimmed(out_dir / "state" / "refresh_token.txt")) {
        refresh_for_payload = std::move(*stored_refresh);
      }
    }
    if (refresh_for_payload) {
      payload["refresh_token"] = *refresh_for_payload;
    }
  }

  auto devices_url = fmt::format("{}/apiv1/device/registration", base_url);

  return http_io<PostJsonTag>(devices_url)
      .map([payload = std::move(payload)](auto ex) mutable {
        ex->setRequestJsonBody(std::move(payload));
        return ex;
      })
  .then(http_request_io<PostJsonTag>(http_client_))
  .then([this, out_dir, write_text_0600](auto ex) mutable {
        if (!ex->is_2xx()) {
          std::string error_msg = "Device registration failed";
          if (ex->response) {
            error_msg += " (HTTP " +
                         std::to_string(ex->response->result_int()) + ")";
            if (!ex->response->body().empty()) {
              error_msg += ": " + std::string(ex->response->body());
            }
          }
          return IO<void>::fail({
              .code = static_cast<int>(ex->response
                                           ? ex->response->result_int()
                                           : 500),
              .what = std::move(error_msg)});
        }

        auto payload_result =
            ex->template parseJsonDataResponse<json::object>();
        if (payload_result.is_err()) {
          return IO<void>::fail(payload_result.error());
        }
        auto payload_obj = payload_result.value();
        const json::object *data_ptr = &payload_obj;
        if (auto *data = payload_obj.if_contains("data");
            data && data->is_object()) {
          data_ptr = &data->as_object();
        }

        auto get_string = [](const json::object &obj,
                             std::string_view key)
            -> std::optional<std::string> {
          if (auto *p = obj.if_contains(key); p && p->is_string()) {
            return json::value_to<std::string>(*p);
          }
          return std::nullopt;
        };

        auto get_int = [](const json::object &obj, std::string_view key)
            -> std::optional<int> {
          if (auto *p = obj.if_contains(key); p && p->is_number()) {
            return json::value_to<int>(*p);
          }
          return std::nullopt;
        };

        std::optional<std::string> new_access_token;
        std::optional<std::string> new_refresh_token;
        std::optional<int> new_expires_in;
        std::optional<std::string> device_id_str;

        if (auto *session_ptr = data_ptr->if_contains("session");
            session_ptr && session_ptr->is_object()) {
          const auto &session_obj = session_ptr->as_object();
          new_access_token = get_string(session_obj, "access_token");
          new_refresh_token = get_string(session_obj, "refresh_token");
          new_expires_in = get_int(session_obj, "expires_in");
        }

        if (auto *device_ptr = data_ptr->if_contains("device");
            device_ptr && device_ptr->is_object()) {
          const auto &device_obj = device_ptr->as_object();
          if (auto *p = device_obj.if_contains("id")) {
            if (p->is_number()) {
              device_id_str =
                  std::to_string(json::value_to<int64_t>(*p));
            } else if (p->is_string()) {
              device_id_str = json::value_to<std::string>(*p);
            }
          }
          if (!device_id_str) {
            device_id_str =
                get_string(device_obj, "device_public_id");
          }
        }

        if (new_access_token) {
          poll_resp_->access_token = *new_access_token;
        }
        if (new_refresh_token) {
          poll_resp_->refresh_token = *new_refresh_token;
        }
        if (new_expires_in) {
          poll_resp_->expires_in = *new_expires_in;
        }
        poll_resp_->registration_code.reset();

        auto decode_device_id = [](const std::string &token)
            -> std::optional<std::string> {
          try {
            auto decoded = jwt::decode(token);
            if (decoded.has_payload_claim("device_id")) {
              return decoded.get_payload_claim("device_id").as_string();
            }
          } catch (...) {
          }
          return std::nullopt;
        };

        const std::string effective_access =
            poll_resp_->access_token.value_or(std::string{});
        const std::string effective_refresh =
            poll_resp_->refresh_token.value_or(std::string{});

        if (!device_id_str && !effective_access.empty()) {
          device_id_str = decode_device_id(effective_access);
        }

        if (!out_dir.empty()) {
          const auto state_dir = out_dir / "state";
          if (!effective_access.empty()) {
            if (auto err =
                    write_text_0600(state_dir / "access_token.txt",
                                    effective_access)) {
              output_hub_.logger().warning() << *err << std::endl;
            }
          }
          if (!effective_refresh.empty()) {
            if (auto err =
                    write_text_0600(state_dir / "refresh_token.txt",
                                    effective_refresh)) {
              output_hub_.logger().warning() << *err << std::endl;
            }
          }
        }

        registration_completed_ = true;
        output_hub_.printer().green()
            << "Device registered successfully" << std::endl;
        if (device_id_str && !device_id_str->empty()) {
          output_hub_.printer().green()
              << "Assigned device ID: " << *device_id_str << std::endl;
        }
        return IO<void>::pure();
      });
}

} // namespace certctrl