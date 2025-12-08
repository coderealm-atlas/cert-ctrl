#include "handlers/session_refresher.hpp"

#include <boost/beast/http.hpp>
#include <boost/json.hpp>
#include <fmt/format.h>

#include "handlers/session_refresh_retry.hpp"
#include "http_client_monad.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <fstream>

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace certctrl {

namespace {

constexpr int kRefreshTokenRotatedCode = 10003;
constexpr std::string_view kRefreshTokenRotatedKey =
    "refresh_token_rotated";

struct ApiErrorDetails {
  std::optional<int> code;
  std::optional<std::string> key;
  std::optional<std::string> message;
};

void capture_error_fields(const boost::json::value &val,
                          ApiErrorDetails &details) {
  if (!val.is_object()) {
    return;
  }

  const auto &obj = val.as_object();
  if (!details.code) {
    if (auto *code = obj.if_contains("code")) {
      if (code->is_int64()) {
        details.code = static_cast<int>(code->as_int64());
      } else if (code->is_string()) {
        try {
          details.code = std::stoi(code->as_string().c_str());
        } catch (...) {
        }
      }
    }
  }

  if (!details.key) {
    if (auto *key = obj.if_contains("key"); key && key->is_string()) {
      details.key = boost::json::value_to<std::string>(*key);
    }
  }

  if (!details.message) {
    if (auto *msg = obj.if_contains("message"); msg && msg->is_string()) {
      details.message = boost::json::value_to<std::string>(*msg);
    } else if (auto *error_msg = obj.if_contains("error");
               error_msg && error_msg->is_string()) {
      details.message = boost::json::value_to<std::string>(*error_msg);
    }
  }

  if (auto *err = obj.if_contains("error")) {
    capture_error_fields(*err, details);
  }
  if (auto *data = obj.if_contains("data")) {
    capture_error_fields(*data, details);
  }
}

std::optional<ApiErrorDetails>
parse_api_error_details(std::string_view raw_body) {
  if (raw_body.empty()) {
    return std::nullopt;
  }

  try {
    auto parsed = boost::json::parse(raw_body);
    ApiErrorDetails details;
    capture_error_fields(parsed, details);
    if (details.code || details.key || details.message) {
      return details;
    }
  } catch (...) {
  }

  return std::nullopt;
}

bool is_rotation_code(const ApiErrorDetails &details) {
  if (details.code && *details.code == kRefreshTokenRotatedCode) {
    return true;
  }
  if (details.key && *details.key == kRefreshTokenRotatedKey) {
    return true;
  }
  if (details.message) {
    return boost::beast::iequals(*details.message, "refresh token has been rotated") ||
           details.message->find("rotated") != std::string::npos;
  }
  return false;
}

bool iequals(std::string_view haystack, std::string_view needle) {
  auto it = std::search(haystack.begin(), haystack.end(), needle.begin(),
                        needle.end(), [](char a, char b) {
                          return std::tolower(a) == std::tolower(b);
                        });
  return it != haystack.end();
}
} // namespace

SessionRefresher::SessionRefresher(
    cjj365::IoContextManager &io_context_manager,
    certctrl::ICertctrlConfigProvider &config_provider,
    customio::ConsoleOutput &output,
    client_async::HttpClientManager &http_client,
    IDeviceStateStore &state_store)
    : io_context_manager_(io_context_manager),
      config_provider_(config_provider), output_(output),
      http_client_(http_client), state_store_(state_store) {
  runtime_dir_ = config_provider_.get().runtime_dir;
}

monad::IO<void> SessionRefresher::refresh(std::string reason) {
  auto self = shared_from_this();
  return monad::IO<void>(
      [self, reason = std::move(reason)](RefreshCallback cb) mutable {
        self->enqueue_refresh(std::move(reason), std::move(cb));
      });
}

void SessionRefresher::enqueue_refresh(std::string reason,
                                       RefreshCallback cb) {
  std::shared_ptr<RefreshState> to_start;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!inflight_) {
      inflight_ = std::make_shared<RefreshState>();
      inflight_->primary_reason = std::move(reason);
      to_start = inflight_;
    } else {
      inflight_->joined_reasons.push_back(std::move(reason));
    }
    inflight_->callbacks.push_back(std::move(cb));
  }

  if (to_start) {
    start_refresh(std::move(to_start));
  } else {
    output_.logger().trace() << "Joining in-flight session refresh" << std::endl;
  }
}

void SessionRefresher::start_refresh(std::shared_ptr<RefreshState> state) {
  auto self = shared_from_this();
  build_refresh_io(state).run([self, state](auto result) {
    self->notify_callbacks(state, std::move(result));
  });
}

monad::IO<void>
SessionRefresher::build_refresh_io(std::shared_ptr<RefreshState> state) {
  return monad::IO<void>::pure().then([self = shared_from_this(),
                                       state]() -> monad::IO<void> {
    auto refresh_token = self->load_refresh_token();
    if (!refresh_token || refresh_token->empty()) {
      return monad::IO<void>::fail(monad::make_error(
          my_errors::GENERAL::INVALID_ARGUMENT,
          "Refresh token not found. Run 'cert-ctrl login' to authenticate."));
    }
    state->refresh_token_snapshot = *refresh_token;
    return self->attempt_refresh(state, /*attempt=*/1,
                                 session_refresh::kInitialRetryDelay);
  });
}

monad::IO<void> SessionRefresher::attempt_refresh(
    std::shared_ptr<RefreshState> state, int attempt,
    std::chrono::milliseconds delay) {
  auto self = shared_from_this();
  const std::string &refresh_token = state->refresh_token_snapshot;
  return perform_refresh_request(state, refresh_token, attempt)
      .catch_then([self, state, attempt, delay](monad::Error err) {
        return self->handle_refresh_error(state, std::move(err))
            .catch_then([self, state, attempt,
                         delay](monad::Error retry_err) {
              if (is_rotation_error(retry_err)) {
                self->output_.logger().warning()
                    << "Session refresh aborted because the server rotated "
                       "the refresh token family." << std::endl;
                self->output_.printer().yellow()
                    << "Device session refresh failed because the refresh "
                       "token has been rotated upstream." << std::endl
                    << "Please rerun 'cert-ctrl login --force' to "
                       "re-authorize this device." << std::endl;
                return monad::IO<void>::fail(std::move(retry_err));
              }

              if (!session_refresh::is_retryable_error(retry_err)) {
                return monad::IO<void>::fail(std::move(retry_err));
              }

              auto wait = std::clamp(delay, session_refresh::kInitialRetryDelay,
                                     session_refresh::kMaxRetryDelay);
              self->output_.logger().warning()
                  << "Device session refresh attempt " << attempt
                  << " failed: " << retry_err.what << "; retrying in "
                  << wait.count() << "ms" << std::endl;
              auto next_delay = session_refresh::next_delay(wait);

              return monad::delay_for<void>(self->io_context_manager_.ioc(),
                                            wait)
                  .then([self, state, attempt, next_delay]() {
                    return self->attempt_refresh(state, attempt + 1,
                                                 next_delay);
                  });
            });
      });
}

monad::IO<void> SessionRefresher::perform_refresh_request(
    std::shared_ptr<RefreshState> state, const std::string &refresh_token,
    int attempt) {
  using namespace monad;
  using monad::PostJsonTag;
  using monad::http_io;
  using monad::http_request_io;

  const auto refresh_url =
      fmt::format("{}/auth/refresh", config_provider_.get().base_url);
  auto payload_obj = std::make_shared<boost::json::object>(
      boost::json::object{{"refresh_token", refresh_token}});

  output_.logger().info()
    << "Refreshing device session via " << refresh_url << " (reason: "
    << state->primary_reason << ", attempt " << attempt << ')' << std::endl;

  return http_io<PostJsonTag>(refresh_url)
      .map([payload_obj](auto ex) {
        ex->setRequestJsonBody(*payload_obj);
        return ex;
      })
      .then(http_request_io<PostJsonTag>(http_client_))
      .then([this, state, refresh_url](auto ex) -> monad::IO<void> {
        if (!ex->is_2xx()) {
          std::string error_msg = "Refresh token request failed";
          int status = 0;
          std::string response_body;
          if (ex->response) {
            status = ex->response->result_int();
            error_msg += " (HTTP " + std::to_string(status) + ")";
            if (!ex->response->body().empty()) {
              response_body = std::string(ex->response->body());
              error_msg += ": " + response_body;
            }
          }

          if (auto api_error = parse_api_error_details(response_body);
              api_error && is_rotation_code(*api_error)) {
            std::string base_msg = api_error->message.value_or(
                "Refresh token has been rotated by the server");
            auto err = monad::make_error(
                my_errors::GENERAL::UNAUTHORIZED,
                fmt::format(
                    "{} (code {}) — please rerun 'cert-ctrl login --force' to "
                    "re-authorize this device.",
                    base_msg, kRefreshTokenRotatedCode));
            err.key = std::string{kRefreshTokenRotatedKey};
            err.response_status = status;
            err.params["server_code"] = kRefreshTokenRotatedCode;
            err.params["server_message"] = base_msg;
            return monad::IO<void>::fail(std::move(err));
          }

          auto err = monad::make_error(my_errors::GENERAL::UNEXPECTED_RESULT,
                                       std::move(error_msg));
          err.response_status = status;
          return monad::IO<void>::fail(std::move(err));
        }

        auto payload_result =
            ex->template parseJsonDataResponse<boost::json::object>();
        if (payload_result.is_err()) {
          return monad::IO<void>::fail(payload_result.error());
        }

        auto payload_obj = payload_result.value();
        const boost::json::object *data_ptr = &payload_obj;
        if (auto *data = payload_obj.if_contains("data");
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

        std::optional<std::string> new_access_token =
            get_string(*data_ptr, "access_token");
        std::optional<std::string> new_refresh_token =
            get_string(*data_ptr, "refresh_token");
        std::optional<int> new_expires_in;
        if (auto *p = data_ptr->if_contains("expires_in");
            p && p->is_number()) {
          new_expires_in = boost::json::value_to<int>(*p);
        }

        if ((!new_access_token || !new_refresh_token) &&
            data_ptr->if_contains("session")) {
          if (auto *session_ptr = data_ptr->if_contains("session");
              session_ptr && session_ptr->is_object()) {
            const auto &session_obj = session_ptr->as_object();
            if (!new_access_token) {
              new_access_token = get_string(session_obj, "access_token");
            }
            if (!new_refresh_token) {
              new_refresh_token = get_string(session_obj, "refresh_token");
            }
            if (!new_expires_in) {
              if (auto *p = session_obj.if_contains("expires_in");
                  p && p->is_number()) {
                new_expires_in = boost::json::value_to<int>(*p);
              }
            }
          }
        }

        if (!new_access_token || new_access_token->empty() ||
            !new_refresh_token || new_refresh_token->empty()) {
          return monad::IO<void>::fail(monad::make_error(
            my_errors::GENERAL::UNEXPECTED_RESULT,
            "Refresh response missing tokens"));
        }

        if (auto err = state_store_.save_tokens(new_access_token,
                                                new_refresh_token,
                                                new_expires_in)) {
          output_.logger().warning()
              << "Failed to persist refreshed tokens in state store: "
              << *err << std::endl;
        }

        auto state_path = state_dir();
        if (state_path.empty()) {
          return monad::IO<void>::fail(monad::make_error(
            my_errors::GENERAL::UNEXPECTED_RESULT,
            "Runtime state directory unavailable"));
        }

        auto access_path = state_path / "access_token.txt";
        auto refresh_path = state_path / "refresh_token.txt";

        if (auto err = write_text_0600(access_path, *new_access_token)) {
          output_.logger().warning() << *err << std::endl;
        }
        if (auto err = write_text_0600(refresh_path, *new_refresh_token)) {
          output_.logger().warning() << *err << std::endl;
        }

        output_.logger().trace()
            << "Device session refreshed; new access token expires in "
            << new_expires_in.value_or(0) << "s" << std::endl;

        return monad::IO<void>::pure();
      });
}

monad::IO<void> SessionRefresher::handle_refresh_error(
    std::shared_ptr<RefreshState> state, monad::Error err) {
  if (is_rotation_error(err) &&
      detect_external_refresh(state->refresh_token_snapshot)) {
    output_.logger().info()
        << "Detected external session refresh while handling reason '"
        << state->primary_reason
        << "'; using updated tokens from disk instead of failing"
        << std::endl;
    return monad::IO<void>::pure();
  }
  return monad::IO<void>::fail(std::move(err));
}

std::optional<std::string> SessionRefresher::load_refresh_token() const {
  if (auto stored = state_store_.get_refresh_token(); stored && !stored->empty()) {
    return stored;
  }

  auto dir = state_dir();
  if (dir.empty()) {
    return std::nullopt;
  }
  auto token_path = dir / "refresh_token.txt";
  std::ifstream ifs(token_path, std::ios::binary);
  if (!ifs.is_open()) {
    return std::nullopt;
  }
  std::string token((std::istreambuf_iterator<char>(ifs)),
                    std::istreambuf_iterator<char>());
  auto first = token.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) {
    return std::nullopt;
  }
  auto last = token.find_last_not_of(" \t\r\n");
  if (last == std::string::npos || last < first) {
    return std::nullopt;
  }
  return token.substr(first, last - first + 1);
}

bool SessionRefresher::detect_external_refresh(
    const std::string &original_token) const {
  auto latest = load_refresh_token();
  return latest && *latest != original_token;
}

std::optional<std::string>
SessionRefresher::write_text_0600(const std::filesystem::path &p,
                                  const std::string &text) {
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
  } catch (const std::exception &e) {
    return std::string{"write_text_0600 exception: "} + e.what();
  }
}

std::filesystem::path SessionRefresher::state_dir() const {
  if (runtime_dir_.empty()) {
    return {};
  }
  return runtime_dir_ / "state";
}

bool SessionRefresher::is_rotation_error(const monad::Error &err) {
  if (err.key == kRefreshTokenRotatedKey) {
    return true;
  }

  if (auto *server_code = err.params.if_contains("server_code");
      server_code && server_code->is_int64() &&
      server_code->as_int64() == kRefreshTokenRotatedCode) {
    return true;
  }

  return iequals(err.what, "refresh token has been rotated") ||
         err.what.find("rotated") != std::string::npos;
}

void SessionRefresher::notify_callbacks(
    std::shared_ptr<RefreshState> state,
    monad::Result<void, monad::Error> result) {
  std::vector<RefreshCallback> callbacks;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (inflight_ == state) {
      inflight_.reset();
    }
    callbacks = std::move(state->callbacks);
  }

  if (callbacks.empty()) {
    return;
  }

  for (size_t i = 0; i < callbacks.size(); ++i) {
    auto cb = std::move(callbacks[i]);
    if (!cb) {
      continue;
    }
    if (i + 1 == callbacks.size()) {
      cb(std::move(result));
    } else {
      cb(result);
    }
  }
}

} // namespace certctrl
