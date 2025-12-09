#include "handlers/device_automation_handler.hpp"

#include "http_client_monad.hpp"
#include "my_error_codes.hpp"
#include "util/device_fingerprint.hpp"
#include "version.h"
#include <algorithm>
#include <boost/beast/http.hpp>
#include <boost/json.hpp>
#include <boost/program_options.hpp>
#include <fmt/format.h>
#include <fstream>
#include <optional>
#include <sstream>
#include <vector>

namespace certctrl {
namespace {

namespace po = boost::program_options;
namespace json = boost::json;
namespace http = boost::beast::http;

std::vector<std::string>
filter_tokens(const std::vector<std::string> &source,
              const std::vector<std::string> &excluded) {
  if (excluded.empty()) {
    return source;
  }

  std::vector<std::string> result;
  result.reserve(source.size());
  std::vector<std::string> remaining = excluded;

  for (const auto &token : source) {
    auto it = std::find(remaining.begin(), remaining.end(), token);
    if (it != remaining.end()) {
      remaining.erase(it);
      continue;
    }
    result.push_back(token);
  }
  return result;
}

std::optional<std::string>
resolve_device_public_id(customio::ConsoleOutput &output,
                         certctrl::IDeviceStateStore &state_store) {
  if (auto stored = state_store.get_device_public_id();
      stored && !stored->empty()) {
    return stored;
  }

  auto device_info = cjj365::device::gather_device_info(
      fmt::format("cert-ctrl/{}", MYAPP_VERSION));
  auto fingerprint =
      cjj365::device::generate_device_fingerprint_hex(device_info);
  if (fingerprint.empty()) {
    output.logger().warning() << "Unable to derive device fingerprint; "
                                 "device_id required for automation."
                              << std::endl;
    return std::nullopt;
  }

  auto derived_id =
      cjj365::device::device_public_id_from_fingerprint(fingerprint);
  if (derived_id.empty()) {
    output.logger().warning()
        << "Unable to derive device_id from fingerprint." << std::endl;
    return std::nullopt;
  }

  const std::optional<std::string> id_payload(derived_id);
  const std::optional<std::string> fp_payload(fingerprint);
  if (auto err = state_store.save_device_identity(id_payload, fp_payload)) {
    output.logger().warning()
        << "Failed to persist derived device identity: " << *err << std::endl;
  }

  return derived_id;
}

std::optional<std::string> read_payload_file(const std::string &path) {
  std::ifstream input(path, std::ios::in | std::ios::binary);
  if (!input.is_open()) {
    return std::nullopt;
  }

  std::ostringstream buffer;
  buffer << input.rdbuf();
  return buffer.str();
}

} // namespace

DeviceAutomationHandler::DeviceAutomationHandler(
    CliCtx &cli_ctx, customio::ConsoleOutput &output,
    certctrl::ICertctrlConfigProvider &config_provider,
    client_async::HttpClientManager &http_client,
    certctrl::IDeviceStateStore &state_store)
    : cli_ctx_(cli_ctx), output_(output), config_provider_(config_provider),
      http_client_(http_client), state_store_(state_store) {}

monad::IO<void> DeviceAutomationHandler::start() {
  if (cli_ctx_.positionals.size() < 2) {
    return show_usage("Missing device action.");
  }

  const std::string action = cli_ctx_.positionals[1];
  auto options = parse_action_options(action);

  if (options.requested_help) {
    return show_usage();
  }

  if (!options.api_key || options.api_key->empty()) {
    return show_usage("--apikey is required for device automation actions.");
  }

  return dispatch_action(action, options);
}

monad::IO<void>
DeviceAutomationHandler::dispatch_action(const std::string &action,
                                         const ActionOptions &options) {
  if (action == "assign-cert") {
    return handle_assign_certificate(*options.api_key);
  }

  if (action == "install-config-update") {
    return handle_install_config_update(options);
  }

  return show_usage(fmt::format("Unknown device action '{}'.", action));
}

DeviceAutomationHandler::ActionOptions
DeviceAutomationHandler::parse_action_options(const std::string &action) const {
  ActionOptions options;
  std::string api_key_value;
  std::string payload_inline_value;
  std::string payload_file_value;

  po::options_description desc("device options");
  desc.add_options()
      ("apikey", po::value<std::string>(&api_key_value),
       "API key that carries automation context")
      ("payload", po::value<std::string>(&payload_inline_value),
       "Inline JSON payload for install-config-update")
      ("payload-file", po::value<std::string>(&payload_file_value),
       "Path to JSON payload file for install-config-update")
      ("help,h", "Show this help message");

  auto args = filter_tokens(cli_ctx_.unrecognized,
                            std::vector<std::string>{command(), action});

  try {
    po::variables_map vm;
    po::store(
        po::command_line_parser(args).options(desc).allow_unregistered().run(),
        vm);
    po::notify(vm);

    if (vm.count("help")) {
      options.requested_help = true;
      return options;
    }

    if (vm.count("apikey")) {
      options.api_key = api_key_value;
    }

    if (vm.count("payload")) {
      options.payload_inline = payload_inline_value;
    }

    if (vm.count("payload-file")) {
      options.payload_file = payload_file_value;
    }
  } catch (const std::exception &ex) {
    output_.logger().error() << "Failed to parse device options: " << ex.what()
                             << std::endl;
  }

  return options;
}

monad::IO<void>
DeviceAutomationHandler::handle_assign_certificate(const std::string &api_key) {
  using namespace monad;

  auto device_public_id = resolve_device_public_id(output_, state_store_);
  if (!device_public_id) {
    return IO<void>::fail(
        monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                          "Unable to resolve device_id; run 'cert-ctrl login' "
                          "to register this device."));
  }

  const auto &base_url = config_provider_.get().base_url;
  const auto url = fmt::format("{}/apiv1/me/certificate-assign", base_url);

  json::object payload;
  payload["device_public_id"] = *device_public_id;

  return http_io<PostJsonTag>(url)
      .map([payload = std::move(payload), api_key](auto ex) mutable {
        ex->setRequestJsonBody(std::move(payload));
        ex->request.set(http::field::authorization,
                        std::string("Bearer ") + api_key);
        return ex;
      })
      .then(http_request_io<PostJsonTag>(http_client_))
      .then([this](auto ex) -> monad::IO<void> {
        if (!ex->is_2xx()) {
          std::string error_msg = "Certificate assignment failed";
          if (ex->response) {
            error_msg += fmt::format(" (HTTP {})", ex->response->result_int());
            if (!ex->response->body().empty()) {
              error_msg += ": " + std::string(ex->response->body());
            }
          }
          return monad::IO<void>::fail(monad::make_error(
              static_cast<int>(ex->response ? ex->response->result_int() : 500),
              std::move(error_msg)));
        }

        std::string status_message =
            "Certificate assignment request completed.";
        auto parsed = ex->template parseJsonDataResponse<json::object>();
        if (!parsed.is_err()) {
          const json::object &root = parsed.value();
          auto extract_message =
              [](const json::object &obj) -> std::optional<std::string> {
            if (auto *msg = obj.if_contains("message");
                msg && msg->is_string()) {
              return std::string(msg->as_string().c_str());
            }
            if (auto *status = obj.if_contains("status");
                status && status->is_string()) {
              return std::string(status->as_string().c_str());
            }
            return std::nullopt;
          };

          if (auto msg = extract_message(root)) {
            status_message = *msg;
          } else if (auto *data = root.if_contains("data");
                     data && data->is_object()) {
            if (auto msg = extract_message(data->as_object())) {
              status_message = *msg;
            }
          }
        }

        output_.printer().green() << status_message << std::endl;
        return monad::IO<void>::pure();
      });
}

monad::IO<void> DeviceAutomationHandler::handle_install_config_update(
    const ActionOptions &options) {
  using namespace monad;

  if (!options.api_key || options.api_key->empty()) {
    return show_usage("--apikey is required for install-config-update.");
  }

  if (options.payload_inline && options.payload_file) {
    return show_usage(
        "Provide only one of --payload or --payload-file for install-config-"
        "update.");
  }

  auto resolved_id = resolve_device_public_id(output_, state_store_);
  if (!resolved_id) {
    return IO<void>::fail(
        monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                          "Unable to resolve device_id; run 'cert-ctrl login' "
                          "to register this device."));
  }
  const std::string device_public_id = *resolved_id;

  std::optional<std::string> payload_source;
  if (options.payload_inline) {
    payload_source = options.payload_inline;
  } else if (options.payload_file) {
    payload_source = read_payload_file(*options.payload_file);
    if (!payload_source) {
      return IO<void>::fail(monad::make_error(
          my_errors::GENERAL::INVALID_ARGUMENT,
          fmt::format("Unable to read payload file '{}'.",
                      *options.payload_file)));
    }
  }

  if (!payload_source || payload_source->empty()) {
    return show_usage(
        "install-config-update requires --payload or --payload-file.");
  }

  json::value payload;
  try {
    payload = json::parse(*payload_source);
  } catch (const std::exception &ex) {
    return IO<void>::fail(monad::make_error(
        my_errors::GENERAL::INVALID_ARGUMENT,
        fmt::format("Payload is not valid JSON: {}", ex.what())));
  }

  if (!payload.is_array()) {
    return IO<void>::fail(monad::make_error(
        my_errors::GENERAL::INVALID_ARGUMENT,
        "Payload must be a JSON array of install steps."));
  }

  auto &steps = payload.as_array();
  for (std::size_t idx = 0; idx < steps.size(); ++idx) {
    auto &entry = steps[idx];
    if (!entry.is_object()) {
      return IO<void>::fail(monad::make_error(
          my_errors::GENERAL::INVALID_ARGUMENT,
          fmt::format("Payload entry {} must be a JSON object.", idx)));
    }

    auto &obj = entry.as_object();
    auto *ob_type = obj.if_contains("ob_type");
    if (!ob_type || !ob_type->is_string() || ob_type->as_string().empty()) {
      return IO<void>::fail(monad::make_error(
          my_errors::GENERAL::INVALID_ARGUMENT,
          fmt::format("Payload entry {} missing non-empty ob_type.", idx)));
    }

    auto *ob_id = obj.if_contains("ob_id");
    if (!ob_id || !(ob_id->is_int64() || ob_id->is_uint64())) {
      return IO<void>::fail(monad::make_error(
          my_errors::GENERAL::INVALID_ARGUMENT,
          fmt::format("Payload entry {} missing numeric ob_id.", idx)));
    }

    if (auto *changes = obj.if_contains("changes")) {
      if (!changes->is_object()) {
        return IO<void>::fail(monad::make_error(
            my_errors::GENERAL::INVALID_ARGUMENT,
            fmt::format("Payload entry {} has non-object changes.", idx)));
      }
    }

    if (auto *details = obj.if_contains("details")) {
      if (!details->is_object()) {
        return IO<void>::fail(monad::make_error(
            my_errors::GENERAL::INVALID_ARGUMENT,
            fmt::format("Payload entry {} has non-object details.", idx)));
      }
    }
  }

  const auto &base_url = config_provider_.get().base_url;
  const auto url = fmt::format("{}/apiv1/me/install-config-update/{}", base_url,
                               device_public_id);

  return http_io<PostJsonTag>(url)
      .map([payload = std::move(payload), api_key = *options.api_key](auto ex) mutable {
        ex->setRequestJsonBody(std::move(payload));
        ex->request.set(http::field::authorization,
                        std::string("Bearer ") + api_key);
        return ex;
      })
      .then(http_request_io<PostJsonTag>(http_client_))
      .then([this](auto ex) -> monad::IO<void> {
        if (!ex->is_2xx()) {
          std::string error_msg = "Install config update failed";
          if (ex->response) {
            error_msg += fmt::format(" (HTTP {})", ex->response->result_int());
            if (!ex->response->body().empty()) {
              error_msg += ": " + std::string(ex->response->body());
            }
          }
          return monad::IO<void>::fail(monad::make_error(
              static_cast<int>(ex->response ? ex->response->result_int() : 500),
              std::move(error_msg)));
        }

        std::string status_message =
            "Install config update request completed.";
        auto parsed = ex->template parseJsonDataResponse<json::object>();
        if (!parsed.is_err()) {
          const json::object &root = parsed.value();
          if (auto *msg = root.if_contains("message");
              msg && msg->is_string()) {
            status_message = std::string(msg->as_string().c_str());
          }
        }

        output_.printer().green() << status_message << std::endl;
        return monad::IO<void>::pure();
      });
}

monad::IO<void>
DeviceAutomationHandler::show_usage(const std::string &error) const {
  if (!error.empty()) {
    output_.logger().error() << error << std::endl;
  }

  output_.printer().yellow()
      << "Usage: cert-ctrl device <action> --apikey <token>" << std::endl;
  output_.printer().white() << "Available actions:" << std::endl
                            << "  assign-cert    Request certificate "
                               "assignment via /apiv1/me/certificate-assign"
                << std::endl
                << "  install-config-update  Send install step "
                   "overrides via /apiv1/me/install-config-update/:device_public_id"
                << std::endl;
    output_.printer().white()
      << "Example: cert-ctrl device assign-cert --apikey $TOKEN" << std::endl
      << "Example: cert-ctrl device install-config-update --apikey $TOKEN "
       "--payload-file steps.json"
      << std::endl;

  return monad::IO<void>::fail(monad::make_error(
      my_errors::GENERAL::SHOW_OPT_DESC, "cert-ctrl device usage"));
}

} // namespace certctrl
