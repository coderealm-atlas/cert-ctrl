#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <unordered_map>

#include "data/install_config_dto.hpp"
#include "handlers/install_actions/exec_environment_resolver.hpp"
#include "handlers/install_actions/resource_materializer.hpp"
#include "io_monad.hpp"
#include "my_error_codes.hpp"
#include "result_monad.hpp"

namespace certctrl::install_actions {

class FunctionResourceMaterializer : public IResourceMaterializer {
public:
  explicit FunctionResourceMaterializer(
      std::function<monad::IO<void>(const dto::InstallItem &)> fn)
      : fn_(std::move(fn)) {}

  monad::IO<void> ensure_materialized(
      const dto::InstallItem &item) override {
    if (!fn_) {
      return monad::IO<void>::fail(monad::make_error(
          my_errors::GENERAL::INVALID_ARGUMENT,
          "resource materializer callback missing"));
    }
    return fn_(item);
  }

private:
  std::function<monad::IO<void>(const dto::InstallItem &)> fn_;
};

class FunctionExecEnvironmentResolver : public IExecEnvironmentResolver {
public:
  explicit FunctionExecEnvironmentResolver(
      std::function<std::optional<std::unordered_map<std::string, std::string>>(
          const dto::InstallItem &)> fn)
      : fn_(std::move(fn)) {}

  std::optional<std::unordered_map<std::string, std::string>> resolve(
      const dto::InstallItem &item) override {
    if (!fn_) {
      return std::nullopt;
    }
    return fn_(item);
  }

private:
  std::function<std::optional<std::unordered_map<std::string, std::string>>(
      const dto::InstallItem &)> fn_;
};

} // namespace certctrl::install_actions
