#pragma once

#include <cstdint>
#include <functional> // IWYU pragma: keep
#include <filesystem> // IWYU pragma: keep
#include <mutex> // IWYU pragma: keep
#include <optional>
#include <string>

#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"

struct sqlite3;

namespace certctrl {

class IDeviceStateStore {
public:
  virtual ~IDeviceStateStore() = default;

  virtual std::optional<std::string> get_access_token() const = 0;
  virtual std::optional<std::string> get_refresh_token() const = 0;

  virtual std::optional<std::string>
  save_tokens(const std::optional<std::string> &access_token,
              const std::optional<std::string> &refresh_token,
              std::optional<int> expires_in = std::nullopt) = 0;

  virtual std::optional<std::string> clear_tokens() = 0;

  virtual std::optional<std::string> get_device_public_id() const = 0;
  virtual std::optional<std::string> get_device_fingerprint_hex() const = 0;
  virtual std::optional<std::string>
  save_device_identity(const std::optional<std::string> &device_public_id,
                       const std::optional<std::string> &fingerprint_hex) = 0;
  virtual std::optional<std::string> clear_device_identity() = 0;

  virtual std::optional<std::string> get_install_config_json() const = 0;
  virtual std::optional<std::int64_t> get_install_config_version() const = 0;
  virtual std::optional<std::string>
  save_install_config(const std::optional<std::string> &serialized_json,
                      std::optional<std::int64_t> version) = 0;
  virtual std::optional<std::string> clear_install_config() = 0;

  virtual std::optional<std::string>
  get_imported_ca_name(std::int64_t ca_id) const = 0;
  virtual std::optional<std::string>
  set_imported_ca_name(std::int64_t ca_id,
                       const std::optional<std::string> &canonical_name) = 0;
  virtual std::optional<std::string>
  clear_imported_ca_name(std::int64_t ca_id) = 0;

  virtual bool available() const = 0;
};

class SqliteDeviceStateStore : public IDeviceStateStore {
public:
  SqliteDeviceStateStore(certctrl::ICertctrlConfigProvider &config_provider,
                         customio::ConsoleOutput &output);
  ~SqliteDeviceStateStore() override;

  std::optional<std::string> get_access_token() const override;
  std::optional<std::string> get_refresh_token() const override;
  std::optional<std::string>
  save_tokens(const std::optional<std::string> &access_token,
              const std::optional<std::string> &refresh_token,
              std::optional<int> expires_in = std::nullopt) override;
  std::optional<std::string> clear_tokens() override;
  std::optional<std::string> get_device_public_id() const override;
  std::optional<std::string> get_device_fingerprint_hex() const override;
  std::optional<std::string>
  save_device_identity(const std::optional<std::string> &device_public_id,
                       const std::optional<std::string> &fingerprint_hex) override;
  std::optional<std::string> clear_device_identity() override;
  std::optional<std::string> get_install_config_json() const override;
  std::optional<std::int64_t> get_install_config_version() const override;
  std::optional<std::string>
  save_install_config(const std::optional<std::string> &serialized_json,
                      std::optional<std::int64_t> version) override;
  std::optional<std::string> clear_install_config() override;
  std::optional<std::string>
  get_imported_ca_name(std::int64_t ca_id) const override;
  std::optional<std::string>
  set_imported_ca_name(std::int64_t ca_id,
                       const std::optional<std::string> &canonical_name) override;
  std::optional<std::string>
  clear_imported_ca_name(std::int64_t ca_id) override;
  bool available() const override;

private:
  bool ensure_initialized() const;
  void migrate_legacy_state_if_present() const;
  void close_db() const;
  std::string import_ca_key(std::int64_t ca_id) const;
  std::optional<std::int64_t> parse_int64(const std::string &value) const;

  std::optional<std::string> get_value(const std::string &key) const;
  std::optional<std::string> upsert_value(const std::string &key,
                                          const std::string &value) const;
  std::optional<std::string> erase_value(const std::string &key) const;

  std::optional<std::string>
  with_transaction(const std::function<std::optional<std::string>()> &body) const;

  static std::optional<std::string>
  read_trimmed_file(const std::filesystem::path &path);
  static std::optional<std::string>
  read_file_contents(const std::filesystem::path &path);

  certctrl::ICertctrlConfigProvider &config_provider_;
  customio::ConsoleOutput &output_;
  mutable std::mutex mutex_;
  mutable std::filesystem::path db_path_;
  mutable sqlite3 *db_{nullptr};
  mutable bool initialized_{false};
  mutable bool legacy_checked_{false};
};

} // namespace certctrl
