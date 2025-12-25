#include "state/device_state_store.hpp"

#include <sqlite3.h>

#include <exception>
#include <filesystem>
#include <fstream>
#include <chrono>
#include <system_error>

namespace {
constexpr const char kAccessTokenKey[] = "access_token";
constexpr const char kRefreshTokenKey[] = "refresh_token";
constexpr const char kExpiresInKey[] = "access_token_expires_in";
constexpr const char kDevicePublicIdKey[] = "device_public_id";
constexpr const char kDeviceFingerprintKey[] = "device_fingerprint_hex";
constexpr const char kInstallConfigKey[] = "install_config_json";
constexpr const char kInstallConfigVersionKey[] = "install_config_version";
constexpr const char kImportCaPrefix[] = "import_ca/ca-";
constexpr const char kImportCaSuffix[] = ".name";
constexpr const char kUpdatesCursorKey[] = "updates_cursor";
constexpr const char kWebsocketResumeTokenKey[] = "websocket_resume_token";
constexpr const char kProcessedSignalsKey[] = "processed_signals_json";

constexpr const char kCreateTableSql[] = R"SQL(
CREATE TABLE IF NOT EXISTS kv_store (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
)SQL";

constexpr const char kCreateLocksTableSql[] = R"SQL(
CREATE TABLE IF NOT EXISTS locks (
  name TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  expires_at_ms INTEGER NOT NULL
);
)SQL";

constexpr const char kUpsertSql[] = R"SQL(
INSERT INTO kv_store(key, value, updated_at)
VALUES(?1, ?2, strftime('%s','now'))
ON CONFLICT(key) DO UPDATE SET
  value = excluded.value,
  updated_at = excluded.updated_at;
)SQL";

constexpr const char kDeleteSql[] = R"SQL(
DELETE FROM kv_store WHERE key = ?1;
)SQL";

constexpr const char kSelectSql[] = R"SQL(
SELECT value FROM kv_store WHERE key = ?1 LIMIT 1;
)SQL";

constexpr const char kTryAcquireLockSql[] = R"SQL(
INSERT INTO locks(name, owner, expires_at_ms)
VALUES(?1, ?2, ?3)
ON CONFLICT(name) DO UPDATE SET
  owner = excluded.owner,
  expires_at_ms = excluded.expires_at_ms
WHERE locks.expires_at_ms <= ?4;
)SQL";

constexpr const char kReleaseLockSql[] = R"SQL(
DELETE FROM locks WHERE name = ?1 AND owner = ?2;
)SQL";

constexpr const char kRefreshLockName[] = "refresh_session";
} // namespace

namespace certctrl {

SqliteDeviceStateStore::SqliteDeviceStateStore(
    certctrl::ICertctrlConfigProvider &config_provider,
    customio::ConsoleOutput &output)
    : config_provider_(config_provider), output_(output) {}

SqliteDeviceStateStore::~SqliteDeviceStateStore() {
  std::scoped_lock lock(mutex_);
  close_db();
}

bool SqliteDeviceStateStore::available() const {
  std::scoped_lock lock(mutex_);
  return initialized_ && db_;
}

std::optional<std::string>
SqliteDeviceStateStore::get_access_token() const {
  std::scoped_lock lock(mutex_);
  if (!ensure_initialized()) {
    return std::nullopt;
  }
  return get_value(kAccessTokenKey);
}

std::optional<std::string>
SqliteDeviceStateStore::get_refresh_token() const {
  std::scoped_lock lock(mutex_);
  if (!ensure_initialized()) {
    return std::nullopt;
  }
  return get_value(kRefreshTokenKey);
}

std::optional<std::string> SqliteDeviceStateStore::save_tokens(
    const std::optional<std::string> &access_token,
    const std::optional<std::string> &refresh_token,
    std::optional<int> expires_in) {
  std::scoped_lock lock(mutex_);
  if (!ensure_initialized()) {
    return std::string{"State database unavailable"};
  }

  auto body = [&]() -> std::optional<std::string> {
    if (access_token) {
      if (auto err = upsert_value(kAccessTokenKey, *access_token)) {
        return err;
      }
    }
    if (refresh_token) {
      if (auto err = upsert_value(kRefreshTokenKey, *refresh_token)) {
        return err;
      }
    }
    if (expires_in) {
      if (auto err = upsert_value(kExpiresInKey,
                                  std::to_string(*expires_in))) {
        return err;
      }
    } else {
      if (auto err = erase_value(kExpiresInKey)) {
        return err;
      }
    }
    return std::nullopt;
  };

  return with_transaction(body);
}

std::optional<std::string>
SqliteDeviceStateStore::clear_tokens() {
  std::scoped_lock lock(mutex_);
  if (!ensure_initialized()) {
    return std::string{"State database unavailable"};
  }
  auto body = [&]() -> std::optional<std::string> {
    if (auto err = erase_value(kAccessTokenKey)) {
      return err;
    }
    if (auto err = erase_value(kRefreshTokenKey)) {
      return err;
    }
    if (auto err = erase_value(kExpiresInKey)) {
      return err;
    }
    return std::nullopt;
  };
  return with_transaction(body);
}

std::optional<std::string>
SqliteDeviceStateStore::get_device_public_id() const {
  std::scoped_lock lock(mutex_);
  if (!ensure_initialized()) {
    return std::nullopt;
  }
  return get_value(kDevicePublicIdKey);
}

std::optional<std::string>
SqliteDeviceStateStore::get_device_fingerprint_hex() const {
  std::scoped_lock lock(mutex_);
  if (!ensure_initialized()) {
    return std::nullopt;
  }
  return get_value(kDeviceFingerprintKey);
}

std::optional<std::string> SqliteDeviceStateStore::save_device_identity(
    const std::optional<std::string> &device_public_id,
    const std::optional<std::string> &fingerprint_hex) {
  std::scoped_lock lock(mutex_);
  if (!ensure_initialized()) {
    return std::string{"State database unavailable"};
  }

  auto body = [&]() -> std::optional<std::string> {
    if (device_public_id && !device_public_id->empty()) {
      if (auto err = upsert_value(kDevicePublicIdKey, *device_public_id)) {
        return err;
      }
    } else {
      if (auto err = erase_value(kDevicePublicIdKey)) {
        return err;
      }
    }

    if (fingerprint_hex && !fingerprint_hex->empty()) {
      if (auto err = upsert_value(kDeviceFingerprintKey, *fingerprint_hex)) {
        return err;
      }
    } else {
      if (auto err = erase_value(kDeviceFingerprintKey)) {
        return err;
      }
    }
    return std::nullopt;
  };

  return with_transaction(body);
}

std::optional<std::string>
SqliteDeviceStateStore::clear_device_identity() {
  std::scoped_lock lock(mutex_);
  if (!ensure_initialized()) {
    return std::string{"State database unavailable"};
  }

  auto body = [&]() -> std::optional<std::string> {
    if (auto err = erase_value(kDevicePublicIdKey)) {
      return err;
    }
    if (auto err = erase_value(kDeviceFingerprintKey)) {
      return err;
    }
    return std::nullopt;
  };

  return with_transaction(body);
}

std::optional<std::string>
SqliteDeviceStateStore::get_install_config_json() const {
  std::scoped_lock lock(mutex_);
  if (!ensure_initialized()) {
    return std::nullopt;
  }
  return get_value(kInstallConfigKey);
}

std::optional<std::int64_t>
SqliteDeviceStateStore::get_install_config_version() const {
  std::scoped_lock lock(mutex_);
  if (!ensure_initialized()) {
    return std::nullopt;
  }
  auto raw = get_value(kInstallConfigVersionKey);
  if (!raw) {
    return std::nullopt;
  }
  return parse_int64(*raw);
}

std::optional<std::string> SqliteDeviceStateStore::save_install_config(
    const std::optional<std::string> &serialized_json,
    std::optional<std::int64_t> version) {
  std::scoped_lock lock(mutex_);
  if (!ensure_initialized()) {
    return std::string{"State database unavailable"};
  }

  auto body = [&]() -> std::optional<std::string> {
    if (serialized_json && !serialized_json->empty()) {
      if (auto err = upsert_value(kInstallConfigKey, *serialized_json)) {
        return err;
      }
    } else {
      if (auto err = erase_value(kInstallConfigKey)) {
        return err;
      }
    }

    if (version) {
      if (auto err =
              upsert_value(kInstallConfigVersionKey, std::to_string(*version))) {
        return err;
      }
    } else {
      if (auto err = erase_value(kInstallConfigVersionKey)) {
        return err;
      }
    }
    return std::nullopt;
  };

  return with_transaction(body);
}

std::optional<std::string>
SqliteDeviceStateStore::clear_install_config() {
  std::scoped_lock lock(mutex_);
  if (!ensure_initialized()) {
    return std::string{"State database unavailable"};
  }
  auto body = [&]() -> std::optional<std::string> {
    if (auto err = erase_value(kInstallConfigKey)) {
      return err;
    }
    if (auto err = erase_value(kInstallConfigVersionKey)) {
      return err;
    }
    return std::nullopt;
  };
  return with_transaction(body);
}

std::optional<std::string>
SqliteDeviceStateStore::get_updates_cursor() const {
  std::scoped_lock lock(mutex_);
  if (!ensure_initialized()) {
    return std::nullopt;
  }
  return get_value(kUpdatesCursorKey);
}

std::optional<std::string> SqliteDeviceStateStore::save_updates_cursor(
    const std::optional<std::string> &cursor) {
  std::scoped_lock lock(mutex_);
  if (!ensure_initialized()) {
    return std::string{"State database unavailable"};
  }

  auto body = [&]() -> std::optional<std::string> {
    if (cursor && !cursor->empty()) {
      return upsert_value(kUpdatesCursorKey, *cursor);
    }
    return erase_value(kUpdatesCursorKey);
  };

  return with_transaction(body);
}

std::optional<std::string>
SqliteDeviceStateStore::get_websocket_resume_token() const {
  std::scoped_lock lock(mutex_);
  if (!ensure_initialized()) {
    return std::nullopt;
  }
  return get_value(kWebsocketResumeTokenKey);
}

std::optional<std::string> SqliteDeviceStateStore::save_websocket_resume_token(
    const std::optional<std::string> &resume_token) {
  std::scoped_lock lock(mutex_);
  if (!ensure_initialized()) {
    return std::string{"State database unavailable"};
  }

  auto body = [&]() -> std::optional<std::string> {
    if (resume_token && !resume_token->empty()) {
      return upsert_value(kWebsocketResumeTokenKey, *resume_token);
    }
    return erase_value(kWebsocketResumeTokenKey);
  };

  return with_transaction(body);
}

std::optional<std::string>
SqliteDeviceStateStore::get_processed_signals_json() const {
  std::scoped_lock lock(mutex_);
  if (!ensure_initialized()) {
    return std::nullopt;
  }
  return get_value(kProcessedSignalsKey);
}

std::optional<std::string> SqliteDeviceStateStore::save_processed_signals_json(
    const std::optional<std::string> &serialized_json) {
  std::scoped_lock lock(mutex_);
  if (!ensure_initialized()) {
    return std::string{"State database unavailable"};
  }

  auto body = [&]() -> std::optional<std::string> {
    if (serialized_json && !serialized_json->empty()) {
      return upsert_value(kProcessedSignalsKey, *serialized_json);
    }
    return erase_value(kProcessedSignalsKey);
  };

  return with_transaction(body);
}

std::optional<std::string>
SqliteDeviceStateStore::get_imported_ca_name(std::int64_t ca_id) const {
  std::scoped_lock lock(mutex_);
  if (!ensure_initialized()) {
    return std::nullopt;
  }
  return get_value(import_ca_key(ca_id));
}

std::optional<std::string> SqliteDeviceStateStore::set_imported_ca_name(
    std::int64_t ca_id, const std::optional<std::string> &canonical_name) {
  std::scoped_lock lock(mutex_);
  if (!ensure_initialized()) {
    return std::string{"State database unavailable"};
  }
  auto body = [&]() -> std::optional<std::string> {
    const auto key = import_ca_key(ca_id);
    if (canonical_name && !canonical_name->empty()) {
      return upsert_value(key, *canonical_name);
    }
    return erase_value(key);
  };
  return with_transaction(body);
}

std::optional<std::string>
SqliteDeviceStateStore::clear_imported_ca_name(std::int64_t ca_id) {
  std::scoped_lock lock(mutex_);
  if (!ensure_initialized()) {
    return std::string{"State database unavailable"};
  }
  auto key = import_ca_key(ca_id);
  return with_transaction([&]() { return erase_value(key); });
}

bool SqliteDeviceStateStore::ensure_initialized() const {
  if (initialized_) {
    return db_ != nullptr;
  }

  const auto runtime_dir = config_provider_.get().runtime_dir;
  if (runtime_dir.empty()) {
    output_.logger().warning()
        << "DeviceStateStore disabled: runtime_dir not configured"
        << std::endl;
    initialized_ = true;
    return false;
  }

  auto state_dir = runtime_dir / "state";
  std::error_code ec;
  std::filesystem::create_directories(state_dir, ec);
  if (ec) {
    output_.logger().error()
        << "Failed to create state directory '" << state_dir
        << "': " << ec.message() << std::endl;
    initialized_ = true;
    return false;
  }

  db_path_ = state_dir / "session_state.db";
  int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX;
  if (sqlite3_open_v2(db_path_.string().c_str(), &db_, flags, nullptr) !=
      SQLITE_OK) {
    output_.logger().error()
        << "Failed to open session_state.db: "
        << sqlite3_errmsg(db_) << std::endl;
    close_db();
    initialized_ = true;
    return false;
  }

  sqlite3_busy_timeout(db_, 5000);
  char *errmsg = nullptr;
  if (sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr,
                   &errmsg) != SQLITE_OK) {
    output_.logger().warning()
        << "Failed to enable WAL mode: " << (errmsg ? errmsg : "unknown")
        << std::endl;
    sqlite3_free(errmsg);
  }
  if (sqlite3_exec(db_, "PRAGMA synchronous=NORMAL;", nullptr, nullptr,
                   &errmsg) != SQLITE_OK) {
    output_.logger().warning()
        << "Failed to set synchronous=NORMAL: "
        << (errmsg ? errmsg : "unknown") << std::endl;
    sqlite3_free(errmsg);
  }
  if (sqlite3_exec(db_, kCreateTableSql, nullptr, nullptr, &errmsg) !=
      SQLITE_OK) {
    output_.logger().error() << "Failed to initialize kv_store table: "
                             << (errmsg ? errmsg : "unknown") << std::endl;
    sqlite3_free(errmsg);
    close_db();
    initialized_ = true;
    return false;
  }

  if (sqlite3_exec(db_, kCreateLocksTableSql, nullptr, nullptr, &errmsg) !=
      SQLITE_OK) {
    output_.logger().error() << "Failed to initialize locks table: "
                             << (errmsg ? errmsg : "unknown") << std::endl;
    sqlite3_free(errmsg);
    close_db();
    initialized_ = true;
    return false;
  }

  migrate_legacy_state_if_present();
  initialized_ = true;
  return true;
}

std::pair<bool, std::optional<std::string>>
SqliteDeviceStateStore::try_acquire_refresh_lock(const std::string &owner,
                                                 std::chrono::milliseconds ttl) {
  std::scoped_lock lock(mutex_);
  if (!ensure_initialized()) {
    return {false, std::string{"State database unavailable"}};
  }

  const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();
  const auto expires_ms = now_ms + static_cast<std::int64_t>(ttl.count());

  bool acquired = false;
  auto body = [&]() -> std::optional<std::string> {
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db_, kTryAcquireLockSql, -1, &stmt, nullptr) !=
        SQLITE_OK) {
      return std::string{"Failed to prepare lock acquire statement"};
    }
    sqlite3_bind_text(stmt, 1, kRefreshLockName, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, owner.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, static_cast<sqlite3_int64>(expires_ms));
    sqlite3_bind_int64(stmt, 4, static_cast<sqlite3_int64>(now_ms));
    const int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
      return std::string{"Failed to execute lock acquire statement"};
    }

    acquired = sqlite3_changes(db_) > 0;
    return std::nullopt;
  };

  if (auto err = with_transaction(body)) {
    return {false, err};
  }

  return {acquired, std::nullopt};
}

std::optional<std::string>
SqliteDeviceStateStore::release_refresh_lock(const std::string &owner) {
  std::scoped_lock lock(mutex_);
  if (!ensure_initialized()) {
    return std::string{"State database unavailable"};
  }

  auto body = [&]() -> std::optional<std::string> {
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db_, kReleaseLockSql, -1, &stmt, nullptr) !=
        SQLITE_OK) {
      return std::string{"Failed to prepare lock release statement"};
    }
    sqlite3_bind_text(stmt, 1, kRefreshLockName, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, owner.c_str(), -1, SQLITE_TRANSIENT);
    const int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
      return std::string{"Failed to execute lock release statement"};
    }
    return std::nullopt;
  };

  return with_transaction(body);
}

void SqliteDeviceStateStore::migrate_legacy_state_if_present() const {
  if (legacy_checked_ || db_path_.empty()) {
    return;
  }

  const auto runtime_dir = config_provider_.get().runtime_dir;
  if (runtime_dir.empty()) {
    legacy_checked_ = true;
    return;
  }

  const auto state_dir = runtime_dir / "state";

  auto migrate_tokens = [&]() {
    const auto access_path = state_dir / "access_token.txt";
    const auto refresh_path = state_dir / "refresh_token.txt";
    auto legacy_access = read_trimmed_file(access_path);
    auto legacy_refresh = read_trimmed_file(refresh_path);
    auto current_access = get_value(kAccessTokenKey);
    auto current_refresh = get_value(kRefreshTokenKey);
    const bool need_access = legacy_access && !current_access;
    const bool need_refresh = legacy_refresh && !current_refresh;
    if (!need_access && !need_refresh) {
      return;
    }

    auto err = with_transaction([&]() -> std::optional<std::string> {
      if (need_access) {
        if (auto upsert_err = upsert_value(kAccessTokenKey, *legacy_access)) {
          return upsert_err;
        }
      }
      if (need_refresh) {
        if (auto upsert_err = upsert_value(kRefreshTokenKey, *legacy_refresh)) {
          return upsert_err;
        }
      }
      return std::nullopt;
    });

    if (err) {
      output_.logger().warning()
          << "Failed to migrate legacy session tokens: " << *err << std::endl;
      return;
    }

    std::error_code remove_ec;
    if (need_access) {
      std::filesystem::remove(access_path, remove_ec);
    }
    if (need_refresh) {
      std::filesystem::remove(refresh_path, remove_ec);
    }
  };

  auto migrate_device_identity = [&]() {
    const auto device_id_path = state_dir / "device_public_id.txt";
    const auto fingerprint_path = state_dir / "device_fingerprint_hex.txt";
    auto legacy_device_id = read_trimmed_file(device_id_path);
    auto legacy_fingerprint = read_trimmed_file(fingerprint_path);
    auto current_device_id = get_value(kDevicePublicIdKey);
    auto current_fingerprint = get_value(kDeviceFingerprintKey);
    const bool need_device_id = legacy_device_id && !current_device_id;
    const bool need_fingerprint = legacy_fingerprint && !current_fingerprint;
    if (!need_device_id && !need_fingerprint) {
      return;
    }

    auto err = with_transaction([&]() -> std::optional<std::string> {
      if (need_device_id) {
        if (auto upsert_err =
                upsert_value(kDevicePublicIdKey, *legacy_device_id)) {
          return upsert_err;
        }
      }
      if (need_fingerprint) {
        if (auto upsert_err =
                upsert_value(kDeviceFingerprintKey, *legacy_fingerprint)) {
          return upsert_err;
        }
      }
      return std::nullopt;
    });

    if (err) {
      output_.logger().warning()
          << "Failed to migrate legacy device identity: " << *err << std::endl;
      return;
    }

    std::error_code remove_ec;
    if (need_device_id) {
      std::filesystem::remove(device_id_path, remove_ec);
    }
    if (need_fingerprint) {
      std::filesystem::remove(fingerprint_path, remove_ec);
    }
  };

  auto migrate_install_config = [&]() {
    const auto config_path = state_dir / "install_config.json";
    const auto version_path = state_dir / "install_version.txt";
    auto legacy_config = read_file_contents(config_path);
    auto legacy_version = read_trimmed_file(version_path);
    auto current_config = get_value(kInstallConfigKey);
    auto current_version = get_value(kInstallConfigVersionKey);
    const bool need_config = legacy_config && !legacy_config->empty() &&
                             !current_config;
    const bool need_version = legacy_version && !current_version;
    if (!need_config && !need_version) {
      return;
    }

    auto err = with_transaction([&]() -> std::optional<std::string> {
      if (need_config) {
        if (auto upsert_err = upsert_value(kInstallConfigKey, *legacy_config)) {
          return upsert_err;
        }
      }
      if (need_version) {
        if (auto upsert_err =
                upsert_value(kInstallConfigVersionKey, *legacy_version)) {
          return upsert_err;
        }
      }
      return std::nullopt;
    });

    if (err) {
      output_.logger().warning()
          << "Failed to migrate install_config cache: " << *err << std::endl;
      return;
    }

    std::error_code remove_ec;
    if (need_config) {
      std::filesystem::remove(config_path, remove_ec);
    }
    if (need_version) {
      std::filesystem::remove(version_path, remove_ec);
    }
  };

  auto migrate_updates_cursor = [&]() {
    const auto cursor_path = state_dir / "last_cursor.txt";
    auto legacy_cursor = read_trimmed_file(cursor_path);
    auto current_cursor = get_value(kUpdatesCursorKey);
    const bool need_cursor = legacy_cursor && !legacy_cursor->empty() && !current_cursor;
    if (!need_cursor) {
      return;
    }

    auto err = with_transaction([&]() -> std::optional<std::string> {
      return upsert_value(kUpdatesCursorKey, *legacy_cursor);
    });

    if (err) {
      output_.logger().warning()
          << "Failed to migrate legacy updates cursor: " << *err << std::endl;
      return;
    }

    std::error_code remove_ec;
    std::filesystem::remove(cursor_path, remove_ec);
  };

  auto migrate_processed_signals = [&]() {
    const auto signals_path = state_dir / "processed_signals.json";
    auto legacy_signals = read_file_contents(signals_path);
    auto current_signals = get_value(kProcessedSignalsKey);
    const bool need_signals = legacy_signals && !legacy_signals->empty() && !current_signals;
    if (!need_signals) {
      return;
    }

    auto err = with_transaction([&]() -> std::optional<std::string> {
      return upsert_value(kProcessedSignalsKey, *legacy_signals);
    });

    if (err) {
      output_.logger().warning()
          << "Failed to migrate processed signals history: " << *err
          << std::endl;
      return;
    }

    std::error_code remove_ec;
    std::filesystem::remove(signals_path, remove_ec);
  };

  auto migrate_imported_cas = [&]() {
    const auto import_dir = state_dir / "import_ca";
    std::error_code exists_ec;
    if (!std::filesystem::exists(import_dir, exists_ec) || exists_ec) {
      return;
    }

    const std::string suffix(kImportCaSuffix);
    std::error_code iter_ec;
    for (std::filesystem::directory_iterator it(import_dir, iter_ec);
         !iter_ec && it != std::filesystem::directory_iterator(); ++it) {
      const auto &entry = *it;
      if (!entry.is_regular_file()) {
        continue;
      }
      auto filename = entry.path().filename().string();
      auto suffix_pos = filename.rfind(suffix);
      if (suffix_pos == std::string::npos ||
          suffix_pos + suffix.size() != filename.size() ||
          filename.rfind("ca-", 0) != 0) {
        continue;
      }
      auto id_str = filename.substr(3, suffix_pos - 3);
      std::int64_t ca_id = 0;
      try {
        if (id_str.empty()) {
          continue;
        }
        ca_id = std::stoll(id_str);
      } catch (...) {
        continue;
      }

      auto canonical = read_trimmed_file(entry.path());
      if (!canonical) {
        continue;
      }

      if (get_value(import_ca_key(ca_id))) {
        continue;
      }

      auto err = with_transaction([&]() -> std::optional<std::string> {
        return upsert_value(import_ca_key(ca_id), *canonical);
      });

      if (err) {
        output_.logger().warning()
          << "Failed to migrate import_ca state for CA " << ca_id
          << ": " << *err << std::endl;
        continue;
      }

      std::error_code remove_ec;
      std::filesystem::remove(entry.path(), remove_ec);
    }

    if (iter_ec) {
      output_.logger().warning()
          << "Failed to enumerate import_ca directory: " << iter_ec.message()
          << std::endl;
    } else {
      std::error_code empty_ec;
      const bool dir_empty = std::filesystem::is_empty(import_dir, empty_ec);
      if (!empty_ec && dir_empty) {
        std::filesystem::remove(import_dir, empty_ec);
      }
    }
  };

  migrate_tokens();
  migrate_device_identity();
  migrate_install_config();
  migrate_updates_cursor();
  migrate_processed_signals();
  migrate_imported_cas();

  legacy_checked_ = true;
}

void SqliteDeviceStateStore::close_db() const {
  if (db_) {
    sqlite3_close(db_);
    db_ = nullptr;
  }
}

std::optional<std::string>
SqliteDeviceStateStore::get_value(const std::string &key) const {
  if (!db_) {
    return std::nullopt;
  }
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db_, kSelectSql, -1, &stmt, nullptr) != SQLITE_OK) {
    return std::nullopt;
  }
  sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
  std::optional<std::string> result;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    const unsigned char *text = sqlite3_column_text(stmt, 0);
    if (text) {
      result = reinterpret_cast<const char *>(text);
    }
  }
  sqlite3_finalize(stmt);
  return result;
}

std::optional<std::string>
SqliteDeviceStateStore::upsert_value(const std::string &key,
                                     const std::string &value) const {
  if (!db_) {
    return std::string{"State database unavailable"};
  }
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db_, kUpsertSql, -1, &stmt, nullptr) != SQLITE_OK) {
    return std::string{"Failed to prepare upsert statement"};
  }
  sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, value.c_str(), -1, SQLITE_TRANSIENT);
  int rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  if (rc != SQLITE_DONE) {
    return std::string{"Failed to upsert value for key "} + key;
  }
  return std::nullopt;
}

std::optional<std::string>
SqliteDeviceStateStore::erase_value(const std::string &key) const {
  if (!db_) {
    return std::string{"State database unavailable"};
  }
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db_, kDeleteSql, -1, &stmt, nullptr) != SQLITE_OK) {
    return std::string{"Failed to prepare delete statement"};
  }
  sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
  int rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  if (rc != SQLITE_DONE) {
    return std::string{"Failed to delete key "} + key;
  }
  return std::nullopt;
}

std::optional<std::string> SqliteDeviceStateStore::with_transaction(
  const std::function<std::optional<std::string>()> &body) const {
  if (!db_) {
    return std::string{"State database unavailable"};
  }
  char *errmsg = nullptr;
  if (sqlite3_exec(db_, "BEGIN IMMEDIATE TRANSACTION;", nullptr, nullptr,
                   &errmsg) != SQLITE_OK) {
    std::string err = errmsg ? errmsg : "Failed to begin transaction";
    sqlite3_free(errmsg);
    return err;
  }

  auto body_err = body();
  if (body_err) {
    sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
    return body_err;
  }

  if (sqlite3_exec(db_, "COMMIT;", nullptr, nullptr, &errmsg) != SQLITE_OK) {
    std::string err = errmsg ? errmsg : "Failed to commit transaction";
    sqlite3_free(errmsg);
    sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
    return err;
  }
  return std::nullopt;
}

std::optional<std::string> SqliteDeviceStateStore::read_trimmed_file(
    const std::filesystem::path &path) {
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
  auto trimmed = contents.substr(first, last - first + 1);
  if (trimmed.empty()) {
    return std::nullopt;
  }
  return trimmed;
}

std::optional<std::string>
SqliteDeviceStateStore::read_file_contents(const std::filesystem::path &path) {
  std::ifstream ifs(path, std::ios::binary);
  if (!ifs.is_open()) {
    return std::nullopt;
  }
  return std::string((std::istreambuf_iterator<char>(ifs)),
                     std::istreambuf_iterator<char>());
}

std::string SqliteDeviceStateStore::import_ca_key(std::int64_t ca_id) const {
  std::string key;
  key.reserve(std::string(kImportCaPrefix).size() + 24 +
              std::string(kImportCaSuffix).size());
  key.append(kImportCaPrefix);
  key.append(std::to_string(ca_id));
  key.append(kImportCaSuffix);
  return key;
}

std::optional<std::int64_t>
SqliteDeviceStateStore::parse_int64(const std::string &value) const {
  if (value.empty()) {
    return std::nullopt;
  }
  try {
    size_t idx = 0;
    auto parsed = std::stoll(value, &idx, 10);
    if (idx != value.size()) {
      output_.logger().warning()
          << "Ignoring malformed integer value stored in session_state.db: '"
          << value << "'" << std::endl;
      return std::nullopt;
    }
    return static_cast<std::int64_t>(parsed);
  } catch (const std::exception &ex) {
    output_.logger().warning()
        << "Failed to parse integer stored in session_state.db: '" << value
        << "' (" << ex.what() << ')'
        << std::endl;
    return std::nullopt;
  }
}

} // namespace certctrl
