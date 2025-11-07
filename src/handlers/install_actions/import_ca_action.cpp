#include "handlers/install_actions/import_ca_action.hpp"

#include <cctype>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fmt/format.h>
#include <fstream>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#ifdef _WIN32
#include <wincrypt.h>
#include <windows.h>
#elif defined(__APPLE__)
#include "base64.h"
#include <Security/Security.h>
#endif

#include <boost/json/serialize.hpp>

#include "my_error_codes.hpp"
#include "result_monad.hpp"
#include "util/browser_trust_sync.hpp"
#include "util/my_logging.hpp"

namespace certctrl::install_actions {

ImportCaActionHandler::ImportCaActionHandler(
    certctrl::ICertctrlConfigProvider &config_provider,
    customio::ConsoleOutput &output,
    install_actions::IResourceMaterializer::Factory
        resource_materializer_factory)
    : config_provider_(config_provider), output_(output),
      runtime_dir_(config_provider.get().runtime_dir),
      resource_materializer_factory_(std::move(resource_materializer_factory)) {
}

namespace {

struct TrustStoreTarget {
  std::filesystem::path directory;
  std::string update_command;
  std::string description;
  bool use_native_mac_import{false};
};

std::string sanitize_label(std::string_view raw_label,
                           std::int64_t fallback_id) {
  std::string sanitized;
  sanitized.reserve(raw_label.size());
  for (char ch : raw_label) {
    unsigned char uch = static_cast<unsigned char>(ch);
    if (std::isalnum(uch)) {
      sanitized.push_back(static_cast<char>(std::tolower(uch)));
    } else if (ch == '-' || ch == '_' || ch == '.') {
      sanitized.push_back(ch);
    } else {
      sanitized.push_back('-');
    }
  }
  while (!sanitized.empty() && sanitized.front() == '-') {
    sanitized.erase(sanitized.begin());
  }
  while (!sanitized.empty() && sanitized.back() == '-') {
    sanitized.pop_back();
  }
  if (sanitized.empty()) {
    sanitized = fmt::format("ca-{}", fallback_id);
  }
  return sanitized;
}

std::filesystem::perms desired_public_permissions() {
#ifdef _WIN32
  return std::filesystem::perms::owner_all;
#else
  return std::filesystem::perms::owner_read |
         std::filesystem::perms::owner_write |
         std::filesystem::perms::group_read |
         std::filesystem::perms::others_read;
#endif
}

std::filesystem::perms default_directory_perms() {
#ifdef _WIN32
  return std::filesystem::perms::owner_all;
#else
  return std::filesystem::perms::owner_read |
         std::filesystem::perms::owner_write |
         std::filesystem::perms::owner_exec |
         std::filesystem::perms::group_read |
         std::filesystem::perms::group_exec;
#endif
}

std::string generate_temp_suffix() {
  auto now = std::chrono::steady_clock::now().time_since_epoch().count();
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<std::uint64_t> dist;
  std::uint64_t random_part = dist(gen);
  return fmt::format("{}.{}", now, random_part);
}

std::optional<std::string>
copy_ca_material(const std::filesystem::path &source,
                 const std::filesystem::path &destination) {
  try {
    BOOST_LOG_SEV(app_logger(), trivial::trace)
        << "copy_ca_material start source='" << source << "' destination='"
        << destination << "'";
    if (!std::filesystem::exists(source)) {
      BOOST_LOG_SEV(app_logger(), trivial::error)
          << "copy_ca_material missing source: " << source;
      return fmt::format("CA source '{}' not found", source.string());
    }

    auto parent = destination.parent_path();
    if (!parent.empty()) {
      std::filesystem::create_directories(parent);
#ifndef _WIN32
      std::filesystem::permissions(parent, default_directory_perms(),
                                   std::filesystem::perm_options::add);
#endif
    }

    auto temp_dest = destination;
    temp_dest += ".tmp-";
    temp_dest += generate_temp_suffix();

    std::filesystem::copy_file(
        source, temp_dest, std::filesystem::copy_options::overwrite_existing);

#ifndef _WIN32
    std::filesystem::permissions(temp_dest, desired_public_permissions(),
                                 std::filesystem::perm_options::replace);
#endif

    if (std::filesystem::exists(destination)) {
      auto backup_dir = parent / ".backups";
      std::error_code mk_ec;
      std::filesystem::create_directories(backup_dir, mk_ec);
      auto backup = backup_dir / destination.filename();
      backup += ".bak";
      backup += generate_temp_suffix();
      std::error_code ec;
      std::filesystem::rename(destination, backup, ec);
    }

    std::filesystem::rename(temp_dest, destination);

#ifndef _WIN32
    std::filesystem::permissions(destination, desired_public_permissions(),
                                 std::filesystem::perm_options::replace);
#endif

    BOOST_LOG_SEV(app_logger(), trivial::trace)
        << "copy_ca_material finished source='" << source << "' destination='"
        << destination << "'";
    return std::nullopt;
  } catch (const std::exception &ex) {
    BOOST_LOG_SEV(app_logger(), trivial::error)
        << "copy_ca_material exception: " << ex.what();
    return ex.what();
  }
}

#if defined(__APPLE__)

template <typename T>
using CfPtr = std::unique_ptr<std::remove_pointer_t<T>, decltype(&CFRelease)>;

std::string cf_string_to_std(CFStringRef cf_string) {
  if (!cf_string) {
    return {};
  }

  auto length = CFStringGetLength(cf_string);
  auto max_size =
      CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;
  if (max_size <= 1) {
    return {};
  }

  std::string buffer(static_cast<std::size_t>(max_size), '\0');
  if (CFStringGetCString(cf_string, buffer.data(), buffer.size(),
                         kCFStringEncodingUTF8)) {
    buffer.resize(std::strlen(buffer.c_str()));
    return buffer;
  }

  return {};
}

std::string describe_osstatus(OSStatus status) {
  CfPtr<CFStringRef> message(SecCopyErrorMessageString(status, nullptr),
                             &CFRelease);
  if (message) {
    auto text = cf_string_to_std(message.get());
    if (!text.empty()) {
      return text;
    }
  }

  return fmt::format("OSStatus({})", status);
}

std::optional<std::string>
load_first_certificate_der(const std::filesystem::path &pem_path,
                           std::string &der_out) {
  std::ifstream ifs(pem_path);
  if (!ifs.is_open()) {
    return fmt::format("failed to open certificate '{}'", pem_path.string());
  }

  bool inside_block = false;
  std::string base64_payload;
  std::string line;
  while (std::getline(ifs, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    if (!inside_block &&
        line.find("-----BEGIN CERTIFICATE-----") != std::string::npos) {
      inside_block = true;
      continue;
    }
    if (inside_block &&
        line.find("-----END CERTIFICATE-----") != std::string::npos) {
      break;
    }
    if (inside_block) {
      for (char ch : line) {
        if (!std::isspace(static_cast<unsigned char>(ch))) {
          base64_payload.push_back(ch);
        }
      }
    }
  }

  if (base64_payload.empty()) {
    return fmt::format("no PEM certificate block found in '{}'",
                       pem_path.string());
  }

  std::string der;
  try {
    der = base64_decode(base64_payload, false);
  } catch (const std::exception &ex) {
    return fmt::format("failed to decode certificate data from '{}': {}",
                       pem_path.string(), ex.what());
  }

  if (der.empty()) {
    return fmt::format("decoded certificate data from '{}' is empty",
                       pem_path.string());
  }

  der_out = std::move(der);
  return std::nullopt;
}

std::optional<std::string>
import_certificate_to_system_keychain(const std::filesystem::path &pem_path,
                                      const std::string &label) {
  std::string der;
  if (auto err = load_first_certificate_der(pem_path, der)) {
    return err;
  }

  CfPtr<CFDataRef> der_data(
      CFDataCreate(kCFAllocatorDefault,
                   reinterpret_cast<const UInt8 *>(der.data()),
                   static_cast<CFIndex>(der.size())),
      &CFRelease);
  if (!der_data) {
    return fmt::format("failed to create CFData for '{}'", pem_path.string());
  }

  CfPtr<SecCertificateRef> certificate(
      SecCertificateCreateWithData(nullptr, der_data.get()), &CFRelease);
  if (!certificate) {
    return fmt::format("SecCertificateCreateWithData failed for '{}'",
                       pem_path.string());
  }

  SecKeychainRef keychain_raw = nullptr;
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif
  OSStatus status =
      SecKeychainCopyDomainDefault(kSecPreferencesDomainSystem, &keychain_raw);
#if defined(__clang__)
#pragma clang diagnostic pop
#endif
  if (status != errSecSuccess) {
    return fmt::format("SecKeychainCopyDomainDefault failed: {}",
                       describe_osstatus(status));
  }

  CfPtr<SecKeychainRef> keychain(keychain_raw, &CFRelease);

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif
  status = SecKeychainUnlock(keychain.get(), 0, nullptr, true);
#if defined(__clang__)
#pragma clang diagnostic pop
#endif
  if (status != errSecSuccess) {
    BOOST_LOG_SEV(app_logger(), trivial::warning)
        << "macOS trust import: SecKeychainUnlock failed with "
        << describe_osstatus(status) << ". Proceeding without explicit unlock.";
  }

  CfPtr<CFStringRef> label_ref(
      CFStringCreateWithCString(nullptr, label.c_str(), kCFStringEncodingUTF8),
      &CFRelease);
  if (!label_ref) {
    return fmt::format("failed to allocate label '{}'", label);
  }

  CfPtr<CFMutableDictionaryRef> delete_query(
      CFDictionaryCreateMutable(nullptr, 0, &kCFTypeDictionaryKeyCallBacks,
                                &kCFTypeDictionaryValueCallBacks),
      &CFRelease);
  CFDictionarySetValue(delete_query.get(), kSecClass, kSecClassCertificate);
  CFDictionarySetValue(delete_query.get(), kSecAttrLabel, label_ref.get());
  CFDictionarySetValue(delete_query.get(), kSecUseKeychain, keychain.get());
  OSStatus delete_status = SecItemDelete(delete_query.get());
  if (delete_status != errSecSuccess && delete_status != errSecItemNotFound) {
    BOOST_LOG_SEV(app_logger(), trivial::warning)
        << "macOS trust import: SecItemDelete for label '" << label
        << "' returned " << describe_osstatus(delete_status);
  }

  CfPtr<CFMutableDictionaryRef> add_query(
      CFDictionaryCreateMutable(nullptr, 0, &kCFTypeDictionaryKeyCallBacks,
                                &kCFTypeDictionaryValueCallBacks),
      &CFRelease);
  CFDictionarySetValue(add_query.get(), kSecClass, kSecClassCertificate);
  CFDictionarySetValue(add_query.get(), kSecValueRef, certificate.get());
  CFDictionarySetValue(add_query.get(), kSecAttrLabel, label_ref.get());
  CFDictionarySetValue(add_query.get(), kSecUseKeychain, keychain.get());

  status = SecItemAdd(add_query.get(), nullptr);
  if (status != errSecSuccess && status != errSecDuplicateItem) {
    return fmt::format("SecItemAdd failed: {}", describe_osstatus(status));
  }

  SecCertificateRef active_certificate = certificate.get();
  CfPtr<SecCertificateRef> fetched_certificate(nullptr, &CFRelease);

  if (status == errSecDuplicateItem) {
    CfPtr<CFMutableDictionaryRef> fetch_query(
        CFDictionaryCreateMutable(nullptr, 0, &kCFTypeDictionaryKeyCallBacks,
                                  &kCFTypeDictionaryValueCallBacks),
        &CFRelease);
    CFDictionarySetValue(fetch_query.get(), kSecClass, kSecClassCertificate);
    CFDictionarySetValue(fetch_query.get(), kSecAttrLabel, label_ref.get());
    CFDictionarySetValue(fetch_query.get(), kSecUseKeychain, keychain.get());
    CFDictionarySetValue(fetch_query.get(), kSecReturnRef, kCFBooleanTrue);

    CFTypeRef fetched_ref = nullptr;
    OSStatus fetch_status =
        SecItemCopyMatching(fetch_query.get(), &fetched_ref);
    if (fetch_status != errSecSuccess || !fetched_ref) {
      return fmt::format(
          "SecItemCopyMatching failed while resolving existing certificate: {}",
          describe_osstatus(fetch_status));
    }
    auto mutable_ref = const_cast<void *>(fetched_ref);
    fetched_certificate.reset(static_cast<SecCertificateRef>(mutable_ref));
    active_certificate = fetched_certificate.get();
  }

  {
    CfPtr<CFMutableDictionaryRef> update_query(
        CFDictionaryCreateMutable(nullptr, 0, &kCFTypeDictionaryKeyCallBacks,
                                  &kCFTypeDictionaryValueCallBacks),
        &CFRelease);
    CfPtr<CFMutableDictionaryRef> update_attrs(
        CFDictionaryCreateMutable(nullptr, 0, &kCFTypeDictionaryKeyCallBacks,
                                  &kCFTypeDictionaryValueCallBacks),
        &CFRelease);
    CFDictionarySetValue(update_query.get(), kSecValueRef, active_certificate);
    CFDictionarySetValue(update_attrs.get(), kSecAttrLabel, label_ref.get());
    OSStatus update_status =
        SecItemUpdate(update_query.get(), update_attrs.get());
    if (update_status != errSecSuccess) {
      BOOST_LOG_SEV(app_logger(), trivial::warning)
          << "macOS trust import: SecItemUpdate for label '" << label
          << "' returned " << describe_osstatus(update_status);
    }
  }

  SecTrustSettingsRemoveTrustSettings(active_certificate,
                                      kSecTrustSettingsDomainAdmin);

  SecTrustSettingsResult trust_result = kSecTrustSettingsResultTrustRoot;
  CfPtr<CFNumberRef> trust_number(
      CFNumberCreate(nullptr, kCFNumberIntType, &trust_result), &CFRelease);
  if (!trust_number) {
    return "CFNumberCreate failed while preparing trust settings";
  }
  const void *trust_keys[] = {kSecTrustSettingsResult};
  const void *trust_values[] = {trust_number.get()};
  CfPtr<CFDictionaryRef> trust_dict(
      CFDictionaryCreate(nullptr, trust_keys, trust_values, 1,
                         &kCFTypeDictionaryKeyCallBacks,
                         &kCFTypeDictionaryValueCallBacks),
      &CFRelease);
  if (!trust_dict) {
    return "CFDictionaryCreate failed while preparing trust settings";
  }
  const void *trust_array_entries[] = {trust_dict.get()};
  CfPtr<CFArrayRef> trust_array(
      CFArrayCreate(nullptr, trust_array_entries, 1, &kCFTypeArrayCallBacks),
      &CFRelease);
  if (!trust_array) {
    return "CFArrayCreate failed while preparing trust settings";
  }

  status = SecTrustSettingsSetTrustSettings(
      active_certificate, kSecTrustSettingsDomainAdmin, trust_array.get());
  if (status != errSecSuccess) {
    return fmt::format("SecTrustSettingsSetTrustSettings failed: {}",
                       describe_osstatus(status));
  }

  return std::nullopt;
}

#endif // defined(__APPLE__)

std::optional<TrustStoreTarget> trust_store_from_env() {
  if (const char *dir = std::getenv("CERTCTRL_CA_IMPORT_DIR")) {
    TrustStoreTarget target;
    target.directory = std::filesystem::path(dir);
    if (const char *cmd = std::getenv("CERTCTRL_CA_UPDATE_COMMAND")) {
      target.update_command = cmd;
    }
    target.description = "environment override";
    return target;
  }
  return std::nullopt;
}

std::optional<TrustStoreTarget> detect_system_trust_store() {
  if (auto override_target = trust_store_from_env()) {
    return override_target;
  }

#if defined(__linux__)
  struct Candidate {
    const char *dir;
    const char *cmd;
    const char *desc;
  };

  constexpr Candidate candidates[] = {
      {"/usr/local/share/ca-certificates", "update-ca-certificates",
       "Debian/Ubuntu trust store"},
      {"/etc/pki/ca-trust/source/anchors", "update-ca-trust extract",
       "RHEL/Fedora trust store"},
      {"/usr/share/pki/trust/anchors", "update-ca-certificates",
       "SUSE trust store"},
  };

  for (const auto &candidate : candidates) {
    std::filesystem::path dir(candidate.dir);
    if (std::filesystem::exists(dir)) {
      TrustStoreTarget target;
      target.directory = std::move(dir);
      target.update_command = candidate.cmd;
      target.description = candidate.desc;
      return target;
    }
  }
#elif defined(_WIN32)
  if (auto override_target = trust_store_from_env()) {
    return override_target;
  }
  // Windows: stage files under ProgramData and import into LocalMachine Root
  // store via PowerShell
  try {
    std::filesystem::path base = [] {
      const char *pd = std::getenv("ProgramData");
      if (pd && *pd)
        return std::filesystem::path(pd);
      return std::filesystem::path("C:/ProgramData");
    }();
    std::filesystem::path dir = base / "certctrl" / "trust-anchors";
    TrustStoreTarget target;
    target.directory = dir;
    // PowerShell imports all .crt files from the directory into
    // LocalMachine\Root Note: requires Administrator privileges.
    std::string cmd = fmt::format(
        "powershell -NoProfile -ExecutionPolicy Bypass -Command "
        "\"$ErrorActionPreference='Stop'; $d='{}'; if (-not (Test-Path "
        "-LiteralPath $d)) {{ New-Item -ItemType Directory -Force -Path $d | "
        "Out-Null }}; Get-ChildItem -LiteralPath $d -Filter *.crt | "
        "ForEach-Object {{ Import-Certificate -FilePath $_.FullName "
        "-CertStoreLocation 'Cert:\\LocalMachine\\Root' }}\"",
        dir.string());
    target.update_command = std::move(cmd);
    target.description =
        "Windows ProgramData staged trust and PowerShell importer";
    return target;
  } catch (...) {
    // Fall through to std::nullopt
  }
#elif defined(__APPLE__)
  TrustStoreTarget target;
  target.directory =
      std::filesystem::path("/Library/Caches/certctrl/trust-anchors");
  target.description = "macOS system keychain";
  target.update_command.clear();
  target.use_native_mac_import = true;
  return target;
#endif

  return std::nullopt;
}

std::filesystem::path
resource_root_for(const std::filesystem::path &runtime_dir,
                  const dto::InstallItem &item) {
  std::filesystem::path root = runtime_dir / "resources";
  if (item.ob_type && *item.ob_type == "ca" && item.ob_id) {
    root /= "cas";
    root /= std::to_string(*item.ob_id);
    root /= "current";
    return root;
  }
  return {};
}

bool should_skip_item(const dto::InstallItem &item,
                      const std::optional<std::string> &target_ob_type,
                      std::optional<std::int64_t> target_ob_id) {
  if (!item.ob_type || !item.ob_id) {
    return true;
  }
  if (target_ob_type && *item.ob_type != *target_ob_type) {
    return true;
  }
  if (target_ob_id && *item.ob_id != *target_ob_id) {
    return true;
  }
  return false;
}

void log_warning(customio::ConsoleOutput &output, const dto::InstallItem &item,
                 std::string_view message) {
  output.logger().warning()
      << "import_ca item '" << item.id << "': " << message << std::endl;
}

std::filesystem::path
import_state_directory(const std::filesystem::path &runtime_dir) {
  return runtime_dir / "state" / "import_ca";
}

std::optional<std::string>
load_canonical_state(const std::filesystem::path &state_file) {
  std::ifstream ifs(state_file);
  if (!ifs.is_open()) {
    return std::nullopt;
  }

  std::string line;
  std::getline(ifs, line);
  if (!ifs && !ifs.eof()) {
    return std::nullopt;
  }

  auto first = line.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) {
    return std::nullopt;
  }
  auto last = line.find_last_not_of(" \t\r\n");
  if (last == std::string::npos) {
    return std::nullopt;
  }

  return line.substr(first, last - first + 1);
}

std::optional<std::string>
persist_canonical_state(const std::filesystem::path &state_file,
                        const std::string &canonical_name) {
  std::ofstream ofs(state_file, std::ios::trunc);
  if (!ofs.is_open()) {
    return fmt::format("failed to open '{}' for writing", state_file.string());
  }

  ofs << canonical_name;
  if (!ofs.good()) {
    return fmt::format("failed to write canonical name '{}' to '{}'",
                       canonical_name, state_file.string());
  }

  return std::nullopt;
}

} // namespace

#if defined(__APPLE__)
namespace detail {
std::optional<MacTrustStoreProbe> detect_mac_trust_store_for_test() {
  auto target = detect_system_trust_store();
  if (!target) {
    return std::nullopt;
  }

  MacTrustStoreProbe probe;
  probe.directory = target->directory;
  probe.update_command = target->update_command;
  probe.uses_native_import = target->use_native_mac_import;
  return probe;
}
} // namespace detail
#endif

monad::IO<void> ImportCaActionHandler::process_one_item(
    const dto::InstallItem &item,
    const std::optional<std::string> &target_ob_type,
    std::optional<std::int64_t> target_ob_id) {
  using ReturnIO = monad::IO<void>;
  if (item.type != "import_ca") {
    return ReturnIO::pure();
  }

  BOOST_LOG_SEV(app_logger(), trivial::trace)
      << "Processing import_ca item '" << item.id << "'";

  if (!item.enabled) {
    BOOST_LOG_SEV(app_logger(), trivial::trace)
        << "import_ca item '" << item.id
        << "' disabled via configuration; skipping";
    return ReturnIO::pure();
  }

  if (should_skip_item(item, target_ob_type, target_ob_id)) {
    return ReturnIO::pure();
  }

  if (!item.ob_type || *item.ob_type != "ca" || !item.ob_id) {
    auto err =
        monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                          "import_ca item requires ob_type 'ca' and ob_id");
    if (item.continue_on_error) {
      log_warning(output_, item, err.what);
      return ReturnIO::pure();
    }
    return ReturnIO::fail(std::move(err));
  }

  auto trust_store = detect_system_trust_store();
  if (!trust_store) {
    auto err = monad::make_error(
        my_errors::GENERAL::NOT_IMPLEMENTED,
        "unable to locate a supported trust store directory; set "
        "CERTCTRL_CA_IMPORT_DIR to override");
    if (item.continue_on_error) {
      log_warning(output_, item, err.what);
      return ReturnIO::pure();
    }
    return ReturnIO::fail(std::move(err));
  }

  auto trust = *trust_store;

  BOOST_LOG_SEV(app_logger(), trivial::trace)
      << "import_ca item '" << item.id << "' resolved trust store target dir='"
      << trust.directory << "' update_cmd='" << trust.update_command << "'";

  auto self = shared_from_this();

  return resource_materializer_->ensure_materialized(item)
      .then([self, item, trust]() -> ReturnIO {
        BOOST_LOG_SEV(app_logger(), trivial::trace)
            << "import_ca item '" << item.id
            << "' resource materialization complete";
        auto resource_root = resource_root_for(self->runtime_dir_, item);
        if (resource_root.empty()) {
          auto err =
              monad::make_error(my_errors::GENERAL::INVALID_ARGUMENT,
                                "unable to resolve resource root for CA");
          if (item.continue_on_error) {
            log_warning(self->output_, item, err.what);
            return ReturnIO::pure();
          }
          return ReturnIO::fail(std::move(err));
        }

        auto ca_pem_path = resource_root / "ca.pem";
        if (!std::filesystem::exists(ca_pem_path)) {
          auto err = monad::make_error(
              my_errors::GENERAL::FILE_NOT_FOUND,
              fmt::format("expected CA PEM missing: {}", ca_pem_path.string()));
          if (item.continue_on_error) {
            log_warning(self->output_, item, err.what);
            return ReturnIO::pure();
          }
          return ReturnIO::fail(std::move(err));
        }

        auto label = item.ob_name.value_or(std::string{});
        auto sanitized = sanitize_label(label, *item.ob_id);
        auto canonical_name = fmt::format("certctrl-ca-{}", *item.ob_id);
        if (!sanitized.empty() && sanitized != canonical_name) {
          canonical_name = fmt::format("{}-{}", canonical_name, sanitized);
        }
        auto destination = trust.directory / (canonical_name + ".crt");

        auto state_dir = import_state_directory(self->runtime_dir_);
        std::error_code state_dir_ec;
        std::filesystem::create_directories(state_dir, state_dir_ec);
        if (state_dir_ec) {
          auto err = monad::make_error(
              my_errors::GENERAL::FILE_READ_WRITE,
              fmt::format("failed to prepare CA state directory '{}': {}",
                          state_dir.string(), state_dir_ec.message()));
          if (item.continue_on_error) {
            log_warning(self->output_, item, err.what);
            return ReturnIO::pure();
          }
          return ReturnIO::fail(std::move(err));
        }

        auto state_file = state_dir / fmt::format("ca-{}.name", *item.ob_id);
        auto previous_canonical = load_canonical_state(state_file);

        BOOST_LOG_SEV(app_logger(), trivial::trace)
            << "import_ca item '" << item.id << "' copying '" << ca_pem_path
            << "' to '" << destination << "'";

        if (auto err = copy_ca_material(ca_pem_path, destination)) {
          auto error_obj =
              monad::make_error(my_errors::GENERAL::FILE_READ_WRITE, *err);
          BOOST_LOG_SEV(app_logger(), trivial::error)
              << "import_ca item '" << item.id
              << "' copy_ca_material failed: " << *err;
          if (item.continue_on_error) {
            log_warning(self->output_, item, error_obj.what);
            return ReturnIO::pure();
          }
          return ReturnIO::fail(std::move(error_obj));
        }

#if defined(__APPLE__)
        if (trust.use_native_mac_import) {
          BOOST_LOG_SEV(app_logger(), trivial::trace)
              << "import_ca item '" << item.id
              << "' performing native macOS keychain import using '"
              << destination << "'";

          if (auto err = import_certificate_to_system_keychain(
                  destination, canonical_name)) {
            auto error_obj =
                monad::make_error(my_errors::GENERAL::UNEXPECTED_RESULT, *err);
            BOOST_LOG_SEV(app_logger(), trivial::error)
                << "import_ca item '" << item.id
                << "' macOS keychain import failed: " << *err;
            if (item.continue_on_error) {
              log_warning(self->output_, item, error_obj.what);
              return ReturnIO::pure();
            }
            return ReturnIO::fail(std::move(error_obj));
          }

          BOOST_LOG_SEV(app_logger(), trivial::trace)
              << "import_ca item '" << item.id
              << "' macOS keychain import succeeded";
        }
#endif

        if (previous_canonical && *previous_canonical != canonical_name) {
          auto legacy_path = trust.directory / (*previous_canonical + ".crt");
          std::error_code remove_ec;
          if (std::filesystem::exists(legacy_path)) {
            std::filesystem::remove(legacy_path, remove_ec);
            if (remove_ec) {
              auto err = monad::make_error(
                  my_errors::GENERAL::FILE_READ_WRITE,
                  fmt::format("failed to remove legacy CA '{}' at '{}': {}",
                              *previous_canonical, legacy_path.string(),
                              remove_ec.message()));
              BOOST_LOG_SEV(app_logger(), trivial::error)
                  << "import_ca item '" << item.id
                  << "' legacy removal failed: " << err.what;
              if (item.continue_on_error) {
                log_warning(self->output_, item, err.what);
                return ReturnIO::pure();
              }
              return ReturnIO::fail(std::move(err));
            }

            BOOST_LOG_SEV(app_logger(), trivial::trace)
                << "import_ca item '" << item.id << "' removed legacy CA "
                << *previous_canonical;
          }
        }

        self->output_.logger().info()
            << "Imported CA '" << canonical_name << "' into " << trust.directory
            << std::endl;

        BOOST_LOG_SEV(app_logger(), trivial::trace)
            << "import_ca item '" << item.id << "' completed filesystem copy";

#ifndef _WIN32
        if (!trust.update_command.empty()) {
          BOOST_LOG_SEV(app_logger(), trivial::trace)
              << "import_ca item '" << item.id
              << "' executing update command: " << trust.update_command;
          int rc = std::system(trust.update_command.c_str());
          if (rc != 0) {
            auto err = monad::make_error(
                my_errors::GENERAL::UNEXPECTED_RESULT,
                fmt::format("command '{}' exited with status {}",
                            trust.update_command, rc));
            BOOST_LOG_SEV(app_logger(), trivial::error)
                << "import_ca item '" << item.id
                << "' update command failed rc=" << rc;
            if (item.continue_on_error) {
              log_warning(self->output_, item, err.what);
              return ReturnIO::pure();
            }
            return ReturnIO::fail(std::move(err));
          }
          BOOST_LOG_SEV(app_logger(), trivial::trace)
              << "import_ca item '" << item.id << "' update command succeeded";
        }
#endif

        certctrl::util::BrowserTrustSync browser_sync(self->output_,
                                                      self->runtime_dir_);
        if (auto sync_err =
                browser_sync.sync_ca(canonical_name, previous_canonical,
                                      ca_pem_path)) {
          auto error_obj = monad::make_error(
              my_errors::GENERAL::UNEXPECTED_RESULT, *sync_err);
          BOOST_LOG_SEV(app_logger(), trivial::error)
              << "import_ca item '" << item.id
              << "' browser trust sync failed: " << *sync_err;
          if (item.continue_on_error) {
            log_warning(self->output_, item, error_obj.what);
            return ReturnIO::pure();
          }
          return ReturnIO::fail(std::move(error_obj));
        }

        if (auto err = persist_canonical_state(state_file, canonical_name)) {
          auto error_obj =
              monad::make_error(my_errors::GENERAL::FILE_READ_WRITE, *err);
          BOOST_LOG_SEV(app_logger(), trivial::error)
              << "import_ca item '" << item.id
              << "' state persistence failed: " << *err;
          if (item.continue_on_error) {
            log_warning(self->output_, item, error_obj.what);
            return ReturnIO::pure();
          }
          return ReturnIO::fail(std::move(error_obj));
        }

        return ReturnIO::pure();
      })
      .catch_then([self, item](monad::Error err) -> ReturnIO {
        BOOST_LOG_SEV(app_logger(), trivial::error)
            << "import_ca item '" << item.id << "' caught error: " << err.what;
        if (item.continue_on_error) {
          log_warning(self->output_, item, err.what);
          return ReturnIO::pure();
        }
        return ReturnIO::fail(std::move(err));
      });
}

monad::IO<void>
ImportCaActionHandler::apply(const dto::DeviceInstallConfigDto &config,
                             const std::optional<std::string> &target_ob_type,
                             std::optional<std::int64_t> target_ob_id) {
  using ReturnIO = monad::IO<void>;
  auto self = shared_from_this();
  resource_materializer_ = resource_materializer_factory_();

  // try {
  auto resource_materializer = resource_materializer_factory_();
  if (!resource_materializer) {
    return ReturnIO::fail(monad::make_error(
        my_errors::GENERAL::INVALID_ARGUMENT,
        "ImportCaActionHandler missing resource materializer"));
  }

  ReturnIO pipeline = ReturnIO::pure();
  for (const auto &item : config.installs) {
    auto item_copy = item;
    pipeline = pipeline.then([self, item_copy, target_ob_type,
                              target_ob_id]() mutable {
      return self->process_one_item(item_copy, target_ob_type, target_ob_id);
    });
  }

  return pipeline.catch_then([](monad::Error err) -> ReturnIO {
    BOOST_LOG_SEV(app_logger(), trivial::error)
        << "import_ca actions pipeline failed code=" << err.code
        << " status=" << err.response_status << " what=" << err.what
        << " params=" << boost::json::serialize(err.params);
    return ReturnIO::fail(std::move(err));
  });
}

} // namespace certctrl::install_actions
