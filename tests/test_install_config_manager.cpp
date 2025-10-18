#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <fmt/format.h>
#include <random>
#include <string>

#include "conf/certctrl_config.hpp"
#include "customio/console_output.hpp"
#include "handlers/install_actions/import_ca_action.hpp"
#include "handlers/install_config_manager.hpp"
#include "io_monad.hpp"
#include "log_stream.hpp"
#include "result_monad.hpp"

namespace {

class StubConfigProvider : public certctrl::ICertctrlConfigProvider {
 public:
  certctrl::CertctrlConfig config_;

  StubConfigProvider() {
    config_.base_url = "https://api.example.test";
  }

  const certctrl::CertctrlConfig &get() const override { return config_; }
  certctrl::CertctrlConfig &get() override { return config_; }

  monad::MyVoidResult save(const boost::json::object &) override {
    return monad::MyVoidResult::Ok();
  }
};

std::filesystem::path make_temp_runtime_dir() {
  auto base = std::filesystem::temp_directory_path();
  std::mt19937_64 gen{std::random_device{}()};
  std::uniform_int_distribution<std::uint64_t> dist;
  auto dir = base / fmt::format("certctrl-test-{}", dist(gen));
  std::filesystem::create_directories(dir);
  return dir;
}

void write_file(const std::filesystem::path &path, std::string_view content) {
  std::filesystem::create_directories(path.parent_path());
  std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
  ofs << content;
}

std::string read_file(const std::filesystem::path &path) {
  std::ifstream ifs(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>()};
}

class ScopedEnvVar {
 public:
  ScopedEnvVar(const char *name, const std::string &value) : name_(name) {
#ifdef _WIN32
    _putenv_s(name, value.c_str());
#else
    ::setenv(name, value.c_str(), 1);
#endif
  }

  ~ScopedEnvVar() {
#ifdef _WIN32
    _putenv_s(name_.c_str(), "");
#else
    ::unsetenv(name_.c_str());
#endif
  }

 private:
  std::string name_;
};

} // namespace

TEST(InstallConfigManagerTest, AppliesCopyActionsFullPlan) {
  auto runtime_dir = make_temp_runtime_dir();

  auto resource_dir = runtime_dir / "resources" / "certs" / "123" / "current";
  write_file(resource_dir / "private.key", "PRIVATE-KEY-CONTENT\n");
  write_file(resource_dir / "fullchain.pem", "FULLCHAIN\n");

  dto::DeviceInstallConfigDto config{};
  config.id = 1;
  config.user_device_id = 10;
  config.version = 42;
  config.installs_hash = "abc123";

  dto::InstallItem copy_item{};
  copy_item.id = "copy-cert";
  copy_item.type = "copy";
  copy_item.ob_type = std::string{"cert"};
  copy_item.ob_id = static_cast<std::int64_t>(123);
  copy_item.from = std::vector<std::string>{"private.key", "fullchain.pem"};
  auto dest_key = runtime_dir / "deploy" / "certs" / "service" / "private.key";
  auto dest_chain = runtime_dir / "deploy" / "certs" / "service" / "fullchain.pem";
  copy_item.to = std::vector<std::string>{dest_key.string(), dest_chain.string()};
  config.installs.push_back(copy_item);

  StubConfigProvider provider;
  provider.config_.runtime_dir = runtime_dir;
  customio::ConsoleOutputWithColor sink(5);
  customio::ConsoleOutput output(sink);

  auto fetch_override = [config](std::optional<std::int64_t>,
                                 const std::optional<std::string> &)
      -> monad::IO<dto::DeviceInstallConfigDto> {
    return monad::IO<dto::DeviceInstallConfigDto>::pure(config);
  };

  auto resource_override = [resource_dir](const dto::InstallItem &item)
      -> std::optional<std::string> {
    if (!item.ob_type || *item.ob_type != "cert") {
      return std::nullopt;
    }
    auto bundle_path = resource_dir / "bundle_raw.json";
    if (!std::filesystem::exists(bundle_path)) {
      std::cerr << "bundle path missing: " << bundle_path << std::endl;
      return std::nullopt;
    }
    auto content = read_file(bundle_path);
    std::cerr << "resource override read bytes=" << content.size() << std::endl;
    return content;
  };

  certctrl::InstallConfigManager manager(runtime_dir, provider, output,
                                         nullptr, fetch_override);

  std::shared_ptr<const dto::DeviceInstallConfigDto> plan;
  manager.ensure_config_version(config.version, config.installs_hash)
      .run([&](auto result) {
        ASSERT_TRUE(result.is_ok());
        plan = result.value();
      });
  ASSERT_TRUE(plan);

  manager.apply_copy_actions(*plan, std::nullopt, std::nullopt)
      .run([&](auto result) {
        if (!result.is_ok()) {
          auto err = result.error();
          std::cerr << "apply_copy_actions error code=" << err.code
                    << " msg='" << err.what << "'" << std::endl;
          FAIL() << "apply_copy_actions failed: " << err.what;
        }
      });

  EXPECT_TRUE(std::filesystem::exists(dest_key));
  EXPECT_TRUE(std::filesystem::exists(dest_chain));
  EXPECT_EQ(read_file(dest_key), "PRIVATE-KEY-CONTENT\n");
  EXPECT_EQ(read_file(dest_chain), "FULLCHAIN\n");

#ifndef _WIN32
  auto key_perms = std::filesystem::status(dest_key).permissions();
  EXPECT_NE(key_perms & std::filesystem::perms::owner_read,
            std::filesystem::perms::none);
  EXPECT_NE(key_perms & std::filesystem::perms::owner_write,
            std::filesystem::perms::none);
  EXPECT_EQ(key_perms & std::filesystem::perms::others_read,
            std::filesystem::perms::none);

  auto chain_perms = std::filesystem::status(dest_chain).permissions();
  EXPECT_NE(chain_perms & std::filesystem::perms::others_read,
            std::filesystem::perms::none);
#endif

  std::filesystem::remove_all(runtime_dir);
}

TEST(InstallConfigManagerTest, SkipsCopyActionsWithEmptyDestinations) {
  auto runtime_dir = make_temp_runtime_dir();

  auto resource_dir = runtime_dir / "resources" / "certs" / "789" / "current";
  write_file(resource_dir / "fullchain.pem", "CHAIN789\n");

  dto::DeviceInstallConfigDto config{};
  config.id = 2;
  config.user_device_id = 20;
  config.version = 99;

  dto::InstallItem copy_item{};
  copy_item.id = "copy-empty";
  copy_item.type = "copy";
  copy_item.ob_type = std::string{"cert"};
  copy_item.ob_id = static_cast<std::int64_t>(789);
  copy_item.from = std::vector<std::string>{"fullchain.pem"};
  copy_item.to = std::vector<std::string>{};
  config.installs.push_back(copy_item);

  StubConfigProvider provider;
  provider.config_.runtime_dir = runtime_dir;
  customio::ConsoleOutputWithColor sink(5);
  customio::ConsoleOutput output(sink);

  auto fetch_override = [config](std::optional<std::int64_t>,
                                 const std::optional<std::string> &)
      -> monad::IO<dto::DeviceInstallConfigDto> {
    return monad::IO<dto::DeviceInstallConfigDto>::pure(config);
  };

  certctrl::InstallConfigManager manager(runtime_dir, provider, output,
                                         nullptr, fetch_override);

  std::shared_ptr<const dto::DeviceInstallConfigDto> plan;
  manager.ensure_config_version(config.version, std::nullopt)
      .run([&](auto result) {
        ASSERT_TRUE(result.is_ok());
        plan = result.value();
      });

  ASSERT_TRUE(plan);

  auto dest_path = runtime_dir / "deploy" / "fullchain.pem";

  manager.apply_copy_actions(*plan, std::nullopt, std::nullopt)
      .run([&](auto result) { ASSERT_TRUE(result.is_ok()); });

  EXPECT_FALSE(std::filesystem::exists(dest_path));

  std::filesystem::remove_all(runtime_dir);
}

TEST(ImportCaActionTest, CopiesCaIntoOverrideDirectory) {
  auto runtime_dir = make_temp_runtime_dir();
  auto resource_dir = runtime_dir / "resources" / "cas" / "55" / "current";
  write_file(resource_dir / "ca.pem", "CA-PEM-DATA\n");

  dto::DeviceInstallConfigDto config{};
  dto::InstallItem import_item{};
  import_item.id = "import-root";
  import_item.type = "import_ca";
  import_item.ob_type = std::string{"ca"};
  import_item.ob_id = static_cast<std::int64_t>(55);
  import_item.ob_name = std::string{"Example Root CA"};
  config.installs.push_back(import_item);

  customio::ConsoleOutputWithColor sink(5);
  customio::ConsoleOutput output(sink);

  certctrl::install_actions::InstallActionContext context{
      runtime_dir,
      output,
      [](const dto::InstallItem &) -> std::optional<monad::Error> {
        return std::nullopt;
      }};

  auto trust_dir = runtime_dir / "trust-anchors";
  ScopedEnvVar dir_env("CERTCTRL_CA_IMPORT_DIR", trust_dir.string());
  ScopedEnvVar cmd_env("CERTCTRL_CA_UPDATE_COMMAND", "true");

  certctrl::install_actions::apply_import_ca_actions(context, config,
                                                     std::nullopt,
                                                     std::nullopt)
      .run([&](auto result) {
        if (!result.is_ok()) {
          auto err = result.error();
          FAIL() << "apply_import_ca_actions failed: " << err.what;
        }
      });

  std::filesystem::path expected = trust_dir / "example-root-ca.crt";
  ASSERT_TRUE(std::filesystem::exists(expected));
  EXPECT_EQ(read_file(expected), "CA-PEM-DATA\n");

  std::filesystem::remove_all(runtime_dir);
}

TEST(InstallConfigManagerTest, FiltersCopyActionsByResource) {
  auto runtime_dir = make_temp_runtime_dir();

  auto resource_dir_123 = runtime_dir / "resources" / "certs" / "123" / "current";
  auto resource_dir_456 = runtime_dir / "resources" / "certs" / "456" / "current";
  write_file(resource_dir_123 / "fullchain.pem", "CHAIN123\n");
  write_file(resource_dir_456 / "fullchain.pem", "CHAIN456\n");

  dto::DeviceInstallConfigDto config{};
  config.id = 11;
  config.user_device_id = 77;
  config.version = 12;

  dto::InstallItem item_a{};
  item_a.id = "cert123";
  item_a.type = "copy";
  item_a.ob_type = std::string{"cert"};
  item_a.ob_id = static_cast<std::int64_t>(123);
  item_a.from = std::vector<std::string>{"fullchain.pem"};
  auto dest_a = runtime_dir / "deploy" / "123" / "fullchain.pem";
  item_a.to = std::vector<std::string>{dest_a.string()};

  dto::InstallItem item_b{};
  item_b.id = "cert456";
  item_b.type = "copy";
  item_b.ob_type = std::string{"cert"};
  item_b.ob_id = static_cast<std::int64_t>(456);
  item_b.from = std::vector<std::string>{"fullchain.pem"};
  auto dest_b = runtime_dir / "deploy" / "456" / "fullchain.pem";
  item_b.to = std::vector<std::string>{dest_b.string()};

  config.installs.push_back(item_a);
  config.installs.push_back(item_b);

  StubConfigProvider provider;
  provider.config_.runtime_dir = runtime_dir;
  customio::ConsoleOutputWithColor sink(5);
  customio::ConsoleOutput output(sink);

  auto fetch_override = [config](std::optional<std::int64_t>,
                                 const std::optional<std::string> &)
      -> monad::IO<dto::DeviceInstallConfigDto> {
    return monad::IO<dto::DeviceInstallConfigDto>::pure(config);
  };

  certctrl::InstallConfigManager manager(runtime_dir, provider, output,
                                         nullptr, fetch_override);

  std::shared_ptr<const dto::DeviceInstallConfigDto> plan;
  manager.ensure_config_version(config.version, std::nullopt)
      .run([&](auto result) {
        ASSERT_TRUE(result.is_ok());
        plan = result.value();
      });

  ASSERT_TRUE(plan);

  // First apply only cert 123
  manager.apply_copy_actions(*plan, std::string("cert"), static_cast<std::int64_t>(123))
      .run([&](auto result) { ASSERT_TRUE(result.is_ok()); });

  EXPECT_TRUE(std::filesystem::exists(dest_a));
  EXPECT_FALSE(std::filesystem::exists(dest_b));
  EXPECT_EQ(read_file(dest_a), "CHAIN123\n");

  // Now apply only cert 456
  manager.apply_copy_actions(*plan, std::string("cert"), static_cast<std::int64_t>(456))
      .run([&](auto result) { ASSERT_TRUE(result.is_ok()); });

  EXPECT_TRUE(std::filesystem::exists(dest_b));
  EXPECT_EQ(read_file(dest_b), "CHAIN456\n");

  std::filesystem::remove_all(runtime_dir);
}

TEST(InstallConfigManagerTest, HandlesMasterOnlyPlaintextBundle) {
  auto runtime_dir = make_temp_runtime_dir();

  const std::int64_t cert_id = 321;
  auto resource_dir = runtime_dir / "resources" / "certs" / std::to_string(cert_id) / "current";

  const std::string private_key_pem =
      "-----BEGIN PRIVATE KEY-----\n"
      "MFMCAQEwBQYDK2dJAzAAMC0CFQC87y2hBtE5g9UoBRB9MYL2EjRHDwIUTDNmHhX8\n"
      "8IaQwv1lvxR++hXaYes=\n"
      "-----END PRIVATE KEY-----\n";

  boost::json::object bundle_data;
  bundle_data["enc_scheme"] = "plaintext";
  bundle_data["private_key_pem"] = private_key_pem;

  boost::json::object payload;
  payload["data"] = bundle_data;
  write_file(resource_dir / "bundle_raw.json", boost::json::serialize(payload));

  dto::DeviceInstallConfigDto config{};
  config.id = 3;
  config.user_device_id = 30;
  config.version = 5;

  dto::InstallItem copy_item{};
  copy_item.id = "plaintext-cert";
  copy_item.type = "copy";
  copy_item.ob_type = std::string{"cert"};
  copy_item.ob_id = cert_id;
  copy_item.from = std::vector<std::string>{"private.key"};
  auto dest = runtime_dir / "deploy" / "certs" / "private.key";
  copy_item.to = std::vector<std::string>{dest.string()};
  config.installs.push_back(copy_item);

  StubConfigProvider provider;
  provider.config_.runtime_dir = runtime_dir;
  customio::ConsoleOutputWithColor sink(5);
  customio::ConsoleOutput output(sink);

  auto fetch_override = [config](std::optional<std::int64_t>,
                                 const std::optional<std::string> &)
      -> monad::IO<dto::DeviceInstallConfigDto> {
    return monad::IO<dto::DeviceInstallConfigDto>::pure(config);
  };

  auto resource_override = [resource_dir](const dto::InstallItem &item)
      -> std::optional<std::string> {
    if (!item.ob_type || *item.ob_type != "cert") {
      return std::nullopt;
    }
    auto bundle_path = resource_dir / "bundle_raw.json";
    if (!std::filesystem::exists(bundle_path)) {
      return std::nullopt;
    }
    return read_file(bundle_path);
  };

  certctrl::InstallConfigManager manager(runtime_dir, provider, output,
                                         nullptr, fetch_override,
                                         resource_override);

  std::shared_ptr<const dto::DeviceInstallConfigDto> plan;
  manager.ensure_config_version(config.version, std::nullopt)
      .run([&](auto result) {
        ASSERT_TRUE(result.is_ok());
        plan = result.value();
      });

  ASSERT_TRUE(plan);

  bool apply_ok = false;
  monad::Error apply_err{};
  manager.apply_copy_actions(*plan, std::nullopt, std::nullopt)
      .run([&](auto result) {
        apply_ok = result.is_ok();
        if (!apply_ok) {
          apply_err = result.error();
        }
      });

  ASSERT_TRUE(apply_ok) << "apply_copy_actions failed: " << apply_err.what;

  ASSERT_TRUE(std::filesystem::exists(dest));
  EXPECT_EQ(read_file(dest), private_key_pem);

  std::filesystem::remove_all(runtime_dir);
}