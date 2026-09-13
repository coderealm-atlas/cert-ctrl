#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string_view>

#include "include/test_config_utils.hpp"

namespace {

class ConfigSourcesYamlTest : public ::testing::Test {
protected:
  std::filesystem::path dir = testinfra::make_temp_dir("certctrl-yaml-test");

  void TearDown() override {
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
  }

  void write(std::string_view filename, std::string_view content) {
    std::ofstream output(dir / filename);
    ASSERT_TRUE(output);
    output << content;
    output.close();
    ASSERT_TRUE(output);
  }
};

TEST_F(ConfigSourcesYamlTest, PreservesScalarTypesAndNestedSequences) {
  write("application.yaml", R"YAML(
enabled: true
interval: 300
quoted_port: "443"
servers:
  - name: local
    enabled: false
)YAML");
  const auto sources = testinfra::make_config_sources({dir});
  ASSERT_TRUE(sources->application_json.has_value());
  const auto &config = sources->application_json->as_object();
  EXPECT_TRUE(config.at("enabled").as_bool());
  EXPECT_EQ(config.at("interval").as_int64(), 300);
  EXPECT_EQ(config.at("quoted_port").as_string(), "443");
  const auto &servers = config.at("servers").as_array();
  ASSERT_EQ(servers.size(), 1u);
  EXPECT_EQ(servers[0].as_object().at("name").as_string(), "local");
  EXPECT_FALSE(servers[0].as_object().at("enabled").as_bool());
}

TEST_F(ConfigSourcesYamlTest, ResolvesAnchorsAndAppliesProfileOverrides) {
  write("application.yaml", R"YAML(
defaults: &defaults
  interval: 300
  enabled: true
client:
  <<: *defaults
  name: local
)YAML");
  write("application.test.yaml", "client:\n  interval: 60\n");
  const auto sources = testinfra::make_config_sources({dir}, {"test"});
  ASSERT_TRUE(sources->application_json.has_value());
  const auto &client =
      sources->application_json->as_object().at("client").as_object();
  EXPECT_EQ(client.at("interval").as_int64(), 60);
  EXPECT_TRUE(client.at("enabled").as_bool());
  EXPECT_EQ(client.at("name").as_string(), "local");
}

} // namespace
