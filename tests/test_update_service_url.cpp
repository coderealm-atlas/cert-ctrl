#include <gtest/gtest.h>

#include "conf/certctrl_config.hpp"

TEST(UpdateServiceUrlTest, MigratesPreservedLegacyConfiguration) {
  for (const auto *url : {
           "https://install.lets-script.com/api/version/check",
           "http://install.lets-script.com/api/version/check"}) {
    const auto config = boost::json::value_to<certctrl::CertctrlConfig>(
        boost::json::value(boost::json::object{{"update_check_url", url}}));
    EXPECT_EQ(config.update_check_url, certctrl::kDefaultUpdateCheckUrl);
  }
  EXPECT_EQ(certctrl::migrate_update_check_url(
                "https://install.lets-script.com/api/version/check?channel=stable"),
            "https://install.never-lost.app/api/version/check?channel=stable");
}

TEST(UpdateServiceUrlTest, PreservesDisabledChecksAndCustomEndpoints) {
  for (const auto *url : {
           "", "https://updates.example.com/api/version/check",
           "https://install.lets-script.com/api/version/check-custom",
           "https://install.lets-script.com.example.com/api/version/check",
           "https://install-selfhost.lets-script.com/api/version/check",
           "https://install.never-lost.app/api/version/check"}) {
    const auto config = boost::json::value_to<certctrl::CertctrlConfig>(
        boost::json::value(boost::json::object{{"update_check_url", url}}));
    EXPECT_EQ(config.update_check_url, url);
  }
}

TEST(UpdateServiceUrlTest, MissingSettingUsesNewService) {
  const auto config = boost::json::value_to<certctrl::CertctrlConfig>(
      boost::json::value(boost::json::object{}));
  EXPECT_EQ(config.update_check_url, certctrl::kDefaultUpdateCheckUrl);
}
