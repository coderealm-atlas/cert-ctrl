#include <gtest/gtest.h>

#include <filesystem>
#include <string>

#include "handlers/install_actions/import_ca_action.hpp"

#if defined(__APPLE__)
TEST(ImportCaActionMac, DetectsDefaultTrustStore) {
  auto probe = certctrl::install_actions::detail::detect_mac_trust_store_for_test();
  ASSERT_TRUE(probe.has_value());

  const auto &result = probe.value();
  EXPECT_EQ(result.directory,
            std::filesystem::path("/Library/Caches/certctrl/trust-anchors"));
  EXPECT_TRUE(result.uses_native_import);
  EXPECT_TRUE(result.update_command.empty());
}
#else
TEST(ImportCaActionMac, DetectsDefaultTrustStore) {
  GTEST_SKIP() << "macOS-specific trust store detection";
}
#endif
