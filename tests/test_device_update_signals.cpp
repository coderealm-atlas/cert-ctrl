#include <gtest/gtest.h>

#include <boost/json.hpp>

#include "data/data_shape.hpp"

namespace json = boost::json;

TEST(DeviceUpdateSignals, ParsesCaUnassignedReference) {
  json::object payload;
  payload["type"] = "ca.unassigned";
  payload["ts_ms"] = 1735689600;
  json::object ref;
  ref["ca_id"] = 77;
  ref["ca_name"] = "Corp Root";
  payload["ref"] = ref;

  json::value payload_value = payload;
  auto signal = json::value_to<data::DeviceUpdateSignal>(payload_value);
  EXPECT_TRUE(data::is_ca_unassigned(signal));
  auto typed = data::get_ca_unassigned(signal);
  ASSERT_TRUE(typed.has_value());
  EXPECT_EQ(typed->ca_id, 77);
  ASSERT_TRUE(typed->ca_name.has_value());
  EXPECT_EQ(*typed->ca_name, "Corp Root");
}

TEST(DeviceUpdateSignals, HandlesMissingCaName) {
  json::object payload;
  payload["type"] = "ca.unassigned";
  payload["ts_ms"] = 1735689601;
  json::object ref;
  ref["ca_id"] = 88;
  payload["ref"] = ref;

  json::value payload_value = payload;
  auto signal = json::value_to<data::DeviceUpdateSignal>(payload_value);
  auto typed = data::get_ca_unassigned(signal);
  ASSERT_TRUE(typed.has_value());
  EXPECT_EQ(typed->ca_id, 88);
  EXPECT_FALSE(typed->ca_name.has_value());
}
