/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// Tests for the operator QoS-authorization config parsing
// (oai::config::pcf::qos_authorization_config). Verifies that the
// `pcf.qos_authorization` YAML block maps to the config getters that pcf_app.cpp
// converts into oai::pcf::app::operator_qos_policy. The BitRate-string ->
// bit/s conversion itself is covered by test_bitrate.cpp.

#include <gtest/gtest.h>

#include <yaml-cpp/yaml.h>

#include <string>

#include "pcf_config_types.hpp"

using oai::config::pcf::qos_authorization_config;

// A fully-populated block maps every field to its getter.
TEST(QosAuthorizationConfig, ParsesAllFields) {
  const YAML::Node node = YAML::Load(R"(
allowed_dynamic_5qi: [128, 130, 131]
max_flow_mbr_ul: "1 Gbps"
max_flow_mbr_dl: "2 Gbps"
max_session_ambr_ul: "2 Gbps"
max_session_ambr_dl: "4 Gbps"
reject_on_missing_subscription: true
)");

  qos_authorization_config cfg;
  cfg.from_yaml(node);

  const std::vector<int32_t> expected_5qi{128, 130, 131};
  EXPECT_EQ(cfg.get_allowed_dynamic_5qi(), expected_5qi);
  EXPECT_EQ(cfg.get_max_flow_mbr_ul(), "1 Gbps");
  EXPECT_EQ(cfg.get_max_flow_mbr_dl(), "2 Gbps");
  EXPECT_EQ(cfg.get_max_session_ambr_ul(), "2 Gbps");
  EXPECT_EQ(cfg.get_max_session_ambr_dl(), "4 Gbps");
  EXPECT_TRUE(cfg.get_reject_on_missing_subscription());
}

// An absent/empty block keeps the permissive defaults (no cap / allow any 5QI /
// fail-open), per TS 29.512 §4.2.2.2.
TEST(QosAuthorizationConfig, DefaultsArePermissive) {
  qos_authorization_config cfg;  // no from_yaml() call

  EXPECT_TRUE(cfg.get_allowed_dynamic_5qi().empty());
  EXPECT_EQ(cfg.get_max_flow_mbr_ul(), "");
  EXPECT_EQ(cfg.get_max_flow_mbr_dl(), "");
  EXPECT_EQ(cfg.get_max_session_ambr_ul(), "");
  EXPECT_EQ(cfg.get_max_session_ambr_dl(), "");
  EXPECT_FALSE(cfg.get_reject_on_missing_subscription());
}

// A partial block updates only the provided fields and leaves the rest at
// their permissive defaults.
TEST(QosAuthorizationConfig, PartialBlockKeepsDefaultsForOmittedFields) {
  const YAML::Node node = YAML::Load(R"(
max_session_ambr_dl: "500 Mbps"
)");

  qos_authorization_config cfg;
  cfg.from_yaml(node);

  EXPECT_TRUE(cfg.get_allowed_dynamic_5qi().empty());
  EXPECT_EQ(cfg.get_max_flow_mbr_ul(), "");
  EXPECT_EQ(cfg.get_max_session_ambr_dl(), "500 Mbps");
  EXPECT_FALSE(cfg.get_reject_on_missing_subscription());
}
