/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// Tests for make_operator_qos_policy() -- the config -> runtime translation that
// converts the parsed pcf.qos_authorization block (3GPP BitRate strings) into
// the operator_qos_policy consumed by the SM-side authorizer and the PA-side
// validator. Verifies bit/s parsing, list->set, empty->nullopt, and the flag.

#include <gtest/gtest.h>

#include <yaml-cpp/yaml.h>

#include <cstdint>
#include <set>

#include "operator_qos_policy.hpp"
#include "operator_qos_policy_builder.hpp"
#include "pcf_config_types.hpp"

using oai::config::pcf::qos_authorization_config;
using oai::pcf::app::make_operator_qos_policy;

namespace {

qos_authorization_config config_from(const std::string& yaml) {
  qos_authorization_config cfg;
  cfg.from_yaml(YAML::Load(yaml));
  return cfg;
}

}  // namespace

// A fully-populated block converts every field, with BitRate strings parsed to
// bit/s [TS 29.512 §4.2.6.6].
TEST(OperatorQosPolicyBuilder, ConvertsAllFieldsToBps) {
  const auto cfg = config_from(R"(
allowed_dynamic_5qi: [128, 130]
max_flow_mbr_ul: "1 Gbps"
max_flow_mbr_dl: "2 Gbps"
max_session_ambr_ul: "500 Mbps"
max_session_ambr_dl: "1 Gbps"
reject_on_missing_subscription: true
)");

  const auto policy = make_operator_qos_policy(cfg);

  EXPECT_EQ(policy.allowed_dynamic_5qi, (std::set<int32_t>{128, 130}));
  ASSERT_TRUE(policy.max_flow_mbr_ul_bps.has_value());
  EXPECT_EQ(*policy.max_flow_mbr_ul_bps, 1000ULL * 1000 * 1000);
  ASSERT_TRUE(policy.max_flow_mbr_dl_bps.has_value());
  EXPECT_EQ(*policy.max_flow_mbr_dl_bps, 2000ULL * 1000 * 1000);
  ASSERT_TRUE(policy.max_session_ambr_ul_bps.has_value());
  EXPECT_EQ(*policy.max_session_ambr_ul_bps, 500ULL * 1000 * 1000);
  ASSERT_TRUE(policy.max_session_ambr_dl_bps.has_value());
  EXPECT_EQ(*policy.max_session_ambr_dl_bps, 1000ULL * 1000 * 1000);
  EXPECT_TRUE(policy.reject_on_missing_subscription);
}

// Defaults (empty block): empty bitrate strings become std::nullopt ("no cap"),
// no allowed 5QIs, fail-open [TS 29.512 §4.2.2.2].
TEST(OperatorQosPolicyBuilder, EmptyConfigYieldsPermissivePolicy) {
  const qos_authorization_config cfg;  // defaults, no from_yaml()

  const auto policy = make_operator_qos_policy(cfg);

  EXPECT_TRUE(policy.allowed_dynamic_5qi.empty());
  EXPECT_FALSE(policy.max_flow_mbr_ul_bps.has_value());
  EXPECT_FALSE(policy.max_flow_mbr_dl_bps.has_value());
  EXPECT_FALSE(policy.max_session_ambr_ul_bps.has_value());
  EXPECT_FALSE(policy.max_session_ambr_dl_bps.has_value());
  EXPECT_FALSE(policy.reject_on_missing_subscription);
}

// A partial block converts only the provided fields; omitted bitrates stay
// nullopt.
TEST(OperatorQosPolicyBuilder, PartialConfigLeavesOmittedCapsUnset) {
  const auto cfg = config_from(R"(
max_session_ambr_dl: "250 Mbps"
)");

  const auto policy = make_operator_qos_policy(cfg);

  EXPECT_TRUE(policy.allowed_dynamic_5qi.empty());
  EXPECT_FALSE(policy.max_flow_mbr_ul_bps.has_value());
  ASSERT_TRUE(policy.max_session_ambr_dl_bps.has_value());
  EXPECT_EQ(*policy.max_session_ambr_dl_bps, 250ULL * 1000 * 1000);
  EXPECT_FALSE(policy.reject_on_missing_subscription);
}
