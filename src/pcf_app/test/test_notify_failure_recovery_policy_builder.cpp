/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// Tests for make_notify_failure_recovery_policy() -- the config -> runtime
// translation that converts the parsed pcf.notify_failure_recovery block
// (plain ints/seconds/ms) into the notify_failure_recovery_policy consumed
// by pcf_smpc's retry_drain_queue and policy_auth_context's
// pending_rollback_tracker.

#include <gtest/gtest.h>

#include <yaml-cpp/yaml.h>

#include <chrono>

#include "pcf_config_types.hpp"
#include "pcf_runtime_policy.hpp"

using oai::config::pcf::notify_failure_recovery_config;
using oai::pcf::app::make_notify_failure_recovery_policy;

namespace {

notify_failure_recovery_config config_from(const std::string& yaml) {
  notify_failure_recovery_config cfg;
  cfg.from_yaml(YAML::Load(yaml));
  return cfg;
}

}  // namespace

// A fully-populated block converts every field into the matching
// std::chrono/size_t/int runtime type.
TEST(NotifyFailureRecoveryPolicyBuilder, ConvertsAllFields) {
  const auto cfg = config_from(R"(
retry_drain_ttl_seconds: 45
retry_drain_max_entries: 500
max_notify_retries: 5
retry_backoff_initial_ms: 250
rollback_tracker_ttl_seconds: 60
rollback_tracker_max_entries: 2000
)");

  const auto policy = make_notify_failure_recovery_policy(cfg);

  EXPECT_EQ(policy.retry_drain_ttl, std::chrono::seconds(45));
  EXPECT_EQ(policy.retry_drain_max_entries, 500u);
  EXPECT_EQ(policy.max_notify_retries, 5);
  EXPECT_EQ(policy.retry_backoff_initial, std::chrono::milliseconds(250));
  EXPECT_EQ(policy.rollback_tracker_ttl, std::chrono::seconds(60));
  EXPECT_EQ(policy.rollback_tracker_max_entries, 2000u);
}

// Defaults (empty block) match notify_failure_recovery_policy's own default
// member initializers, so a default-constructed policy and one built from an
// empty config agree.
TEST(NotifyFailureRecoveryPolicyBuilder, EmptyConfigMatchesDefaultPolicy) {
  const notify_failure_recovery_config cfg;  // defaults, no from_yaml()

  const auto policy = make_notify_failure_recovery_policy(cfg);
  const oai::pcf::app::notify_failure_recovery_policy default_policy;

  EXPECT_EQ(policy.retry_drain_ttl, default_policy.retry_drain_ttl);
  EXPECT_EQ(
      policy.retry_drain_max_entries, default_policy.retry_drain_max_entries);
  EXPECT_EQ(policy.max_notify_retries, default_policy.max_notify_retries);
  EXPECT_EQ(
      policy.retry_backoff_initial, default_policy.retry_backoff_initial);
  EXPECT_EQ(policy.rollback_tracker_ttl, default_policy.rollback_tracker_ttl);
  EXPECT_EQ(
      policy.rollback_tracker_max_entries,
      default_policy.rollback_tracker_max_entries);
}

// A partial block converts only the provided fields; the rest keep their
// default values.
TEST(NotifyFailureRecoveryPolicyBuilder, PartialConfigLeavesOmittedFieldsDefault) {
  const auto cfg = config_from(R"(
max_notify_retries: 10
)");

  const auto policy = make_notify_failure_recovery_policy(cfg);

  EXPECT_EQ(policy.max_notify_retries, 10);
  EXPECT_EQ(policy.retry_drain_ttl, std::chrono::seconds(30));
  EXPECT_EQ(policy.rollback_tracker_max_entries, 10000u);
}
