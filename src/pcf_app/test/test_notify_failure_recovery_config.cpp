/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// Tests for the SMF notify-failure recovery config parsing
// (oai::config::pcf::notify_failure_recovery_config). Verifies that the
// `pcf.notify_failure_recovery` YAML block maps to the config getters that
// pcf_app.cpp converts into oai::pcf::app::notify_failure_recovery_policy
// these were flagged as open,
// unresolved numeric choices, exposed as operator-tunable rather than
// hardcoded].

#include <gtest/gtest.h>

#include <yaml-cpp/yaml.h>

#include <string>

#include "pcf_config_types.hpp"

using oai::config::pcf::notify_failure_recovery_config;

// A fully-populated block maps every field to its getter.
TEST(NotifyFailureRecoveryConfig, ParsesAllFields) {
  const YAML::Node node = YAML::Load(R"(
retry_drain_ttl_seconds: 45
retry_drain_max_entries: 500
max_notify_retries: 5
retry_backoff_initial_ms: 250
rollback_tracker_ttl_seconds: 60
rollback_tracker_max_entries: 2000
)");

  notify_failure_recovery_config cfg;
  cfg.from_yaml(node);

  EXPECT_EQ(cfg.get_retry_drain_ttl_seconds(), 45);
  EXPECT_EQ(cfg.get_retry_drain_max_entries(), 500);
  EXPECT_EQ(cfg.get_max_notify_retries(), 5);
  EXPECT_EQ(cfg.get_retry_backoff_initial_ms(), 250);
  EXPECT_EQ(cfg.get_rollback_tracker_ttl_seconds(), 60);
  EXPECT_EQ(cfg.get_rollback_tracker_max_entries(), 2000);
}

// An absent block keeps the documented defaults (etc/config.yaml).
TEST(NotifyFailureRecoveryConfig, DefaultsMatchDocumentedValues) {
  notify_failure_recovery_config cfg;  // no from_yaml() call

  EXPECT_EQ(cfg.get_retry_drain_ttl_seconds(), 30);
  EXPECT_EQ(cfg.get_retry_drain_max_entries(), 10000);
  EXPECT_EQ(cfg.get_max_notify_retries(), 3);
  EXPECT_EQ(cfg.get_retry_backoff_initial_ms(), 500);
  EXPECT_EQ(cfg.get_rollback_tracker_ttl_seconds(), 30);
  EXPECT_EQ(cfg.get_rollback_tracker_max_entries(), 10000);
}

// A partial block updates only the provided fields and leaves the rest at
// their defaults.
TEST(NotifyFailureRecoveryConfig, PartialBlockKeepsDefaultsForOmittedFields) {
  const YAML::Node node = YAML::Load(R"(
max_notify_retries: 10
)");

  notify_failure_recovery_config cfg;
  cfg.from_yaml(node);

  EXPECT_EQ(cfg.get_max_notify_retries(), 10);
  EXPECT_EQ(cfg.get_retry_drain_ttl_seconds(), 30);
  EXPECT_EQ(cfg.get_rollback_tracker_max_entries(), 10000);
}
