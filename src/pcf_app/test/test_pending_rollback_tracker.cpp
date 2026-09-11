/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// Tests for pending_rollback_tracker: the PA-side "which commit does this
// (association_id, version) refer to" table [N5_QoS_Phase2_§2.8 plan §5.4].
// record()/try_take() form the correctness contract (record then take back
// exactly once); sweep_expired()/record()'s cap enforcement are the two
// bounding safeguards that keep this table from leaking under sustained SMF
// failures.

#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <string>

#include "QosData.h"
#include "SmPolicyDecision.h"
#include "policy_auth/decision_applier.hpp"
#include "sm_policy_delta.hpp"

using oai::_3gpp::model::QosData;
using oai::_3gpp::model::SmPolicyDecision;
using oai::pcf::app::sm_policy_delta;
using oai::pcf::app::policy_auth::pending_commit;
using oai::pcf::app::policy_auth::pending_rollback_tracker;

namespace {

pending_commit make_commit(const std::string& app_session_id) {
  pending_commit commit;
  commit.app_session_id = app_session_id;

  QosData qos;
  qos.setQosId("Q1");
  qos.setR5qi(9);
  commit.committed_delta.upsert_qos_decs["Q1"] = qos;

  commit.base = std::make_shared<const SmPolicyDecision>();
  return commit;
}

}  // namespace

TEST(PendingRollbackTracker, TryTakeOnEmptyReturnsNullopt) {
  pending_rollback_tracker tracker(std::chrono::seconds(30), 100);
  EXPECT_FALSE(tracker.try_take("assoc-1", 1).has_value());
}

TEST(PendingRollbackTracker, RecordThenTryTakeReturnsIt) {
  pending_rollback_tracker tracker(std::chrono::seconds(30), 100);
  tracker.record("assoc-1", 1, make_commit("as-1"));

  auto taken = tracker.try_take("assoc-1", 1);
  ASSERT_TRUE(taken.has_value());
  EXPECT_EQ(taken->app_session_id, "as-1");
  EXPECT_EQ(taken->committed_delta.upsert_qos_decs.count("Q1"), 1u);
}

TEST(PendingRollbackTracker, TryTakeConsumesTheEntry) {
  pending_rollback_tracker tracker(std::chrono::seconds(30), 100);
  tracker.record("assoc-1", 1, make_commit("as-1"));

  ASSERT_TRUE(tracker.try_take("assoc-1", 1).has_value());
  // Second take for the same key: already consumed.
  EXPECT_FALSE(tracker.try_take("assoc-1", 1).has_value());
}

TEST(PendingRollbackTracker, TryTakeWithMismatchedVersionReturnsNullopt) {
  pending_rollback_tracker tracker(std::chrono::seconds(30), 100);
  tracker.record("assoc-1", 1, make_commit("as-1"));

  EXPECT_FALSE(tracker.try_take("assoc-1", 2).has_value());
  // The original key is untouched by the failed lookup.
  EXPECT_TRUE(tracker.try_take("assoc-1", 1).has_value());
}

TEST(PendingRollbackTracker, TryTakeWithMismatchedAssociationIdReturnsNullopt) {
  pending_rollback_tracker tracker(std::chrono::seconds(30), 100);
  tracker.record("assoc-1", 1, make_commit("as-1"));

  EXPECT_FALSE(tracker.try_take("assoc-2", 1).has_value());
}

TEST(PendingRollbackTracker, RecordAtCapacityDropsTheNewEntry) {
  pending_rollback_tracker tracker(std::chrono::seconds(30), 1);
  tracker.record("assoc-1", 1, make_commit("as-1"));
  tracker.record("assoc-2", 1, make_commit("as-2"));  // over cap -- dropped

  EXPECT_TRUE(tracker.try_take("assoc-1", 1).has_value());
  EXPECT_FALSE(tracker.try_take("assoc-2", 1).has_value());
}

TEST(PendingRollbackTracker, RecordAfterFreeingCapacitySucceeds) {
  pending_rollback_tracker tracker(std::chrono::seconds(30), 1);
  tracker.record("assoc-1", 1, make_commit("as-1"));
  ASSERT_TRUE(tracker.try_take("assoc-1", 1).has_value());  // frees the slot

  tracker.record("assoc-2", 1, make_commit("as-2"));
  EXPECT_TRUE(tracker.try_take("assoc-2", 1).has_value());
}

// sweep_expired takes an explicit `now`, so the TTL boundary is tested by
// varying that argument rather than sleeping -- deterministic and fast, per
// the design's own "unit-testable without a real timerfd/thread" goal.
TEST(PendingRollbackTracker, SweepExpiredRemovesEntriesOlderThanTtl) {
  pending_rollback_tracker tracker(std::chrono::seconds(10), 100);
  const auto approx_record_time = std::chrono::steady_clock::now();
  tracker.record("assoc-1", 1, make_commit("as-1"));

  tracker.sweep_expired(approx_record_time + std::chrono::seconds(20));

  EXPECT_FALSE(tracker.try_take("assoc-1", 1).has_value());
}

TEST(PendingRollbackTracker, SweepExpiredLeavesFreshEntriesAlone) {
  pending_rollback_tracker tracker(std::chrono::seconds(10), 100);
  const auto approx_record_time = std::chrono::steady_clock::now();
  tracker.record("assoc-1", 1, make_commit("as-1"));

  tracker.sweep_expired(approx_record_time + std::chrono::seconds(1));

  EXPECT_TRUE(tracker.try_take("assoc-1", 1).has_value());
}

TEST(PendingRollbackTracker, DistinctVersionsOnSameAssociationAreIndependent) {
  pending_rollback_tracker tracker(std::chrono::seconds(30), 100);
  tracker.record("assoc-1", 1, make_commit("as-1"));
  tracker.record("assoc-1", 2, make_commit("as-2"));

  auto v1 = tracker.try_take("assoc-1", 1);
  auto v2 = tracker.try_take("assoc-1", 2);
  ASSERT_TRUE(v1.has_value());
  ASSERT_TRUE(v2.has_value());
  EXPECT_EQ(v1->app_session_id, "as-1");
  EXPECT_EQ(v2->app_session_id, "as-2");
}
