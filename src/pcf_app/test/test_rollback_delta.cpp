/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// Tests for compute_rollback_delta: the pure per-key staleness check that
// decides what a compensating rollback should touch.
// The property under test throughout: a key is compensated only
// if its value in the association's current ("live") decision still matches
// what the original commit set -- otherwise something else touched it since,
// and it must be left alone rather than risk orphaning a dependent PCC rule.

#include <gtest/gtest.h>

#include <memory>
#include <string>

#include "PccRule.h"
#include "QosCharacteristics.h"
#include "QosData.h"
#include "SmPolicyDecision.h"
#include "TrafficControlData.h"
#include "policy_auth/rollback_delta.hpp"
#include "sm_policy_delta.hpp"

using oai::model::pcf::PccRule;
using oai::model::pcf::QosCharacteristics;
using oai::model::pcf::QosData;
using oai::model::pcf::SmPolicyDecision;
using oai::model::pcf::TrafficControlData;
using oai::pcf::app::compute_sm_policy_delta;
using oai::pcf::app::sm_policy_delta;
using oai::pcf::app::policy_auth::compute_rollback_delta;
using oai::pcf::app::policy_auth::pending_commit;

namespace {

QosData make_qos(const std::string& id, int32_t r5qi) {
  QosData q;
  q.setQosId(id);
  q.setR5qi(r5qi);
  return q;
}

PccRule make_rule(const std::string& id, int32_t precedence) {
  PccRule r;
  r.setPccRuleId(id);
  r.setPrecedence(precedence);
  return r;
}

QosCharacteristics make_qos_char(int32_t r5qi) {
  QosCharacteristics c;
  c.setR5qi(r5qi);
  return c;
}

TrafficControlData make_tc(const std::string& id, bool mute_notif) {
  TrafficControlData t;
  t.setTcId(id);
  t.setMuteNotif(mute_notif);
  return t;
}

SmPolicyDecision decision_with_qos(std::map<std::string, QosData> qos_decs) {
  SmPolicyDecision d;
  d.setQosDecs(std::move(qos_decs));
  return d;
}

// Builds a pending_commit exactly the way apply_with_retry does: base
// snapshotted before the commit, committed_delta = the diff that landed.
pending_commit make_pending(
    const SmPolicyDecision& base, const SmPolicyDecision& updated,
    const std::string& app_session_id = "as-1") {
  pending_commit commit;
  commit.app_session_id  = app_session_id;
  commit.committed_delta = compute_sm_policy_delta(base, updated);
  commit.base            = std::make_shared<const SmPolicyDecision>(base);
  return commit;
}

}  // namespace

TEST(RollbackDelta, EmptyCommittedDeltaYieldsEmptyRollback) {
  auto base = decision_with_qos({{"A", make_qos("A", 9)}});
  const auto pending = make_pending(base, base);  // no-op commit

  const auto rollback = compute_rollback_delta(base, pending);

  EXPECT_TRUE(rollback.empty());
}

TEST(RollbackDelta, CreateIsCompensatedByRemoval) {
  auto base    = decision_with_qos({});
  auto updated = decision_with_qos({{"A", make_qos("A", 3)}});
  const auto pending = make_pending(base, updated);

  // Live still shows exactly what was committed -- unchanged since.
  const auto rollback = compute_rollback_delta(updated, pending);

  EXPECT_TRUE(rollback.upsert_qos_decs.empty());
  EXPECT_EQ(rollback.removed_qos_decs, (std::vector<std::string>{"A"}));
}

TEST(RollbackDelta, ModifyIsCompensatedByRestoringThePriorValue) {
  auto base    = decision_with_qos({{"A", make_qos("A", 9)}});
  auto updated = decision_with_qos({{"A", make_qos("A", 3)}});
  const auto pending = make_pending(base, updated);

  const auto rollback = compute_rollback_delta(updated, pending);

  ASSERT_EQ(rollback.upsert_qos_decs.count("A"), 1u);
  EXPECT_EQ(rollback.upsert_qos_decs.at("A").getR5qi(), 9);  // restored
  EXPECT_TRUE(rollback.removed_qos_decs.empty());
}

TEST(RollbackDelta, RemovalIsCompensatedByRestoringThePriorValue) {
  auto base    = decision_with_qos({{"A", make_qos("A", 9)}});
  auto updated = decision_with_qos({});  // A removed
  const auto pending = make_pending(base, updated);

  // Live still shows A absent -- unchanged since.
  const auto rollback = compute_rollback_delta(updated, pending);

  ASSERT_EQ(rollback.upsert_qos_decs.count("A"), 1u);
  EXPECT_EQ(rollback.upsert_qos_decs.at("A").getR5qi(), 9);
}

TEST(RollbackDelta, ChangedSinceUpsertIsSkipped) {
  auto base    = decision_with_qos({});
  auto updated = decision_with_qos({{"A", make_qos("A", 3)}});  // committed value
  const auto pending = make_pending(base, updated);

  // Something else changed A's value since this commit.
  auto live = decision_with_qos({{"A", make_qos("A", 7)}});
  const auto rollback = compute_rollback_delta(live, pending);

  EXPECT_TRUE(rollback.upsert_qos_decs.empty());
  EXPECT_TRUE(rollback.removed_qos_decs.empty());
}

TEST(RollbackDelta, ChangedSinceUpsertKeyNowAbsentIsSkipped) {
  auto base    = decision_with_qos({});
  auto updated = decision_with_qos({{"A", make_qos("A", 3)}});
  const auto pending = make_pending(base, updated);

  // Something else removed A entirely since this commit.
  auto live = decision_with_qos({});
  const auto rollback = compute_rollback_delta(live, pending);

  EXPECT_TRUE(rollback.upsert_qos_decs.empty());
  EXPECT_TRUE(rollback.removed_qos_decs.empty());
}

TEST(RollbackDelta, ChangedSinceRemovalIsSkipped) {
  auto base    = decision_with_qos({{"A", make_qos("A", 9)}});
  auto updated = decision_with_qos({});  // A removed by this commit
  const auto pending = make_pending(base, updated);

  // Something else re-created A since -- must not be clobbered by a restore.
  auto live = decision_with_qos({{"A", make_qos("A", 1)}});
  const auto rollback = compute_rollback_delta(live, pending);

  EXPECT_TRUE(rollback.upsert_qos_decs.empty());
}

TEST(RollbackDelta, IndependentKeysAreEvaluatedOnTheirOwnStaleness) {
  auto base = decision_with_qos({{"A", make_qos("A", 9)}, {"B", make_qos("B", 9)}});
  auto updated =
      decision_with_qos({{"A", make_qos("A", 3)}, {"B", make_qos("B", 4)}});
  const auto pending = make_pending(base, updated);

  // A unchanged since (compensable); B touched by someone else since (skip).
  auto live =
      decision_with_qos({{"A", make_qos("A", 3)}, {"B", make_qos("B", 99)}});
  const auto rollback = compute_rollback_delta(live, pending);

  ASSERT_EQ(rollback.upsert_qos_decs.count("A"), 1u);
  EXPECT_EQ(rollback.upsert_qos_decs.at("A").getR5qi(), 9);
  EXPECT_EQ(rollback.upsert_qos_decs.count("B"), 0u);
}

// Smoke tests: the same templated staleness check is instantiated for
// pccRules/qosChars/traffContDecs too -- not re-exercising every staleness
// permutation again, just confirming the generic path wires up correctly for
// each map type.
TEST(RollbackDelta, PccRulesCreateIsCompensatedByRemoval) {
  SmPolicyDecision base;
  SmPolicyDecision updated;
  updated.setPccRules({{"R1", make_rule("R1", 100)}});
  const auto pending = make_pending(base, updated);

  const auto rollback = compute_rollback_delta(updated, pending);

  EXPECT_EQ(rollback.removed_pcc_rules, (std::vector<std::string>{"R1"}));
}

TEST(RollbackDelta, QosCharsModifyIsCompensatedByRestoringThePriorValue) {
  SmPolicyDecision base;
  base.setQosChars({{"9", make_qos_char(9)}});
  SmPolicyDecision updated;
  updated.setQosChars({{"9", make_qos_char(3)}});
  const auto pending = make_pending(base, updated);

  const auto rollback = compute_rollback_delta(updated, pending);

  ASSERT_EQ(rollback.upsert_qos_chars.count("9"), 1u);
  EXPECT_EQ(rollback.upsert_qos_chars.at("9").getR5qi(), 9);
}

TEST(RollbackDelta, TraffContDecsCreateIsCompensatedByRemoval) {
  SmPolicyDecision base;
  SmPolicyDecision updated;
  updated.setTraffContDecs({{"T1", make_tc("T1", true)}});
  const auto pending = make_pending(base, updated);

  const auto rollback = compute_rollback_delta(updated, pending);

  EXPECT_EQ(rollback.removed_traff_cont_decs, (std::vector<std::string>{"T1"}));
}
