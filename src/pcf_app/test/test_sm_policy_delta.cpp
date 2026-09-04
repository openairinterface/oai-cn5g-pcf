/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// Tests for sm_policy_delta: compute_sm_policy_delta (diff) and
// apply_sm_policy_delta. The critical property is that a delta computed against
// one base can be applied to a *different* base (one a concurrent writer has
// changed) and only touch the keys this writer actually changed -- this is what
// removes the lost-update race on concurrent PATCH of a shared association.

#include <gtest/gtest.h>

#include <map>
#include <set>
#include <string>
#include <vector>

#include "PccRule.h"
#include "QosData.h"
#include "SmPolicyContextData.h"
#include "SmPolicyDecision.h"
#include "policy_auth/qos_context.hpp"
#include "sm_policy/individual_sm_association.hpp"
#include "sm_policy/policy_decision.hpp"
#include "sm_policy_delta.hpp"

using oai::_3gpp::model::PccRule;
using oai::_3gpp::model::QosData;
using oai::_3gpp::model::SmPolicyContextData;
using oai::_3gpp::model::SmPolicyDecision;
using oai::pcf::app::apply_sm_policy_delta;
using oai::pcf::app::compute_sm_policy_delta;
using oai::pcf::app::sm_policy::individual_sm_association;
using oai::pcf::app::sm_policy::policy_decision;

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

SmPolicyDecision decision_with_qos(
    std::map<std::string, QosData> qos_decs,
    std::map<std::string, PccRule> pcc_rules = {}) {
  SmPolicyDecision d;
  d.setQosDecs(qos_decs);
  if (!pcc_rules.empty()) d.setPccRules(pcc_rules);
  return d;
}

std::set<std::string> keys(const std::map<std::string, QosData>& m) {
  std::set<std::string> k;
  for (const auto& e : m) k.insert(e.first);
  return k;
}

}  // namespace

TEST(SmPolicyDelta, ComputeDetectsAdded) {
  auto base    = decision_with_qos({{"A", make_qos("A", 9)}});
  auto updated = decision_with_qos({{"A", make_qos("A", 9)}, {"B", make_qos("B", 5)}});

  const auto delta = compute_sm_policy_delta(base, updated);

  EXPECT_EQ(keys(delta.upsert_qos_decs), (std::set<std::string>{"B"}));
  EXPECT_TRUE(delta.removed_qos_decs.empty());
}

TEST(SmPolicyDelta, ComputeDetectsModified) {
  auto base    = decision_with_qos({{"A", make_qos("A", 9)}});
  auto updated = decision_with_qos({{"A", make_qos("A", 3)}});  // 5QI changed

  const auto delta = compute_sm_policy_delta(base, updated);

  ASSERT_EQ(keys(delta.upsert_qos_decs), (std::set<std::string>{"A"}));
  EXPECT_EQ(delta.upsert_qos_decs.at("A").getR5qi(), 3);
}

TEST(SmPolicyDelta, ComputeDetectsRemoved) {
  auto base    = decision_with_qos({{"A", make_qos("A", 9)}, {"B", make_qos("B", 5)}});
  auto updated = decision_with_qos({{"A", make_qos("A", 9)}});

  const auto delta = compute_sm_policy_delta(base, updated);

  EXPECT_TRUE(delta.upsert_qos_decs.empty());
  EXPECT_EQ(delta.removed_qos_decs, (std::vector<std::string>{"B"}));
}

TEST(SmPolicyDelta, ComputeOmitsUnchangedAndIsEmpty) {
  auto base    = decision_with_qos({{"A", make_qos("A", 9)}});
  auto updated = decision_with_qos({{"A", make_qos("A", 9)}});

  const auto delta = compute_sm_policy_delta(base, updated);

  EXPECT_TRUE(delta.empty());
}

TEST(SmPolicyDelta, ApplyUpsertsAndRemoves) {
  auto base    = decision_with_qos({{"A", make_qos("A", 9)}, {"B", make_qos("B", 5)}});
  auto updated = decision_with_qos({{"A", make_qos("A", 3)}, {"C", make_qos("C", 7)}});
  const auto delta = compute_sm_policy_delta(base, updated);  // mod A, add C, remove B

  SmPolicyDecision live = base;
  apply_sm_policy_delta(live, delta);

  EXPECT_EQ(keys(live.getQosDecs()), (std::set<std::string>{"A", "C"}));
  EXPECT_EQ(live.getQosDecs().at("A").getR5qi(), 3);
}

// The lost-update fix: two writers each read the same base {A}, one adds B, the
// other adds C. Applying both deltas to the shared decision yields {A,B,C} --
// neither overwrites the other, which a whole-decision replace would.
TEST(SmPolicyDelta, ConcurrentDisjointDeltasDoNotLoseUpdates) {
  auto base = decision_with_qos({{"A", make_qos("A", 9)}});

  auto updated1 = decision_with_qos({{"A", make_qos("A", 9)}, {"B", make_qos("B", 5)}});
  auto updated2 = decision_with_qos({{"A", make_qos("A", 9)}, {"C", make_qos("C", 7)}});
  const auto delta1 = compute_sm_policy_delta(base, updated1);  // add B
  const auto delta2 = compute_sm_policy_delta(base, updated2);  // add C

  SmPolicyDecision live = base;
  apply_sm_policy_delta(live, delta1);  // writer 1
  apply_sm_policy_delta(live, delta2);  // writer 2, against writer 1's result

  EXPECT_EQ(keys(live.getQosDecs()), (std::set<std::string>{"A", "B", "C"}));
}

// A delta that only adds must NOT resurrect an entry another writer removed:
// unchanged keys are omitted, so writer-1's "add B" never re-asserts A or C.
TEST(SmPolicyDelta, UpsertDeltaDoesNotResurrectConcurrentlyRemovedEntry) {
  auto base = decision_with_qos({{"A", make_qos("A", 9)}, {"C", make_qos("C", 7)}});
  // Writer 1 only adds B (A and C unchanged in its view).
  auto updated1 = decision_with_qos(
      {{"A", make_qos("A", 9)}, {"C", make_qos("C", 7)}, {"B", make_qos("B", 5)}});
  const auto delta1 = compute_sm_policy_delta(base, updated1);

  // Writer 2 concurrently removed C; live already reflects that.
  SmPolicyDecision live = decision_with_qos({{"A", make_qos("A", 9)}});
  apply_sm_policy_delta(live, delta1);

  EXPECT_EQ(keys(live.getQosDecs()), (std::set<std::string>{"A", "B"}));  // C stays gone
}

TEST(SmPolicyDelta, PccRulesTrackedIndependently) {
  auto base    = decision_with_qos({}, {{"R1", make_rule("R1", 1000)}});
  auto updated = decision_with_qos({}, {{"R1", make_rule("R1", 1000)}, {"R2", make_rule("R2", 1001)}});

  const auto delta = compute_sm_policy_delta(base, updated);

  EXPECT_TRUE(delta.upsert_qos_decs.empty());
  ASSERT_EQ(delta.upsert_pcc_rules.size(), 1u);
  EXPECT_EQ(delta.upsert_pcc_rules.count("R2"), 1u);
}

// Association-level copy-on-write: applying deltas to the association is an
// atomic read-modify-write on the held decision. Two disjoint writers both land
// (the lost-update fix at the layer that actually holds the decision).
TEST(SmPolicyDeltaCow, AssociationApplyDeltaIsAtomicReadModifyWrite) {
  auto base = decision_with_qos({{"A", make_qos("A", 9)}});
  policy_decision pd(base);
  individual_sm_association assoc(SmPolicyContextData{}, pd, "assoc-1");

  const auto add_b = compute_sm_policy_delta(
      base, decision_with_qos({{"A", make_qos("A", 9)}, {"B", make_qos("B", 5)}}));
  const auto add_c = compute_sm_policy_delta(
      base, decision_with_qos({{"A", make_qos("A", 9)}, {"C", make_qos("C", 7)}}));

  const uint64_t v0 = assoc.decision_version();
  assoc.apply_delta(add_b);
  assoc.apply_delta(add_c);

  EXPECT_EQ(
      keys(assoc.get_sm_policy_decision_dto().getQosDecs()),
      (std::set<std::string>{"A", "B", "C"}));
  EXPECT_EQ(assoc.decision_version(), v0 + 2);
}

// A snapshot taken before an apply keeps seeing the old immutable decision;
// this is what lets the notify run off-lock against a stable view.
TEST(SmPolicyDeltaCow, SnapshotIsImmutableAcrossSubsequentApply) {
  auto base = decision_with_qos({{"A", make_qos("A", 9)}});
  policy_decision pd(base);
  individual_sm_association assoc(SmPolicyContextData{}, pd, "assoc-2");

  const auto snap_before = assoc.snapshot_decision();
  const auto add_b = compute_sm_policy_delta(
      base, decision_with_qos({{"A", make_qos("A", 9)}, {"B", make_qos("B", 5)}}));
  assoc.apply_delta(add_b);

  EXPECT_EQ(keys(snap_before->getQosDecs()), (std::set<std::string>{"A"}));
  EXPECT_EQ(
      keys(assoc.snapshot_decision()->getQosDecs()),
      (std::set<std::string>{"A", "B"}));
}

// Mirrors the version-CAS (compare-and-swap) + retry loop in
// pcf_policy_authorization.cpp. Two
// requests read the same (decision, version). Writer 1 commits, so writer 2's
// expected version is now stale: instead of clobbering, it detects the mismatch,
// re-derives its intent against the freshly committed snapshot, and retries. The
// result is the MERGE of both intents -- no lost update, no stale cumulative
// base. This is exactly what closes both races the snapshot analysis surfaced.
TEST(SmPolicyDeltaCow, StaleWriterReDerivesAgainstCommittedBaseAndConverges) {
  auto base = decision_with_qos({{"A", make_qos("A", 9)}});
  policy_decision pd(base);
  individual_sm_association assoc(SmPolicyContextData{}, pd, "assoc-3");

  // Both requests bind and read the same base + version.
  const uint64_t expected_v = assoc.decision_version();
  const auto shared_base    = assoc.snapshot_decision();

  // Writer 1 derives "add B" against the shared base and commits (CAS holds).
  auto w1_updated = *shared_base;
  {
    auto q  = w1_updated.getQosDecs();
    q["B"]  = make_qos("B", 5);
    w1_updated.setQosDecs(q);
  }
  ASSERT_EQ(assoc.decision_version(), expected_v);  // still unchanged: CAS holds
  assoc.apply_delta(compute_sm_policy_delta(*shared_base, w1_updated));

  // Writer 2 wanted "add C" against the same stale base. Its CAS now fails.
  ASSERT_NE(assoc.decision_version(), expected_v);  // conflict detected

  // Retry: re-derive "add C" against the CURRENT committed snapshot (which now
  // has B), then apply. A blind whole-decision write of the stale base would
  // have dropped B here.
  const auto fresh = assoc.snapshot_decision();
  auto w2_updated  = *fresh;
  {
    auto q  = w2_updated.getQosDecs();
    q["C"]  = make_qos("C", 7);
    w2_updated.setQosDecs(q);
  }
  assoc.apply_delta(compute_sm_policy_delta(*fresh, w2_updated));

  EXPECT_EQ(
      keys(assoc.get_sm_policy_decision_dto().getQosDecs()),
      (std::set<std::string>{"A", "B", "C"}));
}

// qos_context is the app-session's ownership ledger. It is reconciled ONLY from a
// committed delta (never during derivation, which writes to a scratch context),
// so a rejected/retried attempt leaves no trace. Upserts become owned; removals
// are dropped.
TEST(QosContextCommit, ApplyCommittedDeltaRecordsUpsertsThenDropsRemovals) {
  using oai::pcf::app::policy_auth::qos_context;

  const auto empty = decision_with_qos({});
  const auto with_entries =
      decision_with_qos({{"Q1", make_qos("Q1", 9)}}, {{"R1", make_rule("R1", 100)}});

  qos_context ctx;
  ctx.apply_committed_delta(compute_sm_policy_delta(empty, with_entries));

  const auto qos_ids  = ctx.owned_qos_ids();
  const auto rule_ids = ctx.owned_rule_ids();
  EXPECT_EQ(
      std::set<std::string>(qos_ids.begin(), qos_ids.end()),
      (std::set<std::string>{"Q1"}));
  EXPECT_EQ(
      std::set<std::string>(rule_ids.begin(), rule_ids.end()),
      (std::set<std::string>{"R1"}));

  // A subsequent committed delta that removes them drops ownership.
  ctx.apply_committed_delta(compute_sm_policy_delta(with_entries, empty));
  EXPECT_TRUE(ctx.owned_qos_ids().empty());
  EXPECT_TRUE(ctx.owned_rule_ids().empty());
}
