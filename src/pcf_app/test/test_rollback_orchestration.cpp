/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// Tests for perform_compensating_rollback: the fetch-live-then-apply
// orchestration step for a compensating rollback.
// This exists specifically to catch a REGRESSION of a real bug: an
// earlier version of this logic fed apply_with_retry the pending commit's own
// stale pre-commit base/post-commit version directly, instead of a freshly
// looked-up live decision/version. That made compute_rollback_delta's
// staleness check misfire as "changed since" for every key (the pre-commit
// base by definition never contains the values the commit itself set),
// silently no-op'ing the rollback whenever nothing else happened to force a
// real CAS conflict first -- the common case, not an edge case. The primary
// test below (UsesFreshLiveDecisionNotStalePendingBase) asserts exactly the
// property that broke: apply_with_retry must be called with the fresh lookup
// result, never the pending commit's own base/version.

#include <gtest/gtest.h>

#include <functional>
#include <memory>
#include <optional>
#include <set>
#include <string>

#include "PccRule.h"
#include "QosData.h"
#include "SmPolicyDecision.h"
#include "policy_auth/rollback_orchestration.hpp"
#include "sm_policy_delta.hpp"

using oai::model::pcf::QosData;
using oai::model::pcf::SmPolicyDecision;
using oai::pcf::app::compute_sm_policy_delta;
using oai::pcf::app::sm_policy_delta;
using oai::pcf::app::policy_auth::handler_result;
using oai::pcf::app::policy_auth::pending_commit;
using oai::pcf::app::policy_auth::perform_compensating_rollback;
using oai::pcf::app::policy_auth::status_code;

namespace {

QosData make_qos(const std::string& id, int32_t r5qi) {
  QosData q;
  q.setQosId(id);
  q.setR5qi(r5qi);
  return q;
}

SmPolicyDecision decision_with_qos(std::map<std::string, QosData> qos_decs) {
  SmPolicyDecision d;
  d.setQosDecs(std::move(qos_decs));
  return d;
}

std::set<std::string> keys(const std::map<std::string, QosData>& m) {
  std::set<std::string> k;
  for (const auto& e : m) k.insert(e.first);
  return k;
}

// A pending_commit whose pre-commit base is deliberately disjoint from any
// "live" decision used below, so accidentally feeding apply_with_retry the
// stale base instead of a fresh lookup is observable.
pending_commit make_pending(const std::string& app_session_id = "as-1") {
  pending_commit commit;
  commit.app_session_id = app_session_id;
  auto stale_base        = decision_with_qos({{"A", make_qos("A", 9)}});
  commit.committed_delta = compute_sm_policy_delta(
      stale_base, decision_with_qos({{"A", make_qos("A", 3)}}));
  commit.base = std::make_shared<const SmPolicyDecision>(stale_base);
  return commit;
}

}  // namespace

TEST(RollbackOrchestration, UsesFreshLiveDecisionNotStalePendingBase) {
  const pending_commit pending = make_pending();

  // The fake lookup returns state deliberately DIFFERENT from
  // pending.base/the tracked version -- simulating real time (and possibly
  // other commits) having passed since the original commit.
  auto live_decision = decision_with_qos({{"B", make_qos("B", 1)}});
  const std::uint64_t live_version = 42;

  bool apply_called = false;
  SmPolicyDecision captured_base;
  std::uint64_t captured_version = 0;

  auto fake_lookup = [&](
                          const std::string&, bool& found,
                          SmPolicyDecision& decision, std::uint64_t& version) {
    found    = true;
    decision = live_decision;
    version  = live_version;
  };
  auto fake_apply_with_retry =
      [&](std::optional<std::string>&, const SmPolicyDecision& base,
          std::uint64_t version, const std::function<handler_result(
                                      const SmPolicyDecision&,
                                      SmPolicyDecision&)>&,
          sm_policy_delta&, std::string&, const std::string&) {
        apply_called     = true;
        captured_base    = base;
        captured_version = version;
        return status_code::OK;
      };

  const auto result = perform_compensating_rollback(
      "assoc-1", /*version=*/5, pending, fake_lookup, fake_apply_with_retry);

  EXPECT_EQ(result, status_code::OK);
  ASSERT_TRUE(apply_called);
  // Fresh values from the lookup -- NOT pending.base ({A}) / tracked
  // version (5).
  EXPECT_EQ(captured_version, live_version);
  EXPECT_EQ(keys(captured_base.getQosDecs()), (std::set<std::string>{"B"}));
}

TEST(RollbackOrchestration, AssociationGoneSkipsRollbackAttemptEntirely) {
  const pending_commit pending = make_pending();
  bool apply_called = false;

  auto fake_lookup = [](
                          const std::string&, bool& found, SmPolicyDecision&,
                          std::uint64_t&) { found = false; };
  auto fake_apply_with_retry =
      [&](std::optional<std::string>&, const SmPolicyDecision&,
          std::uint64_t, const std::function<handler_result(
                              const SmPolicyDecision&, SmPolicyDecision&)>&,
          sm_policy_delta&, std::string&, const std::string&) {
        apply_called = true;
        return status_code::OK;
      };

  const auto result = perform_compensating_rollback(
      "assoc-1", 5, pending, fake_lookup, fake_apply_with_retry);

  EXPECT_EQ(result, status_code::NOT_FOUND);
  EXPECT_FALSE(apply_called);
}

TEST(RollbackOrchestration, PropagatesApplyWithRetryFailureResult) {
  const pending_commit pending = make_pending();

  auto fake_lookup = [](
                          const std::string&, bool& found,
                          SmPolicyDecision& decision, std::uint64_t& version) {
    found    = true;
    decision = SmPolicyDecision{};
    version  = 1;
  };
  auto fake_apply_with_retry =
      [](std::optional<std::string>&, const SmPolicyDecision&, std::uint64_t,
         const std::function<handler_result(
             const SmPolicyDecision&, SmPolicyDecision&)>&,
         sm_policy_delta&, std::string& problem_details,
         const std::string&) {
        problem_details = "REQUESTED_SERVICE_TEMPORARILY_NOT_AUTHORIZED";
        return status_code::FORBIDDEN;
      };

  const auto result = perform_compensating_rollback(
      "assoc-1", 5, pending, fake_lookup, fake_apply_with_retry);

  EXPECT_EQ(result, status_code::FORBIDDEN);
}

// Higher-fidelity check: the `derive` lambda perform_compensating_rollback
// builds internally must actually apply compute_rollback_delta's result
// against whatever base apply_with_retry hands it -- re-validating the glue
// between the two, not just that apply_with_retry receives fresh inputs.
TEST(RollbackOrchestration, DeriveLambdaAppliesTheComputedRollbackDelta) {
  auto pre_commit_base = decision_with_qos({});  // Q1 didn't exist yet
  auto committed        = decision_with_qos({{"Q1", make_qos("Q1", 9)}});

  pending_commit pending;
  pending.app_session_id  = "as-1";
  pending.committed_delta = compute_sm_policy_delta(pre_commit_base, committed);
  pending.base = std::make_shared<const SmPolicyDecision>(pre_commit_base);

  // Live == what was committed -- unchanged since, so compensable (§5.6).
  auto fake_lookup = [&](
                          const std::string&, bool& found,
                          SmPolicyDecision& decision, std::uint64_t& version) {
    found    = true;
    decision = committed;
    version  = 7;
  };

  SmPolicyDecision resulting_working;
  auto fake_apply_with_retry =
      [&](std::optional<std::string>&, const SmPolicyDecision& base,
          std::uint64_t, const std::function<handler_result(
                              const SmPolicyDecision&, SmPolicyDecision&)>&
                              derive,
          sm_policy_delta&, std::string&, const std::string&) {
        SmPolicyDecision working = base;
        derive(base, working);
        resulting_working = working;
        return status_code::OK;
      };

  const auto result = perform_compensating_rollback(
      "assoc-1", 7, pending, fake_lookup, fake_apply_with_retry);

  EXPECT_EQ(result, status_code::OK);
  // Q1's creation was rolled back.
  EXPECT_TRUE(resulting_working.getQosDecs().empty());
}
