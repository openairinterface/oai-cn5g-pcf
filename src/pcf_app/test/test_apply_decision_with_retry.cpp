/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// Tests for apply_decision_with_retry: the optimistic-concurrency CAS-retry
// loop shared by every Policy Authorization handler (create/modify/delete/
// rollback). Extracted from pcf_policy_authorization::apply_with_retry so
// this mechanics -- deterministic-failure short-circuit, conflict-then-
// re-derive, retry exhaustion, and the pending_rollback_tracker recording
// on commit -- is directly unit-tested without pcf_event/pcf_smpc.

#include <gtest/gtest.h>

#include <memory>
#include <optional>
#include <string>

#include "QosData.h"
#include "SmPolicyDecision.h"
#include "policy_auth/apply_decision_with_retry.hpp"

using oai::model::pcf::QosData;
using oai::model::pcf::SmPolicyDecision;
using oai::pcf::app::decision_apply_result;
using oai::pcf::app::sm_policy_delta;
using oai::pcf::app::policy_auth::apply_decision_with_retry;
using oai::pcf::app::policy_auth::handler_result;
using oai::pcf::app::policy_auth::pending_rollback_tracker;
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

// A derive that always adds/refreshes key "X" -> the given r5qi, regardless
// of base -- pure and idempotent, fine to re-run on a conflict retry.
auto make_derive(int32_t r5qi) {
  return [r5qi](
             const SmPolicyDecision& base,
             SmPolicyDecision& working) -> handler_result {
    working         = base;
    auto qos        = working.getQosDecs();
    qos["X"]        = make_qos("X", r5qi);
    working.setQosDecs(qos);
    return {};
  };
}

}  // namespace

TEST(ApplyDecisionWithRetry, FirstAttemptCommitsAndRecordsToTracker) {
  pending_rollback_tracker tracker(std::chrono::seconds(30), 100);
  std::optional<std::string> association_id = "assoc-1";
  SmPolicyDecision initial_base = decision_with_qos({});
  sm_policy_delta committed_delta;
  std::string problem_details;

  int sm_update_decision_calls = 0;
  auto sm_update_decision = [&](
                                std::optional<std::string>&, std::uint64_t,
                                const sm_policy_delta&,
                                decision_apply_result& result) {
    ++sm_update_decision_calls;
    result.committed = true;
    result.version   = 1;
    result.decision =
        std::make_shared<const SmPolicyDecision>(decision_with_qos({}));
  };

  const auto result = apply_decision_with_retry(
      association_id, initial_base, /*initial_version=*/0, /*max_retries=*/3,
      make_derive(9), sm_update_decision, tracker, "as-1", committed_delta,
      problem_details);

  EXPECT_EQ(result, status_code::OK);
  EXPECT_EQ(sm_update_decision_calls, 1);
  ASSERT_EQ(committed_delta.upsert_qos_decs.count("X"), 1u);
  EXPECT_EQ(committed_delta.upsert_qos_decs.at("X").getR5qi(), 9);

  auto tracked = tracker.try_take("assoc-1", 1);
  ASSERT_TRUE(tracked.has_value());
  EXPECT_EQ(tracked->app_session_id, "as-1");
}

TEST(ApplyDecisionWithRetry, DeterministicDeriveFailureShortCircuits) {
  pending_rollback_tracker tracker(std::chrono::seconds(30), 100);
  std::optional<std::string> association_id = "assoc-1";
  SmPolicyDecision initial_base = decision_with_qos({});
  sm_policy_delta committed_delta;
  std::string problem_details;

  bool sm_update_decision_called = false;
  auto sm_update_decision = [&](
                                std::optional<std::string>&, std::uint64_t,
                                const sm_policy_delta&,
                                decision_apply_result&) {
    sm_update_decision_called = true;
  };
  auto derive = [](const SmPolicyDecision&, SmPolicyDecision&)
      -> handler_result {
    return {status_code::FORBIDDEN, std::string("REQUESTED_SERVICE_NOT_AUTHORIZED")};
  };

  const auto result = apply_decision_with_retry(
      association_id, initial_base, 0, 3, derive, sm_update_decision, tracker,
      "as-1", committed_delta, problem_details);

  EXPECT_EQ(result, status_code::FORBIDDEN);
  EXPECT_EQ(problem_details, "REQUESTED_SERVICE_NOT_AUTHORIZED");
  // A deterministic failure never even reaches the CAS call -- retrying
  // would fail identically.
  EXPECT_FALSE(sm_update_decision_called);
}

TEST(ApplyDecisionWithRetry, ConflictRederivesAgainstFreshlyCommittedBase) {
  pending_rollback_tracker tracker(std::chrono::seconds(30), 100);
  std::optional<std::string> association_id = "assoc-1";
  SmPolicyDecision initial_base = decision_with_qos({});
  sm_policy_delta committed_delta;
  std::string problem_details;

  // Each attempt's derive receives whatever `base` the loop hands it; record
  // what "Y"'s value in base was, so the test can confirm the SECOND attempt
  // really did see the freshly-committed base (Y=42), not the stale initial
  // one (Y absent).
  std::vector<std::optional<int32_t>> bases_seen_y;
  auto derive = [&](
                    const SmPolicyDecision& base,
                    SmPolicyDecision& working) -> handler_result {
    const auto qos_decs = base.getQosDecs();
    auto y_it = qos_decs.find("Y");
    bases_seen_y.push_back(
        y_it == qos_decs.end() ? std::nullopt
                                : std::optional<int32_t>(y_it->second.getR5qi()));
    working  = base;
    auto qos = working.getQosDecs();
    qos["X"] = make_qos("X", 9);
    working.setQosDecs(qos);
    return {};
  };

  int call_count = 0;
  auto sm_update_decision = [&](
                                std::optional<std::string>&, std::uint64_t,
                                const sm_policy_delta&,
                                decision_apply_result& result) {
    ++call_count;
    if (call_count == 1) {
      // First attempt conflicts: someone else committed "Y" first.
      result.committed = false;
      result.version   = 5;
      result.decision  = std::make_shared<const SmPolicyDecision>(
          decision_with_qos({{"Y", make_qos("Y", 42)}}));
      return;
    }
    // Second attempt (re-derived against the fresh base) commits.
    result.committed = true;
    result.version   = 6;
    result.decision  = std::make_shared<const SmPolicyDecision>(
        decision_with_qos({{"Y", make_qos("Y", 42)}}));
  };

  const auto result = apply_decision_with_retry(
      association_id, initial_base, 0, /*max_retries=*/3, derive,
      sm_update_decision, tracker, "as-1", committed_delta, problem_details);

  EXPECT_EQ(result, status_code::OK);
  EXPECT_EQ(call_count, 2);
  ASSERT_EQ(bases_seen_y.size(), 2u);
  EXPECT_FALSE(bases_seen_y[0].has_value());   // 1st attempt: stale, no Y
  ASSERT_TRUE(bases_seen_y[1].has_value());    // 2nd attempt: fresh, has Y
  EXPECT_EQ(*bases_seen_y[1], 42);
}

TEST(ApplyDecisionWithRetry, ExhaustsAfterMaxRetriesReturnsForbidden) {
  pending_rollback_tracker tracker(std::chrono::seconds(30), 100);
  std::optional<std::string> association_id = "assoc-1";
  SmPolicyDecision initial_base = decision_with_qos({});
  sm_policy_delta committed_delta;
  std::string problem_details;

  int call_count = 0;
  auto sm_update_decision = [&](
                                std::optional<std::string>&, std::uint64_t,
                                const sm_policy_delta&,
                                decision_apply_result& result) {
    ++call_count;
    // Perpetual conflict -- never commits, always hands back a valid,
    // freshly-conflicting decision.
    result.committed = false;
    result.version   = 100 + call_count;
    result.decision  = std::make_shared<const SmPolicyDecision>(initial_base);
  };

  const auto result = apply_decision_with_retry(
      association_id, initial_base, 0, /*max_retries=*/1, make_derive(9),
      sm_update_decision, tracker, "as-1", committed_delta, problem_details);

  EXPECT_EQ(result, status_code::FORBIDDEN);
  EXPECT_EQ(problem_details, "REQUESTED_SERVICE_TEMPORARILY_NOT_AUTHORIZED");
  // attempt 0 (0>=1? no, retry) and attempt 1 (1>=1? yes, exhaust): 2 calls.
  EXPECT_EQ(call_count, 2);
  // Nothing committed -- the tracker must stay empty.
  EXPECT_FALSE(tracker.try_take("assoc-1", 101).has_value());
  EXPECT_FALSE(tracker.try_take("assoc-1", 102).has_value());
}

TEST(ApplyDecisionWithRetry, ConflictWithNoDecisionExhaustsImmediately) {
  pending_rollback_tracker tracker(std::chrono::seconds(30), 100);
  std::optional<std::string> association_id = "assoc-1";
  SmPolicyDecision initial_base = decision_with_qos({});
  sm_policy_delta committed_delta;
  std::string problem_details;

  int call_count = 0;
  auto sm_update_decision = [&](
                                std::optional<std::string>&, std::uint64_t,
                                const sm_policy_delta&,
                                decision_apply_result& result) {
    ++call_count;
    // Association gone: conflict reported with no decision to re-derive
    // against, regardless of how many retries remain.
    result.committed = false;
    result.decision  = nullptr;
  };

  const auto result = apply_decision_with_retry(
      association_id, initial_base, 0, /*max_retries=*/5, make_derive(9),
      sm_update_decision, tracker, "as-1", committed_delta, problem_details);

  EXPECT_EQ(result, status_code::FORBIDDEN);
  EXPECT_EQ(call_count, 1);
}
