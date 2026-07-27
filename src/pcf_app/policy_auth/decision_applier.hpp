/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_DECISION_APPLIER_HPP_SEEN
#define FILE_DECISION_APPLIER_HPP_SEEN

#include <cstdint>
#include <functional>
#include <optional>
#include <string>

#include "SmPolicyDecision.h"
#include "pcf_policy_authorization_status_code.hpp"
#include "pending_rollback_tracker.hpp"
#include "sm_policy_delta.hpp"

namespace oai::pcf::app::policy_auth {

// Matches pcf_event::sm_update_decision's shape
using sm_update_decision_fn = std::function<void(
    std::optional<std::string>& association_id, std::uint64_t expected_version,
    const oai::pcf::app::sm_policy_delta& delta,
    oai::pcf::app::decision_apply_result& result)>;

// Everything about a single apply() call that varies request-to-request, as
// opposed to sm_update_decision/tracker/max_retries -- constant across every
// call, so they are bound once at decision_applier construction instead.
struct decision_apply_request {
  std::optional<std::string>& association_id;
  const oai::model::pcf::SmPolicyDecision& initial_base;
  std::uint64_t initial_version;
  const std::string& app_session_id;
};

/**
 * @brief Pushes a request's decision change to the bound association with
 * optimistic concurrency + bounded retry.
 *
 * `derive` is invoked once per attempt with the current base decision; it
 * must copy-and-mutate `working` into this request's intended decision and
 * return an empty handler_result, or a set handler_result for a
 * *deterministic* failure (403/400/...) that no retry can fix. The delta
 * (base -> working) is applied to the association only if it is still at
 * the base's version (via the injected `sm_update_decision`); on a version
 * conflict `derive` is re-run against the freshly committed decision, up to
 * `max_retries` times.
 *
 * On success returns status_code::OK, fills `committed_delta` (the delta
 * that was applied -- callers use it for their own post-commit side
 * effects, e.g. updating a session ledger) and `committed_version` (the
 * version the commit landed at -- callers use it to drive the SMF notify
 * step, which this class deliberately does NOT do;
 *
 * On a deterministic failure returns that failure. On retry
 * exhaustion returns FORBIDDEN with problem_details =
 * REQUESTED_SERVICE_TEMPORARILY_NOT_AUTHORIZED [TS 29.514 Table 5.7.3-1].
 *
 * sm_update_decision, the pending_rollback_tracker, and max_retries are
 * identical on every call for a given owner (e.g. every Policy Authorization
 * handler -- create/modify/delete/rollback -- shares one instance), so they
 * are constructor-injected instead of re-supplied as arguments. `tracker` is
 * a real (not injected) pending_rollback_tracker.
 */
class decision_applier {
 public:
  decision_applier(
      sm_update_decision_fn sm_update_decision,
      pending_rollback_tracker& tracker, int max_retries);

  [[nodiscard]] status_code apply(
      decision_apply_request request,
      const std::function<handler_result(
          const oai::model::pcf::SmPolicyDecision& base,
          oai::model::pcf::SmPolicyDecision& working)>& derive,
      oai::pcf::app::sm_policy_delta& committed_delta,
      std::string& problem_details, std::uint64_t& committed_version);

 private:
  sm_update_decision_fn m_sm_update_decision;
  pending_rollback_tracker& m_tracker;
  int m_max_retries;
};

}  // namespace oai::pcf::app::policy_auth

#endif  // FILE_DECISION_APPLIER_HPP_SEEN
