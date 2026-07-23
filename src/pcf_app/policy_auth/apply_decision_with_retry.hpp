/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_APPLY_DECISION_WITH_RETRY_HPP_SEEN
#define FILE_APPLY_DECISION_WITH_RETRY_HPP_SEEN

#include <cstdint>
#include <functional>
#include <optional>
#include <string>

#include "SmPolicyDecision.h"
#include "pcf_policy_authorization_status_code.hpp"
#include "pending_rollback_tracker.hpp"
#include "sm_policy_delta.hpp"

namespace oai::pcf::app::policy_auth {

// Matches pcf_event::sm_update_decision's shape.
using sm_update_decision_fn = std::function<void(
    std::optional<std::string>& association_id, std::uint64_t expected_version,
    const oai::pcf::app::sm_policy_delta& delta,
    oai::pcf::app::decision_apply_result& result)>;

/**
 * @brief Push a request's decision change to the bound association with
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
 * effects, e.g. updating a session ledger), and records
 * `(association_id, committed version) -> what would need to be undone`
 * into `tracker`. On a deterministic failure
 * returns that failure. On retry exhaustion returns FORBIDDEN with
 * problem_details = REQUESTED_SERVICE_TEMPORARILY_NOT_AUTHORIZED
 * [TS 29.514 Table 5.7.3-1].
 *
 * Extracted as a free, dependency-injected function (sm_update_decision
 * injected instead of called via pcf_event/pcf_smpc directly) so the
 * CAS-retry/conflict/exhaustion mechanics -- shared by every Policy
 * Authorization handler (create/modify/delete/rollback) -- are directly
 * unit-testable without pcf_event/pcf_smpc. `tracker` is a real (not
 * injected) pending_rollback_tracker: recording into it on commit is a
 * cheap, already-independently-tested operation, not an external-system
 * boundary worth mocking.
 */
[[nodiscard]] status_code apply_decision_with_retry(
    std::optional<std::string>& association_id,
    const oai::model::pcf::SmPolicyDecision& initial_base,
    std::uint64_t initial_version, int max_retries,
    const std::function<handler_result(
        const oai::model::pcf::SmPolicyDecision& base,
        oai::model::pcf::SmPolicyDecision& working)>& derive,
    const sm_update_decision_fn& sm_update_decision,
    pending_rollback_tracker& tracker, const std::string& app_session_id,
    oai::pcf::app::sm_policy_delta& committed_delta,
    std::string& problem_details);

}  // namespace oai::pcf::app::policy_auth

#endif  // FILE_APPLY_DECISION_WITH_RETRY_HPP_SEEN
