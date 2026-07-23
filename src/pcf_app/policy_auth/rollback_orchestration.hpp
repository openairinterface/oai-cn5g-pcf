/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_ROLLBACK_ORCHESTRATION_HPP_SEEN
#define FILE_ROLLBACK_ORCHESTRATION_HPP_SEEN

#include <cstdint>
#include <functional>
#include <optional>
#include <string>

#include "SmPolicyDecision.h"
#include "pcf_policy_authorization_status_code.hpp"
#include "pending_rollback_tracker.hpp"
#include "sm_policy_delta.hpp"

namespace oai::pcf::app::policy_auth {

// Matches pcf_event::sm_get_association_decision's shape: given an
// association_id, report whether it still exists and, if so, its CURRENT
// decision + version. (association_id in; found, decision, version out.)
using live_decision_lookup_fn = std::function<void(
    const std::string& association_id, bool& found,
    oai::model::pcf::SmPolicyDecision& decision, std::uint64_t& version)>;

// Matches pcf_policy_authorization::apply_with_retry's shape.
using apply_with_retry_fn = std::function<status_code(
    std::optional<std::string>& association_id,
    const oai::model::pcf::SmPolicyDecision& initial_base,
    std::uint64_t initial_version,
    const std::function<handler_result(
        const oai::model::pcf::SmPolicyDecision& base,
        oai::model::pcf::SmPolicyDecision& working)>& derive,
    oai::pcf::app::sm_policy_delta& committed_delta,
    std::string& problem_details, const std::string& app_session_id)>;

/**
 * @brief Push a compensating-delta rollback for `commit` through the CAS-
 * retry loop `apply_with_retry` implements, fed a rollback-shaped `derive`
 * instead of an AF-request-shaped one.
 *
 * `lookup_live_decision` and `apply_with_retry` are injected rather than
 * called directly (pcf_event::sm_get_association_decision /
 * pcf_policy_authorization::apply_with_retry) so this orchestration step --
 * specifically, that it ALWAYS feeds apply_with_retry a freshly-looked-up
 * live decision/version, never `commit`'s own stale pre-commit
 * base/post-commit version -- is unit-testable without a real pcf_event/
 * pcf_smpc/HTTP stack.
 *
 * Returns status_code::NOT_FOUND if the association no longer exists
 * (nothing left to roll back), otherwise whatever apply_with_retry returns.
 */
[[nodiscard]] status_code perform_compensating_rollback(
    const std::string& association_id, std::uint64_t version,
    const pending_commit& commit,
    const live_decision_lookup_fn& lookup_live_decision,
    const apply_with_retry_fn& apply_with_retry);

}  // namespace oai::pcf::app::policy_auth

#endif  // FILE_ROLLBACK_ORCHESTRATION_HPP_SEEN
