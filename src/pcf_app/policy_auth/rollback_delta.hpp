/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_ROLLBACK_DELTA_HPP_SEEN
#define FILE_ROLLBACK_DELTA_HPP_SEEN

#include "SmPolicyDecision.h"
#include "pending_rollback_tracker.hpp"
#include "sm_policy_delta.hpp"

namespace oai::pcf::app::policy_auth {

/**
 * @brief Compute the compensating delta that would undo `pending`, against
 * the association's current `live` decision.
 *
 * Per-key staleness check: a key from `pending.committed_delta` is
 * included only if its value in `live` still matches what this commit
 * recorded as committed -- i.e. unchanged since. Otherwise something else
 * (plausibly a later request referencing this id) touched it since, so the
 * key is skipped (left as-is in `live`) and logged at WARN, rather than risk
 * orphaning a dependent PCC rule.
 *
 * A create (key absent from pending.base) compensates by removal; a modify
 * (key present in pending.base) compensates by restoring pending.base's
 * value; a removal (key in pending.committed_delta.removed_*) compensates by
 * restoring pending.base's value for it, provided it's still absent from
 * `live`.
 *
 * Deliberately a pure function of its three inputs -- no threading/timer
 * glue -- so it's unit-testable without a real timerfd/thread (§6.11).
 */
[[nodiscard]] oai::pcf::app::sm_policy_delta compute_rollback_delta(
    const oai::model::pcf::SmPolicyDecision& live, const pending_commit& pending);

}  // namespace oai::pcf::app::policy_auth

#endif  // FILE_ROLLBACK_DELTA_HPP_SEEN
