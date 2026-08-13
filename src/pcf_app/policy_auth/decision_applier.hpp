/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_DECISION_APPLIER_HPP_SEEN
#define FILE_DECISION_APPLIER_HPP_SEEN

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "SmPolicyDecision.h"
#include "guarded.hpp"
#include "pcf_policy_authorization_status_code.hpp"
#include "sm_policy_delta.hpp"

/**
 * @file
 * @brief The commit-and-compensate path for Policy Authorization decision
 * changes.
 *
 * One concern, four collaborating pieces, in dependency order:
 *   1. pending_commit / pending_rollback_tracker -- "which commit does this
 *      (association_id, version) refer to", with TTL + hard cap.
 *   2. decision_applier -- CAS-retry apply, recording into (1) on commit.
 *   3. compute_rollback_delta -- pure: the staleness-checked compensating delta.
 *   4. perform_compensating_rollback -- fetch-live-then-apply orchestration,
 *      with both collaborators injected.
 */

namespace oai::pcf::app::policy_auth {

// ---- 1. pending-commit tracking ------------------------------------------

/**
 * @brief What would need to be undone if this commit is later reported as a
 * permanent SMF rejection.
 *
 * `base` reuses snapshot_decision()'s shape (individual_sm_association.hpp)
 * rather than a fresh full-decision copy.
 */
struct pending_commit {
  std::string app_session_id;
  oai::pcf::app::sm_policy_delta committed_delta;
  std::shared_ptr<const oai::_3gpp::model::SmPolicyDecision> base;
  std::chrono::steady_clock::time_point recorded_at;
};

/**
 * @brief PA-side tracking table: "which commit does this (association_id,
 * version) refer to".
 *
 * Populated at the exact point apply_with_retry currently discards this data
 * (pcf_policy_authorization.cpp, right where it commits and returns OK);
 * consumed when the SM->PA permanent-rejection event arrives. Bounded
 * by an explicit TTL (sweep_expired, meant to be driven by the task_tick
 * heartbeat) and a hard cap (record) -- "some retention window" isn't enough
 * on its own, or this is a slow leak under sustained SMF failures.
 *
 * Its own aspect class (own `guarded<T>` member, minimal focused interface),
 * rather than fields bolted onto pcf_policy_authorization.
 */
class pending_rollback_tracker {
 public:
  pending_rollback_tracker(std::chrono::seconds ttl, std::size_t max_entries);

  /**
   * @brief Record what would need to be undone for (association_id,
   * version). Silently drops the record (after a WARN log) once at capacity
   * -- a later permanent-rejection report for that commit becomes
   * unattributable rather than growing this table without bound.
   */
  void record(
      const std::string& association_id, std::uint64_t version,
      pending_commit commit);

  /**
   * @brief Consume and return the record for (association_id, version), if
   * still tracked. std::nullopt if never recorded, already taken, or
   * expired/evicted -- the caller should log at WARN and drop in that case,
   * it can no longer attribute or notify an AF that's untraceable.
   */
  [[nodiscard]] std::optional<pending_commit> try_take(
      const std::string& association_id, std::uint64_t version);

  /** @brief Evict every entry older than the configured TTL. */
  void sweep_expired(std::chrono::steady_clock::time_point now);

 private:
  using key_t = std::pair<std::string, std::uint64_t>;

  const std::chrono::seconds m_ttl;
  const std::size_t m_max_entries;
  oai::utils::guarded<std::map<key_t, pending_commit>> m_pending;
};

// ---- 2. the applier -------------------------------------------------------

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
  const oai::_3gpp::model::SmPolicyDecision& initial_base;
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
          const oai::_3gpp::model::SmPolicyDecision& base,
          oai::_3gpp::model::SmPolicyDecision& working)>& derive,
      oai::pcf::app::sm_policy_delta& committed_delta,
      std::string& problem_details, std::uint64_t& committed_version);

 private:
  sm_update_decision_fn m_sm_update_decision;
  pending_rollback_tracker& m_tracker;
  int m_max_retries;
};

// ---- 3. compensating delta (pure) -----------------------------------------

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
    const oai::_3gpp::model::SmPolicyDecision& live, const pending_commit& pending);

// ---- 4. rollback orchestration ---------------------------------------------

// Matches pcf_event::sm_get_association_decision's shape: given an
// association_id, report whether it still exists and, if so, its CURRENT
// decision + version. (association_id in; found, decision, version out.)
using live_decision_lookup_fn = std::function<void(
    const std::string& association_id, bool& found,
    oai::_3gpp::model::SmPolicyDecision& decision, std::uint64_t& version)>;

// Mirrors decision_applier::apply's shape (minus the class binding), so
// perform_compensating_rollback's tests inject a fake without constructing a
// real decision_applier.
using apply_with_retry_fn = std::function<status_code(
    decision_apply_request request,
    const std::function<handler_result(
        const oai::_3gpp::model::SmPolicyDecision& base,
        oai::_3gpp::model::SmPolicyDecision& working)>& derive,
    oai::pcf::app::sm_policy_delta& committed_delta,
    std::string& problem_details)>;

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

#endif  // FILE_DECISION_APPLIER_HPP_SEEN
