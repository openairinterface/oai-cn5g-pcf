/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "apply_decision_with_retry.hpp"

#include "logger.hpp"

namespace oai::pcf::app::policy_auth {

using oai::pcf::app::compute_sm_policy_delta;

status_code apply_decision_with_retry(
    std::optional<std::string>& association_id,
    const oai::model::pcf::SmPolicyDecision& initial_base,
    std::uint64_t initial_version, int max_retries,
    const std::function<handler_result(
        const oai::model::pcf::SmPolicyDecision&,
        oai::model::pcf::SmPolicyDecision&)>& derive,
    const sm_update_decision_fn& sm_update_decision,
    pending_rollback_tracker& tracker, const std::string& app_session_id,
    oai::pcf::app::sm_policy_delta& committed_delta,
    std::string& problem_details) {
  const oai::model::pcf::SmPolicyDecision* base = &initial_base;
  std::uint64_t base_version = initial_version;
  // Holds a conflict snapshot so `base` stays valid across iterations.
  oai::model::pcf::SmPolicyDecision fresh_base;
  decision_apply_result result;

  for (int attempt = 0;; ++attempt) {
    // Recompute this request's intended decision against the current base.
    // Pure w.r.t. shared state, so re-running on a conflict is safe.
    oai::model::pcf::SmPolicyDecision working = *base;
    handler_result derived = derive(*base, working);
    if (derived.problem_details.has_value()) {
      // Deterministic failure (authorization/validation/derivation) --
      // retrying would fail identically, so surface it now.
      problem_details = derived.problem_details.value();
      return derived.status.value();
    }

    committed_delta = compute_sm_policy_delta(*base, working);
    sm_update_decision(association_id, base_version, committed_delta, result);
    if (result.committed) {
      // Retain "what would need to be undone" if this commit is later
      // reported as a permanent SMF rejection, keyed on the post-commit
      // version (result.version) that SM's sm_policy_update_failed signal
      // reports. `base` is copied into the shared_ptr snapshot pending_commit
      // expects; a one-time cost paid once per successful commit, not
      // multiplied by retries.
      tracker.record(
          association_id.value_or(""), result.version,
          pending_commit{
              app_session_id, committed_delta,
              std::make_shared<const oai::model::pcf::SmPolicyDecision>(
                  *base),
              {}});
      return status_code::OK;
    }

    // Version conflict: another update committed since we read the base.
    if (attempt >= max_retries || !result.decision) {
      Logger::pcf_app().error(fmt::format(
          "Association {} update abandoned after {} attempt(s): persistent "
          "concurrent updates (or association gone)",
          association_id.value_or("<none>"), attempt + 1));
      // TS 29.514 Table 5.7.3-1: "the service information provided in the
      // request is temporarily rejected" -- exactly this condition
      // (persistent version-CAS contention on the association).
      problem_details = "REQUESTED_SERVICE_TEMPORARILY_NOT_AUTHORIZED";
      return status_code::FORBIDDEN;
    }
    Logger::pcf_app().debug(fmt::format(
        "Association {} update: version conflict on attempt {}; re-deriving "
        "against committed version {}",
        association_id.value_or("<none>"), attempt + 1, result.version));
    fresh_base   = *result.decision;
    base         = &fresh_base;
    base_version = result.version;
  }
}

}  // namespace oai::pcf::app::policy_auth
