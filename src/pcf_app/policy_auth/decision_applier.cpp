/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "decision_applier.hpp"

#include "logger.hpp"
#include "policy_authorization_causes.hpp"

namespace oai::pcf::app::policy_auth {

using oai::pcf::app::compute_sm_policy_delta;

decision_applier::decision_applier(
    sm_update_decision_fn sm_update_decision, pending_rollback_tracker& tracker,
    int max_retries)
    : m_sm_update_decision(std::move(sm_update_decision)),
      m_tracker(tracker),
      m_max_retries(max_retries) {}

status_code decision_applier::apply(
    decision_apply_request request,
    const std::function<handler_result(
        const oai::model::pcf::SmPolicyDecision&,
        oai::model::pcf::SmPolicyDecision&)>& derive,
    oai::pcf::app::sm_policy_delta& committed_delta,
    std::string& problem_details, std::uint64_t& committed_version) {
  const oai::model::pcf::SmPolicyDecision* base = &request.initial_base;
  std::uint64_t base_version = request.initial_version;
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
    m_sm_update_decision(
        request.association_id, base_version, committed_delta, result);
    if (result.committed) {
      // Retain "what would need to be undone" if this commit is later
      // reported as a permanent SMF rejection, keyed on the post-commit
      // version. `base` is copied into the shared_ptr snapshot
      // pending_commit expects; a one-time cost paid once per successful
      // commit, not multiplied by retries. Safe to record unconditionally
      // here -- sm_update_decision (CAS-commit only) never triggers a
      // notify or any signal of its own, so there is nothing this could
      // race against.
      m_tracker.record(
          request.association_id.value_or(""), result.version,
          pending_commit{
              request.app_session_id, committed_delta,
              std::make_shared<const oai::model::pcf::SmPolicyDecision>(
                  *base),
              {}});
      committed_version = result.version;
      return status_code::OK;
    }

    // Version conflict: another update committed since we read the base.
    if (attempt >= m_max_retries || !result.decision) {
      Logger::pcf_app().error(
          "Association %s update abandoned after %d attempt(s): persistent "
          "concurrent updates (or association gone)",
          request.association_id.value_or("<none>").c_str(), attempt + 1);
      // TS 29.514 Table 5.7.3-1: "the service information provided in the
      // request is temporarily rejected" -- exactly this condition
      // (persistent version-CAS contention on the association).
      problem_details = kCauseRequestedServiceTemporarilyNotAuthorized;
      return status_code::FORBIDDEN;
    }
    Logger::pcf_app().debug(
        "Association %s update: version conflict on attempt %d; re-deriving "
        "against committed version %lu",
        request.association_id.value_or("<none>").c_str(), attempt + 1,
        result.version);
    fresh_base   = *result.decision;
    base         = &fresh_base;
    base_version = result.version;
  }
}

}  // namespace oai::pcf::app::policy_auth
