/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "rollback_orchestration.hpp"

#include "logger.hpp"
#include "rollback_delta.hpp"

namespace oai::pcf::app::policy_auth {

status_code perform_compensating_rollback(
    const std::string& association_id, std::uint64_t version,
    const pending_commit& commit,
    const live_decision_lookup_fn& lookup_live_decision,
    const apply_with_retry_fn& apply_with_retry) {
  bool association_found = false;
  oai::model::pcf::SmPolicyDecision live_decision;
  std::uint64_t live_version = 0;
  lookup_live_decision(association_id, association_found, live_decision, live_version);

  if (!association_found) {
    Logger::pcf_app().warn(
        "handle_sm_policy_update_failed: association %s no longer exists -- "
        "nothing left to roll back (was version %lu)",
        association_id.c_str(), version);
    return status_code::NOT_FOUND;
  }

  auto derive =
      [&](const oai::model::pcf::SmPolicyDecision& base,
          oai::model::pcf::SmPolicyDecision& working) -> handler_result {
    const sm_policy_delta rollback_delta = compute_rollback_delta(base, commit);
    apply_sm_policy_delta(working, rollback_delta);
    return {};  // a rollback only reverts what this commit itself set
                // (filtered by the staleness check), so it never fails
                // validation the way an AF request can
  };

  std::optional<std::string> rollback_association_id = association_id;
  sm_policy_delta rollback_committed_delta;
  std::string rollback_problem_details;
  // Note on the follow-on notify to the SMF -- not suppressed, deliberately:
  // since the SMF's response was permanent_rejection ("should not be
  // attempted again"), its enforcement state never moved from the pre-change
  // state, so the rollback notify simply resends that same (now-current-
  // again) decision -- at worst a harmless no-op resync.
  const status_code rollback_push = apply_with_retry(
      decision_apply_request{
          rollback_association_id, live_decision, live_version,
          commit.app_session_id},
      derive, rollback_committed_delta, rollback_problem_details);

  if (rollback_push == status_code::OK) {
    Logger::pcf_app().info(
        "handle_sm_policy_update_failed: compensating rollback committed "
        "for association %s (was version %lu)",
        association_id.c_str(), version);
  } else {
    Logger::pcf_app().error(
        "handle_sm_policy_update_failed: compensating rollback for "
        "association %s (was version %lu) did not commit: %s",
        association_id.c_str(), version, rollback_problem_details.c_str());
  }

  return rollback_push;
}

}  // namespace oai::pcf::app::policy_auth
