/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "decision_applier.hpp"

#include "logger.hpp"

namespace oai::pcf::app::policy_auth {

using oai::model::pcf::SmPolicyDecision;
using oai::pcf::app::compute_sm_policy_delta;

// ---- 1. pending-commit tracking ------------------------------------------

pending_rollback_tracker::pending_rollback_tracker(
    std::chrono::seconds ttl, std::size_t max_entries)
    : m_ttl(ttl), m_max_entries(max_entries) {}

void pending_rollback_tracker::record(
    const std::string& association_id, std::uint64_t version,
    pending_commit commit) {
  auto pending = m_pending.write();
  if (pending->size() >= m_max_entries) {
    Logger::pcf_app().warn(
        "pending_rollback_tracker: at capacity (%zu entries) -- dropping "
        "record for association %s version %lu; a later permanent-rejection "
        "report for it won't be attributable",
        m_max_entries, association_id.c_str(), version);
    return;
  }
  commit.recorded_at = std::chrono::steady_clock::now();
  (*pending)[key_t{association_id, version}] = std::move(commit);
}

std::optional<pending_commit> pending_rollback_tracker::try_take(
    const std::string& association_id, std::uint64_t version) {
  auto pending = m_pending.write();
  auto it      = pending->find(key_t{association_id, version});
  if (it == pending->end()) return std::nullopt;
  pending_commit commit = std::move(it->second);
  pending->erase(it);
  return commit;
}

void pending_rollback_tracker::sweep_expired(
    std::chrono::steady_clock::time_point now) {
  auto pending = m_pending.write();
  for (auto it = pending->begin(); it != pending->end();) {
    if (now - it->second.recorded_at > m_ttl) {
      it = pending->erase(it);
    } else {
      ++it;
    }
  }
}

// ---- 2. the applier -------------------------------------------------------

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

// ---- 3. compensating delta (pure) -----------------------------------------

namespace {

// One map's worth of the staleness-checked compensating delta. `live`
// is the association's current value for this map; `committed_upsert`/
// `committed_removed` are what `pending`'s original commit did; `pre_commit`
// is that commit's pre-commit base -- the value to restore on a compensated
// modify/removal.
//
// Per-key staleness rule: a key is compensated only if it still holds exactly
// what this commit left there. If someone else has changed it since, this
// commit no longer owns that value and reverting it would clobber a newer,
// legitimate write -- so the key is skipped and logged.
//
// KNOWN LIMITATION [QOS][ROLLBACK] -- the skip is per-key and reference-blind,
// so a partly-skipped rollback can leave the decision referentially
// inconsistent, and nothing downstream catches it: perform_compensating_
// rollback's derive does NOT call validate_policy_decision() (unlike the
// POST/PATCH derives), so the result is committed AND notified to the SMF.
// Worked example: a commit created QosData Q and PccRule R with
// refQosData=[Q]; another writer then modified R (say its precedence) but left
// Q alone. Compensating finds Q unchanged -> removes it, and R changed -> skips
// it, so R is sent to the SMF referencing a Q that is gone.
// TODO Fix in two parts:
// (A) validate in the rollback derive, so an inconsistent rollback is abandoned
// rather than pushed; (B) make this delta reference-aware -- project the
// candidate onto `live`, drop any removal whose key is still referenced and any
// restored rule whose own references would dangle, iterating until stable.
// Deliberately not attempted here: (B) changes what a rollback means from "undo
// my keys" to "undo my keys as far as the result stays valid", and needs its
// own tests.
template <typename MapT>
void rollback_map(
    const MapT& live, const MapT& committed_upsert,
    const std::vector<std::string>& committed_removed, const MapT& pre_commit,
    MapT& out_upsert, std::vector<std::string>& out_removed,
    const char* map_name) {
  for (const auto& [key, committed_value] : committed_upsert) {
    const auto live_it = live.find(key);
    const bool unchanged_since =
        live_it != live.end() && live_it->second == committed_value;
    if (!unchanged_since) {
      Logger::pcf_app().warn(
          "compute_rollback_delta: %s key %s changed since this commit; "
          "skipping its compensation (a newer writer owns that value now). "
          "The rollback may therefore be partial -- see the reference-awareness "
          "limitation in rollback_map()",
          map_name, key.c_str());
      continue;
    }
    const auto pre_it = pre_commit.find(key);
    if (pre_it == pre_commit.end()) {
      out_removed.push_back(key);  // was a create -- compensate by removing
    } else {
      out_upsert.emplace(key, pre_it->second);  // was a modify -- restore
    }
  }

  for (const auto& key : committed_removed) {
    const bool unchanged_since = live.find(key) == live.end();  // still absent
    if (!unchanged_since) {
      Logger::pcf_app().warn(
          "compute_rollback_delta: %s key %s was re-created since this commit "
          "removed it; skipping its compensation (a newer writer owns it now). "
          "The rollback may therefore be partial -- see the reference-awareness "
          "limitation in rollback_map()",
          map_name, key.c_str());
      continue;
    }
    const auto pre_it = pre_commit.find(key);
    if (pre_it != pre_commit.end()) {
      out_upsert.emplace(key, pre_it->second);  // restore what was removed
    }
    // Absent from pre_commit too: nothing to restore. Shouldn't happen --
    // compute_sm_policy_delta only records a removal for a key that existed
    // in the pre-commit base.
  }
}

}  // namespace

sm_policy_delta compute_rollback_delta(
    const SmPolicyDecision& live, const pending_commit& pending) {
  sm_policy_delta rollback;
  const SmPolicyDecision& pre_commit = *pending.base;
  const sm_policy_delta& committed   = pending.committed_delta;

  rollback_map(
      live.getQosDecs(), committed.upsert_qos_decs, committed.removed_qos_decs,
      pre_commit.getQosDecs(), rollback.upsert_qos_decs,
      rollback.removed_qos_decs, "qosDecs");
  rollback_map(
      live.getPccRules(), committed.upsert_pcc_rules,
      committed.removed_pcc_rules, pre_commit.getPccRules(),
      rollback.upsert_pcc_rules, rollback.removed_pcc_rules, "pccRules");
  rollback_map(
      live.getQosChars(), committed.upsert_qos_chars,
      committed.removed_qos_chars, pre_commit.getQosChars(),
      rollback.upsert_qos_chars, rollback.removed_qos_chars, "qosChars");
  rollback_map(
      live.getTraffContDecs(), committed.upsert_traff_cont_decs,
      committed.removed_traff_cont_decs, pre_commit.getTraffContDecs(),
      rollback.upsert_traff_cont_decs, rollback.removed_traff_cont_decs,
      "traffContDecs");

  return rollback;
}

// ---- 4. rollback orchestration ---------------------------------------------

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
