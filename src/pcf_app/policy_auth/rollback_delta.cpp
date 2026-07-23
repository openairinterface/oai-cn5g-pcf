/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "rollback_delta.hpp"

#include "logger.hpp"

namespace oai::pcf::app::policy_auth {

using oai::model::pcf::SmPolicyDecision;

namespace {

// One map's worth of the staleness-checked compensating delta. `live`
// is the association's current value for this map; `committed_upsert`/
// `committed_removed` are what `pending`'s original commit did; `pre_commit`
// is that commit's pre-commit base -- the value to restore on a compensated
// modify/removal.
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
          "compute_rollback_delta: %s key %s modified/referenced since this "
          "commit; skipping compensation to avoid orphaning a dependent PCC "
          "rule",
          map_name, key.c_str());
      // TODO [QOS][ROLLBACK] key modified/referenced since this commit;
      // skipping compensation to avoid orphaning a dependent PCC rule. Needs
      // proper reference-aware rollback (e.g. refQosData dependency check)
      // [Phase 3?].
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
          "compute_rollback_delta: %s key %s modified/referenced since this "
          "commit; skipping compensation to avoid orphaning a dependent PCC "
          "rule",
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

}  // namespace oai::pcf::app::policy_auth
