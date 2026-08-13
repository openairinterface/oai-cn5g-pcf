/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "sm_policy_delta.hpp"

namespace oai::pcf::app {

using oai::_3gpp::model::SmPolicyDecision;

namespace {

// Diff one map: upsert keys new-or-changed in `updated`, collect keys dropped
// from `base`. Relies on the generated models' operator== to detect changes.
template <typename MapT>
void diff_map(
    const MapT& base, const MapT& updated, MapT& upsert,
    std::vector<std::string>& removed) {
  for (const auto& [key, value] : updated) {
    const auto it = base.find(key);
    if (it == base.end() || !(it->second == value)) {
      upsert.emplace(key, value);
    }
  }
  for (const auto& [key, value] : base) {
    if (updated.find(key) == updated.end()) {
      removed.push_back(key);
    }
  }
}

// Apply one map's upserts and removals onto a decision map. getXxx() returns a
// copy, so mutate the copy and set it back (matches the rest of the codebase).
template <typename MapT>
void apply_map(
    MapT decision_map, const MapT& upsert,
    const std::vector<std::string>& removed, MapT& out) {
  for (const auto& [key, value] : upsert) decision_map.insert_or_assign(key, value);
  for (const auto& key : removed) decision_map.erase(key);
  out = std::move(decision_map);
}

}  // namespace

bool sm_policy_delta::empty() const {
  return upsert_qos_decs.empty() && upsert_pcc_rules.empty() &&
         upsert_qos_chars.empty() && upsert_traff_cont_decs.empty() &&
         removed_qos_decs.empty() && removed_pcc_rules.empty() &&
         removed_qos_chars.empty() && removed_traff_cont_decs.empty();
}

sm_policy_delta compute_sm_policy_delta(
    const SmPolicyDecision& base, const SmPolicyDecision& updated) {
  sm_policy_delta delta;
  diff_map(
      base.getQosDecs(), updated.getQosDecs(), delta.upsert_qos_decs,
      delta.removed_qos_decs);
  diff_map(
      base.getPccRules(), updated.getPccRules(), delta.upsert_pcc_rules,
      delta.removed_pcc_rules);
  diff_map(
      base.getQosChars(), updated.getQosChars(), delta.upsert_qos_chars,
      delta.removed_qos_chars);
  diff_map(
      base.getTraffContDecs(), updated.getTraffContDecs(),
      delta.upsert_traff_cont_decs, delta.removed_traff_cont_decs);
  return delta;
}

void apply_sm_policy_delta(
    SmPolicyDecision& decision, const sm_policy_delta& delta) {
  if (!delta.upsert_qos_decs.empty() || !delta.removed_qos_decs.empty()) {
    std::map<std::string, oai::_3gpp::model::QosData> merged;
    apply_map(
        decision.getQosDecs(), delta.upsert_qos_decs, delta.removed_qos_decs,
        merged);
    decision.setQosDecs(merged);
  }
  if (!delta.upsert_pcc_rules.empty() || !delta.removed_pcc_rules.empty()) {
    std::map<std::string, oai::_3gpp::model::PccRule> merged;
    apply_map(
        decision.getPccRules(), delta.upsert_pcc_rules, delta.removed_pcc_rules,
        merged);
    decision.setPccRules(merged);
  }
  if (!delta.upsert_qos_chars.empty() || !delta.removed_qos_chars.empty()) {
    std::map<std::string, oai::_3gpp::model::QosCharacteristics> merged;
    apply_map(
        decision.getQosChars(), delta.upsert_qos_chars, delta.removed_qos_chars,
        merged);
    decision.setQosChars(merged);
  }
  if (!delta.upsert_traff_cont_decs.empty() ||
      !delta.removed_traff_cont_decs.empty()) {
    std::map<std::string, oai::_3gpp::model::TrafficControlData> merged;
    apply_map(
        decision.getTraffContDecs(), delta.upsert_traff_cont_decs,
        delta.removed_traff_cont_decs, merged);
    decision.setTraffContDecs(merged);
  }
}

}  // namespace oai::pcf::app
