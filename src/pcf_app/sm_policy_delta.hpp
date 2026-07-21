/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_SM_POLICY_DELTA_HPP_SEEN
#define FILE_SM_POLICY_DELTA_HPP_SEEN

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "PccRule.h"
#include "QosCharacteristics.h"
#include "QosData.h"
#include "SmPolicyDecision.h"
#include "TrafficControlData.h"

namespace oai::pcf::app {

/**
 * @brief Incremental change set for an SmPolicyDecision
 * [TS 29.512 §4.2.3.2, §5.6.2.5].
 *
 * Carries only what Policy Authorization changed, so the SM Policy association
 * can apply it to the authoritative decision under a single lock -- turning the
 * previous read-modify-write (read a full copy, mutate locally, write the whole
 * object back) into an atomic apply. That removes the lost-update race on
 * concurrent PATCH: because unchanged entries are omitted, applying a delta to a
 * decision another writer has concurrently changed only touches the keys this
 * writer actually changed.
 *
 * This is a PCF-internal representation only; the notification sent to the SMF
 * remains the full SmPolicyDecision (the partner SMF diffs the full object
 * itself, so sending it a partial decision would be an interop hazard).
 *
 * `upsert_*` entries are added or replaced, keyed exactly as in
 * SmPolicyDecision; `removed_*` are keys to delete. Covers the four maps Policy
 * Authorization contributes to; sessRules (SM-owned) and qosMonDecs (Phase 4)
 * are intentionally out of scope.
 */
struct sm_policy_delta {
  std::map<std::string, oai::model::pcf::QosData> upsert_qos_decs;
  std::map<std::string, oai::model::pcf::PccRule> upsert_pcc_rules;
  std::map<std::string, oai::model::pcf::QosCharacteristics> upsert_qos_chars;
  std::map<std::string, oai::model::pcf::TrafficControlData>
      upsert_traff_cont_decs;

  std::vector<std::string> removed_qos_decs;
  std::vector<std::string> removed_pcc_rules;
  std::vector<std::string> removed_qos_chars;
  std::vector<std::string> removed_traff_cont_decs;

  [[nodiscard]] bool empty() const;
};

/**
 * @brief Compute the delta that turns `base` into `updated` across qosDecs,
 * pccRules, qosChars and traffContDecs.
 *
 * A key is an upsert when it is new in `updated` or its value differs from
 * `base` (by the model's operator==); a key present in `base` but absent from
 * `updated` is a removal. Unchanged keys are omitted -- this is what makes the
 * result safe to apply to a base other than the one it was computed against
 * (see sm_policy_delta).
 */
sm_policy_delta compute_sm_policy_delta(
    const oai::model::pcf::SmPolicyDecision& base,
    const oai::model::pcf::SmPolicyDecision& updated);

/**
 * @brief Apply `delta` to `decision` in place: upserts first, then removals.
 */
void apply_sm_policy_delta(
    oai::model::pcf::SmPolicyDecision& decision, const sm_policy_delta& delta);

/**
 * @brief Outcome of an optimistic (version-checked) delta apply on an
 * association.
 *
 * `committed` is true iff the association was still at the version the caller
 * read (`expected_version`) and the delta was applied. On a conflict it is
 * false and `version`/`decision` carry the association's *current* state so the
 * caller can re-derive against it without a second round-trip. When committed,
 * `version`/`decision` are the post-apply state.
 */
struct decision_apply_result {
  bool committed = false;
  std::uint64_t version = 0;
  std::shared_ptr<const oai::model::pcf::SmPolicyDecision> decision;
};

}  // namespace oai::pcf::app

#endif  // FILE_SM_POLICY_DELTA_HPP_SEEN
