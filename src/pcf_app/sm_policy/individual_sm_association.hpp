/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_INDIVIDUAL_SM_ASSOCIATION_SEEN
#define FILE_INDIVIDUAL_SM_ASSOCIATION_SEEN

#include "SmPolicyContextData.h"
#include "SmPolicyDecision.h"
#include "policy_decision.hpp"
#include "sm_policy_delta.hpp"

#include <cstdint>
#include <memory>

namespace oai::pcf::app::sm_policy {

class individual_sm_association {
 public:
  explicit individual_sm_association(
      const oai::_3gpp::model::SmPolicyContextData& context,
      const oai::pcf::app::sm_policy::policy_decision& decision,
      const std::string& id)
      : m_decision(decision) {
    m_context = context;
    m_id      = id;
  }

  virtual ~individual_sm_association() = default;

  [[nodiscard]] virtual const oai::_3gpp::model::SmPolicyContextData&
  get_sm_policy_context_data() const;

  [[nodiscard]] virtual const oai::_3gpp::model::SmPolicyDecision&
  get_sm_policy_decision_dto() const;

  // Use apply_delta() for incremental Policy-Authorization updates
  // so concurrent writers don't lose each other's changes; this remains
  // for full-decision writes (e.g. the SM native create/update paths).
  virtual void set_sm_policy_decision(
      oai::_3gpp::model::SmPolicyDecision& new_decision);

  // Apply an incremental change set to the held decision under the caller's
  // lock (copy-on-write) [TS 29.512 §4.2.3.2]. This is how Policy Authorization
  // mutates an active association without the read-modify-write lost-update.
  virtual void apply_delta(const oai::pcf::app::sm_policy_delta& delta);

  // Cheap immutable snapshot of the current decision; safe to keep after the
  // association lock is released (used to notify the SMF off-lock).
  [[nodiscard]] virtual std::shared_ptr<const oai::_3gpp::model::SmPolicyDecision>
  snapshot_decision() const;

  [[nodiscard]] virtual uint64_t decision_version() const;

  [[nodiscard]] virtual oai::pcf::app::sm_policy::status_code redecide_policy(
      const oai::_3gpp::model::SmPolicyUpdateContextData& update_data,
      oai::_3gpp::model::SmPolicyDecision& new_decision,
      std::string& problem_details);

  [[nodiscard]] virtual oai::pcf::app::sm_policy::status_code decide_policy(
      oai::_3gpp::model::SmPolicyDecision& decision);

  [[nodiscard]] virtual std::string get_id() const;

 private:
  oai::_3gpp::model::SmPolicyContextData m_context;
  oai::pcf::app::sm_policy::policy_decision m_decision;
  std::string m_id;
};
}  // namespace oai::pcf::app::sm_policy
#endif
