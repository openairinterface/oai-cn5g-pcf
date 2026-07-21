/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "individual_sm_association.hpp"

using namespace oai::model::pcf;
using namespace oai::pcf::app::sm_policy;

const SmPolicyContextData&
individual_sm_association::get_sm_policy_context_data() const {
  return m_context;
}

const SmPolicyDecision& individual_sm_association::get_sm_policy_decision_dto()
    const {
  return m_decision.get_sm_policy_decision();
}

void individual_sm_association::set_sm_policy_decision(
    oai::model::pcf::SmPolicyDecision& new_decision) {
  m_decision.set_sm_policy_decision(new_decision);
}

void individual_sm_association::apply_delta(
    const oai::pcf::app::sm_policy_delta& delta) {
  m_decision.apply_delta(delta);
}

std::shared_ptr<const oai::model::pcf::SmPolicyDecision>
individual_sm_association::snapshot_decision() const {
  return m_decision.snapshot_decision();
}

uint64_t individual_sm_association::decision_version() const {
  return m_decision.decision_version();
}

std::string individual_sm_association::get_id() const {
  return m_id;
}

oai::pcf::app::sm_policy::status_code
individual_sm_association::redecide_policy(
    const SmPolicyUpdateContextData& update_data,
    SmPolicyDecision& new_decision, std::string& problem_details) {
  return m_decision.redecide(
      m_context, update_data, new_decision, problem_details);
}

oai::pcf::app::sm_policy::status_code individual_sm_association::decide_policy(
    SmPolicyDecision& decision) {
  return m_decision.decide(m_context, decision);
}
