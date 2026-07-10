/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "qos_context.hpp"

#include <chrono>

#include "logger.hpp"

namespace oai::pcf::app::policy_auth {

void qos_context::record_qos_flow(const std::string& qos_id) {
  const auto now = std::chrono::system_clock::now();
  auto ledger    = m_ledger.write();

  qos_flow_metadata meta;
  meta.qos_id             = qos_id;
  meta.state              = qos_flow_state::pending;
  meta.created_at         = now;
  meta.updated_at         = now;
  ledger->qos_flows[qos_id] = std::move(meta);
  Logger::pcf_app().trace(
      "qos_context: recorded QoS flow %s (owned flows: %zu)", qos_id.c_str(),
      ledger->qos_flows.size());
}

void qos_context::record_pcc_rule(
    const std::string& rule_id, uint32_t precedence,
    std::vector<std::string> ref_qos_data) {
  const auto now = std::chrono::system_clock::now();
  auto ledger    = m_ledger.write();

  pcc_rule_context ctx;
  ctx.pcc_rule_id            = rule_id;
  ctx.precedence             = precedence;
  ctx.state                  = qos_flow_state::pending;
  ctx.ref_qos_data           = std::move(ref_qos_data);
  ctx.created_at             = now;
  ctx.updated_at             = now;
  ledger->pcc_rules[rule_id] = std::move(ctx);
  Logger::pcf_app().trace(
      "qos_context: recorded PCC rule %s (precedence %u, owned rules: %zu)",
      rule_id.c_str(), precedence, ledger->pcc_rules.size());
}

std::vector<std::string> qos_context::owned_qos_ids() const {
  std::vector<std::string> ids;
  auto ledger = m_ledger.read();
  ids.reserve(ledger->qos_flows.size());
  for (const auto& entry : ledger->qos_flows) ids.push_back(entry.first);
  return ids;
}

std::vector<std::string> qos_context::owned_rule_ids() const {
  std::vector<std::string> ids;
  auto ledger = m_ledger.read();
  ids.reserve(ledger->pcc_rules.size());
  for (const auto& entry : ledger->pcc_rules) ids.push_back(entry.first);
  return ids;
}

void qos_context::erase_owned_from(
    oai::model::pcf::SmPolicyDecision& decision) const {
  auto ledger = m_ledger.read();

  auto pcc_rules = decision.getPccRules();
  for (const auto& entry : ledger->pcc_rules) pcc_rules.erase(entry.first);
  decision.setPccRules(pcc_rules);

  auto qos_decs = decision.getQosDecs();
  for (const auto& entry : ledger->qos_flows) qos_decs.erase(entry.first);
  decision.setQosDecs(qos_decs);

  Logger::pcf_app().debug(
      "qos_context: erased %zu PCC rule(s) and %zu QoS flow(s) from decision",
      ledger->pcc_rules.size(), ledger->qos_flows.size());

  // qos_mon_ids -> decision.getQosMonDecs()/setQosMonDecs() when monitoring
  // lands (Phase 4).
}

qos_ledger qos_context::snapshot() const {
  auto ledger = m_ledger.read();
  return *ledger;
}

void qos_context::restore(const qos_ledger& ledger) {
  auto handle = m_ledger.write();
  *handle     = ledger;
}

}  // namespace oai::pcf::app::policy_auth
