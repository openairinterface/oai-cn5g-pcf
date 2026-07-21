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

void qos_context::remove(
    const std::string& qos_id, const std::string& rule_id) {
  auto ledger = m_ledger.write();
  ledger->qos_flows.erase(qos_id);
  ledger->pcc_rules.erase(rule_id);
  Logger::pcf_app().trace(
      "qos_context: removed QoS flow %s and PCC rule %s from ledger",
      qos_id.c_str(), rule_id.c_str());
}

void qos_context::apply_committed_delta(
    const oai::pcf::app::sm_policy_delta& delta) {
  const auto now = std::chrono::system_clock::now();
  auto ledger    = m_ledger.write();

  // Upserts: record (or refresh) ownership of each qos flow / PCC rule the
  // committed delta added or modified.
  for (const auto& [qos_id, unused] : delta.upsert_qos_decs) {
    (void)unused;
    auto& meta      = ledger->qos_flows[qos_id];
    meta.qos_id     = qos_id;
    meta.state      = qos_flow_state::established;
    if (meta.created_at.time_since_epoch().count() == 0) meta.created_at = now;
    meta.updated_at = now;
  }
  for (const auto& [rule_id, rule] : delta.upsert_pcc_rules) {
    auto& ctx        = ledger->pcc_rules[rule_id];
    ctx.pcc_rule_id  = rule_id;
    ctx.precedence   = rule.precedenceIsSet()
                           ? static_cast<uint32_t>(rule.getPrecedence())
                           : 0;
    ctx.ref_qos_data = rule.refQosDataIsSet() ? rule.getRefQosData()
                                              : std::vector<std::string>{};
    ctx.state        = qos_flow_state::established;
    if (ctx.created_at.time_since_epoch().count() == 0) ctx.created_at = now;
    ctx.updated_at   = now;
  }

  // Removals: drop ownership of anything the delta removed.
  for (const auto& qos_id : delta.removed_qos_decs)
    ledger->qos_flows.erase(qos_id);
  for (const auto& rule_id : delta.removed_pcc_rules)
    ledger->pcc_rules.erase(rule_id);

  Logger::pcf_app().trace(
      "qos_context: applied committed delta (+%zu/-%zu qos flows, "
      "+%zu/-%zu PCC rules; now %zu flows, %zu rules)",
      delta.upsert_qos_decs.size(), delta.removed_qos_decs.size(),
      delta.upsert_pcc_rules.size(), delta.removed_pcc_rules.size(),
      ledger->qos_flows.size(), ledger->pcc_rules.size());
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
