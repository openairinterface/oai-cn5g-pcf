/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_QOS_CONTEXT_HPP_SEEN
#define FILE_QOS_CONTEXT_HPP_SEEN

#include <map>
#include <string>
#include <vector>

#include "SmPolicyDecision.h"
#include "guarded.hpp"
#include "qos_types.hpp"

namespace oai::pcf::app::policy_auth {

/**
 * @brief Pure data: the set of QoS entries an app-session contributed to the
 * association's SmPolicyDecision.
 *
 * Holds identifiers only (the payload's source of truth is the decision owned by
 * the SM policy association) plus internal-only lifecycle metadata.
 */
struct qos_ledger {
  std::map<std::string, qos_flow_metadata> qos_flows;  // keyed by qosId
  std::map<std::string, pcc_rule_context> pcc_rules;   // keyed by pccRuleId
  std::vector<std::string> qos_mon_ids;                // qosMonId
};

/**
 * @brief The QoS "aspect" of an app-session: behaviour plus its own lock.
 *
 * Fine-grained locking: QoS operations lock only this ledger, not the whole
 *  session. AF-subscription and monitoring add their own aspect classes
 * following this exact shape.
 */
class qos_context {
 public:
  qos_context() = default;

  /** Record a QoS flow (qosId) this session added to the decision. */
  void record_qos_flow(const std::string& qos_id);

  /** Record a PCC rule (pccRuleId) this session added to the decision. */
  void record_pcc_rule(
      const std::string& rule_id, uint32_t precedence,
      std::vector<std::string> ref_qos_data);

  [[nodiscard]] std::vector<std::string> owned_qos_ids() const;
  [[nodiscard]] std::vector<std::string> owned_rule_ids() const;

  /**
   * @brief Remove exactly the entries this session owns from a decision that
   * Policy Authorization fetched (used on DELETE / cleanup).
   *
   * When the SmPolicyDelta refactor lands (plan §4.7) this becomes
   * build_remove_delta() feeding an association-side apply_delta().
   */
  void erase_owned_from(oai::model::pcf::SmPolicyDecision& decision) const;

  /** Durable projection helpers (for app_session_record / future DB backend). */
  [[nodiscard]] qos_ledger snapshot() const;
  void restore(const qos_ledger& ledger);

 private:
  oai::utils::guarded<qos_ledger> m_ledger;
};

}  // namespace oai::pcf::app::policy_auth

#endif  // FILE_QOS_CONTEXT_HPP_SEEN
