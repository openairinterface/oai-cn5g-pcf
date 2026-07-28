/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_QOS_CONTEXT_HPP_SEEN
#define FILE_QOS_CONTEXT_HPP_SEEN

#include <chrono>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "SmPolicyDecision.h"
#include "guarded.hpp"
#include "sm_policy_delta.hpp"

namespace oai::pcf::app::policy_auth {

// Lifecycle states. These have no 3GPP wire equivalent; they are internal-only.
// Scoped enums per C++ Core Guidelines Enum.3.
enum class qos_flow_state { pending, established, modified, released };
enum class app_session_state { pending, established, modified, released };

/**
 * @brief Ledger entry for a QoS flow this app-session contributed.
 *
 * Keyed by qosId (the key into SmPolicyDecision.qosDecs, which remains the
 * source of truth for the QosData payload). Holds only internal-only state --
 * 5QI, GBR/MBR and resource type live in QosData/QosCharacteristics and are NOT
 * copied here. [TS 29.512 §5.6.2.8]
 */
struct qos_flow_metadata {
  std::string qos_id;
  qos_flow_state state{qos_flow_state::pending};
  std::chrono::system_clock::time_point created_at{};
  std::chrono::system_clock::time_point updated_at{};
};

/**
 * @brief Ledger entry for a PCC rule this app-session contributed.
 *
 * Keyed by pccRuleId (the key into SmPolicyDecision.pccRules). [TS 29.512
 * §4.1.4.2.1]
 */
struct pcc_rule_context {
  std::string pcc_rule_id;
  uint32_t precedence{0};
  qos_flow_state state{qos_flow_state::pending};
  std::vector<std::string> ref_qos_data;
  std::chrono::system_clock::time_point created_at{};
  std::chrono::system_clock::time_point updated_at{};
};

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
   * @brief Drop a single owned QoS flow + PCC rule from the ledger (used on a
   * PATCH that removes a media component, fStatus=REMOVED). Ids not owned by
   * this session are ignored.
   */
  void remove(const std::string& qos_id, const std::string& rule_id);

  /**
   * @brief Reconcile the ledger with a delta that has just been committed to
   * the association, as the post-commit side-effect of an update.
   *
   * The ledger is only ever mutated here (after a successful association apply),
   * never during QoS derivation -- derivation writes to a scratch context, so a
   * request that is rejected/retried leaves this ledger untouched. Upserted
   * qosDecs/pccRules are recorded (created-or-updated), removed ones dropped.
   */
  void apply_committed_delta(const oai::pcf::app::sm_policy_delta& delta);

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
