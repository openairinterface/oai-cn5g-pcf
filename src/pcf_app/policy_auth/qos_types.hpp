/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_QOS_TYPES_HPP_SEEN
#define FILE_QOS_TYPES_HPP_SEEN

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

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

}  // namespace oai::pcf::app::policy_auth

#endif  // FILE_QOS_TYPES_HPP_SEEN
