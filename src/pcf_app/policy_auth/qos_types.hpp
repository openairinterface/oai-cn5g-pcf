/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_QOS_TYPES_HPP_SEEN
#define FILE_QOS_TYPES_HPP_SEEN

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "ReservPriority.h"

namespace oai::pcf::app::policy_auth {

// Lifecycle states. These have no 3GPP wire equivalent; they are internal-only.
// Scoped enums per C++ Core Guidelines Enum.3.
enum class qos_flow_state { pending, established, modified, released };
enum class app_session_state { pending, established, modified, released };

/**
 * @brief Transient, parsed view of a MediaComponent's QoS parameters.
 *
 * Built locally from a MediaComponent during extraction/validation and then
 * discarded -- it is deliberately NOT stored. It exists only because
 * MediaComponent encodes bit rates as 3GPP BitRate strings ("10 Mbps") while
 * validation and slice-limit summation need integers. [TS 29.514 §5.6.2.7]
 *
 * NOTE: not populated yet; defined so §1.4 validation and §1.6
 * update-diffing have a home..
 */
struct qos_requirements {
  std::optional<uint64_t> mar_bw_dl_bps;
  std::optional<uint64_t> mar_bw_ul_bps;
  std::optional<uint64_t> mir_bw_dl_bps;
  std::optional<uint64_t> mir_bw_ul_bps;
  std::optional<uint64_t> min_des_bw_dl_bps;
  std::optional<uint64_t> min_des_bw_ul_bps;
  std::optional<double> des_max_latency_ms;
  std::optional<double> des_max_loss;
  std::optional<std::string> qos_reference;
  std::optional<oai::model::pcf::ReservPriority> res_prio;
};

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
