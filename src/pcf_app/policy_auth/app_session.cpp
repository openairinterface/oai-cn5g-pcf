/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include <chrono>
#include <sstream>
#include <string>
#include <utility>

#include "AppSessionContext.h"
#include "TrafficControlData.h"
#include "PccRule.h"
#include "QosData.h"
#include "Arp.h"
#include "FlowInformation.h"
#include "FlowDirectionRm.h"
#include "SmPolicyDecision.h"
#include "AfSfcRequirement.h"
#include "policy_auth/pcf_policy_authorization_status_code.hpp"
#include "logger.hpp"
#include "app_session.hpp"
#include "uint_generator.hpp"

#define DEFAULT_PCC_RULE_PRECEDENCE 255
namespace oai::pcf::app {
namespace policy_auth {

using namespace oai::model::pcf;
using namespace oai::pcf::app;
using namespace oai::utils;

app_session::app_session(
    std::string id, oai::model::pcf::AppSessionContextReqData context,
    std::optional<std::string> association_id)
    : m_id(std::move(id)),
      m_created_at(std::chrono::system_clock::now()),
      m_context(std::move(context)),
      m_association_id(std::move(association_id)) {}

oai::model::pcf::AppSessionContextReqData app_session::context_snapshot()
    const {
  auto context = m_context.read();
  return *context;
}

void app_session::update_context(
    const oai::model::pcf::AppSessionContextReqData& context) {
  auto handle = m_context.write();
  *handle     = context;
}

app_session_record app_session::to_record() const {
  app_session_record record;
  record.app_session_id     = m_id;
  record.association_id      = m_association_id;
  record.state              = m_state.load();
  record.owned_qos_ids      = m_qos.owned_qos_ids();
  record.owned_pcc_rule_ids = m_qos.owned_rule_ids();
  record.created_at         = m_created_at;
  record.updated_at         = std::chrono::system_clock::now();
  {
    auto context   = m_context.read();
    record.supi    = context->getSupi();
    record.dnn     = context->getDnn();
    record.ue_ipv4 = context->getUeIpv4();
  }
  // af_app_id and context_json are serialized when the DB storage backend lands
  // the in-memory backend does not use to_record().
  return record;
}

handler_result handle_service_function_chaining(
    const oai::model::pcf::AfSfcRequirement& af_sfc,
    oai::model::pcf::SmPolicyDecision& decision) {
  // Extract N6-LAN Traffic Steering Requirements
  std::shared_ptr<oai::model::pcf::TrafficControlData> traffic_control_data =
      std::make_shared<oai::model::pcf::TrafficControlData>();

  if (!af_sfc.sfcIdDlIsSet() && !af_sfc.sfcIdUlIsSet()) {
    Logger::pcf_app().error(
        "Failed either UL SFC ID or DL SFC ID should be set");
    return handler_result{
        .status          = status_code::BAD_REQUEST,
        .problem_details = "INVALID_SERVICE_INFORMATION"};
  }

  // Set Traffic Steering Policy ID for DL and/or UL based on the presence of
  // corresponding SFC IDs
  if (af_sfc.sfcIdDlIsSet()) {
    traffic_control_data->setTrafficSteeringPolIdDl(af_sfc.getSfcIdDl());
  }

  if (af_sfc.sfcIdUlIsSet()) {
    traffic_control_data->setTrafficSteeringPolIdUl(af_sfc.getSfcIdUl());
  }

  // TODO [PAS]: Transparently include SFC Metadata if available

  // Add the traffic control to PCC rules
  std::shared_ptr<oai::model::pcf::PccRule> pcc_rule =
      std::make_shared<oai::model::pcf::PccRule>();
  // Generate Id using id generator
  auto& uid_generator =
      oai::utils::uint_uid_generator<uint32_t>::get_instance();
  uint32_t uid = uid_generator.get_uid();
  Logger::pcf_app().debug(fmt::format("Generated PCC Rule ID: {}", uid));

  std::string pcc_rule_id            = std::to_string(uid);
  std::string rcId                   = "rc-" + pcc_rule_id;
  std::vector<std::string> refTcData = {rcId};

  pcc_rule->setRefTcData(refTcData);
  pcc_rule->setPccRuleId(pcc_rule_id);

  // // Create and set TCId on traffic control data and add it as RefTc to PCC
  traffic_control_data->setTcId(rcId);

  // Set traffic control to decision
  // decision.setTraffContDecs(used_traffic_control);
  auto traffic_control_map = decision.getTraffContDecs();
  traffic_control_map.insert(std::make_pair(rcId, *traffic_control_data));
  decision.setTraffContDecs(traffic_control_map);

  // Set PCC rule to decision
  auto pcc_rules_map = decision.getPccRules();
  pcc_rules_map.insert(std::make_pair(pcc_rule_id, *pcc_rule));
  decision.setPccRules(pcc_rules_map);

  return handler_result{.status = status_code::OK};
}

handler_result handle_service_function_chaining_update(
    const oai::model::pcf::AfSfcRequirement& af_sfc,
    oai::model::pcf::SmPolicyDecision& decision,
    oai::model::pcf::AppSessionContextReqData& context) {
  Logger::pcf_app().info("Handling Service Function Chaining Update");
  auto result = handle_service_function_chaining(af_sfc, decision);
  if (result.problem_details.has_value()) {
    return result;
  }

  auto af_sfc_req = context.getAfSfcReq();

  if (af_sfc.sfcIdDlIsSet()) {
    af_sfc_req.setSfcIdDl(af_sfc.getSfcIdDl());
  }

  if (af_sfc.sfcIdUlIsSet()) {
    af_sfc_req.setSfcIdUl(af_sfc.getSfcIdUl());
  }

  // TODO [PAS] Transparently include SFC Metadata if available

  context.setAfSfcReq(af_sfc_req);

  return handler_result{.status = status_code::OK};
}

handler_result validate_and_merge_decision(
    const oai::model::pcf::SmPolicyDecision& request_decision,
    oai::model::pcf::SmPolicyDecision& current_decision, bool update) {
  Logger::pcf_app().info("Validating and Merging Decision");

  // TODO [PAS] Discuss with team how to handle creation of new PCC rules for
  // the same traffic control data

  /* Note: Current implementation. The request decision contains the decision to
   * be made by the PCF. The PCC rules in the request decision will be assigned
   * a precedence value higher than the highest precedence value in the current
   * decision. During update new PCC rules will be added to the current
   * decision. With a new precedence value higher than the highest precedence
   * value in the current decision.
   */

  // Get the highest precedence value from current_decision PCC rules
  int highest_precedence = 0;
  for (const auto& [key, value] : current_decision.getPccRules()) {
    if (value.getPrecedence() > highest_precedence) {
      highest_precedence = value.getPrecedence();
    }
  }
  if (highest_precedence == 0) {
    highest_precedence = DEFAULT_PCC_RULE_PRECEDENCE;
  }

  // Check if PCC rule id in request decision exists in current decision
  if (request_decision.getPccRules().size() > 0 && !update) {
    for (const auto& [key, value] : request_decision.getPccRules()) {
      auto iter = current_decision.getPccRules().find(key.c_str());
      if (iter != current_decision.getPccRules().end() &&
          !iter->first.empty()) {
        Logger::pcf_app().debug(fmt::format(
            "PCC Rule ID: {} already exists in current decision", key.c_str()));
        return handler_result{
            .status          = status_code::FORBIDDEN,
            .problem_details = "INVALID_SERVICE_INFORMATION"};
      }
    }
  }

  // Check if TcId in traffic control data in request decision exists in current
  // decision
  if (request_decision.getTraffContDecs().size() > 0 && !update) {
    for (const auto& [key, value] : request_decision.getTraffContDecs()) {
      auto iter = current_decision.getTraffContDecs().find(key);
      if (iter != current_decision.getTraffContDecs().end() &&
          !iter->first.empty()) {
        Logger::pcf_app().debug(fmt::format(
            "Traffic Cont ID: {} already exists in current decision",
            key.c_str()));
        return handler_result{
            .status          = status_code::FORBIDDEN,
            .problem_details = "INVALID_SERVICE_INFORMATION"};
      }
    }
  }

  // Merge the request decision with current decision
  auto pccRulesMap = current_decision.getPccRules();
  for (auto& [key, value] : request_decision.getPccRules()) {
    if (value.getPrecedence() == 0) {
      value.setPrecedence(highest_precedence + 1);
    }
    pccRulesMap.insert(std::make_pair(key, value));
  }
  current_decision.setPccRules(pccRulesMap);

  // TODO [QOS] Merge QoS-related decision data [TS 29.512 §4.2.6.2.3, §5.6.2.4]
  // Tasks:
  //   - Merge QosData entries from request_decision into current_decision [TS 29.512 §5.6.2.8]
  //   - Merge QosChars (QoS Characteristics) for non-standard 5QIs [TS 29.512 §5.6.2.16]
  //   - Merge QosMonDecs (QoS Monitoring Data) entries [TS 29.512 §5.6.2.40]
  //   - Validate QoS parameter consistency across merged rules [TS 23.503 §6.1.3.7]
  //
  // [QOS-MOCK] Mocks the TODO [QOS] task above:
  //   - QosData is written directly to current_decision by
  //     create_qos_data_from_media_component() before this call, so no merge
  //     from request_decision is needed on the QoS mock path.
  //   - QosChars and QosMonDecs merge is not performed (stubs only log).
  Logger::pcf_app().debug(
      "validate_and_merge_decision() [mock]: QoS data merge "
      "(QosData, QosChars, QosMonDecs)");

  // Merge Traffic Control Data
  auto trafficControlMap = current_decision.getTraffContDecs();
  for (auto& [key, value] : request_decision.getTraffContDecs()) {
    trafficControlMap.insert(std::make_pair(key, value));
  }

  try {
    auto pcc_rules = current_decision.getPccRules();
    // pcc_rules.erase(key);
    for (auto& [key, value] : pcc_rules) {
      for (auto& refTcData : value.getRefTcData()) {
        // Check if refTcData is in trafficControlMap, if not remove PCC rule
        if (trafficControlMap.find(refTcData) == trafficControlMap.end()) {
          Logger::pcf_app().debug(fmt::format(
              "Removing PCC Rule ID: {} from current decision", key.c_str()));
          auto refTcDataVector = pcc_rules[key].getRefTcData();
          // Set empty vector
          refTcDataVector.clear();
          pcc_rules[key].setRefTcData(refTcDataVector);
          current_decision.setPccRules(pcc_rules);
        }
      }
    }
  } catch (const std::exception& e) {
    Logger::pcf_app().error(
        fmt::format("Error while processing PCC rules: {}", e.what()));
  }

  current_decision.setTraffContDecs(trafficControlMap);

  // TODO [QOS] Apply merged QoS data to current_decision [TS 29.512 §4.2.6.2.3, §5.6.2.8]
  // if (request_decision.qosDataIsSet()) {
  //   auto qosDataMap = current_decision.getQosData();
  //   for (const auto& [key, value] : request_decision.getQosData()) {
  //     qosDataMap.insert(std::make_pair(key, value));
  //   }
  //   current_decision.setQosData(qosDataMap);
  // }

  // TODO [QOS] Apply merged QoS Characteristics to current_decision [TS 29.512 §4.2.6.6.3, §5.6.2.16]
  // if (request_decision.qosCharsIsSet()) {
  //   auto qosCharsMap = current_decision.getQosChars();
  //   for (const auto& [key, value] : request_decision.getQosChars()) {
  //     qosCharsMap.insert(std::make_pair(key, value));
  //   }
  //   current_decision.setQosChars(qosCharsMap);
  // }

  // TODO [QOS] Apply merged QoS Monitoring Data to current_decision [TS 29.512 §4.2.3.25.1, §5.6.2.40]
  // if (request_decision.qosMonDecsIsSet()) {
  //   auto qosMonDecsMap = current_decision.getQosMonDecs();
  //   for (const auto& [key, value] : request_decision.getQosMonDecs()) {
  //     qosMonDecsMap.insert(std::make_pair(key, value));
  //   }
  //   current_decision.setQosMonDecs(qosMonDecsMap);
  // }

  return handler_result{.status = status_code::OK};
}

handler_result authorize_service_info(
    const oai::model::pcf::AppSessionContextReqData& reqData) {
  // TODO: Implement service authorization

  // TODO [QOS] Add QoS authorization checks [TS 29.514 §4.1.3.1, TS 23.503 §6.1.3.2.3]
  // Validate QoS requirements in MediaComponents against:
  // - User subscription QoS profile [TS 29.512 §4.2.6.6.1]
  // - Network slice QoS limits [TS 29.512 §4.2.6.7, TS 23.503 §6.1.4]
  // - Current network resource availability [TS 23.503 §6.1.3.2.3]
  // - Service level agreements [TS 23.503 §6.1.3.2.3]

  return handler_result{.status = status_code::OK};
}

// ---------------------------------------------------------------------------
// Phase 1 QoS stub implementations
// Each stub is preceded by the TODO [QOS/QOS-MON] task it mocks and a
// [QOS-MOCK] block that states what is hardcoded vs. done for real.
// ---------------------------------------------------------------------------

// TODO [QOS] Extract and process QoS requirements from a MediaComponent
// [TS 29.514 §4.2.2.2, TS 29.513 §7.3.3]
// Tasks:
//   - Read bandwidth params (marBwDl/Ul, mirBwDl/Ul) from MediaComponent [TS 29.514 §5.6.2.7]
//   - Read latency param (desMaxLatency) to map to 5QI [TS 29.514 §5.6.2.7]
//   - Read packet-loss params (desMaxLoss, maxPacketLossRateDl/Ul) [TS 29.514 §5.6.2.7]
//   - Map resPrio to arp.priorityLevel [TS 29.514 §5.6.2.7]
//   - Call create_qos_data_from_media_component, create_qos_characteristics,
//     and setup_qos_monitoring in sequence [TS 29.513 §7.3.3]
//
// [QOS-MOCK] Phase 1 — QoS requirements orchestration (mock; no business logic).
// Mocks the TODO [QOS] task above:
//   - MediaComponent params are not read; hardcoded QosData and PccRule are
//     written to decision inside create_qos_data_from_media_component().
//   - create_qos_characteristics() and setup_qos_monitoring() only log.
handler_result handle_qos_requirements(
    SmPolicyDecision& decision, qos_context& qos_ctx) {
  Logger::pcf_app().debug("handle_qos_requirements() [mock]");
  create_qos_data_from_media_component(decision, qos_ctx);
  create_qos_characteristics(decision);
  setup_qos_monitoring(decision);
  return handler_result{.status = status_code::OK};
}

// TODO [QOS] Create QosData and PccRule entries from MediaComponent QoS parameters
// [TS 29.512 §5.6.2.8, TS 29.513 §7.3.3, TS 29.514 §5.6.2.7]
// Tasks:
//   - Derive 5QI from MediaComponent latency/bandwidth requirements [TS 29.513 §7.3.3]
//   - Map resPrio to arp.priorityLevel (Arp) [TS 29.514 §5.6.2.7]
//   - Set QoS flow priorityLevel from 5QI defaults [TS 23.501 Table 5.7.4-1]
//   - Build SDF filters (flowInfos) from medSubComponents [TS 29.512 §4.1.4.2.1]
//   - Assign PCC rule precedence from operator policy [TS 29.512 §4.1.4.2.1]
//   - Write QosData and PccRule entries to SmPolicyDecision [TS 29.512 §5.6.2.8]
//
// [QOS-MOCK] Phase 1 — QosData and PccRule creation (mock; hardcoded values).
// Mocks the TODO [QOS] task above:
//   - 5QI: hardcoded to 9 (best-effort) instead of derived from latency/BW.
//   - ARP: hardcoded priorityLevel=8, NOT_PREEMPT/NOT_PREEMPTABLE instead of
//     mapped from MediaComponent.resPrio.
//   - priorityLevel: hardcoded to 9 (TS 23.501 Table 5.7.4-1 default for 5QI=9).
//   - flowInfos: permit-all bidirectional filter instead of SDF filters from
//     medSubComponents.
//   - precedence: hardcoded to 100 instead of policy-assigned.
handler_result create_qos_data_from_media_component(
    SmPolicyDecision& decision, qos_context& qos_ctx) {
  Logger::pcf_app().debug("create_qos_data_from_media_component() [mock]");

  const std::string qos_id = "qos-mock-1";
  QosData qos_data;
  qos_data.setQosId(qos_id);
  qos_data.setR5qi(9);

  oai::model::common::Arp arp;
  arp.setPriorityLevel(8);
  oai::model::common::PreemptionCapability preempt_cap;
  preempt_cap.setEnumValue(
      oai::model::common::PreemptionCapability_anyOf::ePreemptionCapability_anyOf::NOT_PREEMPT);
  arp.setPreemptCap(preempt_cap);
  oai::model::common::PreemptionVulnerability preempt_vuln;
  preempt_vuln.setEnumValue(
      oai::model::common::PreemptionVulnerability_anyOf::ePreemptionVulnerability_anyOf::NOT_PREEMPTABLE);
  arp.setPreemptVuln(preempt_vuln);
  qos_data.setArp(arp);

  // 5QI=9 default scheduling priority (TS 23.501 Table 5.7.4-1)
  qos_data.setPriorityLevel(9);

  auto qos_data_map = decision.getQosDecs();
  qos_data_map.insert(std::make_pair(qos_id, qos_data));
  decision.setQosDecs(qos_data_map);

  const std::string rule_id = "qos-rule-mock-1";
  PccRule pcc_rule;
  pcc_rule.setPccRuleId(rule_id);
  pcc_rule.setPrecedence(100);
  pcc_rule.setRefQosData({qos_id});

  // Permit-all bidirectional filter — placeholder for real SDF filters
  FlowInformation flow_info;
  flow_info.setFlowDescription("permit out ip from any to assigned");
  FlowDirectionRm flow_direction;
  flow_direction.setEnumValue(
      FlowDirection_anyOf::eFlowDirection_anyOf::BIDIRECTIONAL);
  flow_info.setFlowDirection(flow_direction);
  pcc_rule.setFlowInfos({flow_info});

  auto pcc_rules_map = decision.getPccRules();
  pcc_rules_map.insert(std::make_pair(rule_id, pcc_rule));
  decision.setPccRules(pcc_rules_map);

  // Record the ids this app-session contributed into its ledger so PATCH/DELETE
  // can later edit exactly these entries. The QosData/PccRule
  // payload itself lives in the decision owned by the SM policy association.
  qos_ctx.record_qos_flow(qos_id);
  qos_ctx.record_pcc_rule(rule_id, 100, {qos_id});

  return handler_result{.status = status_code::OK};
}

// TODO [QOS] Generate QoS characteristics for non-standard 5QI values
// [TS 29.512 §5.6.2.16, §4.2.6.6.3]
// Tasks:
//   - Check if the 5QI in QosData is a non-standard (dynamic) value [TS 29.512 §5.6.2.16]
//   - If non-standard: populate QosCharacteristics (resource type, priority,
//     packet delay budget, packet error rate, averaging window) [TS 29.512 §5.6.2.16]
//   - Add QosCharacteristics entry to SmPolicyDecision.qosChars [TS 29.512 §5.6.2.16]
//
// [QOS-MOCK] Phase 1 — QoS characteristics (mock; no-op).
// Mocks the TODO [QOS] task above:
//   - 5QI=9 is a standardised value; no QosCharacteristics entry is needed.
//     This stub only logs to confirm the call order.
handler_result create_qos_characteristics([[maybe_unused]] SmPolicyDecision& decision) {
  Logger::pcf_app().debug("create_qos_characteristics() [mock]");
  return handler_result{.status = status_code::OK};
}

// TODO [QOS-MON] Setup QoS monitoring based on MediaComponent requirements
// [TS 29.512 §4.1.4.4.6, TS 29.514 §4.2.2.23]
// Tasks:
//   - Read monitoring thresholds from MediaComponent (if present) [TS 29.514 §4.2.2.23]
//   - Create QosMonitoringData entries with threshold and reporting params [TS 29.512 §5.6.2.40]
//   - Add QosMonitoringData to SmPolicyDecision.qosMonDecs [TS 29.512 §5.6.2.40]
//   - Link QosMonitoringData to the PccRule via refQosMon [TS 29.512 §5.6.2.6]
//
// [QOS-MOCK] Phase 1 — QoS monitoring setup (mock; no-op).
// Mocks the TODO [QOS-MON] task above:
//   - No monitoring thresholds are read and no QosMonitoringData is created.
//     This stub only logs to confirm the call order.
handler_result setup_qos_monitoring([[maybe_unused]] SmPolicyDecision& decision) {
  Logger::pcf_app().debug("setup_qos_monitoring() [mock]");
  return handler_result{.status = status_code::OK};
}

// TODO [QOS] Validate QoS requirements against policies and subscription
// [TS 29.514 §4.1.3.1, TS 23.503 §6.1.3.2.3]
// Tasks:
//   - Check QoS params against user subscription QoS profile [TS 29.512 §4.2.6.6.1]
//   - Verify cumulative bandwidth against network slice limits [TS 29.512 §4.2.6.7, TS 23.503 §6.1.4]
//   - Validate resource availability for requested QoS [TS 23.503 §6.1.3.2.3]
//   - Return FORBIDDEN if any check fails [TS 29.514 §4.1.3.1]
//
// [QOS-MOCK] Phase 1 — QoS authorization (mock; always approved).
// Mocks the TODO [QOS] task above:
//   - No subscription or resource checks are performed; always returns OK.
handler_result validate_qos_authorization() {
  Logger::pcf_app().debug("validate_qos_authorization() [mock]");
  return handler_result{.status = status_code::OK};
}

}  // namespace policy_auth

}  // namespace oai::pcf::app
