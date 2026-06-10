/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include <string>
#include <sstream>

#include "AppSessionContext.h"
#include "TrafficControlData.h"
#include "PccRule.h"
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

std::string app_session::get_id() const {
  return m_id;
}

const oai::model::pcf::AppSessionContextReqData&
app_session::get_app_session_context() const {
  return m_context;
}

void app_session::set_app_session_context(
    oai::model::pcf::AppSessionContextReqData& context) {
  m_context = context;
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
  // Merge QosData entries from request_decision to current_decision [TS 29.512 §5.6.2.8]
  // Handle QosChars (QoS Characteristics) for non-standard 5QIs [TS 29.512 §5.6.2.16]
  // Merge QosMonDecs (QoS Monitoring Data) entries [TS 29.512 §5.6.2.40]
  // Validate QoS parameter consistency across merged rules [TS 23.503 §6.1.3.7]

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

// TODO [QOS] Implement QoS handling functions [TS 29.514 §4.2.2.2, TS 29.513 §7.3, TS 29.512 §4.2.6.6]
// The following functions need to be implemented to handle QoS requirements
// as specified in 3GPP TS 29.514:

// TODO [QOS] handler_result handle_qos_requirements( [TS 29.514 §4.2.2.2, TS 29.513 §7.3.3]
//     const oai::model::pcf::MediaComponent& media_component,
//     oai::model::pcf::SmPolicyDecision& decision) {
//   Logger::pcf_app().info("Processing QoS requirements for MediaComponent");
//
//   // Extract bandwidth requirements
//   if (media_component.marBwDlIsSet() || media_component.marBwUlIsSet()) {
//     // Process maximum bandwidth requirements
//   }
//
//   if (media_component.mirBwDlIsSet() || media_component.mirBwUlIsSet()) {
//     // Process minimum bandwidth requirements
//   }
//
//   // Extract latency requirements
//   if (media_component.desMaxLatencyIsSet()) {
//     // Process maximum latency requirements
//   }
//
//   // Extract packet loss requirements
//   if (media_component.desMaxLossIsSet()) {
//     // Process maximum packet loss requirements
//   }
//
//   // Create QosData entries and update decision
//   // Generate appropriate PCC rules for QoS enforcement
//
//   return handler_result{.status = status_code::OK};
// }

// TODO [QOS-MON] handler_result setup_qos_monitoring( [TS 29.512 §4.1.4.4.6, TS 29.514 §4.2.2.23]
//     const oai::model::pcf::MediaComponent& media_component,
//     oai::model::pcf::SmPolicyDecision& decision) {
//   Logger::pcf_app().info("Setting up QoS monitoring for MediaComponent");
//
//   // Create QosMonitoringData entries based on MediaComponent requirements
//   // Configure monitoring parameters (thresholds, reporting frequency)
//   // Add monitoring data to SmPolicyDecision
//
//   return handler_result{.status = status_code::OK};
// }

}  // namespace policy_auth

}  // namespace oai::pcf::app
