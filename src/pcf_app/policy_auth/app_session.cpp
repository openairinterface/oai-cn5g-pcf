/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include <string>
#include <sstream>

#include "AppSessionContext.h"
#include "TrafficControlData.h"
#include "PccRule.h"
#include "SmPolicyDecision.h"
#include "policy_auth/pcf_policy_authorization_status_code.hpp"
#include "logger.hpp"
#include "app_session.hpp"
#include "uint_generator.hpp"

#define DEFAULT_PCC_RULE_PRECEDENCE 255
namespace oai::pcf::app {
namespace policy_auth {

using namespace oai::_3gpp::model;
using namespace oai::pcf::app;
using namespace oai::utils;

std::string app_session::get_id() const {
  return m_id;
}

const oai::_3gpp::model::AppSessionContextReqData&
app_session::get_app_session_context() const {
  return m_context;
}

void app_session::set_app_session_context(
    oai::_3gpp::model::AppSessionContextReqData& context) {
  m_context = context;
}

// TODO: Restore handle_service_function_chaining and
// handle_service_function_chaining_update once AfSfcRequirement and
// AppSessionContextReqData::afSfcReq are regenerated in the new model.
// Ref: 3GPP TS 29.514 §4.2.2.8 N6-LAN traffic steering (SFC).

handler_result validate_and_merge_decision(
    const oai::_3gpp::model::SmPolicyDecision& request_decision,
    oai::_3gpp::model::SmPolicyDecision& current_decision, bool update) {
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

  return handler_result{.status = status_code::OK};
}

handler_result authorize_service_info(
    const oai::_3gpp::model::AppSessionContextReqData& reqData) {
  // TODO: Implement service authorization

  return handler_result{.status = status_code::OK};
}

}  // namespace policy_auth

}  // namespace oai::pcf::app
