/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

/*! \file pcf_policy_authorization_status_code.hpp
 \brief
 \author  Tariro Mukute
 \company University of Cape Town
 \date 2024
 \email: mkttar001@myuct.ac.za
 */

#include <sstream>

#include "AppSessionContext.h"
#include "TrafficControlData.h"
#include "PccRule.h"
#include "SmPolicyDecision.h"
#include "AfSfcRequirement.h"
#include "policy_auth/pcf_policy_authorization_status_code.hpp"
#include "logger.hpp"
#include "app_session.hpp"

namespace oai::pcf::app {
namespace policy_auth {
    
using namespace oai::model::pcf;
using namespace oai::pcf::app;

std::string app_session::get_id() const {
  return m_id;
}

const oai::model::pcf::AppSessionContextReqData& app_session::get_app_session_context() const {
  return m_context;
}


handler_result handle_service_function_chaining(
    const oai::model::pcf::AfSfcRequirement& af_sfc,
    oai::model::pcf::SmPolicyDecision& decision) {
  Logger::pcf_app().info("Handling Service Function Chaining");

  // Extract N6-LAN Traffic Steering Requirements
  std::shared_ptr<oai::model::pcf::TrafficControlData> traffic_control_data = std::make_shared<oai::model::pcf::TrafficControlData>();

  if (!af_sfc.sfcIdDlIsSet() && !af_sfc.sfcIdUlIsSet()) {
    Logger::pcf_app().error(
        "Failed either UL SFC ID or DL SFC ID should be set");
    return handler_result{ .status = status_code::BAD_REQUEST, .problem_details = "INVALID_SERVICE_INFORMATION"};
  }

  // Set Traffic Steering Policy ID for DL and/or UL based on the presence of
  // corresponding SFC IDs
  if (af_sfc.sfcIdDlIsSet()) {
    Logger::pcf_app().debug("Setting DL SFC ID on Traffic Control Data");
    traffic_control_data->setTrafficSteeringPolIdDl(af_sfc.getSfcIdDl());
  }

  if (af_sfc.sfcIdUlIsSet()) {
    Logger::pcf_app().debug("Setting UL SFC ID on Traffic Control Data");
    traffic_control_data->setTrafficSteeringPolIdUl(af_sfc.getSfcIdUl());
  }

  // TODO [PAS]: Transparently include SFC Metadata if available

  // Add the traffic control to PCC rules
  std::shared_ptr<oai::model::pcf::PccRule> pcc_rule = std::make_shared<oai::model::pcf::PccRule>();
  std::string  pcc_rule_id = "app-session-rule-1";
  std::string rcId = "app-session";
  std::vector<std::string> refTcData = { rcId };

  pcc_rule->setRefTcData(refTcData);
  pcc_rule->setPccRuleId(pcc_rule_id);

  // // Create and set TCId on traffic control data and add it as RefTc to PCC
  traffic_control_data->setTcId(rcId);


  // Set traffic control to decision decision.setTraffContDecs(used_traffic_control);
  auto traffic_control_map = decision.getTraffContDecs();
  traffic_control_map.insert(std::make_pair(rcId, *traffic_control_data));
  decision.setTraffContDecs(traffic_control_map);

  // Set PCC rule to decision
  auto pcc_rules_map = decision.getPccRules();
  pcc_rules_map.insert(std::make_pair(pcc_rule_id, *pcc_rule));
  decision.setPccRules(pcc_rules_map);

  std::stringstream ss2;
  ss2 << "Handled Decision: " << "\n";
  ss2 << " -- " << decision << "\n";
  Logger::pcf_app().info(ss2.str());

  return handler_result{ .status = status_code::OK };
}

handler_result validate_and_merge_decision(
    const oai::model::pcf::SmPolicyDecision& request_decision,
    oai::model::pcf::SmPolicyDecision& current_decision) {
    Logger::pcf_app().info("Validating and Merging Decision");

    // If PCC rules in request conflict with current decision, return 403 Forbidden

    // Check if PCC rule id in request decision exists in current decision
    if (request_decision.getPccRules().size() > 0) {
        for (const auto& [key, value] : request_decision.getPccRules()) {
            auto iter = current_decision.getPccRules().find(key.c_str());
            if (iter != current_decision.getPccRules().end() && !iter->first.empty()) {
                Logger::pcf_app().debug(fmt::format("PCC Rule ID: {} already exists in current decision", key.c_str()));
                return handler_result{ .status = status_code::FORBIDDEN, .problem_details = "INVALID_SERVICE_INFORMATION" };
            }
        }
    }

    // Check if TcId in traffic control data in request decision exists in current decision
    if (request_decision.getTraffContDecs().size() > 0) {
        for (const auto& [key, value] : request_decision.getTraffContDecs()) {
            auto iter = current_decision.getTraffContDecs().find(key);
            if (iter != current_decision.getTraffContDecs().end() && !iter->first.empty()) {
                Logger::pcf_app().debug(fmt::format("Traffic Cont ID: {} already exists in current decision", key.c_str()));
                return handler_result{ .status = status_code::FORBIDDEN, .problem_details = "INVALID_SERVICE_INFORMATION" };
            }
        }
    }

    // Merge the request decision with current decision

    // Merge PCC rules
    auto pccRulesMap = current_decision.getPccRules();
    for (auto& [key, value] : request_decision.getPccRules()) {
        pccRulesMap.insert(std::make_pair(key, value));
    }
    current_decision.setPccRules(pccRulesMap);

    // Merge Traffic Control Data
    auto trafficControlMap = current_decision.getTraffContDecs();
    // Now pass the map to the function
    for (auto& [key, value] : request_decision.getTraffContDecs()) {
        trafficControlMap.insert(std::make_pair(key, value));
    }
    current_decision.setTraffContDecs(trafficControlMap);

    return handler_result{ .status = status_code::OK };

}

handler_result authorize_service_info(const oai::model::pcf::AppSessionContextReqData& reqData) {
    // TODO: Implement service authorization

    return handler_result{ .status = status_code::OK };
}

}  // namespace oai::pcf::app::policy_auth

}  // namespace oai::pcf::app
