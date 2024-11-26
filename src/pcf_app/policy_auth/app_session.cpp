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

#include "AppSessionContext.h"
#include "TrafficControlData.h"
#include "PccRule.h"
#include "SmPolicyDecision.h"
#include "AfSfcRequirement.h"
#include "policy_auth/pcf_policy_authorization_status_code.hpp"
#include "logger.hpp"

namespace oai::pcf::app {
namespace policy_auth {
    
using namespace oai::model::pcf;
using namespace oai::pcf::app;

class app_session {
 public:
 private:
};

handler_result handle_service_function_chaining(
    const oai::model::pcf::AfSfcRequirement& af_sfc,
    oai::model::pcf::SmPolicyDecision& decision) {
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


  // // Set traffic control to decision decision.setTraffContDecs(used_traffic_control);
  // decision.setPccRules(std::make_pair(pcc_rule_id, pcc_rule));
  // decision.setTraffContDecs(std::make_pair(rcId, traffic_control_data));

  
  return handler_result{ .status = status_code::OK };
}

}


}  // namespace oai::pcf::app::policy_auth