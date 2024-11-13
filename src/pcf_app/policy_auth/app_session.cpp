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
#include "AfSfcRequirement.h"
#include "policy_auth/pcf_policy_authorization_status_code.hpp"
#include "logger.hpp"

namespace oai::pcf::app::policy_auth {
    
using namespace oai::model::pcf;
using namespace oai::pcf::app;

class app_session {
 public:
 private:
  oai::model::pcf::TrafficControlData handle_service_function_chaining(
      oai::model::pcf::AfSfcRequirement& af_sfc, std::string& problem_details) {

  }
};

handler_result handle_service_function_chaining(
    oai::model::pcf::AfSfcRequirement& af_sfc,
    oai::model::pcf::TrafficControlData& traffic_control_data) {
  // Extract N6-LAN Traffic Steering Requirements

  if (!af_sfc.sfcIdDlIsSet() && !af_sfc.sfcIdUlIsSet()) {
    Logger::pcf_app().error(
        "Failed either UL SFC ID or DL SFC ID should be set");
    return handler_result{ .status = status_code::BAD_REQUEST, .problem_details = "INVALID_SERVICE_INFORMATION"};
  }

  // Set Traffic Steering Policy ID for DL and/or UL based on the presence of
  // corresponding SFC IDs
  if (af_sfc.sfcIdDlIsSet()) {
    traffic_control_data.setTrafficSteeringPolIdDl(af_sfc.getSfcIdDl());
  }

  if (af_sfc.sfcIdUlIsSet()) {
    traffic_control_data.setTrafficSteeringPolIdUl(af_sfc.getSfcIdUl());
  }

  // TODO: Transparently include SFC Metadata if available

  return handler_result{ .status = status_code::OK };
}

}  // namespace oai::pcf::app::policy_auth