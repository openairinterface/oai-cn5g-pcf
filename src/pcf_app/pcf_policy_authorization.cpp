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

/*! \file pcf_policy_authorization.cpp
 \brief
 \author  Tariro Mukute
 \company University of Cape Town
 \date 2024
 \email: mkttar001@myuct.ac.za
 */

#include "pcf_policy_authorization.hpp"
#include "logger.hpp"
#include "pcf_config.hpp"
#include "pcf_event.hpp"
#include "AppSessionContext.h"
#include "AppSessionContextReqData.h"
#include "AppSessionContextUpdateDataPatch.h"

#include <boost/uuid/uuid_io.hpp>
#include <unordered_map>
#include <map>
#include <memory>
#include <string>

using namespace oai::pcf::app;
using namespace oai::pcf::app::policy_auth;
using namespace oai::config::pcf;
using namespace oai::model::pcf;

using namespace std;

//------------------------------------------------------------------------------
pcf_policy_authorization::pcf_policy_authorization(pcf_event& ev)
    : m_event_sub(ev) {}

//------------------------------------------------------------------------------
status_code pcf_policy_authorization::post_app_sessions_handler(
    const oai::model::pcf::AppSessionContext& context,
    std::string& problem_details) {
  oai::model::pcf::SmPolicyDecision decision = {};

   Logger::pcf_app().info("post_app_sessions_handler");

  const oai::model::pcf::AppSessionContextReqData reqContext = context.getAscReqData();
  try {
    // Perform session binding using the session_binding_key
    decision.setSuppFeat("F");
    m_event_sub.sm_session_binding(reqContext.getUeIpv4(), reqContext.getSupi(), reqContext.getDnn(), decision);
    Logger::pcf_app().warn(fmt::format("Policy auth, changed suppFeat: {}, pccRulesIsSet: {}", decision.getSuppFeat(), decision.pccRulesIsSet()));
    // handler_result binding_result = perform_binding(session_key, &decision);
    // if (binding_result.problem_details.has_value()) {
    //     problem_details = binding_result.problem_details.value();
    //     return status_code::INTERNAL_SERVER_ERROR;
    // }
  } catch (const std::exception& e) {
    Logger::pcf_app().info(e.what());
    problem_details = "PDU_SESSION_NOT_AVAILABLE";
    return status_code::INTERNAL_SERVER_ERROR;
  }

  // // If the request contains the "medComponents" store the received service
  // // information
  // if (context.getAscReqData().medComponentsIsSet()) {
  //   store_service_info(context.getAscReqData().getMedComponents());
  // }

  // We are saving the entire app context at the end

  // // Authorise the service information received
  // handler_result auth_result = authorize_service_info(context.getAscReqData());
  // if (auth_result.problem_details.has_value()) {
  //   problem_details = auth_result.problem_details.value();
  //   return auth_result.status.value();
  // }

  oai::model::pcf::TrafficControlData traffic_control_data;

  // If the service information provided in the body of the HTTP POST request is
  // rejected, return HTTP "403 Forbidden" response message the cause for the
  // rejection
  // if (context.getAscReqData().afSfcReqIsSet()) {
  //   handler_result result = policy_auth::handle_service_function_chaining(
  //       context.getAscReqData().getAfSfcReq(), &traffic_control_data);
  //   if (result.problem_details.has_value()) {
  //     problem_details = result.problem_details();
  //     return result.status.value();
  //   }
  // }

  // // Fetch current PCC for the PDU session retrieved session binding
  // auto pcc_result = fetch_current_pcc(session_key);
  // if (!pcc_result) {
  //   problem_details = "PDU_SESSION_NOT_AVAILABLE";
  //   return status_code::internal_server_error;
  // }

  // // Modify PCC Rules with Traffic Control Data
  // Event with updated decision and supi



  // // Success, create Application Session Context resource
  // auto created_resource =
  //     create_app_session_context(context.getAppSessionContextReqData());
  // if (!created_resource) {
  //   problem_details = "Internal Server Error";
  //   return status_code::internal_server_error;
  // }

  // Return "201 Created" response to the HTTP POST request
  return status_code::OK;
}

//------------------------------------------------------------------------------
policy_auth::status_code pcf_policy_authorization::mod_app_session_handler(
    const std::string& app_session_id,
    const oai::model::pcf::AppSessionContextUpdateDataPatch&
        app_session_context_update_data_patch,
    const oai::model::pcf::AppSessionContext& context,
    std::string& problem_details) {
  Logger::pcf_app().warn("App session, but not implemented!");

  return status_code::NOT_FOUND;
}

session_binding_key oai::pcf::app::extract_session_key(
    const oai::model::pcf::AppSessionContextReqData& context) {
  return session_binding_key(
      context.getUeIpv4(), context.getUeIpv6(), context.getUeMac(),
      context.getDnn(), context.getSliceInfo(), context.getSupi(),
      context.getGpsi(), context.getIpDomain());
}

//------------------------------------------------------------------------------
pcf_policy_authorization::~pcf_policy_authorization() {
  Logger::pcf_app().debug("Delete PCF PA instance...");
}