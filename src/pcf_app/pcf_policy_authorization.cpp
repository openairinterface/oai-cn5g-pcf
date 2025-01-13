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
#include "policy_auth/app_session.hpp"

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
  oai::model::pcf::SmPolicyDecision current_decision = {};
  oai::model::pcf::SmPolicyDecision request_decision = {};

   Logger::pcf_app().info("post_app_sessions_handler");

  const oai::model::pcf::AppSessionContextReqData reqContext = context.getAscReqData();
  std::optional<std::string> association_id = {};
  try {
    // Perform session binding
    m_event_sub.sm_session_binding(reqContext.getUeIpv4(), reqContext.getSupi(), reqContext.getDnn(), association_id, current_decision);
  } catch (const std::exception& e) {
    Logger::pcf_app().info(e.what());
    problem_details = "PDU_SESSION_NOT_AVAILABLE";
    return status_code::INTERNAL_SERVER_ERROR;
  }

  if (!association_id.has_value()) {
    Logger::pcf_app().debug("Failed to find session");
    return status_code::NOT_FOUND;
  }

  std::stringstream ss;
  ss << "Association ID: " << association_id.value() << "\n";
  ss << " -- " << current_decision << "\n";

  // Log the current decision
  Logger::pcf_app().info(ss.str());

  // We are saving the entire app context at the end

  // Authorise the service information received
  handler_result auth_result = authorize_service_info(context.getAscReqData());
  if (auth_result.problem_details.has_value()) {
    problem_details = auth_result.problem_details.value();
    return auth_result.status.value();
  }

  // If the service information provided in the body of the HTTP POST request is
  // rejected, return HTTP "403 Forbidden" response message the cause for the
  // rejection

  /**
   * Handle Initial provisioning of service function chaining information
   * 
   * the "afSfcReq" attribute of "AfSfcRequirement" data type with specific N6-LAN 
   * traffic steering requirements for the application traffic flows either within "AppSessionContextReqData" data type for
   * the service indicated in the "afAppId" attribute, or within the "medComponents" attribute. When provided at both
   * levels, the "afSfcReq" attribute value in the "medComponents" attribute shall have precedence over the "afSfcReq"
   * attribute included in the "AppSessionContextReqData" data type
   */

  // Check if the request contains the "afSfcReq" attribute or medComponents is present. Pick medComponents if both are present
  if (context.getAscReqData().medComponentsIsSet()) {
    Logger::pcf_app().info("MedComponents is set");
    // TODO [PAS] handle multiple medComponents
    for (const auto& medComponent : context.getAscReqData().getMedComponents()) {
      if (medComponent.second.afSfcReqIsSet()) {
        handler_result result = policy_auth::handle_service_function_chaining(
            medComponent.second.getAfSfcReq(), request_decision);
        if (result.problem_details.has_value()) {
          problem_details = result.problem_details.value();
          Logger::pcf_app().error("Service function chaining failed. Problem details: {}", result.problem_details.value());
          return result.status.value();
        }
        break;
      }
    }
  } else if (context.getAscReqData().afSfcReqIsSet()) {
    Logger::pcf_app().info("AfSfcReq is set");
    handler_result result = policy_auth::handle_service_function_chaining(
        context.getAscReqData().getAfSfcReq(), request_decision);
    if (result.problem_details.has_value()) {
      problem_details = result.problem_details.value();
      Logger::pcf_app().error("Service function chaining failed. Problem details: {}", result.problem_details.value());
      return result.status.value();
    }
  }

  std::stringstream ss2;
  ss2 << "Request Decision: " << "\n";
  ss2 << " -- " << request_decision << "\n";
  Logger::pcf_app().info(ss2.str());

  // Validate the request decision against the current decision
  // merge the request decision with the current decision if the request decision is valid
  handler_result decision_result = validate_and_merge_decision(request_decision, current_decision);
  if (decision_result.problem_details.has_value()) {
      problem_details = decision_result.problem_details.value();
      Logger::pcf_app().error("Validation and merge of Decision failed. Problem details: {}", decision_result.problem_details.value());
      return decision_result.status.value();
  }
  

  auto app_session_id = std::to_string(m_app_sessions_id_generator.get_uid());
  policy_auth::app_session app_session(context.getAscReqData(), current_decision, app_session_id);

  // Create an association
  m_app_sessions.insert(std::make_pair(app_session_id, app_session));

  // Log the decision after the merge
  std::stringstream ss3;
  ss3 << "App Session ID: " << app_session_id << "\n";
  ss3 << " -- " << current_decision << "\n";
  Logger::pcf_app().info(ss3.str());

  // Event with updated decision
  m_event_sub.sm_update_decision(association_id, current_decision);

  // TODO [PAS] send notification if notifcation is required

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

//------------------------------------------------------------------------------
pcf_policy_authorization::~pcf_policy_authorization() {
  Logger::pcf_app().debug("Delete PCF PA instance...");
}