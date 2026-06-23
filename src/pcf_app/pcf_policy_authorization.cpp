/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
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
using namespace oai::_3gpp::model;

using namespace std;

//------------------------------------------------------------------------------
pcf_policy_authorization::pcf_policy_authorization(pcf_event& ev)
    : m_event_sub(ev) {}

//------------------------------------------------------------------------------
status_code pcf_policy_authorization::post_app_sessions_handler(
    const oai::_3gpp::model::AppSessionContext& context,
    std::string& app_session_id, std::string& problem_details) {
  oai::_3gpp::model::SmPolicyDecision current_decision = {};
  oai::_3gpp::model::SmPolicyDecision request_decision = {};

  Logger::pcf_app().info("POST /app-sessions");

  const oai::_3gpp::model::AppSessionContextReqData reqContext =
      context.getAscReqData();
  std::optional<std::string> association_id = {};
  try {
    // Perform session binding
    m_event_sub.sm_session_binding(
        reqContext.getUeIpv4(), reqContext.getSupi(), reqContext.getDnn(),
        association_id, current_decision);
  } catch (const std::exception& e) {
    Logger::pcf_app().info(e.what());
    problem_details = "PDU_SESSION_NOT_AVAILABLE";
    return status_code::INTERNAL_SERVER_ERROR;
  }

  if (!association_id.has_value()) {
    Logger::pcf_app().debug("Failed to find session");
    return status_code::NOT_FOUND;
  }

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

  // TODO [QOS] Handle Initial provisioning of QoS information [TS 29.514 §4.2.2.2, TS 29.513 §7.3]
  // Process QoS parameters from MediaComponents including:
  // - Bandwidth requirements (marBwDl, marBwUl, mirBwDl, mirBwUl, minDesBwDl, minDesBwUl) [TS 29.514 §5.6.2.7]
  // - Latency requirements (desMaxLatency) [TS 29.514 §5.6.2.7]
  // - Packet loss requirements (desMaxLoss, maxPacketLossRateDl, maxPacketLossRateUl) [TS 29.514 §5.6.2.7, TS 29.512 §5.6.2.8]
  // - Priority and preemption settings (resPrio, preemptCap, preemptVuln) [TS 29.514 §5.6.2.7]
  // - QoS reference and flow status (qosReference, fStatus) [TS 29.514 §5.6.2.7]
  // Create QosData entries and update SmPolicyDecision with QoS rules [TS 29.512 §5.6.2.8, TS 29.513 §7.3.3]

  /**
   * Handle Initial provisioning of service function chaining information
   *
   * the "afSfcReq" attribute of "AfSfcRequirement" data type with specific
   * N6-LAN traffic steering requirements for the application traffic flows
   * either within "AppSessionContextReqData" data type for the service
   * indicated in the "afAppId" attribute, or within the "medComponents"
   * attribute. When provided at both levels, the "afSfcReq" attribute value in
   * the "medComponents" attribute shall have precedence over the "afSfcReq"
   * attribute included in the "AppSessionContextReqData" data type
   */

  // Check if the request contains the "afSfcReq" attribute or medComponents is
  // present. Pick medComponents if both are present
  bool qos_flow_processed = false;
  if (context.getAscReqData().medComponentsIsSet()) {
    Logger::pcf_app().info("MedComponents is set");
    // TODO [PAS] handle multiple medComponents
    for (const auto& medComponent :
         context.getAscReqData().getMedComponents()) {

      if (medComponent.second.afSfcReqIsSet()) {
        handler_result result = policy_auth::handle_service_function_chaining(
            medComponent.second.getAfSfcReq(), request_decision);
        if (result.problem_details.has_value()) {
          problem_details = result.problem_details.value();
          Logger::pcf_app().error(
              "Service function chaining failed. Problem details: {}",
              result.problem_details.value());
          return result.status.value();
        }
        break;
      } else if (medComponent.second.qosReferenceIsSet()) {
        // TODO [QOS] Process QoS parameters from each MediaComponent
        // [TS 29.514 §4.2.2.2, TS 29.513 §7.3.3]
        // Tasks: extract bandwidth/latency/loss params and resPrio from
        // MediaComponent; derive 5QI and ARP; create QosData + PccRule.
        // Also mocks TODO [QOS] Handle Initial provisioning of QoS information.
        //
        // [QOS-MOCK] Phase 1 — per-MediaComponent QoS processing (mock).
        // Mocks the TODO [QOS] tasks above:
        //   - MediaComponent fields are not read; handle_qos_requirements()
        //     delegates to create_qos_data_from_media_component() which writes
        //     hardcoded mock QosData (5QI=9, ARP priorityLevel=8) and a
        //     permit-all PccRule to current_decision.
        policy_auth::handle_qos_requirements(current_decision);
        qos_flow_processed = true;
      }
    }
  } else if (context.getAscReqData().afSfcReqIsSet()) {
    Logger::pcf_app().info("AfSfcReq is set");
    handler_result result = policy_auth::handle_service_function_chaining(
        context.getAscReqData().getAfSfcReq(), request_decision);
    if (result.problem_details.has_value()) {
      problem_details = result.problem_details.value();
      Logger::pcf_app().error(
          "Service function chaining failed. Problem details: {}",
          result.problem_details.value());
      return result.status.value();
    }
  }

  // TODO [QOS] Handle QoS requirements at AppSessionContextReqData level [TS 29.514 §4.2.2.2, §5.6.2.6]

  // TODO [QOS] Validate QoS requirements against policies and subscription
  // [TS 29.514 §4.1.3.1, TS 23.503 §6.1.3.2.3]
  // Tasks: check subscription QoS profile, network slice limits, resource
  // availability; return FORBIDDEN if any check fails.
  //
  // [QOS-MOCK] Phase 1 — post-loop QoS authorization (mock; always approved).
  // Mocks the TODO [QOS] task above:
  //   - No subscription or resource checks performed; validate_qos_authorization()
  //     always returns OK.
  if (qos_flow_processed) {
    handler_result qos_auth_result = policy_auth::validate_qos_authorization();
    if (qos_auth_result.problem_details.has_value()) {
      problem_details = qos_auth_result.problem_details.value();
      return qos_auth_result.status.value();
    }
  }

  // Validate the request decision against the current decision
  // merge the request decision with the current decision if the request
  // decision is valid
  handler_result decision_result =
      validate_and_merge_decision(request_decision, current_decision);
  if (decision_result.problem_details.has_value()) {
    problem_details = decision_result.problem_details.value();
    Logger::pcf_app().error(
        "Validation and merge of Decision failed. Problem details: {}",
        decision_result.problem_details.value());
    return decision_result.status.value();
  }

  app_session_id = std::to_string(m_app_sessions_id_generator.get_uid());
  policy_auth::app_session app_session(
      reqContext, current_decision, app_session_id);

  // Create an association
  m_app_sessions.insert(std::make_pair(app_session_id, app_session));
  context.getAscReqData().setAfAppId(app_session_id);

  // Event with updated decision (contains QoS data when qos_flow_processed)
  m_event_sub.sm_update_decision(association_id, current_decision);

  // TODO [PAS] send notification if notifcation is required

  // Return "201 Created" response to the HTTP POST request
  return status_code::CREATED;
}

//------------------------------------------------------------------------------
policy_auth::status_code pcf_policy_authorization::mod_app_session_handler(
    const std::string& app_session_id,
    const oai::_3gpp::model::AppSessionContextUpdateDataPatch&
        app_session_context_update_data_patch,
    const oai::_3gpp::model::AppSessionContext& context,
    std::string& problem_details) {
  oai::_3gpp::model::SmPolicyDecision current_decision = {};
  oai::_3gpp::model::SmPolicyDecision request_decision = {};

  const oai::_3gpp::model::AppSessionContextUpdateData reqContext =
      app_session_context_update_data_patch.getAscReqData();
  std::optional<std::string> association_id = {};

  // Get app session
  auto iter = m_app_sessions.find(app_session_id);
  if (iter == m_app_sessions.end()) {
    Logger::pcf_app().error("App session not found");
    return status_code::NOT_FOUND;
  }

  auto& app_session        = iter->second;
  auto app_session_context = app_session.get_app_session_context();

  try {
    // Perform session binding
    m_event_sub.sm_session_binding(
        app_session_context.getUeIpv4(), app_session_context.getSupi(),
        app_session_context.getDnn(), association_id, current_decision);
  } catch (const std::exception& e) {
    Logger::pcf_app().info(e.what());
    problem_details = "PDU_SESSION_NOT_AVAILABLE";
    return status_code::INTERNAL_SERVER_ERROR;
  }

  // TODO: Restore SFC update once AfSfcRequirement and
  // AppSessionContextReqData::afSfcReq are regenerated. Ref: 3GPP TS 29.514
  // §4.2.2.8.

  // Validate the request decision against the current decision
  // merge the request decision with the current decision if the request
  // decision is valid
  handler_result decision_result =
      validate_and_merge_decision(request_decision, current_decision, true);

  if (decision_result.problem_details.has_value()) {
    problem_details = decision_result.problem_details.value();
    Logger::pcf_app().error(
        "Validation and merge of Decision failed. Problem details: {}",
        decision_result.problem_details.value());
    return decision_result.status.value();
  }

  // Event with updated decision
  m_event_sub.sm_update_decision(association_id, current_decision);

  // Update app session
  // m_app_sessions[app_session_id] = app_session;
  std::shared_lock lock_associations(m_app_sessions_mutex);
  app_session.set_app_session_context(app_session_context);
  // Get mutex

  auto iter2 = m_app_sessions.find(app_session_id);
  if (iter2 == m_app_sessions.end()) {
    Logger::pcf_app().error("App session not found");
    return status_code::NOT_FOUND;
  }

  // TODO [PAS] send notification if notifcation is required

  return status_code::OK;
}

//------------------------------------------------------------------------------
pcf_policy_authorization::~pcf_policy_authorization() {
  Logger::pcf_app().debug("Delete PCF PA instance...");
}