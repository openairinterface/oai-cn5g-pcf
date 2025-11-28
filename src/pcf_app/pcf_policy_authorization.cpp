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
using namespace oai::model::pcf;

using namespace std;

//------------------------------------------------------------------------------
pcf_policy_authorization::pcf_policy_authorization(pcf_event& ev)
    : m_event_sub(ev) {

  // TODO [QOS-AF] Initialize Application Function monitoring and notification infrastructure
  // Set up comprehensive AF communication framework as per 3GPP TS 29.514:
  //
  // 1. NOTIFICATION CLIENT SETUP:
  //    - Initialize HTTP/2 client for AF notifications (support both HTTP and HTTPS)
  //    - Configure retry mechanisms for failed AF notifications
  //    - Setup connection pooling for multiple AF endpoints
  //    - Implement authentication/authorization for AF callbacks
  //
  // 2. SUBSCRIPTION REGISTRY:
  //    - Create registry for AF notification subscriptions by session
  //    - Implement subscription filtering by event types and QoS parameters
  //    - Setup automatic subscription cleanup on session termination
  //    - Maintain AF endpoint health status and availability
  //
  // 3. NOTIFICATION QUEUING AND DELIVERY:
  //    - Create notification queue with priority handling (critical vs informational)
  //    - Implement batching for non-urgent notifications to same AF
  //    - Setup dead letter queue for failed notifications with retry logic
  //    - Provide notification delivery status tracking and reporting

  // TODO [QOS-MON] Initialize QoS monitoring infrastructure
  // Set up QoS monitoring framework for AF reporting:
  //
  // 1. MONITORING EVENT TRIGGERS:
  //    - Register for SM Policy Control service events (QoS flow changes)
  //    - Subscribe to UPF monitoring reports via N4 interface
  //    - Setup periodic monitoring report generation timers
  //    - Implement threshold-based event triggering for QoS violations
}

//------------------------------------------------------------------------------
status_code pcf_policy_authorization::post_app_sessions_handler(
    const oai::model::pcf::AppSessionContext& context,
    std::string& app_session_id, std::string& problem_details) {
  oai::model::pcf::SmPolicyDecision current_decision = {};
  oai::model::pcf::SmPolicyDecision request_decision = {};

  Logger::pcf_app().info("POST /app-sessions");

  // TODO [QOS] Overview of QoS handling in Policy Authorization Service
  // This handler processes application session requests containing QoS requirements
  // and translates them into 5G system policy decisions as per 3GPP TS 29.514:
  //
  // 1. Extract QoS parameters from MediaComponents (bandwidth, latency, packet loss)
  // 2. Validate QoS requirements against user subscription and network policies
  // 3. Create QosData, QosCharacteristics, and QosMonitoringData entries
  // 4. Generate PCC rules with appropriate QoS enforcement actions
  // 5. Merge QoS decisions with existing session policies
  // 6. Notify SMF and other NFs about QoS policy decisions
  // 7. Setup QoS monitoring if required by the application or operator policy

  const oai::model::pcf::AppSessionContextReqData reqContext =
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

  // TODO [QOS] Handle Initial provisioning of QoS information as per 3GPP TS 29.514
  // Process QoS parameters from MediaComponents including:
  // - Bandwidth requirements (marBwDl, marBwUl, mirBwDl, mirBwUl, minDesBwDl, minDesBwUl)
  // - Latency requirements (desMaxLatency)
  // - Packet loss requirements (desMaxLoss, maxPacketLossRateDl, maxPacketLossRateUl)
  // - Priority and preemption settings (resPrio, preemptCap, preemptVuln)
  // - QoS reference and flow status (qosReference, fStatus)
  // Create QosData entries and update SmPolicyDecision with QoS rules

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
  if (context.getAscReqData().medComponentsIsSet()) {
    Logger::pcf_app().info("MedComponents is set");
    // TODO [PAS] handle multiple medComponents
    for (const auto& medComponent :
         context.getAscReqData().getMedComponents()) {

      // TODO [QOS] Process QoS parameters from each MediaComponent
      // Extract and validate QoS requirements:
      // - Check bandwidth parameters (marBwDl, marBwUl, mirBwDl, mirBwUl)
      // - Process latency constraints (desMaxLatency)
      // - Handle packet loss limits (desMaxLoss, maxPacketLossRateDl/Ul)
      // - Extract priority settings (resPrio, preemptCap, preemptVuln)
      // - Process QoS reference if set (qosReference)
      // Create corresponding QosData and QosCharacteristics objects
      // Update request_decision with QoS-specific PCC rules and QoS monitoring data

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

  // TODO [QOS] Handle QoS requirements at AppSessionContextReqData level
  // Check for global QoS requirements that apply to the entire application session
  // Process any QoS monitoring requirements (qosMonitoringInfo)
  // Validate against operator QoS policies and subscription limits

  // TODO [QOS] Validate QoS decision compatibility
  // Check that QoS requirements are feasible and compatible with:
  // - Current session QoS configuration
  // - Network slice QoS policies
  // - Subscription QoS profiles
  // - Available network resources
  // Resolve conflicts between different QoS requirements

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

  // Event with updated decision
  m_event_sub.sm_update_decision(association_id, current_decision);

  // TODO [QOS] Send QoS policy decision notifications
  // Notify relevant network functions about QoS policy updates:
  // - SMF about new QoS flows and QoS rules
  // - UPF about traffic control and forwarding rules
  // - UE about QoS flow establishment (via AMF/gNB)
  // Include QoS monitoring setup if required

  // TODO [QOS-AF] Setup Application Function monitoring and notification framework
  // As per 3GPP TS 29.514, implement bidirectional communication with Application Functions:
  //
  // 1. AF SUBSCRIPTION MANAGEMENT:
  //    - Register AF notification endpoints from AppSessionContextReqData
  //    - Store AF callback URIs for different event types (QoS changes, session events)
  //    - Implement subscription lifecycle management for AF notifications

  // TODO [QOS-MON] Setup QoS monitoring reports to Application Functions
  // Implement QoS measurement and threshold monitoring for AF notifications:
  //
  // 1. QOS MONITORING REPORTS TO AF:
  //    - Send QoS flow status updates (established, modified, released)
  //    - Report QoS monitoring measurements when thresholds are exceeded
  //    - Notify about QoS guarantee failures or degradation
  //    - Provide bandwidth utilization and congestion status updates
  //
  // 3. PDU SESSION EVENT NOTIFICATIONS:
  //    - Notify AF about PDU session establishment/termination
  //    - Report session modification events affecting QoS
  //    - Send UE mobility events that impact application QoS
  //    - Provide session binding status updates
  //
  // 4. POLICY DECISION NOTIFICATIONS:
  //    - Inform AF when policy decisions are updated by operator
  //    - Report conflicts between AF requests and network policies
  //    - Notify about resource availability changes affecting QoS
  //    - Send charging policy updates if applicable

  // TODO [PAS] send notification if notifcation is required

  // Return "201 Created" response to the HTTP POST request
  return status_code::CREATED;
}

//------------------------------------------------------------------------------
policy_auth::status_code pcf_policy_authorization::mod_app_session_handler(
    const std::string& app_session_id,
    const oai::model::pcf::AppSessionContextUpdateDataPatch&
        app_session_context_update_data_patch,
    const oai::model::pcf::AppSessionContext& context,
    std::string& problem_details) {
  oai::model::pcf::SmPolicyDecision current_decision = {};
  oai::model::pcf::SmPolicyDecision request_decision = {};

  // TODO [QOS] Overview of QoS handling in session modification requests
  // This handler processes updates to existing application sessions with QoS changes:
  //
  // 1. Compare new QoS parameters with existing session configuration
  // 2. Authorize QoS changes against user subscription and operator policies
  // 3. Handle QoS upgrade/downgrade requests appropriately
  // 4. Update QosData, QosCharacteristics, and monitoring configurations
  // 5. Modify existing PCC rules or create new ones for QoS changes
  // 6. Ensure QoS modification procedures maintain service continuity
  // 7. Send appropriate notifications to SMF for QoS flow updates

  const oai::model::pcf::AppSessionContextUpdateData reqContext =
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

  // TODO [QOS] Handle QoS modification requests as per 3GPP TS 29.514
  // Process QoS parameter updates from MediaComponents:
  // - Validate QoS parameter changes against current session state
  // - Check for QoS degradation or improvement requests
  // - Ensure compatibility with subscription and slice policies
  // - Update existing QoS flows or create new ones as needed
  // - Handle QoS monitoring parameter changes

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
  if (app_session_context_update_data_patch.getAscReqData()
          .medComponentsIsSet()) {
    Logger::pcf_app().info("MedComponents is set");
    // TODO [PAS] handle multiple medComponents
    for (const auto& medComponent :
         app_session_context_update_data_patch.getAscReqData()
             .getMedComponents()) {

      // TODO [QOS] Process QoS parameter updates in MediaComponent modifications
      // Compare new QoS parameters with existing session parameters:
      // - Identify changed bandwidth requirements
      // - Check latency and packet loss updates
      // - Handle priority and preemption changes
      // - Update QoS monitoring parameters if specified
      // Generate appropriate QoS rule modifications for SMF

      if (medComponent.second.afSfcReqIsSet()) {
        handler_result result =
            policy_auth::handle_service_function_chaining_update(
                medComponent.second.getAfSfcReq(), request_decision,
                app_session_context);
        if (result.problem_details.has_value()) {
          problem_details = result.problem_details.value();
          Logger::pcf_app().error(
              "Service function chaining failed. Problem details: {}",
              result.problem_details.value());
          return result.status.value();
        }
        break;
      }
    }

  } else if (app_session_context_update_data_patch.getAscReqData()
                 .afSfcReqIsSet()) {
    handler_result result =
        policy_auth::handle_service_function_chaining_update(
            app_session_context_update_data_patch.getAscReqData().getAfSfcReq(),
            request_decision, app_session_context);
    if (result.problem_details.has_value()) {
      problem_details = result.problem_details.value();
      Logger::pcf_app().error(
          "Service function chaining failed. Problem details: {}",
          result.problem_details.value());
      return result.status.value();
    }
  }

  // TODO [QOS] Validate QoS modification compatibility and authorization
  // Perform additional checks for QoS updates:
  // - Verify user authorization for QoS changes
  // - Check resource availability for upgraded QoS
  // - Validate against network slice QoS limits
  // - Ensure QoS changes don't violate SLA agreements

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

  // TODO [QOS] Send QoS policy update notifications
  // Notify network functions about QoS policy changes:
  // - Send updated QoS rules to SMF
  // - Update QoS monitoring configurations
  // - Trigger QoS flow modification procedures

  // TODO [QOS-AF] Send Application Function update notifications for session modifications
  // As per 3GPP TS 29.514, notify AF about QoS and session changes:
  //
  // 1. QOS MODIFICATION NOTIFICATIONS:
  //    - Report successful QoS parameter changes (bandwidth, latency updates)
  //    - Notify about rejected QoS modification requests with reasons
  //    - Send QoS flow reconfiguration status (success/failure)
  //    - Provide updated QoS characteristics after network optimization

  // TODO [QOS-MON] Handle monitoring threshold updates during session modifications
  // Implement QoS monitoring parameter updates and threshold management:
  //
  // 1. MONITORING THRESHOLD UPDATES:
  //    - Notify when QoS monitoring parameters change
  //    - Report threshold breach events for modified QoS flows
  //    - Send congestion status updates affecting modified sessions
  //    - Provide packet loss and latency measurement reports
  //
  // 3. SESSION MODIFICATION EVENTS:
  //    - Report session context updates to subscribed AFs
  //    - Notify about media component changes and their QoS impact
  //    - Send service function chain modification results
  //    - Provide updated charging correlation information
  //
  // 4. POLICY ENFORCEMENT NOTIFICATIONS:
  //    - Report policy rule activation/deactivation status
  //    - Notify about conflicts resolved during modification
  //    - Send resource allocation updates for modified sessions
  //    - Provide operator policy override notifications

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