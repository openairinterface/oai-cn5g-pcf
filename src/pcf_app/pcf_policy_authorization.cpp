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
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>

using namespace oai::pcf::app;
using namespace oai::pcf::app::policy_auth;
using namespace oai::config::pcf;
using namespace oai::model::pcf;

using namespace std;

//------------------------------------------------------------------------------
pcf_policy_authorization::pcf_policy_authorization(
    std::shared_ptr<policy_auth::app_session_storage> app_session_storage,
    pcf_event& ev)
    : m_app_session_storage(std::move(app_session_storage)), m_event_sub(ev) {

  // TODO [QOS-SUB] Initialize Application Function monitoring and notification infrastructure [TS 29.514 §4.2.5, TS 29.500 §6.2]
  // Set up comprehensive AF communication framework as per 3GPP TS 29.514:
  //
  // 1. NOTIFICATION CLIENT SETUP [TS 29.500 §5.2.6]:
  //    - Initialize HTTP/2 client for AF notifications (support both HTTP and HTTPS) [TS 29.500 §5.2.6]
  //    - Configure retry mechanisms for failed AF notifications [TS 29.500 §5.2.8]
  //    - Setup connection pooling for multiple AF endpoints [TS 29.500 §5.2.6]
  //    - Implement authentication/authorization for AF callbacks [TS 29.514 §5.9, TS 33.501 §13.4.1]
  //
  // 2. SUBSCRIPTION REGISTRY [TS 29.514 §4.2.6]:
  //    - Create registry for AF notification subscriptions by session [TS 29.514 §5.3.4.1]
  //    - Implement subscription filtering by event types and QoS parameters [TS 29.514 §5.6.2.6]
  //    - Setup automatic subscription cleanup on session termination [TS 29.514 §4.2.7.1]
  //    - Maintain AF endpoint health status and availability [TS 29.500 §5.2.6]
  //
  // 3. NOTIFICATION QUEUING AND DELIVERY [TS 29.500 §6.8]:
  //    - Create notification queue with priority handling (critical vs informational) [TS 29.500 §6.8.2, §6.8.5]
  //    - Implement batching for non-urgent notifications to same AF
  //    - Setup dead letter queue for failed notifications with retry logic [TS 29.500 §5.2.8]
  //    - Provide notification delivery status tracking and reporting [TS 29.500 §5.2.8]

  // TODO [QOS-MON] Initialize QoS monitoring infrastructure [TS 29.512 §4.2.3.25, TS 23.503 §6.1.3.21]
  // Set up QoS monitoring framework for AF reporting:
  //
  // 1. MONITORING EVENT TRIGGERS [TS 29.512 §4.2.3.25.1, TS 23.503 §6.1.3.21]:
  //    - Register for SM Policy Control service events (QoS flow changes) [TS 29.512 §4.2.3.2]
  //    - Subscribe to UPF monitoring reports via N4 interface [TS 29.244 §5.39.2]
  //    - Setup periodic monitoring report generation timers [TS 29.244 §5.24.4.2]
  //    - Implement threshold-based event triggering for QoS violations [TS 29.244 §5.39.3]
}

//------------------------------------------------------------------------------
status_code pcf_policy_authorization::post_app_sessions_handler(
    const oai::model::pcf::AppSessionContext& context,
    std::string& app_session_id, std::string& problem_details) {
  oai::model::pcf::SmPolicyDecision current_decision = {};
  oai::model::pcf::SmPolicyDecision request_decision = {};

  Logger::pcf_app().info("POST /app-sessions");

  // TODO [QOS] Overview of QoS handling in Policy Authorization Service [TS 29.514 §4.2.2, TS 29.513 §7.3]
  // This handler processes application session requests containing QoS requirements
  // and translates them into 5G system policy decisions as per 3GPP TS 29.514:
  //
  // 1. Extract QoS parameters from MediaComponents (bandwidth, latency, packet loss) [TS 29.514 §5.6.2.7, TS 29.513 §7.3.3]
  // 2. Validate QoS requirements against user subscription and network policies [TS 29.514 §4.1.3.1, TS 23.503 §6.1.3.2.3]
  // 3. Create QosData, QosCharacteristics, and QosMonitoringData entries [TS 29.512 §5.6.2.8, §5.6.2.16, §5.6.2.40]
  // 4. Generate PCC rules with appropriate QoS enforcement actions [TS 29.512 §4.1.4.2, TS 23.503 §6.3.1]
  // 5. Merge QoS decisions with existing session policies [TS 29.512 §4.2.6.2.3]
  // 6. Notify SMF and other NFs about QoS policy decisions [TS 29.512 §4.2.3.2, TS 29.513 §5.2.2.2.1]
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
  // Create the app-session up front (storage-generated, restart-safe id) so QoS
  // processing can record the ids it contributes into this session's ledger
  // . The full decision is not stored on the session.
  app_session_id = m_app_session_storage->generate_id();
  auto session   = std::make_shared<policy_auth::app_session>(
      app_session_id, reqContext, association_id);

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
        policy_auth::handle_qos_requirements(current_decision, session->qos());
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

  // Persist the app-session (working set + app-session <-> association binding).
  m_app_session_storage->insert(session);

  // The SM policy association is the single owner of the SmPolicyDecision; push
  // the merged decision to it (contains QoS data when qos_flow_processed). The
  // SmPolicyDelta optimization is deferred (TODO)
  m_event_sub.sm_update_decision(association_id, current_decision);

  session->set_state(app_session_state::established);

  // TODO [QOS] Send QoS policy decision notifications [TS 29.512 §4.2.3.2, TS 29.513 §5.2.2.2.1]
  // Notify relevant network functions about QoS policy updates:
  // - SMF about new QoS flows and QoS rules [TS 29.512 §4.2.3.2]
  // - UPF about traffic control and forwarding rules [via SMF N4]
  // - UE about QoS flow establishment (via AMF/gNB) [TS 23.502 §4.3.3.2]
  // Include QoS monitoring setup if required [TS 29.512 §4.2.3.25.1]

  // TODO [QOS-SUB] Setup Application Function monitoring and notification framework [TS 29.514 §4.2.6, TS 29.500 §6.2]
  // As per 3GPP TS 29.514, implement bidirectional communication with Application Functions:
  //
  // 1. AF SUBSCRIPTION MANAGEMENT [TS 29.514 §4.2.6]:
  //    - Register AF notification endpoints from AppSessionContextReqData [TS 29.514 §5.6.2.6]
  //    - Store AF callback URIs for different event types (QoS changes, session events) [TS 29.514 §5.6.2.6]
  //    - Implement subscription lifecycle management for AF notifications [TS 29.514 §4.2.6.2]

  // TODO [QOS-MON] Setup QoS monitoring reports to Application Functions [TS 29.514 §4.2.5.14, TS 23.503 §6.1.3.21]
  // Implement QoS measurement and threshold monitoring for AF notifications:
  //
  // 1. QOS MONITORING REPORTS TO AF [TS 29.514 §4.2.5.14]:
  //    - Send QoS flow status updates (established, modified, released) [TS 29.514 §4.2.5.4]
  //    - Report QoS monitoring measurements when thresholds are exceeded [TS 29.514 §5.6.2.37]
  //    - Notify about QoS guarantee failures or degradation [TS 29.514 §4.2.5.4]
  //    - Provide bandwidth utilization and congestion status updates [TS 29.514 §5.6.2.37]
  //
  // 3. PDU SESSION EVENT NOTIFICATIONS [TS 29.514 §4.2.5.22]:
  //    - Notify AF about PDU session establishment/termination [TS 29.514 §5.6.3.24]
  //    - Report session modification events affecting QoS [TS 29.514 §4.2.5.2]
  //    - Send UE mobility events that impact application QoS [TS 29.514 §5.6.3.7]
  //    - Provide session binding status updates [TS 29.514 §4.2.5.22]
  //
  // 4. POLICY DECISION NOTIFICATIONS [TS 29.514 §4.2.5.2]:
  //    - Inform AF when policy decisions are updated by operator
  //    - Report conflicts between AF requests and network policies
  //    - Notify about resource availability changes affecting QoS [TS 29.514 §5.6.3.7]
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

  // TODO [QOS] Overview of QoS handling in session modification requests [TS 29.514 §4.2.3, TS 29.512 §4.2.6.2]
  // This handler processes updates to existing application sessions with QoS changes:
  //
  // 1. Compare new QoS parameters with existing session configuration [TS 29.514 §4.2.3.2]
  // 2. Authorize QoS changes against user subscription and operator policies [TS 29.514 §4.1.3.1, TS 23.503 §6.1.3.2.3]
  // 3. Handle QoS upgrade/downgrade requests appropriately [TS 23.503 §4.3.3.2.2, TS 29.512 §4.2.6.6.1]
  // 4. Update QosData, QosCharacteristics, and monitoring configurations [TS 29.512 §5.6.2.8, §5.6.2.16, §5.6.2.40]
  // 5. Modify existing PCC rules or create new ones for QoS changes [TS 29.512 §4.2.6.2.1]
  // 6. Ensure QoS modification procedures maintain service continuity [TS 23.502 §4.3.3.2]
  // 7. Send appropriate notifications to SMF for QoS flow updates [TS 29.512 §4.2.3.2, §5.6.2.5]

  const oai::model::pcf::AppSessionContextUpdateData reqContext =
      app_session_context_update_data_patch.getAscReqData();
  std::optional<std::string> association_id = {};

  // Get app session
  auto session = m_app_session_storage->find(app_session_id);
  if (!session) {
    Logger::pcf_app().error("App session not found");
    return status_code::NOT_FOUND;
  }
  // Zombie-session guard: abort if a concurrent DELETE released it.
  if (session->state() == app_session_state::released) {
    Logger::pcf_app().error("App session already released");
    return status_code::NOT_FOUND;
  }

  auto app_session_context = session->context_snapshot();

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

  // TODO [QOS] Handle QoS modification requests [TS 29.514 §4.2.3.2, TS 29.512 §4.2.6.2.1]
  // Process QoS parameter updates from MediaComponents:
  // - Validate QoS parameter changes against current session state [TS 29.514 §4.2.3.2]
  // - Check for QoS degradation or improvement requests [TS 29.512 §4.2.6.6.1]
  // - Ensure compatibility with subscription and slice policies [TS 29.512 §4.2.6.7, TS 23.503 §6.1.4]
  // - Update existing QoS flows or create new ones as needed [TS 23.503 §6.1.3.2.4]
  // - Handle QoS monitoring parameter changes [TS 29.512 §4.1.4.4.6]

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

      // TODO [QOS] Process QoS parameter updates in MediaComponent modifications [TS 29.514 §4.2.3.2]
      // Compare new QoS parameters with existing session parameters:
      // - Identify changed bandwidth requirements [TS 29.514 §5.6.2.7]
      // - Check latency and packet loss updates [TS 29.514 §5.6.2.7]
      // - Handle priority and preemption changes [TS 29.514 §5.6.2.7, TS 29.512 §4.2.6.2.9]
      // - Update QoS monitoring parameters if specified [TS 29.512 §5.6.2.40]
      // Generate appropriate QoS rule modifications for SMF [TS 29.512 §4.2.6.2.1, §5.6.2.5]

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

  // TODO [QOS] Validate QoS modification compatibility and authorization [TS 29.514 §4.2.3.2, TS 23.503 §6.1.3.2.3]
  // Perform additional checks for QoS updates:
  // - Verify user authorization for QoS changes [TS 29.514 §4.1.3.1]
  // - Check resource availability for upgraded QoS [TS 23.503 §6.1.3.2.3]
  // - Validate against network slice QoS limits [TS 29.512 §4.2.6.7, TS 23.503 §6.1.4]
  // - Ensure QoS changes don't violate SLA agreements [TS 23.503 §6.1.3.2.3]

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

  // TODO [QOS] Send QoS policy update notifications [TS 29.512 §4.2.3.2, §5.6.2.5]
  // Notify network functions about QoS policy changes:
  // - Send updated QoS rules to SMF [TS 29.512 §4.2.3.2]
  // - Update QoS monitoring configurations [TS 29.512 §4.2.3.25.1]
  // - Trigger QoS flow modification procedures [TS 23.502 §4.3.3.2]

  // TODO [QOS-SUB] Send Application Function update notifications for session modifications [TS 29.514 §4.2.5.2]
  // As per 3GPP TS 29.514, notify AF about QoS and session changes:
  //
  // 1. QOS MODIFICATION NOTIFICATIONS [TS 29.514 §4.2.5.2, §5.6.2.9]:
  //    - Report successful QoS parameter changes (bandwidth, latency updates)
  //    - Notify about rejected QoS modification requests with reasons
  //    - Send QoS flow reconfiguration status (success/failure) [TS 29.514 §4.2.5.4]
  //    - Provide updated QoS characteristics after network optimization

  // TODO [QOS-MON] Handle monitoring threshold updates during session modifications [TS 29.514 §4.2.3.2, §4.2.2.23]
  // Implement QoS monitoring parameter updates and threshold management:
  //
  // 1. MONITORING THRESHOLD UPDATES [TS 29.514 §4.2.2.23.1, §4.2.5.14]:
  //    - Notify when QoS monitoring parameters change
  //    - Report threshold breach events for modified QoS flows [TS 29.514 §5.6.2.37]
  //    - Send congestion status updates affecting modified sessions [TS 29.514 §5.6.2.37]
  //    - Provide packet loss and latency measurement reports [TS 29.514 §5.6.2.37]
  //
  // 3. SESSION MODIFICATION EVENTS [TS 29.514 §4.2.5.2]:
  //    - Report session context updates to subscribed AFs
  //    - Notify about media component changes and their QoS impact
  //    - Send service function chain modification results
  //    - Provide updated charging correlation information
  //
  // 4. POLICY ENFORCEMENT NOTIFICATIONS [TS 29.514 §4.2.5.2]:
  //    - Report policy rule activation/deactivation status
  //    - Notify about conflicts resolved during modification
  //    - Send resource allocation updates for modified sessions
  //    - Provide operator policy override notifications

  // Persist the updated request context on the session and advance lifecycle.
  session->update_context(app_session_context);
  session->next_version();
  session->set_state(app_session_state::modified);

  // TODO [PAS] send notification if notifcation is required

  return status_code::OK;
}

//------------------------------------------------------------------------------
policy_auth::status_code pcf_policy_authorization::delete_app_session_handler(
    const std::string& app_session_id, std::string& problem_details) {
  Logger::pcf_app().info("DELETE /app-sessions/{}", app_session_id);

  auto session = m_app_session_storage->find(app_session_id);
  if (!session) {
    Logger::pcf_app().error("App session not found");
    problem_details = "APP_SESSION_CONTEXT_NOT_FOUND";
    return status_code::NOT_FOUND;
  }
  if (session->state() == app_session_state::released) {
    Logger::pcf_app().error("App session already released");
    problem_details = "APP_SESSION_CONTEXT_NOT_FOUND";
    return status_code::NOT_FOUND;
  }

  // Mark released first so a concurrent PATCH aborts (plan §5.5).
  session->set_state(app_session_state::released);

  // Re-fetch the bound association's current decision (existing binding signal,
  // keyed by the session's stored context), remove exactly the entries this
  // session contributed (from its ledger), and push the reduced decision back
  // to the SM policy association (the single owner). CP.22: no storage lock is
  // held across the emits below.
  const auto app_session_context = session->context_snapshot();
  std::optional<std::string> association_id      = {};
  oai::model::pcf::SmPolicyDecision current_decision = {};
  try {
    m_event_sub.sm_session_binding(
        app_session_context.getUeIpv4(), app_session_context.getSupi(),
        app_session_context.getDnn(), association_id, current_decision);
  } catch (const std::exception& e) {
    // The PDU session/association may already be gone; still drop the
    // app-session from storage below.
    Logger::pcf_app().info(e.what());
  }

  if (association_id.has_value()) {
    session->qos().erase_owned_from(current_decision);
    m_event_sub.sm_update_decision(association_id, current_decision);
  } else {
    Logger::pcf_app().debug(
        "No SM policy association bound; skipping SMF decision update");
  }

  // TODO [QOS-SUB] If the DELETE carried an EventsSubscReqData, send the
  // termination EventsNotification to the AF here (Phase 3) [TS 29.514 §4.2.4].

  m_app_session_storage->remove(app_session_id);

  return status_code::OK;
}

//------------------------------------------------------------------------------
pcf_policy_authorization::~pcf_policy_authorization() {
  Logger::pcf_app().debug("Delete PCF PA instance...");
}