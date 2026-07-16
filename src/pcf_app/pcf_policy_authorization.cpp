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
#include "MediaComponentRm.h"
#include "FlowStatus.h"
#include "policy_auth/app_session.hpp"

#include "AppSessionContextRespData.h"

#include <boost/uuid/uuid_io.hpp>
#include <exception>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>

using namespace oai::pcf::app;
using namespace oai::pcf::app::policy_auth;
using namespace oai::config::pcf;
using namespace oai::_3gpp::model;

using namespace std;

namespace {
// Bitwise intersection of the AF's supported features with the PCF's, formatted
// as a 3GPP SupportedFeatures hex string [TS 29.500 §6.6.2, TS 29.571 §5.2.2].
// Phase 1: the PCF advertises no optional Npcf_PolicyAuthorization features, so
// the negotiated set is empty ("0"). When the PCF starts supporting a feature,
// set the corresponding bit(s) in kPcfSupportedFeatures.
std::string negotiate_supported_features(const std::string& af_supp_feat) {
  static constexpr unsigned long long kPcfSupportedFeatures = 0x0ULL;
  unsigned long long af = 0;
  try {
    if (!af_supp_feat.empty())
      af = std::stoull(af_supp_feat, nullptr, /*base=*/16);
  } catch (const std::exception&) {
    af = 0;  // unparseable / out of range -> negotiate no features
  }
  std::stringstream ss;
  ss << std::hex << std::nouppercase << (af & kPcfSupportedFeatures);
  return ss.str();  // "0" today
}
}  // namespace

//------------------------------------------------------------------------------
pcf_policy_authorization::pcf_policy_authorization(
    std::shared_ptr<policy_auth::policy_auth_context> context, pcf_event& ev)
    : m_context(std::move(context)), m_event_sub(ev) {

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
  // Create the app-session up front (storage-generated, restart-safe id) so QoS
  // processing can record the ids it contributes into this session's ledger
  // . The full decision is not stored on the session.
  app_session_id = m_context->app_sessions().generate_id();
  auto session   = std::make_shared<policy_auth::app_session>(
      app_session_id, reqContext, association_id);

  bool qos_flow_processed = false;
  if (context.getAscReqData().medComponentsIsSet()) {
    Logger::pcf_app().info("MedComponents is set");
    // TODO [PAS] handle multiple medComponents
    for (const auto& medComponent :
         context.getAscReqData().getMedComponents()) {

      const auto& med_component = medComponent.second;

      if (med_component.afSfcReqIsSet()) {
        handler_result result = policy_auth::handle_service_function_chaining(
            med_component.getAfSfcReq(), request_decision);
        if (result.problem_details.has_value()) {
          problem_details = result.problem_details.value();
          Logger::pcf_app().error(
              "Service function chaining failed. Problem details: {}",
              result.problem_details.value());
          return result.status.value();
        }
        break;
      } else if (
          // Process QoS for any MediaComponent bearing QoS intent
          // [TS 29.513 §7.3.3]: an explicit qosReference, service data flows to
          // authorize, or an AF-requested bandwidth.
          med_component.qosReferenceIsSet() ||
          med_component.medSubCompsIsSet() || med_component.marBwUlIsSet() ||
          med_component.marBwDlIsSet() || med_component.mirBwUlIsSet() ||
          med_component.mirBwDlIsSet()) {
        // Derive QosData + PccRule (SDF filters) from the MediaComponent per
        // TS 29.513 §7.3.3 and write them into current_decision; the ids are
        // recorded in the session ledger.
        handler_result result = policy_auth::handle_qos_requirements(
            med_component, app_session_id, current_decision, session->qos(),
            m_context->qos_references());
        if (result.problem_details.has_value()) {
          problem_details = result.problem_details.value();
          Logger::pcf_app().error(
              "QoS requirements processing failed. Problem details: {}",
              result.problem_details.value());
          return result.status.value();
        }
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

  // Authorize the QoS this request derived against operator policy and the
  // subscribed envelope (the authorized Session-AMBR carried in the decision's
  // sessRules, populated by the SM side). Returns FORBIDDEN with a cause on
  // violation [TS 29.514 §4.1.3.1, TS 23.503 §6.1.3.2.3, TS 29.512 §4.2.6.6].
  if (qos_flow_processed) {
    handler_result qos_auth_result = policy_auth::validate_qos_authorization(
        current_decision, session->qos().owned_qos_ids(),
        m_context->qos_authorization_policy());
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

  // Pre-notification validation gate: never notify the SMF with a structurally
  // or referentially inconsistent decision [TS 29.512 §4.2.6.2, §5.6.2.4].
  // (The same gate should guard the PATCH/DELETE pushes when that lifecycle
  // work lands.)
  handler_result decision_validation =
      policy_auth::validate_policy_decision(current_decision);
  if (decision_validation.problem_details.has_value()) {
    problem_details = decision_validation.problem_details.value();
    return decision_validation.status.value();
  }

  // Persist the app-session (working set + app-session <-> association binding).
  m_context->app_sessions().insert(session);

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
    const oai::_3gpp::model::AppSessionContextUpdateDataPatch&
        app_session_context_update_data_patch,
    oai::_3gpp::model::AppSessionContext& app_session_context,
    std::string& problem_details) {
  oai::_3gpp::model::SmPolicyDecision current_decision = {};
  oai::_3gpp::model::SmPolicyDecision request_decision = {};

  const oai::_3gpp::model::AppSessionContextUpdateData reqContext =
      app_session_context_update_data_patch.getAscReqData();
  std::optional<std::string> association_id = {};

  // Get app session
  auto session = m_context->app_sessions().find(app_session_id);
  if (!session) {
    Logger::pcf_app().error("App session not found");
    problem_details = "APP_SESSION_CONTEXT_NOT_FOUND";
    return status_code::NOT_FOUND;
  }
  // Zombie-session guard: abort if a concurrent DELETE released it.
  if (session->state() == app_session_state::released) {
    Logger::pcf_app().error("App session already released");
    problem_details = "APP_SESSION_CONTEXT_NOT_FOUND";
    return status_code::NOT_FOUND;
  }

  auto req_context = session->context_snapshot();

  try {
    // Perform session binding
    m_event_sub.sm_session_binding(
        req_context.getUeIpv4(), req_context.getSupi(), req_context.getDnn(),
        association_id, current_decision);
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

  // Process each updated media component: SFC, QoS removal (fStatus=REMOVED),
  // or QoS modify/add. Because the derived ids are deterministic per medCompN,
  // re-deriving an existing component modifies its flow in place
  // [TS 29.514 §4.2.3.2, TS 29.512 §4.2.6.2.1].
  bool qos_flow_processed = false;
  if (app_session_context_update_data_patch.getAscReqData()
          .medComponentsIsSet()) {
    Logger::pcf_app().info("MedComponents is set");
    for (const auto& [med_comp_key, med_component] :
         app_session_context_update_data_patch.getAscReqData()
             .getMedComponents()) {
      // Service function chaining update [TS 29.514 §4.2.2.8].
      if (med_component.afSfcReqIsSet()) {
        handler_result result =
            policy_auth::handle_service_function_chaining_update(
                med_component.getAfSfcReq(), request_decision, req_context);
        if (result.problem_details.has_value()) {
          problem_details = result.problem_details.value();
          Logger::pcf_app().error(
              "Service function chaining failed. Problem details: {}",
              result.problem_details.value());
          return result.status.value();
        }
        continue;
      }

      const int32_t med_comp_n = med_component.getMedCompN();
      const std::string qos_id =
          "PA-QOS-" + app_session_id + "-qos-" + std::to_string(med_comp_n);
      const std::string rule_id =
          "PA-QOS-" + app_session_id + "-" + std::to_string(med_comp_n);

      // Removal: a component flagged REMOVED deletes its QoS flow + PCC rule
      // from the decision and the session ledger [TS 29.514 §4.2.3.2].
      const bool removed =
          med_component.fStatusIsSet() &&
          med_component.getFStatus().getEnumValue() ==
              oai::model::pcf::FlowStatus_anyOf::eFlowStatus_anyOf::REMOVED;
      if (removed) {
        auto pcc_rules = current_decision.getPccRules();
        auto qos_decs  = current_decision.getQosDecs();
        pcc_rules.erase(rule_id);
        qos_decs.erase(qos_id);
        current_decision.setPccRules(pcc_rules);
        current_decision.setQosDecs(qos_decs);
        session->qos().remove(qos_id, rule_id);
        Logger::pcf_app().info(fmt::format(
            "Removed QoS for media component {} (qosId '{}', pccRuleId '{}')",
            med_comp_n, qos_id, rule_id));
        qos_flow_processed = true;
        continue;
      }

      // Modify / add: derive QoS for any component bearing QoS intent. Reusing
      // the same deterministic ids overwrites an existing flow (upgrade/
      // downgrade) or installs a new one [TS 29.513 §7.3.3].
      if (med_component.qosReferenceIsSet() ||
          med_component.medSubCompsIsSet() || med_component.marBwUlIsSet() ||
          med_component.marBwDlIsSet() || med_component.mirBwUlIsSet() ||
          med_component.mirBwDlIsSet()) {
        handler_result result = policy_auth::handle_qos_requirements(
            med_component, app_session_id, current_decision, session->qos(),
            m_context->qos_references());
        if (result.problem_details.has_value()) {
          problem_details = result.problem_details.value();
          Logger::pcf_app().error(
              "QoS modification failed. Problem details: {}",
              result.problem_details.value());
          return result.status.value();
        }
        qos_flow_processed = true;
      }
    }

  } else if (app_session_context_update_data_patch.getAscReqData()
                 .afSfcReqIsSet()) {
    handler_result result =
        policy_auth::handle_service_function_chaining_update(
            app_session_context_update_data_patch.getAscReqData().getAfSfcReq(),
            request_decision, req_context);
    if (result.problem_details.has_value()) {
      problem_details = result.problem_details.value();
      Logger::pcf_app().error(
          "Service function chaining failed. Problem details: {}",
          result.problem_details.value());
      return result.status.value();
    }
  }

  // Authorize the modified/added QoS against operator policy and the subscribed
  // envelope, same gate as create [TS 29.514 §4.1.3.1, TS 23.503 §6.1.3.2.3].
  if (qos_flow_processed) {
    handler_result qos_auth_result = policy_auth::validate_qos_authorization(
        current_decision, session->qos().owned_qos_ids(),
        m_context->qos_authorization_policy());
    if (qos_auth_result.problem_details.has_value()) {
      problem_details = qos_auth_result.problem_details.value();
      return qos_auth_result.status.value();
    }
  }

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

  // Pre-notification validation gate
  handler_result decision_validation =
      policy_auth::validate_policy_decision(current_decision);
  if (decision_validation.problem_details.has_value()) {
    problem_details = decision_validation.problem_details.value();
    return decision_validation.status.value();
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

  // Apply the AF's JSON Merge Patch (RFC 7396) onto the stored request data so a
  // subsequent GET reflects the modification: scalar fields replaced, media
  // components merged in place, added, or removed [TS 29.514 §4.2.3.2].
  req_context = policy_auth::merge_patch_context(
      req_context, app_session_context_update_data_patch.getAscReqData());

  // Persist the merged request context on the session and advance lifecycle.
  session->update_context(req_context);
  session->next_version();
  session->set_state(app_session_state::modified);

  app_session_context.setAscReqData(req_context);
  app_session_context.setAscRespData(build_response_data(req_context));

  // TODO [PAS] send notification if notifcation is required

  return status_code::OK;
}

//------------------------------------------------------------------------------
policy_auth::status_code pcf_policy_authorization::delete_app_session_handler(
    const std::string& app_session_id, std::string& problem_details) {
  Logger::pcf_app().info("DELETE /app-sessions/{}", app_session_id);

  auto session = m_context->app_sessions().find(app_session_id);
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

  m_context->app_sessions().remove(app_session_id);

  return status_code::OK;
}

//------------------------------------------------------------------------------
policy_auth::status_code pcf_policy_authorization::get_app_session_handler(
    const std::string& app_session_id,
    oai::model::pcf::AppSessionContext& app_session_context,
    std::string& problem_details) {
  Logger::pcf_app().info("GET /app-sessions/{}", app_session_id);

  auto session = m_context->app_sessions().find(app_session_id);
  // A session mid-termination (marked released before storage removal) is
  // treated as gone, so GET never returns a context that is being torn down.
  if (!session || session->state() == app_session_state::released) {
    Logger::pcf_app().debug("App session '{}' not found", app_session_id);
    problem_details = "APP_SESSION_CONTEXT_NOT_FOUND";
    return status_code::NOT_FOUND;
  }

  // The resource representation is the AppSessionContext; PA stores the request
  // data (ascReqData) the AF created the session with [TS 29.514 §4.2.5.1], and
  // returns the negotiated response data (ascRespData) alongside it.
  const auto req_data = session->context_snapshot();
  app_session_context.setAscReqData(req_data);
  app_session_context.setAscRespData(build_response_data(req_data));
  return status_code::OK;
}

//------------------------------------------------------------------------------
oai::model::pcf::AppSessionContextRespData
pcf_policy_authorization::build_response_data(
    const oai::model::pcf::AppSessionContextReqData& req) {
  AppSessionContextRespData resp;
  // Negotiate supported features against the AF request (suppFeat is mandatory
  // in the request) [TS 29.514 §4.2.2.2, §5.8].
  resp.setSuppFeat(negotiate_supported_features(req.getSuppFeat()));
  return resp;
}

//------------------------------------------------------------------------------
pcf_policy_authorization::~pcf_policy_authorization() {
  Logger::pcf_app().debug("Delete PCF PA instance...");
}