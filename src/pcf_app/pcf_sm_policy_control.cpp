/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "pcf_sm_policy_control.hpp"
#include "logger.hpp"
#include "pcf_config.hpp"
#include "sm_policy/policy_decision.hpp"
#include "SmPolicyDecision.h"

#include <boost/uuid/uuid_io.hpp>
#include <unordered_map>
#include <map>
#include <memory>
#include <string>
#include <optional>
#include "nlohmann/json.hpp"
#include "3gpp_29.500.h"
#include "ProblemDetails.h"
#include "http_client.hpp"

using namespace oai::pcf::app;
using namespace oai::pcf::app::sm_policy;
using namespace oai::config::pcf;
using namespace oai::model::pcf;
using namespace oai::model::common;
using namespace oai::http;

using namespace std;

extern std::shared_ptr<oai::http::http_client> http_client_inst;

//------------------------------------------------------------------------------
pcf_smpc::pcf_smpc(
    const std::shared_ptr<oai::pcf::app::sm_policy::policy_storage>&
        policy_storage,
    pcf_event& ev)
    : m_event_sub(ev) {
  m_policy_storage = policy_storage;

  std::function<void(const std::shared_ptr<policy_decision>& decision)> f =
      std::bind(&pcf_smpc::handle_policy_change, this, std::placeholders::_1);

  m_policy_storage->subscribe_to_decision_change(f);

  m_sm_session_binding_connection =
      m_event_sub.subscribe_sm_session_binding(boost::bind(
          &pcf_smpc::handle_session_binding_request, this,
          boost::placeholders::_1, boost::placeholders::_2,
          boost::placeholders::_3, boost::placeholders::_4,
          boost::placeholders::_5));

  m_sm_update_decision_connection =
      m_event_sub.subscribe_sm_update_decision(boost::bind(
          &pcf_smpc::handle_update_decision_request, this,
          boost::placeholders::_1, boost::placeholders::_2));
  // m_sm_session_binding_connection =
  //     m_event_sub.subscribe_sm_session_binding(f2);
}

void pcf_smpc::handle_policy_change(
    const std::shared_ptr<policy_decision>& /* decision */) {
  Logger::pcf_app().warn("Policy changed, but not implemented!");
}

sm_policy::status_code pcf_smpc::send_sm_policy_control_update_notify(
    const oai::pcf::app::sm_policy::individual_sm_association& association) {
  // TODO [QOS] Enhanced notification for QoS policy updates to SMF
  // This function sends updated policy decisions including QoS-related changes from
  // Policy Authorization Service to SMF. Key QoS elements to include:
  // 1. Updated PCC rules with QoS enforcement actions
  // 2. QoS Data entries for flow-specific QoS parameters
  // 3. QoS Characteristics for non-standard 5QI values
  // 4. QoS Monitoring Data configurations
  // 5. Traffic Control Data with QoS steering information
  // 6. Updated QoS flow identifiers and bindings

  std::string uri =
      association.get_sm_policy_context_data().getNotificationUri() + "/update";
  nlohmann::json json_data;
  // to_json(json_data, association.decsion);
  nlohmann::json decision_json;
  to_json(decision_json, association.get_sm_policy_decision_dto());

  json_data["smPolicyDecision"] = decision_json;

  Logger::pcf_app().info(
      "Sending PCF SM policy association creation request: uri -> %s",
      uri.c_str());
  request req   = http_client_inst->prepare_json_request(uri, json_data.dump());
  response resp = http_client_inst->send_http_request(method_e::POST, req);

  if (resp.status_code == http_status_code::OK) {
    // TODO [PAS] check if for required headers
    Logger::pcf_app().info(
        "Successful SM Policy Update Notification for SUPI %s",
        association.get_sm_policy_context_data().getSupi().c_str());

    // TODO [QOS-AF] Coordinate Application Function notifications after successful SMF update
    // Following successful SMF notification, trigger AF notifications as per 3GPP TS 29.514:
    //
    // 1. EXTRACT AF NOTIFICATION TARGETS:
    //    - Identify AF applications affected by the policy update
    //    - Retrieve AF notification URIs from associated application sessions
    //    - Determine notification event types required by each AF
    //
    // 2. PREPARE AF NOTIFICATION DATA:
    //    - Extract QoS status changes from the policy decision
    //    - Compile monitoring measurements if available from UPF reports
    //    - Prepare session context updates for AF consumption
    //
    // 3. TRIGGER ASYNCHRONOUS AF NOTIFICATIONS:
    //    - Emit events to Policy Authorization service for AF notification delivery
    //    - Include session binding information to correlate AF applications
    //    - Schedule retry for failed AF notifications with appropriate backoff
    //
    // 4. LOG COORDINATION STATUS:
    //    - Track successful AF notification triggers
    //    - Log any coordination failures for troubleshooting
    //    - Update AF subscription health status
    //
    // Example coordination:
    // std::string supi = association.get_sm_policy_context_data().getSupi();
    // std::string dnn = association.get_sm_policy_context_data().getDnn();
    // m_event_sub.coordinate_af_notifications(supi, dnn, association.get_sm_policy_decision_dto());

    return status_code::CREATED;
  }

  // failure case
  ProblemDetails problem_details;
  from_json(resp.body, problem_details);

  std::string info;
  status_code response;
  switch (resp.status_code) {
    case http_status_code::FORBIDDEN:
      info     = "SM Policy Update Notification Forbidden";
      response = status_code::CONTEXT_DENIED;
      break;
    case http_status_code::BAD_REQUEST:
      if (problem_details.getCause() == "USER_UNKNOWN") {
        response = status_code::USER_UNKOWN;
        info     = "SM Policy Association Creation: Unknown User";
      } else {
        response = status_code::INVALID_PARAMETERS;
        info     = "SM Policy Update Notification: Bad Request";
      }
      break;
    case http_status_code::INTERNAL_SERVER_ERROR:
      response = status_code::INTERNAL_SERVER_ERROR;
      info     = "SM Policy Update Notification: Internal Error";
      break;
    default:
      response = status_code::INTERNAL_SERVER_ERROR;
      info =
          "SM Policy Update Notification: Unknown Error Code from "
          "SMF: " +
          std::to_string(resp.status_code);
  }

  Logger::pcf_app().warn(
      "%s -- Details: %s - %s", info.c_str(),
      problem_details.getCause().c_str(), problem_details.getDetail().c_str());
  return response;
}

void pcf_smpc::handle_session_binding_request(
    const std::optional<std::string>& ipv4,
    const std::optional<std::string>& supi,
    const std::optional<std::string>& dnn, std::optional<std::string>& assoc_id,
    oai::model::pcf::SmPolicyDecision& decision) {
  // TODO [QOS] Handle QoS requirements during session binding
  // When Policy Authorization requests session binding, provide comprehensive QoS context:
  //
  // 1. QOS CONTEXT RETRIEVAL:
  //    - Retrieve existing QoS policies for this SUPI/DNN combination
  //    - Include base QoS characteristics from subscription profile
  //    - Provide network slice-specific QoS limits and policies
  //
  // 2. QOS BASELINE ESTABLISHMENT:
  //    - Set baseline QoS parameters that Policy Authorization can build upon
  //    - Ensure default QoS flows are properly configured
  //    - Provide QoS rule precedence ranges available for Policy Auth use
  //
  // 3. RESOURCE AVAILABILITY:
  //    - Include current QoS resource utilization information
  //    - Provide available bandwidth and priority level ranges
  //    - Share network congestion status affecting QoS decisions

  // TODO: support multiple sessions

  std::shared_ptr<std::string> association_id =
      m_policy_storage->find_association(ipv4, supi, dnn);

  if (!association_id) {
    Logger::pcf_app().debug(
        fmt::format("handle_session_binding_request, association_id is null"));
    return;
  }

  assoc_id = association_id->c_str();

  std::unique_lock lock_assocations(m_associations_mutex);
  auto iter = m_associations.find(association_id->c_str());
  if (iter == m_associations.end()) {
    Logger::pcf_app().info(fmt::format(
        "Could not find policy association: ID {} not found",
        association_id->c_str()));
    return;
  }

  decision = iter->second.get_sm_policy_decision_dto();

  // TODO [QOS] Enhance decision with QoS binding information
  // Before returning decision to Policy Authorization, enrich it with:
  // - Current QoS flow configurations and available flow identifiers
  // - Precedence ranges that Policy Authorization can safely use
  // - QoS monitoring capabilities and current monitoring status
  // - Resource reservation status and available QoS budget

  // Get PCC from decision
}

void pcf_smpc::handle_update_decision_request(
    std::optional<std::string>& association_id,
    oai::model::pcf::SmPolicyDecision& decision) {
  // TODO [QOS] Process QoS policy updates from Policy Authorization Service
  // This function receives updated policy decisions from pcf_policy_authorization
  // containing QoS requirements that need to be integrated with existing SM policies:
  //
  // 1. CONFLICT RESOLUTION:
  //    - Check for PCC rule ID conflicts between Policy Auth and SM Policy Control
  //    - Ensure QoS rule precedence values don't overlap with existing SM rules
  //    - Resolve conflicts between Policy Auth QoS requirements and SM QoS policies
  //
  // 2. QOS DATA INTEGRATION:
  //    - Merge QosData entries from Policy Authorization with existing SM QoS data
  //    - Validate QoS parameters against subscription and network slice limits
  //    - Update QoS Characteristics for new or modified 5QI values
  //
  // 3. PCC RULE COORDINATION:
  //    - Generate unique PCC rule IDs that don't conflict across services
  //    - Assign appropriate precedence values considering both Policy Auth and SM rules
  //    - Ensure QoS enforcement actions are consistent across rule sets

  // Fetch the association related to the decision
  std::unique_lock lock_assocations(m_associations_mutex);
  auto iter = m_associations.find(association_id.value());
  if (iter == m_associations.end()) {
    Logger::pcf_app().info(fmt::format(
        "Could not delete policy association: ID {} not found",
        association_id.value()));
    return;
  }

  // TODO [QOS] Validate and merge QoS decisions from Policy Authorization
  // Before setting the new decision, perform comprehensive validation:
  // - Check QoS parameter consistency across all active PCC rules
  // - Validate total bandwidth allocations don't exceed session limits
  // - Ensure QoS flow mappings are consistent and non-conflicting
  // - Resolve any QoS precedence conflicts with existing rules

  iter->second.set_sm_policy_decision(decision);

  // TODO [QOS] Coordinate QoS policy storage updates between Policy Auth and SM Policy Control
  // The QoS policy updates from Policy Authorization need careful storage management:
  //
  // 1. STORAGE STRATEGY:
  //    - Decide whether QoS policies from Policy Auth should be persisted in storage
  //    - Consider separating dynamic QoS policies (from apps) from static SM policies
  //    - Implement versioning for QoS policy updates to track changes
  //
  // 2. POLICY COORDINATION:
  //    - Ensure Policy Authorization QoS updates don't overwrite critical SM policies
  //    - Implement merge strategy for combining Policy Auth and SM QoS requirements
  //    - Maintain separate namespaces for PCC rule IDs from different sources
  //
  // 3. PERSISTENCE CONSIDERATIONS:
  //    - Policy Auth QoS rules may be session-specific and shouldn't persist
  //    - SM Policy QoS rules should persist across UE reconnections
  //    - Consider hybrid approach: persist base QoS policies, cache dynamic ones

  // TODO [PAS] confirm if the storage should be updated
  /**
   * The changes from the update policy authorisation request should be
   * be for an existing policy association for an existing PDU session.
   * THe SMF gets the updated policy decision from the PCF for which the
   * PCF reads the new decision from the policy storage. However the policy
   * storage persists over new UE connections.
   *
   * The TODO is to confirm if the policy storage should be updated with the
   * new decision and to look for an alternative way to store the updates for
   * the policy decisions that are not persisted.
   */
  auto context = iter->second.get_sm_policy_context_data();
  if (!context.getSupi().empty()) {
    m_policy_storage->insert_supi_decision(context.getSupi(), decision);
  } else if (!context.getDnn().empty()) {
    m_policy_storage->insert_dnn_decision(context.getDnn(), decision);
  } else {
    Logger::pcf_app().error("Failed to update policy decision");
  }

  // TODO [QOS] Enhanced SMF notification for QoS policy changes
  // Before sending notification, ensure comprehensive QoS update preparation:
  // 1. Validate all QoS flows have consistent parameters
  // 2. Generate QoS flow setup/modification instructions for SMF
  // 3. Include QoS monitoring setup parameters if required
  // 4. Provide clear indication of which QoS flows are new/modified/deleted

  // Send a notification to the SMF related to the updated decision
  const auto& association_ref = iter->second;
  auto ret = send_sm_policy_control_update_notify(association_ref);
  if (ret != status_code::CREATED) {
    Logger::pcf_app().error("Policy update notification failed");

    // TODO [QOS] Handle QoS notification failures gracefully
    // On notification failure, consider:
    // - Rolling back QoS policy changes to maintain consistency
    // - Implementing retry mechanism for critical QoS updates
    // - Alerting operator about QoS policy synchronization issues
    // - Maintaining fallback QoS policies for service continuity
  }

  // TODO [QOS-AF] Trigger Application Function notifications for QoS policy updates
  // After successful SM policy update, coordinate AF notifications as per 3GPP TS 29.514:
  //
  // 1. IDENTIFY AFFECTED AF APPLICATIONS:
  //    - Determine which AF applications are impacted by the QoS policy changes
  //    - Extract AF application identifiers from the updated policy decision
  //    - Check for active AF subscriptions requiring notifications
  //
  // 2. GENERATE AF QOS NOTIFICATIONS:
  //    - Emit af_qos_status_notification signal for QoS flow changes
  //    - Include updated QoS parameters (bandwidth, latency, packet loss)
  //    - Report QoS guarantee status (met/violated) based on network conditions
  //
  // 3. SEND AF MONITORING REPORTS:
  //    - Emit af_monitoring_report_notification for threshold-based events
  //    - Include current QoS measurements and congestion status
  //    - Provide bandwidth utilization and performance metrics
  //
  // 4. COORDINATE WITH POLICY AUTHORIZATION SERVICE:
  //    - Signal Policy Authorization service about completed QoS updates
  //    - Request AF notification delivery for related application sessions
  //    - Ensure consistent notification content across both services
  //
  // Example event emissions:
  // m_event_sub.emit_af_qos_status_notification(af_app_id, session_id, qos_flows, "QoS_UPDATED");
  // m_event_sub.emit_af_monitoring_report_notification(af_app_id, session_id, monitoring_data, threshold_events);
}

//------------------------------------------------------------------------------
status_code pcf_smpc::create_sm_policy_handler(
    const SmPolicyContextData& context, SmPolicyDecision& decision,
    std::string& association_id, std::string& problem_details) {
  // TODO [QOS] Initialize QoS framework for new SM policy associations
  // When creating new SM policy associations, establish QoS foundation:
  //
  // 1. QOS BASELINE SETUP:
  //    - Initialize default QoS characteristics from subscription profile
  //    - Set up base QoS flows for the PDU session
  //    - Reserve QoS precedence ranges for different services (Policy Auth, SM Policy, etc.)
  //
  // 2. RESOURCE ALLOCATION:
  //    - Allocate initial QoS flow identifiers for this association
  //    - Reserve bandwidth quotas based on subscription and slice policies
  //    - Initialize QoS monitoring framework if required
  //
  // 3. COORDINATION PREPARATION:
  //    - Set up coordination structures for future Policy Authorization requests
  //    - Initialize conflict resolution mechanisms for PCC rule management
  //    - Prepare QoS update notification framework

  std::shared_ptr<policy_decision> chosen_decision =
      m_policy_storage->find_policy(context);

  if (!chosen_decision) {
    problem_details = fmt::format(
        "SM policy request from SUPI {}: No policies found", context.getSupi());
    Logger::pcf_app().debug(fmt::format(problem_details));
    return status_code::CONTEXT_DENIED;
  }

  association_id = std::to_string(m_association_id_generator.get_uid());

  individual_sm_association assoc(context, *chosen_decision, association_id);

  status_code res = assoc.decide_policy(decision);

  // XXX: Perform session binding
  m_policy_storage->insert_associations(context, association_id);

  if (res != status_code::CREATED) {
    problem_details = fmt::format(
        "SM Policy request from SUPI {}: Invalid policy decision provisioned",
        context.getSupi());
    Logger::pcf_app().debug(fmt::format(problem_details));
  } else {
    std::unique_lock lock_assocations(m_associations_mutex);
    m_associations.insert(std::make_pair(association_id, assoc));

    Logger::pcf_app().info(fmt::format(
        "Created Policy Decision for SUPI {} with ID {}", context.getSupi(),
        association_id));
  }
  return res;
}

//------------------------------------------------------------------------------
sm_policy::status_code pcf_smpc::delete_sm_policy_handler(
    const std::string& id, const SmPolicyDeleteData& /* delete_data */,
    std::string& problem_details) {
  // TODO for now, just delete, ignore the delete_data
  std::unique_lock lock_associations(m_associations_mutex);
  auto iter = m_associations.find(id);
  if (iter == m_associations.end()) {
    problem_details =
        fmt::format("Could not delete policy association: ID {} not found", id);
    Logger::pcf_app().info(problem_details);
    return status_code::NOT_FOUND;
  }
  m_associations.erase(iter);
  Logger::pcf_app().info(
      fmt::format("Deleted policy association with ID {}", id));

  // TODO [PAS]: Perform session binding delete

  return status_code::OK;
}

//------------------------------------------------------------------------------
sm_policy::status_code pcf_smpc::get_sm_policy_handler(
    const std::string& id, SmPolicyControl& control,
    std::string& problem_details) {
  Logger::pcf_app().debug(fmt::format("get_sm_policy_handler: ID {}", id));
  std::shared_lock lock_associations(m_associations_mutex);
  auto iter = m_associations.find(id);
  if (iter == m_associations.end()) {
    problem_details = fmt::format(
        "Could not retrieve policy association: ID {} not found", id);
    Logger::pcf_app().info(problem_details);
    return status_code::NOT_FOUND;
  }
  control.setContext(iter->second.get_sm_policy_context_data());
  control.setPolicy(iter->second.get_sm_policy_decision_dto());

  Logger::pcf_app().info(
      fmt::format("Retrieved policy association with ID {}", id));

  return status_code::OK;
}

//------------------------------------------------------------------------------
sm_policy::status_code pcf_smpc::update_sm_policy_handler(
    const std::string& id, const SmPolicyUpdateContextData& update_context,
    SmPolicyDecision& decision, std::string& problem_details) {
  Logger::pcf_app().info("Entering update_sm_policy_handler");

  // TODO [QOS] Handle QoS-related SM policy updates and coordination
  // When SM policy context changes, ensure QoS policies remain consistent:
  //
  // 1. QOS IMPACT ASSESSMENT:
  //    - Analyze how SM context changes affect existing QoS policies
  //    - Check if Policy Authorization QoS rules need updates
  //    - Validate that updated context doesn't violate QoS commitments
  //
  // 2. CROSS-SERVICE COORDINATION:
  //    - Notify Policy Authorization of relevant context changes
  //    - Update QoS monitoring parameters if context affects QoS requirements
  //    - Ensure QoS flow mappings remain valid after context updates
  //
  // 3. QOS RULE CONSISTENCY:
  //    - Maintain consistency between SM-generated and Policy Auth-generated QoS rules
  //    - Update QoS precedence mappings if service priorities change
  //    - Validate that all QoS flows remain properly configured

  std::unique_lock lock_associations(m_associations_mutex);
  auto iter = m_associations.find(id);

  if (iter == m_associations.end()) {
    problem_details =
        fmt::format("Could not update policy association: ID {} not found", id);
    Logger::pcf_app().info(problem_details);
    return status_code::NOT_FOUND;
  }

  // TODO [PAS]: Perform session binding update
  // TODO [QOS]: Update QoS session binding and coordinate with Policy Authorization

  SmPolicyDecision new_decision;

  return iter->second.redecide_policy(
      update_context, decision, problem_details);
}

//------------------------------------------------------------------------------
pcf_smpc::~pcf_smpc() {
  Logger::pcf_app().debug("Delete PCF SMPC instance...");
}
