/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_APP_SESSION_SEEN
#define FILE_APP_SESSION_SEEN

#include "AppSessionContext.h"
#include "AppSessionContextReqData.h"

namespace oai::pcf::app::policy_auth {

class app_session {
 public:
  explicit app_session(
      const oai::model::pcf::AppSessionContextReqData& context,
      const oai::model::pcf::SmPolicyDecision& decision, const std::string& id)
      : m_decision(decision) {
    m_context = context;
    // TODO [PAS] add association id to be used during update
    m_id = id;
  }

  virtual ~app_session() = default;

  [[nodiscard]] virtual const oai::model::pcf::AppSessionContextReqData&
  get_app_session_context() const;

  [[nodiscard]] virtual void set_app_session_context(
      oai::model::pcf::AppSessionContextReqData& context);

  [[nodiscard]] virtual std::string get_id() const;

 private:
  // TODO: create a struct only for attributes that need to be stored?
  oai::model::pcf::AppSessionContextReqData m_context;
  // TODO: create a struct only for attributes that need to be stored?
  oai::model::pcf::SmPolicyDecision m_decision;
  // attributes that need to be stored
  // reference session
  // reference pcc rules
  std::string m_id;

  // TODO [QOS-SUB] Application Function subscription and notification state [TS 29.514 §4.2.6, §5.3.4.1]
  // Add member variables for AF monitoring and notification management:

  // TODO [QOS-SUB] AF notification subscription information [TS 29.514 §4.2.2.2, §5.6.2.6]
  // std::string m_af_notification_uri;           // AF callback URI for notifications [TS 29.514 §5.6.2.6]
  // std::vector<std::string> m_subscribed_events; // List of events AF wants to receive [TS 29.514 §5.6.2.6]
  // std::string m_af_app_identifier;              // AF application identifier [TS 29.514 §3.1]
  // std::chrono::system_clock::time_point m_subscription_expiry; // Subscription validity

  // TODO [QOS-MON] QoS monitoring configuration for AF notifications [TS 29.512 §5.6.2.40, TS 29.514 §4.2.2.23]
  // std::map<std::string, uint32_t> m_qos_monitoring_thresholds; // QoS parameter thresholds [TS 29.512 §5.6.2.40]
  // std::chrono::milliseconds m_monitoring_report_interval;       // Periodic report frequency [TS 29.512 §5.6.2.40]
  // bool m_monitoring_enabled;                                   // Enable/disable monitoring [TS 23.503 §6.1.3.21]

  // TODO [QOS-SUB] AF notification delivery tracking [TS 29.500 §5.2.8, §6.8]
  // std::queue<std::string> m_pending_notifications;             // Queue of pending notifications [TS 29.500 §6.8.1]
  // std::map<std::string, std::chrono::system_clock::time_point> m_notification_history; // Delivery tracking [TS 29.500 §5.2.8]
  // uint32_t m_failed_notification_count;                       // Count of failed deliveries [TS 29.500 §5.2.8]
};

/**
 * Handlers for processing different App Session operation procedures
 *
 * 3GPP TS 29.514 4.2.x
 */

/**
 * Extracts the N6-LAN Traffic Steering Requirements from the given
 * AfSfcRequirement object. 3GPP TS 29.514 4.2.2.8.
 *
 * @param af_sfc           The AfSfcRequirement object containing the SFC
 * requirements.
 * @param traffic_control_data The TrafficControlData object to store the
 * extracted requirements.
 * @param problem_details  A reference string to hold any error details if
 * extraction fails.
 *
 * @return status_code::OK on success or a failure code if an issue occurs
 * during extraction.
 */
oai::pcf::app::policy_auth::handler_result handle_service_function_chaining(
    const oai::model::pcf::AfSfcRequirement& af_sfc,
    oai::model::pcf::SmPolicyDecision& decision);

oai::pcf::app::policy_auth::handler_result
handle_service_function_chaining_update(
    const oai::model::pcf::AfSfcRequirement& af_sfc,
    oai::model::pcf::SmPolicyDecision& decision,
    oai::model::pcf::AppSessionContextReqData& context);

// TODO [QOS] Add QoS handling functions [TS 29.514 §4.2.2.2, TS 29.513 §7.3, TS 29.512 §4.2.6.6]
// Implement the following QoS processing functions:

// TODO [QOS] Extract and process QoS requirements from MediaComponent [TS 29.514 §4.2.2.2, TS 29.513 §7.3]
// oai::pcf::app::policy_auth::handler_result handle_qos_requirements(
//     const oai::model::pcf::MediaComponent& media_component,
//     oai::model::pcf::SmPolicyDecision& decision);

// TODO [QOS] Create QosData entries from MediaComponent QoS parameters [TS 29.512 §5.6.2.8, TS 29.513 §7.3.3]
// oai::pcf::app::policy_auth::handler_result create_qos_data_from_media_component(
//     const oai::model::pcf::MediaComponent& media_component,
//     oai::model::pcf::QosData& qos_data);

// TODO [QOS] Generate QoS characteristics for non-standard 5QI values [TS 29.512 §5.6.2.16, §4.2.6.6.3]
// oai::pcf::app::policy_auth::handler_result create_qos_characteristics(
//     const oai::model::pcf::MediaComponent& media_component,
//     oai::model::pcf::QosCharacteristics& qos_chars);

// TODO [QOS-MON] Setup QoS monitoring based on MediaComponent requirements [TS 29.512 §4.1.4.4.6, TS 29.514 §4.2.2.23]
// oai::pcf::app::policy_auth::handler_result setup_qos_monitoring(
//     const oai::model::pcf::MediaComponent& media_component,
//     oai::model::pcf::SmPolicyDecision& decision);

// TODO [QOS] Validate QoS requirements against policies and subscription [TS 29.514 §4.1.3.1, TS 23.503 §6.1.3.2.3]
// oai::pcf::app::policy_auth::handler_result validate_qos_authorization(
//     const oai::model::pcf::AppSessionContextReqData& req_data,
//     const oai::model::pcf::SmPolicyDecision& current_decision);

// TODO [QOS] Handle QoS parameter updates during session modification [TS 29.514 §4.2.3.2, TS 29.512 §4.2.6.2.1]
// oai::pcf::app::policy_auth::handler_result handle_qos_update(
//     const oai::model::pcf::MediaComponent& updated_media_component,
//     const oai::model::pcf::MediaComponent& existing_media_component,
//     oai::model::pcf::SmPolicyDecision& decision);

// TODO [QOS-SUB] Application Function notification and monitoring handlers [TS 29.514 §4.2.5, TS 29.500 §6.2]
// Implement AF communication functions as per 3GPP TS 29.514:

// TODO [QOS-SUB] Send QoS status notifications to Application Function [TS 29.514 §4.2.5.4, §5.6.2.15]
// oai::pcf::app::policy_auth::handler_result notify_af_qos_status(
//     const std::string& af_app_id,
//     const std::string& session_id,
//     const std::map<std::string, oai::model::pcf::QosData>& qos_flows,
//     const std::string& status_event);
// - Notify AF about QoS flow establishment, modification, release [TS 29.514 §4.2.5.4]
// - Include QoS guarantee status, bandwidth measurements, latency reports [TS 29.514 §5.6.2.15]
// - Handle both successful operations and failure notifications [TS 29.514 §4.2.5.2]

// TODO [QOS-SUB] Send PDU session event notifications to Application Function [TS 29.514 §4.2.5.22, §5.6.3.24]
// oai::pcf::app::policy_auth::handler_result notify_af_pdu_session_event(
//     const std::string& af_app_id,
//     const std::string& session_id,
//     const std::string& event_type,
//     const std::map<std::string, std::string>& session_info);
// - Notify AF about PDU session lifecycle events (establish, modify, terminate) [TS 29.514 §5.6.3.24]
// - Include UE mobility events affecting application performance [TS 29.514 §5.6.3.7]
// - Provide session context updates and binding information [TS 29.514 §4.2.5.22]

// TODO [QOS-MON] Send QoS monitoring reports to Application Function [TS 29.514 §4.2.5.14, §5.6.2.37]
// oai::pcf::app::policy_auth::handler_result notify_af_monitoring_report(
//     const std::string& af_app_id,
//     const std::string& session_id,
//     const std::map<std::string, oai::model::pcf::QosMonitoringData>& monitoring_data,
//     const std::vector<std::string>& threshold_events);
// - Send periodic monitoring measurements to subscribed AFs [TS 29.514 §4.2.5.14]
// - Report threshold breach events and congestion status [TS 29.514 §5.6.2.37]
// - Include bandwidth utilization, packet loss, and latency measurements [TS 29.514 §5.6.2.37]

// TODO [QOS-SUB] Send policy decision updates to Application Function [TS 29.514 §4.2.5.2, §5.6.2.9]
// oai::pcf::app::policy_auth::handler_result notify_af_policy_update(
//     const std::string& af_app_id,
//     const std::string& session_id,
//     const std::map<std::string, std::string>& policy_changes,
//     const std::string& update_reason);
// - Notify AF about policy decision changes affecting their application [TS 29.514 §4.2.5.2]
// - Include resource availability updates and operator policy overrides [TS 29.514 §5.6.3.7]
// - Report charging policy updates and conflict resolutions [TS 29.514 §4.2.5.2]

// TODO [QOS-SUB] Manage AF subscription lifecycle for notifications [TS 29.514 §4.2.6, §5.3.4.1]
// oai::pcf::app::policy_auth::handler_result register_af_subscription(
//     const std::string& af_app_id,
//     const std::string& session_id,
//     const std::string& notification_uri,
//     const std::vector<std::string>& event_types);
// - Register AF endpoints for different types of notifications [TS 29.514 §4.2.6.2]
// - Validate AF authentication and authorization for subscriptions [TS 29.514 §5.9, TS 33.501 §13.4.1]
// - Setup subscription filtering based on QoS parameters and events [TS 29.514 §5.6.2.6]

// TODO [QOS-MON] Process AF monitoring configuration from requests [TS 29.514 §4.2.2.23, TS 29.512 §4.2.3.25]
// oai::pcf::app::policy_auth::handler_result configure_af_monitoring(
//     const oai::model::pcf::AppSessionContextReqData& req_data,
//     oai::model::pcf::SmPolicyDecision& decision);
// - Extract AF notification requirements from application session requests [TS 29.514 §4.2.2.23.1]
// - Configure QoS monitoring thresholds based on AF requirements [TS 29.512 §5.6.2.40, TS 23.503 §6.1.3.21]
// - Setup notification triggers and periodic reporting schedules [TS 29.514 §4.2.2.23.1]

//   oai::pcf::app::policy_auth::status_code handle_traffic_routing(
//       oai::model::pcf::SmPolicyContextData& orig_context,
//       const oai::model::pcf::SmPolicyUpdateContextData& update,
//       std::string& problem_details);

oai::pcf::app::policy_auth::handler_result authorize_service_info(
    const oai::model::pcf::AppSessionContextReqData& reqData);

oai::pcf::app::policy_auth::handler_result validate_and_merge_decision(
    const oai::model::pcf::SmPolicyDecision& request_decision,
    oai::model::pcf::SmPolicyDecision& current_decision, bool update = false);

}  // namespace oai::pcf::app::policy_auth

#endif  // FILE_APP_SESSION_SEEN
