/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_APP_SESSION_SEEN
#define FILE_APP_SESSION_SEEN

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "AppSessionContext.h"
#include "AppSessionContextReqData.h"
#include "SmPolicyDecision.h"
#include "app_session_record.hpp"
#include "guarded.hpp"
#include "pcf_policy_authorization_status_code.hpp"
#include "qos_context.hpp"
#include "qos_types.hpp"

namespace oai::pcf::app::policy_auth {

/**
 * @brief Aggregate root for an application session (3GPP TS 29.514).
 *
 * Deliberately thin: each cross-cutting concern is a self-contained "aspect"
 * object with its own lock (qos_context; AF-subscription and monitoring),
 * so this class never accretes unrelated state.
 * The full SmPolicyDecision is NOT stored here -- it is owned by the SM
 * policy association; this object keeps only a ledger (via qos_context) of the
 * ids it contributed, plus the app-session <-> association binding.
 *
 * AF-subscription and monitoring state become their own aspect classes,
 * added as one member line -- not fields on this class.
 */
class app_session {
 public:
  app_session(
      std::string id, const oai::_3gpp::model::AppSessionContextReqData& context,
      std::optional<std::string> association_id);

  app_session(const app_session&)            = delete;
  app_session& operator=(const app_session&) = delete;
  virtual ~app_session()                     = default;

  [[nodiscard]] const std::string& id() const { return m_id; }

  [[nodiscard]] app_session_state state() const { return m_state.load(); }
  void set_state(app_session_state state) { m_state.store(state); }

  // Monotonic version stamped on each update; lets stale notifications be
  // detected once cross-service coordination is delta-based (plan §4.7).
  uint64_t next_version() { return ++m_version; }
  [[nodiscard]] uint64_t version() const { return m_version.load(); }

  // app-session <-> SM policy association binding (set at construction).
  [[nodiscard]] const std::optional<std::string>& association_id() const {
    return m_association_id;
  }

  // QoS aspect (Phase 1). Phase 3 adds af(), Phase 4 adds mon() the same way.
  [[nodiscard]] qos_context& qos() { return m_qos; }
  [[nodiscard]] const qos_context& qos() const { return m_qos; }

  [[nodiscard]] oai::_3gpp::model::AppSessionContextReqData context_snapshot()
      const;
  void update_context(
      const oai::_3gpp::model::AppSessionContextReqData& context);

  // Durable projection (documents the app_session_binding schema). from_record()
  // ships with the future DB storage backend.
  [[nodiscard]] app_session_record to_record() const;

 private:
  const std::string m_id;
  const std::chrono::system_clock::time_point m_created_at;
  std::atomic<app_session_state> m_state{app_session_state::pending};
  std::atomic<uint64_t> m_version{0};
  oai::utils::guarded<oai::_3gpp::model::AppSessionContextReqData> m_context;
  std::optional<std::string> m_association_id;
  qos_context m_qos;
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

// TODO [QOS] Extract and process QoS requirements from a MediaComponent
// [TS 29.514 §4.2.2.2, TS 29.513 §7.3]. Internally calls
// create_qos_data_from_media_component, create_qos_characteristics, and
// setup_qos_monitoring in sequence.
oai::pcf::app::policy_auth::handler_result handle_qos_requirements(
    oai::model::pcf::SmPolicyDecision& decision, qos_context& qos_ctx);

// TODO [QOS] Create QosData entries from MediaComponent QoS parameters
// [TS 29.512 §5.6.2.8, TS 29.513 §7.3.3]
oai::pcf::app::policy_auth::handler_result
create_qos_data_from_media_component(
    oai::model::pcf::SmPolicyDecision& decision, qos_context& qos_ctx);

// TODO [QOS] Generate QoS characteristics for non-standard 5QI values
// [TS 29.512 §5.6.2.16, §4.2.6.6.3]
oai::pcf::app::policy_auth::handler_result create_qos_characteristics(
    oai::model::pcf::SmPolicyDecision& decision);

// TODO [QOS-MON] Setup QoS monitoring based on MediaComponent requirements
// [TS 29.512 §4.1.4.4.6, TS 29.514 §4.2.2.23]
oai::pcf::app::policy_auth::handler_result setup_qos_monitoring(
    oai::model::pcf::SmPolicyDecision& decision);

// TODO [QOS] Validate QoS requirements against policies and subscription
// [TS 29.514 §4.1.3.1, TS 23.503 §6.1.3.2.3]
oai::pcf::app::policy_auth::handler_result validate_qos_authorization();

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
//       oai::_3gpp::model::SmPolicyContextData& orig_context,
//       const oai::_3gpp::model::SmPolicyUpdateContextData& update,
//       std::string& problem_details);

oai::pcf::app::policy_auth::handler_result authorize_service_info(
    const oai::_3gpp::model::AppSessionContextReqData& reqData);

oai::pcf::app::policy_auth::handler_result validate_and_merge_decision(
    const oai::_3gpp::model::SmPolicyDecision& request_decision,
    oai::_3gpp::model::SmPolicyDecision& current_decision, bool update = false);

}  // namespace oai::pcf::app::policy_auth

#endif  // FILE_APP_SESSION_SEEN
