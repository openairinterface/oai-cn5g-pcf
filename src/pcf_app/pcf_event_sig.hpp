/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_PCF_EVENT_SIG_HPP_SEEN
#define FILE_PCF_EVENT_SIG_HPP_SEEN

#include <boost/signals2.hpp>
#include <string>
#include "SmPolicyDecision.h"

namespace bs2 = boost::signals2;

namespace oai::pcf::app {

using namespace oai::model::pcf;

typedef bs2::signal_type<
    void(uint64_t), bs2::keywords::mutex_type<bs2::dummy_mutex>>::type
    task_sig_t;

// Signal for Loss of Connectivity
// SUPI, Connectivity status, HTTP version
typedef bs2::signal_type<
    void(std::string, uint8_t, uint8_t),
    bs2::keywords::mutex_type<bs2::dummy_mutex>>::type
    loss_of_connectivity_sig_t;

// Signal for UE Reachability for Data
// SUPI, Reachability status, HTTP version
typedef bs2::signal_type<
    void(std::string, uint8_t, uint8_t),
    bs2::keywords::mutex_type<bs2::dummy_mutex>>::type
    ue_reachability_for_data_sig_t;

// UE_REACHABILITY_FOR_SMS
// LOCATION_REPORTING
// CHANGE_OF_SUPI_PEI_ASSOCIATION
// ROAMING_STATUS
// COMMUNICATION_FAILURE
// AVAILABILITY_AFTER_DNN_FAILURE
// CN_TYPE_CHANGE

// Signal for sm_policy_control to perform session binding
typedef bs2::signal_type<
    void(
        const std::optional<std::string>&, const std::optional<std::string>&,
        const std::optional<std::string>&, std::optional<std::string>&,
        oai::model::pcf::SmPolicyDecision&),
    bs2::keywords::mutex_type<bs2::dummy_mutex>>::type sm_session_binding_sig_t;

// Signal for sm_policy_control to update policy decision
typedef bs2::signal_type<
    void(std::optional<std::string>&, oai::model::pcf::SmPolicyDecision&),
    bs2::keywords::mutex_type<bs2::dummy_mutex>>::type sm_update_decision_sig_t;

// TODO [QOS] Define QoS coordination signal types for cross-service communication
// The following signals enable coordination between Policy Authorization and SM Policy Control:

// TODO [QOS] Signal for PCC rule conflict resolution between services
// Parameters: association_id, policy_auth_rules, sm_policy_rules, resolution_strategy
// typedef bs2::signal_type<
//     void(const std::string&,
//          const std::map<std::string, oai::model::pcf::PccRule>&,
//          const std::map<std::string, oai::model::pcf::PccRule>&,
//          std::string&),
//     bs2::keywords::mutex_type<bs2::dummy_mutex>>::type pcc_rule_conflict_sig_t;

// TODO [QOS] Signal for QoS resource availability status updates
// Parameters: association_id, available_bandwidth_ul, available_bandwidth_dl, congestion_status
// typedef bs2::signal_type<
//     void(const std::string&, uint64_t, uint64_t, uint8_t),
//     bs2::keywords::mutex_type<bs2::dummy_mutex>>::type qos_resource_status_sig_t;

// TODO [QOS-MON] Signal for QoS monitoring coordination between services
// Parameters: association_id, monitoring_data, service_id, coordination_action
// typedef bs2::signal_type<
//     void(const std::string&,
//          const std::map<std::string, oai::model::pcf::QosMonitoringData>&,
//          const std::string&,
//          const std::string&),
//     bs2::keywords::mutex_type<bs2::dummy_mutex>>::type qos_monitoring_coordination_sig_t;

// TODO [QOS] Signal for cross-service QoS validation requests
// Parameters: association_id, qos_data, validation_context, validation_result
// typedef bs2::signal_type<
//     void(const std::string&,
//          const std::map<std::string, oai::model::pcf::QosData>&,
//          const std::string&,
//          bool&),
//     bs2::keywords::mutex_type<bs2::dummy_mutex>>::type qos_validation_request_sig_t;

// TODO [QOS-AF] Define Application Function notification signal types as per 3GPP TS 29.514
// The following signals trigger notifications to Application Functions about QoS and session events:

// TODO [QOS-AF] Signal for AF QoS status notifications
// Parameters: af_app_id, session_id, qos_flow_info, qos_status, measurements
// Triggered when QoS flows are established, modified, released or when QoS guarantees change
// typedef bs2::signal_type<
//     void(const std::string&,
//          const std::string&,
//          const std::map<std::string, oai::model::pcf::QosData>&,
//          const std::string&,
//          const std::map<std::string, std::string>&),
//     bs2::keywords::mutex_type<bs2::dummy_mutex>>::type af_qos_status_notification_sig_t;

// TODO [QOS-AF] Signal for AF PDU session event notifications
// Parameters: af_app_id, session_id, pdu_session_info, event_type, ue_location_info
// Triggered on PDU session lifecycle events: establishment, modification, termination, UE mobility
// typedef bs2::signal_type<
//     void(const std::string&,
//          const std::string&,
//          const std::map<std::string, std::string>&,
//          const std::string&,
//          const std::string&),
//     bs2::keywords::mutex_type<bs2::dummy_mutex>>::type af_pdu_session_event_notification_sig_t;

// TODO [QOS-MON] Signal for AF monitoring report notifications
// Parameters: af_app_id, session_id, monitoring_data, threshold_events, congestion_info
// Triggered when monitoring thresholds are exceeded or periodic reports are generated
// typedef bs2::signal_type<
//     void(const std::string&,
//          const std::string&,
//          const std::map<std::string, oai::model::pcf::QosMonitoringData>&,
//          const std::vector<std::string>&,
//          const std::string&),
//     bs2::keywords::mutex_type<bs2::dummy_mutex>>::type af_monitoring_report_notification_sig_t;

// TODO [QOS-AF] Signal for AF policy decision update notifications
// Parameters: af_app_id, session_id, policy_changes, resource_updates, conflict_resolutions
// Triggered when network policy decisions affecting AF applications are updated
// typedef bs2::signal_type<
//     void(const std::string&,
//          const std::string&,
//          const std::map<std::string, std::string>&,
//          const std::map<std::string, std::string>&,
//          const std::vector<std::string>&),
//     bs2::keywords::mutex_type<bs2::dummy_mutex>>::type af_policy_decision_notification_sig_t;

}  // namespace oai::pcf::app
#endif
