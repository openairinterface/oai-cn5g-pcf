/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_PCF_EVENT_SIG_HPP_SEEN
#define FILE_PCF_EVENT_SIG_HPP_SEEN

#include <boost/signals2.hpp>
#include <cstdint>
#include <string>
#include "SmPolicyDecision.h"
#include "sm_policy_delta.hpp"
#include "sm_policy/smf_notify_outcome.hpp"

namespace bs2 = boost::signals2;

namespace oai::pcf::app {

using namespace oai::_3gpp::model;

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

// Signal for sm_policy_control to perform session binding.
// Out-params: association_id, the current decision, and its version -- the
// version lets Policy Authorization detect (at update time) whether the
// decision changed under it and retry against the newer base [TS 29.512
// §4.2.3.2]. (ipv4, supi, dnn in; assoc_id, decision, version out.)
typedef bs2::signal_type<
    void(
        const std::optional<std::string>&, const std::optional<std::string>&,
        const std::optional<std::string>&, std::optional<std::string>&,
        oai::model::pcf::SmPolicyDecision&, std::uint64_t&),
    bs2::keywords::mutex_type<bs2::dummy_mutex>>::type sm_session_binding_sig_t;

// Signal for sm_policy_control to update a policy decision.
//
// Optimistic concurrency: carries the base version the caller read plus an
// sm_policy_delta (added/modified/removed qosDecs, pccRules, qosChars,
// traffContDecs). The association applies the delta copy-on-write under one
// lock ONLY IF it is still at that version; otherwise it reports a conflict via
// the out result, and the caller re-derives against the returned newer decision
// and retries. This makes updates to one association serialisable, so neither
// a stale write-back nor a stale cumulative-limit check can slip through
// [TS 29.512 §4.2.3.2]. The notification the SM side sends the SMF is still the
// full decision.
// (association_id in/out, expected_version in, delta in, result out.)
typedef bs2::signal_type<
    void(
        std::optional<std::string>&, std::uint64_t, const sm_policy_delta&,
        decision_apply_result&),
    bs2::keywords::mutex_type<bs2::dummy_mutex>>::type sm_update_decision_sig_t;

// Signal for sm_policy_control to report a definitively "permanent" SMF
// notify rejection back to Policy Authorization
// a new channel, symmetric to sm_update_decision_sig_t but in the
// opposite direction. Fired by SM only when a notify's outcome is
// smf_notify_outcome::permanent_rejection (cause == PCC_RULE_EVENT per TS
// 29.512 Table 5.7.3-2 -- the SMF has told us, unambiguously, that it will
// not apply this change). Never fired for timeouts, transport failures, or
// temporary_rejection outcomes.
// (association_id in, version in, reason in.)
typedef bs2::signal_type<
    void(std::string, std::uint64_t, oai::pcf::app::sm_policy::smf_notify_outcome),
    bs2::keywords::mutex_type<bs2::dummy_mutex>>::type
    sm_policy_update_failed_sig_t;

// Signal for sm_policy_control to look up an association's CURRENT decision +
// version directly by its already-known association_id.
// Distinct from sm_session_binding_sig_t, which
// looks up BY (ipv4, supi, dnn) and returns the association_id as an out-param
// -- this one is for a caller that already has the association_id (Policy
// Authorization's rollback path) and needs a fresh snapshot immediately
// before its own apply_with_retry call, rather than reusing a stale historical
// one
// (association_id in; found, decision, version out.)
typedef bs2::signal_type<
    void(
        const std::string&, bool&, oai::model::pcf::SmPolicyDecision&,
        std::uint64_t&),
    bs2::keywords::mutex_type<bs2::dummy_mutex>>::type
    sm_get_association_decision_sig_t;

// TODO [QOS] Define QoS coordination signal types for cross-service communication [TS 29.513 §5.2.2.2, TS 29.512 §4.2.3]
// The following signals enable coordination between Policy Authorization and SM Policy Control:

// TODO [QOS] Signal for PCC rule conflict resolution between services [TS 23.503 §6.1.3.7, TS 29.512 §4.1.4.2.1]
// Parameters: association_id, policy_auth_rules, sm_policy_rules, resolution_strategy
// typedef bs2::signal_type<
//     void(const std::string&,
//          const std::map<std::string, oai::model::pcf::PccRule>&,
//          const std::map<std::string, oai::model::pcf::PccRule>&,
//          std::string&),
//     bs2::keywords::mutex_type<bs2::dummy_mutex>>::type pcc_rule_conflict_sig_t;

// TODO [QOS] Signal for QoS resource availability status updates [TS 29.512 §4.2.6.5.5, §4.2.3.16]
// Parameters: association_id, available_bandwidth_ul, available_bandwidth_dl, congestion_status
// typedef bs2::signal_type<
//     void(const std::string&, uint64_t, uint64_t, uint8_t),
//     bs2::keywords::mutex_type<bs2::dummy_mutex>>::type qos_resource_status_sig_t;

// TODO [QOS-MON] Signal for QoS monitoring coordination between services [TS 29.512 §4.2.3.25, TS 23.503 §6.1.3.21]
// Parameters: association_id, monitoring_data, service_id, coordination_action
// typedef bs2::signal_type<
//     void(const std::string&,
//          const std::map<std::string, oai::model::pcf::QosMonitoringData>&,
//          const std::string&,
//          const std::string&),
//     bs2::keywords::mutex_type<bs2::dummy_mutex>>::type qos_monitoring_coordination_sig_t;

// TODO [QOS] Signal for cross-service QoS validation requests [TS 29.513 §7.3.3]
// Parameters: association_id, qos_data, validation_context, validation_result
// typedef bs2::signal_type<
//     void(const std::string&,
//          const std::map<std::string, oai::model::pcf::QosData>&,
//          const std::string&,
//          bool&),
//     bs2::keywords::mutex_type<bs2::dummy_mutex>>::type qos_validation_request_sig_t;

// TODO [QOS-SUB] Define Application Function notification signal types as per 3GPP TS 29.514
// The following signals trigger notifications to Application Functions about QoS and session events:

// TODO [QOS-SUB] Signal for AF QoS status notifications [TS 29.514 §4.2.5.4, §5.6.2.15]
// Parameters: af_app_id, session_id, qos_flow_info, qos_status, measurements
// Triggered when QoS flows are established, modified, released or when QoS guarantees change
// typedef bs2::signal_type<
//     void(const std::string&,
//          const std::string&,
//          const std::map<std::string, oai::model::pcf::QosData>&,
//          const std::string&,
//          const std::map<std::string, std::string>&),
//     bs2::keywords::mutex_type<bs2::dummy_mutex>>::type af_qos_status_notification_sig_t;

// TODO [QOS-SUB] Signal for AF PDU session event notifications [TS 29.514 §4.2.5.22, §5.6.3.24]
// Parameters: af_app_id, session_id, pdu_session_info, event_type, ue_location_info
// Triggered on PDU session lifecycle events: establishment, modification, termination, UE mobility
// typedef bs2::signal_type<
//     void(const std::string&,
//          const std::string&,
//          const std::map<std::string, std::string>&,
//          const std::string&,
//          const std::string&),
//     bs2::keywords::mutex_type<bs2::dummy_mutex>>::type af_pdu_session_event_notification_sig_t;

// TODO [QOS-MON] Signal for AF monitoring report notifications [TS 29.514 §4.2.5.14, §5.6.2.37]
// Parameters: af_app_id, session_id, monitoring_data, threshold_events, congestion_info
// Triggered when monitoring thresholds are exceeded or periodic reports are generated
// typedef bs2::signal_type<
//     void(const std::string&,
//          const std::string&,
//          const std::map<std::string, oai::model::pcf::QosMonitoringData>&,
//          const std::vector<std::string>&,
//          const std::string&),
//     bs2::keywords::mutex_type<bs2::dummy_mutex>>::type af_monitoring_report_notification_sig_t;

// TODO [QOS-SUB] Signal for AF policy decision update notifications [TS 29.514 §4.2.5.2, §5.6.2.9]
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
