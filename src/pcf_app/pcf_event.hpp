/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_PCF_EVENT_HPP_SEEN
#define FILE_PCF_EVENT_HPP_SEEN

#include <boost/signals2.hpp>
#include <optional>
namespace bs2 = boost::signals2;

#include "pcf_event_sig.hpp"
#include "task_manager.hpp"

namespace oai::pcf::app {
class task_manager;
class pcf_event {
 public:
  pcf_event(){};
  pcf_event(pcf_event const&) = delete;
  void operator=(pcf_event const&) = delete;

  static pcf_event& get_instance() {
    static pcf_event instance;
    return instance;
  }

  // class register/handle event
  friend class pcf_app;
  friend class pcf_nrf;
  friend class task_manager;
  friend class pcf_policy_authorization;
  friend class pcf_smpc;

  //------------------------------------------------------------------------------
  /*
   * Subscribe to the task tick event
   * @param [const task_sig_t::slot_type &] sig
   * @param [uint64_t] period: interval between two events
   * @param [uint64_t] start:
   * @return void
   */
  bs2::connection subscribe_task_nf_heartbeat(
      const task_sig_t::slot_type& sig, uint64_t period, uint64_t start = 0);
  //------------------------------------------------------------------------------
  /*
   * Subscribe to UE Loss of Connectivity Status signal
   * @param [const loss_of_connectivity_sig_t::slot_type&] sig: slot_type
   * parameter
   * @return boost::signals2::connection: the connection between the signal and
   * the slot
   */
  bs2::connection subscribe_loss_of_connectivity(
      const loss_of_connectivity_sig_t::slot_type& sig);

  /*
   * Subscribe to UE Reachability for Data signal
   * @param [const ue_reachability_for_data_sig_t::slot_type&] sig: slot_type
   * parameter
   * @return boost::signals2::connection: the connection between the signal and
   * the slot
   */
  bs2::connection subscribe_ue_reachability_for_data(
      const ue_reachability_for_data_sig_t::slot_type& sig);

  /**
   * Subscribe to SM Session Binding signal.
   * @param [const sm_session_binding_sig_t::slot_type&] sig: slot_type
   * parameter
   * @return boost::signals2::connection: the connection between the signal and
   * the slot
   */
  bs2::connection subscribe_sm_session_binding(
      const sm_session_binding_sig_t::slot_type& sig);

  /**
   * Subscribe to SM Update Decision signal.
   * @param [const sm_update_decision_sig_t::slot_type&] sig: slot_type
   * parameter
   * @return boost::signals2::connection: the connection between the signal and
   * the slot
   */
  bs2::connection subscribe_sm_update_decision(
      const sm_update_decision_sig_t::slot_type& sig);

  /**
   * Subscribe to Policy Authorization's request to notify the SMF of a
   * decision it just committed, and report back the classified outcome.
   * @param [const sm_notify_committed_decision_sig_t::slot_type&] sig:
   * slot_type parameter
   * @return boost::signals2::connection: the connection between the signal
   * and the slot
   */
  bs2::connection subscribe_notify_committed_decision(
      const sm_notify_committed_decision_sig_t::slot_type& sig);

  /**
   * Subscribe to a definitively "permanent" SMF notify rejection.
   * Invariant (finding F): connect only once,
   * at Policy Authorization's construction, before any HTTP thread starts --
   * dummy_mutex gives no protection against a runtime connect/disconnect
   * racing an invocation.
   * @param [const sm_policy_update_failed_sig_t::slot_type&] sig: slot_type
   * parameter
   * @return boost::signals2::connection: the connection between the signal
   * and the slot
   */
  bs2::connection subscribe_sm_policy_update_failed(
      const sm_policy_update_failed_sig_t::slot_type& sig);

  /**
   * Subscribe to a lookup of an association's current decision + version by
   * association_id.
   * @param [const sm_get_association_decision_sig_t::slot_type&] sig:
   * slot_type parameter
   * @return boost::signals2::connection: the connection between the signal
   * and the slot
   */
  bs2::connection subscribe_sm_get_association_decision(
      const sm_get_association_decision_sig_t::slot_type& sig);

  // TODO [QOS] Add QoS coordination events between Policy Authorization and SM Policy Control [TS 29.513 §5.2.2.2, TS 29.512 §4.2.3]
  // Implement the following events for comprehensive QoS coordination:

  // TODO [QOS] PCC rule coordination events [TS 23.503 §6.1.3.7, TS 29.512 §4.2.6.2.1]
  // bs2::connection subscribe_pcc_rule_conflict_resolution(
  //     const pcc_rule_conflict_sig_t::slot_type& sig);

  // TODO [QOS] QoS resource availability events [TS 29.512 §4.2.6.5.5, §4.2.3.16]
  // bs2::connection subscribe_qos_resource_status_update(
  //     const qos_resource_status_sig_t::slot_type& sig);

  // TODO [QOS-MON] QoS monitoring coordination events [TS 29.512 §4.2.3.25, TS 23.503 §6.1.3.21]
  // bs2::connection subscribe_qos_monitoring_coordination(
  //     const qos_monitoring_coordination_sig_t::slot_type& sig);

  // TODO [QOS] Cross-service QoS validation events [TS 29.513 §7.3.3]
  // bs2::connection subscribe_qos_validation_request(
  //     const qos_validation_request_sig_t::slot_type& sig);

  // TODO [QOS-SUB] Application Function notification events
  // Add event subscriptions for AF monitoring and notification as per 3GPP TS 29.514:

  // TODO [QOS-SUB] AF QoS status notification events [TS 29.514 §4.2.5.4, §5.6.2.15]
  // bs2::connection subscribe_af_qos_status_notification(
  //     const af_qos_status_notification_sig_t::slot_type& sig);
  // - Triggered when QoS flows are established, modified, or released
  // - Includes QoS guarantee status, bandwidth utilization, latency measurements

  // TODO [QOS-SUB] AF PDU session event notifications [TS 29.514 §4.2.5.22, §5.6.3.24]
  // bs2::connection subscribe_af_pdu_session_event_notification(
  //     const af_pdu_session_event_notification_sig_t::slot_type& sig);
  // - Triggered on PDU session establishment, modification, termination
  // - Includes UE mobility events affecting application QoS

  // TODO [QOS-MON] AF monitoring report events [TS 29.514 §4.2.5.14, §5.6.2.37]
  // bs2::connection subscribe_af_monitoring_report_notification(
  //     const af_monitoring_report_notification_sig_t::slot_type& sig);
  // - Triggered when monitoring thresholds are exceeded or measurements available
  // - Includes congestion status, packet loss reports, bandwidth usage

  // TODO [QOS-SUB] AF policy decision update events [TS 29.514 §4.2.5.2, §5.6.2.9]
  // bs2::connection subscribe_af_policy_decision_notification(
  //     const af_policy_decision_notification_sig_t::slot_type& sig);
  // - Triggered when policy decisions are updated by network operator
  // - Includes resource availability changes, policy conflicts, charging updates

 private:
  task_sig_t task_tick;

  loss_of_connectivity_sig_t
      loss_of_connectivity;  // Signal for Loss of Connectivity Report
  ue_reachability_for_data_sig_t
      ue_reachability_for_data;  // Signal for UE Reachability for Data Report

  sm_session_binding_sig_t sm_session_binding;  // Signal for SM Session Binding

  sm_update_decision_sig_t sm_update_decision;  // Signal for SM Update Decision

  sm_notify_committed_decision_sig_t
      notify_committed_decision;  // Signal for PA to ask SM to notify the SMF

  sm_policy_update_failed_sig_t
      sm_policy_update_failed;  // Signal for a permanent SMF notify rejection

  sm_get_association_decision_sig_t
      sm_get_association_decision;  // Signal for association lookup by id

  // TODO [QOS] Add QoS coordination signals [TS 29.513 §5.2.2.2, TS 29.512 §4.2.3]
  // Private signal definitions for QoS coordination between services:

  // TODO [QOS] Signal for PCC rule conflict resolution [TS 23.503 §6.1.3.7, TS 29.512 §4.1.4.2.1]
  // pcc_rule_conflict_sig_t pcc_rule_conflict_resolution;

  // TODO [QOS] Signal for QoS resource status updates [TS 29.512 §4.2.6.5.5, §4.2.3.16]
  // qos_resource_status_sig_t qos_resource_status_update;

  // TODO [QOS-MON] Signal for QoS monitoring coordination [TS 29.512 §4.2.3.25, TS 23.503 §6.1.3.21]
  // qos_monitoring_coordination_sig_t qos_monitoring_coordination;

  // TODO [QOS] Signal for cross-service QoS validation [TS 29.513 §7.3.3]
  // qos_validation_request_sig_t qos_validation_request;

  // TODO [QOS-SUB] Application Function notification signals [TS 29.514 §4.2.5, TS 29.500 §6.2]
  // Private signal definitions for AF monitoring and notification:

  // TODO [QOS-SUB] Signal for AF QoS status notifications [TS 29.514 §4.2.5.4, §5.6.2.15]
  // af_qos_status_notification_sig_t af_qos_status_notification;
  // - Emitted when QoS flow status changes need to be reported to AF
  // - Carries QoS flow ID, status, measurements, guarantee information

  // TODO [QOS-SUB] Signal for AF PDU session event notifications [TS 29.514 §4.2.5.22, §5.6.3.24]
  // af_pdu_session_event_notification_sig_t af_pdu_session_event_notification;
  // - Emitted on PDU session lifecycle events affecting AF applications
  // - Carries session info, UE context, mobility events, session modifications

  // TODO [QOS-MON] Signal for AF monitoring report notifications [TS 29.514 §4.2.5.14, §5.6.2.37]
  // af_monitoring_report_notification_sig_t af_monitoring_report_notification;
  // - Emitted when monitoring data needs to be reported to subscribed AFs
  // - Carries measurement reports, threshold violations, congestion status

  // TODO [QOS-SUB] Signal for AF policy decision notifications [TS 29.514 §4.2.5.2, §5.6.2.9]
  // af_policy_decision_notification_sig_t af_policy_decision_notification;
  // - Emitted when policy decisions affecting AF applications are updated
  // - Carries policy changes, resource updates, conflict resolutions, charging info
};
}  // namespace oai::pcf::app
#endif
