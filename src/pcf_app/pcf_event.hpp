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

  // TODO [QOS] Add QoS coordination events between Policy Authorization and SM Policy Control
  // Implement the following events for comprehensive QoS coordination:

  // TODO [QOS] PCC rule coordination events
  // bs2::connection subscribe_pcc_rule_conflict_resolution(
  //     const pcc_rule_conflict_sig_t::slot_type& sig);

  // TODO [QOS] QoS resource availability events
  // bs2::connection subscribe_qos_resource_status_update(
  //     const qos_resource_status_sig_t::slot_type& sig);

  // TODO [QOS-MON] QoS monitoring coordination events
  // bs2::connection subscribe_qos_monitoring_coordination(
  //     const qos_monitoring_coordination_sig_t::slot_type& sig);

  // TODO [QOS] Cross-service QoS validation events
  // bs2::connection subscribe_qos_validation_request(
  //     const qos_validation_request_sig_t::slot_type& sig);

  // TODO [QOS-AF] Application Function notification events
  // Add event subscriptions for AF monitoring and notification as per 3GPP TS 29.514:

  // TODO [QOS-AF] AF QoS status notification events
  // bs2::connection subscribe_af_qos_status_notification(
  //     const af_qos_status_notification_sig_t::slot_type& sig);
  // - Triggered when QoS flows are established, modified, or released
  // - Includes QoS guarantee status, bandwidth utilization, latency measurements

  // TODO [QOS-AF] AF PDU session event notifications
  // bs2::connection subscribe_af_pdu_session_event_notification(
  //     const af_pdu_session_event_notification_sig_t::slot_type& sig);
  // - Triggered on PDU session establishment, modification, termination
  // - Includes UE mobility events affecting application QoS

  // TODO [QOS-MON] AF monitoring report events
  // bs2::connection subscribe_af_monitoring_report_notification(
  //     const af_monitoring_report_notification_sig_t::slot_type& sig);
  // - Triggered when monitoring thresholds are exceeded or measurements available
  // - Includes congestion status, packet loss reports, bandwidth usage

  // TODO [QOS-AF] AF policy decision update events
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

  // TODO [QOS] Add QoS coordination signals
  // Private signal definitions for QoS coordination between services:

  // TODO [QOS] Signal for PCC rule conflict resolution
  // pcc_rule_conflict_sig_t pcc_rule_conflict_resolution;

  // TODO [QOS] Signal for QoS resource status updates
  // qos_resource_status_sig_t qos_resource_status_update;

  // TODO [QOS-MON] Signal for QoS monitoring coordination
  // qos_monitoring_coordination_sig_t qos_monitoring_coordination;

  // TODO [QOS] Signal for cross-service QoS validation
  // qos_validation_request_sig_t qos_validation_request;

  // TODO [QOS-AF] Application Function notification signals
  // Private signal definitions for AF monitoring and notification:

  // TODO [QOS-AF] Signal for AF QoS status notifications
  // af_qos_status_notification_sig_t af_qos_status_notification;
  // - Emitted when QoS flow status changes need to be reported to AF
  // - Carries QoS flow ID, status, measurements, guarantee information

  // TODO [QOS-AF] Signal for AF PDU session event notifications
  // af_pdu_session_event_notification_sig_t af_pdu_session_event_notification;
  // - Emitted on PDU session lifecycle events affecting AF applications
  // - Carries session info, UE context, mobility events, session modifications

  // TODO [QOS-MON] Signal for AF monitoring report notifications
  // af_monitoring_report_notification_sig_t af_monitoring_report_notification;
  // - Emitted when monitoring data needs to be reported to subscribed AFs
  // - Carries measurement reports, threshold violations, congestion status

  // TODO [QOS-AF] Signal for AF policy decision notifications
  // af_policy_decision_notification_sig_t af_policy_decision_notification;
  // - Emitted when policy decisions affecting AF applications are updated
  // - Carries policy changes, resource updates, conflict resolutions, charging info
};
}  // namespace oai::pcf::app
#endif
