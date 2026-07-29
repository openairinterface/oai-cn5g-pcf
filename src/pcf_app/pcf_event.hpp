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

  // TODO [QOS-SUB] AF notification subscriptions (Phase 3) [TS 29.514 §4.2.5]:
  // QoS status, PDU session events, policy updates and monitoring reports.
  // Signal types are declared in pcf_event_sig.hpp; each needs a
  // subscribe_*() here plus a member below.

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

  // TODO [QOS-SUB] AF notification signal members (Phase 3) -- see the
  // subscribe_*() note above.
};
}  // namespace oai::pcf::app
#endif
