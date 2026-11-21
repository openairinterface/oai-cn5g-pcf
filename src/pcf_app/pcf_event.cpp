/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "pcf_event.hpp"
using namespace oai::pcf::app;

bs2::connection pcf_event::subscribe_loss_of_connectivity(
    const loss_of_connectivity_sig_t::slot_type& sig) {
  return loss_of_connectivity.connect(sig);
}

//------------------------------------------------------------------------------
bs2::connection pcf_event::subscribe_ue_reachability_for_data(
    const ue_reachability_for_data_sig_t::slot_type& sig) {
  return ue_reachability_for_data.connect(sig);
}

bs2::connection pcf_event::subscribe_sm_session_binding(
    const sm_session_binding_sig_t::slot_type& sig) {
  return sm_session_binding.connect(sig);
}

bs2::connection pcf_event::subscribe_sm_update_decision(
    const sm_update_decision_sig_t::slot_type& sig) {
  return sm_update_decision.connect(sig);
}

bs2::connection pcf_event::subscribe_notify_committed_decision(
    const sm_notify_committed_decision_sig_t::slot_type& sig) {
  return notify_committed_decision.connect(sig);
}

bs2::connection pcf_event::subscribe_sm_policy_update_failed(
    const sm_policy_update_failed_sig_t::slot_type& sig) {
  return sm_policy_update_failed.connect(sig);
}

bs2::connection pcf_event::subscribe_sm_get_association_decision(
    const sm_get_association_decision_sig_t::slot_type& sig) {
  return sm_get_association_decision.connect(sig);
}
