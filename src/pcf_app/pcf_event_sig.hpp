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

// Signal for sm_policy_control to perform session binding
typedef bs2::signal_type<
    void(
        const std::optional<std::string>&, const std::optional<std::string>&,
        const std::optional<std::string>&, std::optional<std::string>&,
        oai::_3gpp::model::SmPolicyDecision&),
    bs2::keywords::mutex_type<bs2::dummy_mutex>>::type sm_session_binding_sig_t;

// Signal for sm_policy_control to update policy decision
//
// TODO [QOS][REFACTOR] Replace this full-SmPolicyDecision push with an
// SmPolicyDelta. Today Policy Authorization fetches the current decision (via
// sm_session_binding), merges its changes into a transient copy, and pushes the
// whole decision back here; the association then re-stores the full object.
// Recommendation: carry an sm_policy_delta { added/modified/removed pccRules,
// qosData, qosChars, qosMon } and apply it association-side with copy-on-write
// (shared_ptr<const SmPolicyDecision> + versioned swap). Benefits: no transient
// full-decision copy per request; fixes lost-update on concurrent PATCH
// (read-modify-write under one lock); enables incremental SMF notifications
// [TS 29.512 §4.2.3.2, §5.6.2.5]. The per-app-session ledger (qos_context)
// already holds the id sets the delta needs, so this is a drop-in.
// DEFERRED to Phase 2: this changes shared event-bus signal signatures and
// individual_sm_association internals consumed by the SM Policy Control feature;
// coordinate the change once, together with Phase 2 PCC-rule conflict
// resolution [TS 29.513 §5.2.2.2.2].
typedef bs2::signal_type<
    void(std::optional<std::string>&, oai::_3gpp::model::SmPolicyDecision&),
    bs2::keywords::mutex_type<bs2::dummy_mutex>>::type sm_update_decision_sig_t;

}  // namespace oai::pcf::app
#endif
