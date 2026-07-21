/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_PCF_EVENT_SIG_HPP_SEEN
#define FILE_PCF_EVENT_SIG_HPP_SEEN

#include <boost/signals2.hpp>
#include <string>
#include "SmPolicyDecision.h"
#include "sm_policy_delta.hpp"

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

}  // namespace oai::pcf::app
#endif
