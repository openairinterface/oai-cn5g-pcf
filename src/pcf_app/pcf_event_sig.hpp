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

// Signal for sm_policy_control to commit a policy decision change (CAS only
// -- no notify, no persist-triggered signal).
//
// Optimistic concurrency: carries the base version the caller read plus an
// sm_policy_delta (added/modified/removed qosDecs, pccRules, qosChars,
// traffContDecs). The association applies the delta copy-on-write under one
// lock ONLY IF it is still at that version; otherwise it reports a conflict via
// the out result, and the caller re-derives against the returned newer decision
// and retries. This makes updates to one association serialisable, so neither
// a stale write-back nor a stale cumulative-limit check can slip through
// [TS 29.512 §4.2.3.2].
// (association_id in/out, expected_version in, delta in, result out.)
typedef bs2::signal_type<
    void(
        std::optional<std::string>&, std::uint64_t, const sm_policy_delta&,
        decision_apply_result&),
    bs2::keywords::mutex_type<bs2::dummy_mutex>>::type sm_update_decision_sig_t;

// Signal for Policy Authorization to ask sm_policy_control to notify the SMF
// of a decision this same PA instance just committed (via
// sm_update_decision_sig_t) and get back the classified outcome directly --
// a plain synchronous call/return, not a signal PA has to wait on
// asynchronously, since the caller here is already blocked on the answer.
typedef bs2::signal_type<
    void(
        const std::string&, std::uint64_t,
        oai::pcf::app::sm_policy::smf_notify_outcome&),
    bs2::keywords::mutex_type<bs2::dummy_mutex>>::type
    sm_notify_committed_decision_sig_t;

// Signal for sm_policy_control to report a definitively "permanent" SMF
// notify rejection back to Policy Authorization, discovered ON A DELAYED
// RETRY (retry_drain_queue's drain path) -- NOT fired for a rejection
// discovered inline on the same attempt that committed; that case is
// reported directly via sm_notify_committed_decision_sig_t's return value
// instead, so there is nothing here for it to race against.
// Fired only when a
// notify's outcome is smf_notify_outcome::permanent_rejection (cause ==
// PCC_RULE_EVENT per TS 29.512 Table 5.7.3-2 -- the SMF has told us,
// unambiguously, that it will not apply this change). Never fired for
// timeouts, transport failures, or temporary_rejection outcomes.
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

// NOTE: cross-service QoS ans SFC coordination between Policy Authorization and
// SM Policy Control needs no signals of its own beyond the five above.

// TODO [QOS-SUB] AF notification signal types (Phase 3) [TS 29.514 §4.2.5]:
// QoS status (§4.2.5.4), PDU session events (§4.2.5.22), policy/resource
// allocation outcome (§4.2.5.2, §4.2.5.8).
// TODO [QOS-MON] AF monitoring report signal type (Phase 4) [TS 29.514
// §4.2.5.14].

}  // namespace oai::pcf::app
#endif
