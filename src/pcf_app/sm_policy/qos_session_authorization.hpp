/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_QOS_SESSION_AUTHORIZATION_HPP_SEEN
#define FILE_QOS_SESSION_AUTHORIZATION_HPP_SEEN

#include <string>

#include "SessionRule.h"
#include "SmPolicyContextData.h"
#include "SmPolicyDecision.h"
#include "operator_qos_policy.hpp"

namespace oai::pcf::app::sm_policy {

/**
 * @brief Authorize the subscribed Session-AMBR / default QoS into a SessionRule.
 *
 * Implements the PCF's QoS control per TS 29.512 §4.2.6.6.1: the SMF forwards
 * the subscribed Session-AMBR (subsSessAmbr) and default 5QI/ARP (subsDefQos) in
 * the SmPolicyContextData; the PCF authorizes them against operator policy and,
 * in the home-routed roaming case, clamps the Session-AMBR to the VPLMN
 * Session-AMBR when provided. The authorized values are returned in a
 * SessionRule [TS 29.512 §5.6.2.4].
 *
 * A field is left unset when its subscription input is absent, so the caller can
 * rely on SessionRule::authSessAmbrIsSet() / authDefQosIsSet().
 *
 * @param context        the SM policy context from the SMF (source of the
 *                       subscribed values and any VPLMN limits).
 * @param association_id used to derive the per-PDU-session-unique sessRuleId.
 * @param op_policy      operator authorization limits.
 */
oai::model::pcf::SessionRule authorize_session_rule(
    const oai::model::pcf::SmPolicyContextData& context,
    const std::string& association_id,
    const oai::pcf::app::operator_qos_policy& op_policy);

/**
 * @brief Merge the authorized SessionRule into `decision` in place.
 *
 * No-op when the context carries neither a subscribed Session-AMBR nor a
 * subscribed default QoS (nothing to authorize) -- consistent with the
 * fail-open rule of TS 29.512 §4.2.2.2. Enriching the decision here (rather than
 * inside policy_decision::decide()) keeps this uniform across every
 * policy_decision subclass (supi/dnn/slice/default) and out of the
 * config-unaware decision layer.
 */
void authorize_session_rule_into(
    oai::model::pcf::SmPolicyDecision& decision,
    const oai::model::pcf::SmPolicyContextData& context,
    const std::string& association_id,
    const oai::pcf::app::operator_qos_policy& op_policy);

}  // namespace oai::pcf::app::sm_policy

#endif  // FILE_QOS_SESSION_AUTHORIZATION_HPP_SEEN
