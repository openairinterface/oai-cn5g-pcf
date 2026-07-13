/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "qos_session_authorization.hpp"

#include <algorithm>
#include <map>
#include <optional>

#include "Ambr.h"
#include "AuthorizedDefaultQos.h"
#include "SubscribedDefaultQos.h"
#include "bitrate.hpp"
#include "logger.hpp"

namespace oai::pcf::app::sm_policy {

using oai::model::common::Ambr;
using oai::model::common::SubscribedDefaultQos;
using oai::model::pcf::AuthorizedDefaultQos;
using oai::model::pcf::SessionRule;
using oai::model::pcf::SmPolicyContextData;
using oai::model::pcf::SmPolicyDecision;

namespace {

// Clamp a subscribed 3GPP BitRate string down to the tightest of the operator
// cap and the VPLMN cap (each optional). The subscribed string is preserved
// verbatim when no clamp bites (so "10 Mbps" is not reformatted) and when it or
// a cap is unparseable [TS 29.512 §4.2.6.6.1].
std::string clamp_bitrate(
    const std::string& subscribed, const std::optional<uint64_t>& op_cap_bps,
    const std::optional<std::string>& vplmn_cap) {
  const std::optional<uint64_t> sub_bps = oai::utils::bitrate::to_bps(subscribed);
  if (!sub_bps) return subscribed;  // unparseable subscribed value: leave as-is

  uint64_t effective = *sub_bps;
  if (op_cap_bps) effective = std::min(effective, *op_cap_bps);
  if (vplmn_cap) {
    if (const std::optional<uint64_t> v = oai::utils::bitrate::to_bps(*vplmn_cap))
      effective = std::min(effective, *v);
  }

  if (effective == *sub_bps) return subscribed;  // no clamp: preserve original
  return oai::utils::bitrate::from_bps(effective);
}

}  // namespace

SessionRule authorize_session_rule(
    const SmPolicyContextData& context, const std::string& association_id,
    const operator_qos_policy& op_policy) {
  SessionRule rule;
  // One session rule per PDU session; a deterministic id keeps PATCH/DELETE
  // bookkeeping simple and restart-stable [TS 29.512 §5.6.2.4].
  rule.setSessRuleId("SR-" + association_id);

  // Authorized Session-AMBR: subscribed value clamped by operator policy and,
  // in home-routed roaming, the VPLMN Session-AMBR [TS 29.512 §4.2.6.6.1].
  if (context.subsSessAmbrIsSet()) {
    const Ambr subs = context.getSubsSessAmbr();

    std::optional<std::string> vplmn_ul;
    std::optional<std::string> vplmn_dl;
    if (context.vplmnQosIsSet()) {
      const auto vplmn_qos = context.getVplmnQos();
      if (vplmn_qos.sessionAmbrIsSet()) {
        const Ambr vplmn_ambr = vplmn_qos.getSessionAmbr();
        vplmn_ul              = vplmn_ambr.getUplink();
        vplmn_dl              = vplmn_ambr.getDownlink();
      }
    }

    Ambr authorized;
    authorized.setUplink(clamp_bitrate(
        subs.getUplink(), op_policy.max_session_ambr_ul_bps, vplmn_ul));
    authorized.setDownlink(clamp_bitrate(
        subs.getDownlink(), op_policy.max_session_ambr_dl_bps, vplmn_dl));
    rule.setAuthSessAmbr(authorized);
  }

  // Authorized default 5QI/ARP: the subscribed default QoS is inherently
  // authorized, so it is mapped through verbatim [TS 29.512 §4.2.6.6.1].
  if (context.subsDefQosIsSet()) {
    const SubscribedDefaultQos subs = context.getSubsDefQos();
    AuthorizedDefaultQos authorized;
    authorized.setR5qi(subs.getR5qi());
    authorized.setArp(subs.getArp());
    if (subs.priorityLevelIsSet())
      authorized.setPriorityLevel(subs.getPriorityLevel());
    rule.setAuthDefQos(authorized);
  }

  return rule;
}

void authorize_session_rule_into(
    SmPolicyDecision& decision, const SmPolicyContextData& context,
    const std::string& association_id, const operator_qos_policy& op_policy) {
  if (!context.subsSessAmbrIsSet() && !context.subsDefQosIsSet()) {
    Logger::pcf_app().debug(
        "No subscribed Session-AMBR or default QoS in the SM policy context; "
        "no SessionRule authorized (fail-open per TS 29.512 §4.2.2.2).");
    return;
  }

  const SessionRule rule =
      authorize_session_rule(context, association_id, op_policy);

  auto session_rules = decision.getSessRules();
  session_rules.insert(std::make_pair(rule.getSessRuleId(), rule));
  decision.setSessRules(session_rules);

  Logger::pcf_app().info(fmt::format(
      "Authorized SessionRule '{}' (authSessAmbr={}, authDefQos={}) "
      "[TS 29.512 §4.2.6.6.1]",
      rule.getSessRuleId(), rule.authSessAmbrIsSet() ? "set" : "unset",
      rule.authDefQosIsSet() ? "set" : "unset"));
}

}  // namespace oai::pcf::app::sm_policy
