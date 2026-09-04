/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// Tests for the SM-side QoS authorization in
// sm_policy/qos_session_authorization.cpp: authorize_session_rule() and
// authorize_session_rule_into().
//
// PCF authorizes the SMF-forwarded subscribed Session-AMBR (subsSessAmbr)
// and default 5QI/ARP (subsDefQos) -- clamped by operator policy and, in
// home-routed roaming, the VPLMN Session-AMBR -- into a SessionRule on the
// SmPolicyDecision. Populating that SessionRule is what later lets Policy
// Authorization validate AF-requested QoS against the authorized envelope
// (delivered via the unchanged sm_session_binding).
//
// Bit-rate assertions go through oai::utils::bitrate::to_bps so they are robust
// to BitRate string formatting (e.g. "5 Mbps" vs "5000 Kbps").

#include <gtest/gtest.h>

#include <optional>
#include <string>

#include "Ambr.h"
#include "Arp.h"
#include "SessionRule.h"
#include "SmPolicyContextData.h"
#include "SmPolicyDecision.h"
#include "SubscribedDefaultQos.h"
#include "VplmnQos.h"
#include "bitrate.hpp"
#include "pcf_runtime_policy.hpp"
#include "sm_policy/qos_session_authorization.hpp"

using oai::pcf::app::operator_qos_policy;
using oai::pcf::app::sm_policy::authorize_session_rule;
using oai::pcf::app::sm_policy::authorize_session_rule_into;
using oai::utils::bitrate::to_bps;

using oai::_3gpp::model::Ambr;
using oai::_3gpp::model::SubscribedDefaultQos;
using oai::_3gpp::model::SmPolicyContextData;
using oai::_3gpp::model::SmPolicyDecision;

namespace {

Ambr make_ambr(const std::string& uplink, const std::string& downlink) {
  Ambr ambr;
  ambr.setUplink(uplink);
  ambr.setDownlink(downlink);
  return ambr;
}

// A context carrying a subscribed Session-AMBR only.
SmPolicyContextData context_with_session_ambr(
    const std::string& ul, const std::string& dl) {
  SmPolicyContextData context;
  context.setSubsSessAmbr(make_ambr(ul, dl));
  return context;
}

}  // namespace

/*
 * TS 29.512 §4.2.6.6.1: with no operator or VPLMN constraint, the authorized
 * Session-AMBR equals the subscribed Session-AMBR.
 */
TEST(SessionAuthorization, PassesThroughSubscribedSessionAmbrWhenNoCaps) {
  const auto context = context_with_session_ambr("10 Mbps", "20 Mbps");

  const auto rule = authorize_session_rule(context, "assoc-1", {});

  ASSERT_TRUE(rule.authSessAmbrIsSet());
  const Ambr authorized = rule.getAuthSessAmbr();
  EXPECT_EQ(to_bps(authorized.getUplink()), 10ULL * 1000 * 1000);
  EXPECT_EQ(to_bps(authorized.getDownlink()), 20ULL * 1000 * 1000);
  // The original string is preserved verbatim when no clamp bites.
  EXPECT_EQ(authorized.getUplink(), "10 Mbps");
}

/*
 * TS 29.512 §4.2.6.6.1: the PCF authorizes the Session-AMBR "based on the
 * operator's policy" -- a subscribed value above the operator ceiling is
 * clamped down.
 */
TEST(SessionAuthorization, ClampsSessionAmbrToOperatorCap) {
  const auto context = context_with_session_ambr("10 Mbps", "20 Mbps");
  operator_qos_policy op_policy;
  op_policy.max_session_ambr_ul_bps = 5ULL * 1000 * 1000;   // 5 Mbps
  op_policy.max_session_ambr_dl_bps = 15ULL * 1000 * 1000;  // 15 Mbps

  const auto rule = authorize_session_rule(context, "assoc-1", op_policy);

  const Ambr authorized = rule.getAuthSessAmbr();
  EXPECT_EQ(to_bps(authorized.getUplink()), 5ULL * 1000 * 1000);
  EXPECT_EQ(to_bps(authorized.getDownlink()), 15ULL * 1000 * 1000);
}

/*
 * A subscribed value already within the operator ceiling is left untouched
 * (no gratuitous clamp).
 */
TEST(SessionAuthorization, DoesNotRaiseSessionAmbrBelowOperatorCap) {
  const auto context = context_with_session_ambr("2 Mbps", "3 Mbps");
  operator_qos_policy op_policy;
  op_policy.max_session_ambr_ul_bps = 5ULL * 1000 * 1000;
  op_policy.max_session_ambr_dl_bps = 5ULL * 1000 * 1000;

  const auto rule = authorize_session_rule(context, "assoc-1", op_policy);

  const Ambr authorized = rule.getAuthSessAmbr();
  EXPECT_EQ(authorized.getUplink(), "2 Mbps");
  EXPECT_EQ(authorized.getDownlink(), "3 Mbps");
}

/*
 * TS 29.512 §4.2.6.6.1 (home-routed roaming): the authorized Session-AMBR must
 * not exceed the VPLMN Session-AMBR when provided.
 */
TEST(SessionAuthorization, ClampsSessionAmbrToVplmnWhenRoaming) {
  auto context = context_with_session_ambr("100 Mbps", "200 Mbps");
  oai::_3gpp::model::VplmnQos vplmn;
  vplmn.setSessionAmbr(make_ambr("50 Mbps", "80 Mbps"));
  context.setVplmnQos(vplmn);

  const auto rule = authorize_session_rule(context, "assoc-1", {});

  const Ambr authorized = rule.getAuthSessAmbr();
  EXPECT_EQ(to_bps(authorized.getUplink()), 50ULL * 1000 * 1000);
  EXPECT_EQ(to_bps(authorized.getDownlink()), 80ULL * 1000 * 1000);
}

/*
 * When both an operator cap and a VPLMN cap apply, the tightest wins.
 */
TEST(SessionAuthorization, AppliesTightestOfOperatorAndVplmnCaps) {
  auto context = context_with_session_ambr("100 Mbps", "100 Mbps");
  oai::_3gpp::model::VplmnQos vplmn;
  vplmn.setSessionAmbr(make_ambr("50 Mbps", "90 Mbps"));
  context.setVplmnQos(vplmn);
  operator_qos_policy op_policy;
  op_policy.max_session_ambr_ul_bps = 70ULL * 1000 * 1000;  // VPLMN tighter (50)
  op_policy.max_session_ambr_dl_bps = 60ULL * 1000 * 1000;  // operator tighter (60)

  const auto rule = authorize_session_rule(context, "assoc-1", op_policy);

  const Ambr authorized = rule.getAuthSessAmbr();
  EXPECT_EQ(to_bps(authorized.getUplink()), 50ULL * 1000 * 1000);
  EXPECT_EQ(to_bps(authorized.getDownlink()), 60ULL * 1000 * 1000);
}

/*
 * TS 29.512 §4.2.6.6.1: the subscribed default 5QI/ARP is inherently authorized
 * and mapped through into AuthorizedDefaultQos.
 */
TEST(SessionAuthorization, MapsSubscribedDefaultQos) {
  SmPolicyContextData context;
  SubscribedDefaultQos subs_def;
  subs_def.setR5qi(9);
  oai::_3gpp::model::Arp arp;
  arp.setPriorityLevel(8);
  subs_def.setArp(arp);
  subs_def.setPriorityLevel(5);
  context.setSubsDefQos(subs_def);

  const auto rule = authorize_session_rule(context, "assoc-1", {});

  ASSERT_TRUE(rule.authDefQosIsSet());
  const auto authorized = rule.getAuthDefQos();
  EXPECT_EQ(authorized.getR5qi(), 9);
  EXPECT_EQ(authorized.getArp().getPriorityLevel(), 8);
  ASSERT_TRUE(authorized.priorityLevelIsSet());
  EXPECT_EQ(authorized.getPriorityLevel(), 5);
}

/*
 * The optional default-QoS 5QI Priority Level is omitted when the subscription
 * did not carry one.
 */
TEST(SessionAuthorization, OmitsDefaultQosPriorityLevelWhenUnset) {
  SmPolicyContextData context;
  SubscribedDefaultQos subs_def;
  subs_def.setR5qi(9);
  oai::_3gpp::model::Arp arp;
  arp.setPriorityLevel(8);
  subs_def.setArp(arp);
  context.setSubsDefQos(subs_def);

  const auto rule = authorize_session_rule(context, "assoc-1", {});

  ASSERT_TRUE(rule.authDefQosIsSet());
  EXPECT_FALSE(rule.getAuthDefQos().priorityLevelIsSet());
}

/*
 * The session rule id is derived deterministically from the association id
 * (one session rule per PDU session, TS 29.512 §5.6.2.4).
 */
TEST(SessionAuthorization, DerivesSessRuleIdFromAssociationId) {
  const auto context = context_with_session_ambr("10 Mbps", "20 Mbps");

  const auto rule = authorize_session_rule(context, "assoc-42", {});

  EXPECT_EQ(rule.getSessRuleId(), "SR-assoc-42");
}

/*
 * A subscribed default QoS alone yields a SessionRule with authDefQos set but
 * no authorized Session-AMBR.
 */
TEST(SessionAuthorization, LeavesAuthSessAmbrUnsetWhenNoSubscribedAmbr) {
  SmPolicyContextData context;
  SubscribedDefaultQos subs_def;
  subs_def.setR5qi(9);
  oai::_3gpp::model::Arp arp;
  arp.setPriorityLevel(8);
  subs_def.setArp(arp);
  context.setSubsDefQos(subs_def);

  const auto rule = authorize_session_rule(context, "assoc-1", {});

  EXPECT_FALSE(rule.authSessAmbrIsSet());
  EXPECT_TRUE(rule.authDefQosIsSet());
}

/*
 * authorize_session_rule_into() adds exactly one SessionRule to the decision,
 * keyed by the derived sessRuleId.
 */
TEST(SessionAuthorization, IntoAddsRuleToDecision) {
  const auto context = context_with_session_ambr("10 Mbps", "20 Mbps");
  SmPolicyDecision decision;

  authorize_session_rule_into(decision, context, "assoc-7", {});

  const auto sess_rules = decision.getSessRules();
  ASSERT_EQ(sess_rules.size(), 1u);
  ASSERT_NE(sess_rules.find("SR-assoc-7"), sess_rules.end());
  EXPECT_TRUE(sess_rules.at("SR-assoc-7").authSessAmbrIsSet());
}

/*
 * TS 29.512 §4.2.2.2 (fail-open): with no subscribed Session-AMBR or default
 * QoS in the context, no SessionRule is authorized.
 */
TEST(SessionAuthorization, IntoIsNoopWhenNoSubscription) {
  SmPolicyContextData context;  // neither subsSessAmbr nor subsDefQos set
  SmPolicyDecision decision;

  authorize_session_rule_into(decision, context, "assoc-1", {});

  EXPECT_TRUE(decision.getSessRules().empty());
}
