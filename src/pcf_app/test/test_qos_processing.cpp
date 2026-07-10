/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// Tests for the QoS processing functions in app_session.cpp:
// create_qos_data_from_media_component, create_qos_characteristics,
// setup_qos_monitoring, validate_qos_authorization, handle_qos_requirements
// (orchestration), the pure mapping helpers (is_standardized_5qi, derive_5qi),
// and validate_and_merge_decision (the PCC-rule/traffic-control merge).
//
// The QoS derivation is expected to evolve (e.g. once medType/resPrio become
// readable and the authoritative latency->5QI table is wired in). Most
// assertions therefore target the CONTRACT that must hold regardless of the
// derived values -- referential integrity, mandatory fields, ledger/decision
// consistency -- rather than pinning specific numbers. Where a rule IS fully
// specified today (per-SDF bandwidth sum, fStatus=REMOVED, qosReference lookup,
// the latency heuristic bands, the merge algorithm) the concrete behaviour is
// asserted directly.

#include <gtest/gtest.h>

#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "Arp.h"
#include "FlowStatus.h"
#include "MediaComponent.h"
#include "MediaSubComponent.h"
#include "PccRule.h"
#include "QosCharacteristics.h"
#include "QosData.h"
#include "SmPolicyDecision.h"
#include "TrafficControlData.h"
#include "app_session.hpp"
#include "crud_store.hpp"
#include "qos_context.hpp"
#include "qos_reference_store.hpp"

using namespace oai::pcf::app::policy_auth;
using namespace oai::model::pcf;

namespace {

// The generic in-memory store doubles as the test store: find() comes from the
// crud_store base and insert() seeds preconfigured sets -- no bespoke double.
using fake_qos_reference_store = oai::utils::crud_store_memory<const QosData>;

MediaSubComponent make_sub(
    int32_t f_num, const std::vector<std::string>& fdescs,
    std::optional<std::string> mar_bw_ul = std::nullopt,
    bool removed = false) {
  MediaSubComponent sub;
  sub.setFNum(f_num);
  if (!fdescs.empty()) sub.setFDescs(fdescs);
  if (mar_bw_ul) sub.setMarBwUl(*mar_bw_ul);
  if (removed) {
    FlowStatus fs;
    fs.setEnumValue(FlowStatus_anyOf::eFlowStatus_anyOf::REMOVED);
    sub.setFStatus(fs);
  }
  return sub;
}

std::set<std::string> qos_data_ids(const SmPolicyDecision& decision) {
  std::set<std::string> ids;
  for (const auto& entry : decision.getQosDecs()) ids.insert(entry.first);
  return ids;
}

std::set<std::string> pcc_rule_ids(const SmPolicyDecision& decision) {
  std::set<std::string> ids;
  for (const auto& entry : decision.getPccRules()) ids.insert(entry.first);
  return ids;
}

std::set<std::string> to_set(const std::vector<std::string>& v) {
  return std::set<std::string>(v.begin(), v.end());
}

// The single QosData in a decision (tests here create exactly one per component).
const QosData& only_qos_data(const SmPolicyDecision& decision) {
  return decision.getQosDecs().begin()->second;
}
const PccRule& only_pcc_rule(const SmPolicyDecision& decision) {
  return decision.getPccRules().begin()->second;
}

}  // namespace

// ---------------------------------------------------------------------------
// Pure mapping helpers
// ---------------------------------------------------------------------------

TEST(Is5qiStandardized, KnownStandardizedValuesAreRecognized) {
  for (int32_t v : {1, 2, 3, 4, 5, 6, 7, 8, 9, 82, 85}) {
    EXPECT_TRUE(is_standardized_5qi(v)) << "5QI " << v;
  }
}

TEST(Is5qiStandardized, DynamicRangeValuesAreNotStandardized) {
  for (int32_t v : {0, 11, 100, 128, 200}) {
    EXPECT_FALSE(is_standardized_5qi(v)) << "5QI " << v;
  }
}

TEST(Derive5qi, DefaultsToBestEffortWhenNoLatency) {
  EXPECT_EQ(derive_5qi(std::nullopt, /*has_gbr=*/false), 9);
  EXPECT_EQ(derive_5qi(std::nullopt, /*has_gbr=*/true), 9);
}

TEST(Derive5qi, GbrBandsByLatency) {
  EXPECT_EQ(derive_5qi(30.0f, /*has_gbr=*/true), 3);
  EXPECT_EQ(derive_5qi(120.0f, /*has_gbr=*/true), 2);
  EXPECT_EQ(derive_5qi(250.0f, /*has_gbr=*/true), 4);
}

TEST(Derive5qi, NonGbrBandsByLatency) {
  EXPECT_EQ(derive_5qi(50.0f, /*has_gbr=*/false), 7);
  EXPECT_EQ(derive_5qi(200.0f, /*has_gbr=*/false), 6);
  EXPECT_EQ(derive_5qi(500.0f, /*has_gbr=*/false), 9);
}

TEST(Derive5qi, AllDerivedValuesAreStandardized) {
  for (float ms : {10.0f, 80.0f, 120.0f, 250.0f, 400.0f}) {
    EXPECT_TRUE(is_standardized_5qi(derive_5qi(ms, true)));
    EXPECT_TRUE(is_standardized_5qi(derive_5qi(ms, false)));
  }
}

// ---------------------------------------------------------------------------
// create_qos_data_from_media_component
// ---------------------------------------------------------------------------

TEST(QosDataGeneration, CreatesOneQosDataAndOnePccRule) {
  MediaComponent mc;
  SmPolicyDecision decision;
  qos_context qos_ctx;
  fake_qos_reference_store store;
  QosData out;

  auto result = create_qos_data_from_media_component(
      mc, "sess-1", decision, qos_ctx, store, out);

  ASSERT_TRUE(result.status.has_value());
  EXPECT_EQ(result.status.value(), status_code::OK);
  EXPECT_EQ(decision.getQosDecs().size(), 1u);
  EXPECT_EQ(decision.getPccRules().size(), 1u);
}

TEST(QosDataGeneration, IdsUseThePaQosSessionScopedConvention) {
  MediaComponent mc;
  SmPolicyDecision decision;
  qos_context qos_ctx;
  fake_qos_reference_store store;
  QosData out;
  create_qos_data_from_media_component(mc, "sess-42", decision, qos_ctx, store, out);

  EXPECT_EQ(only_qos_data(decision).getQosId().rfind("PA-QOS-sess-42-", 0), 0u);
  EXPECT_EQ(only_pcc_rule(decision).getPccRuleId().rfind("PA-QOS-sess-42-", 0), 0u);
}

TEST(QosDataGeneration, MandatoryQosFieldsAreSet) {
  // 5QI and ARP are always set by the PCF. (priorityLevel is an optional
  // override for standardized 5QI and is intentionally not asserted here.)
  MediaComponent mc;
  SmPolicyDecision decision;
  qos_context qos_ctx;
  fake_qos_reference_store store;
  QosData out;
  create_qos_data_from_media_component(mc, "s", decision, qos_ctx, store, out);

  const QosData& qos = only_qos_data(decision);
  EXPECT_TRUE(qos.r5qiIsSet());
  EXPECT_TRUE(qos.arpIsSet());
}

TEST(QosDataGeneration, ArpPreemptionFieldsAreExplicitlySet) {
  MediaComponent mc;
  SmPolicyDecision decision;
  qos_context qos_ctx;
  fake_qos_reference_store store;
  QosData out;
  create_qos_data_from_media_component(mc, "s", decision, qos_ctx, store, out);

  const oai::model::common::Arp& arp = only_qos_data(decision).getArp();
  EXPECT_NE(arp.getPreemptCap().getEnumValue(),
            oai::model::common::PreemptionCapability_anyOf::
                ePreemptionCapability_anyOf::INVALID_VALUE_OPENAPI_GENERATED);
  EXPECT_NE(arp.getPreemptVuln().getEnumValue(),
            oai::model::common::PreemptionVulnerability_anyOf::
                ePreemptionVulnerability_anyOf::INVALID_VALUE_OPENAPI_GENERATED);
}

TEST(QosDataGeneration, PccRuleReferencesTheCreatedQosData) {
  MediaComponent mc;
  SmPolicyDecision decision;
  qos_context qos_ctx;
  fake_qos_reference_store store;
  QosData out;
  create_qos_data_from_media_component(mc, "s", decision, qos_ctx, store, out);

  auto known = qos_data_ids(decision);
  for (const auto& ref : only_pcc_rule(decision).getRefQosData()) {
    EXPECT_TRUE(known.count(ref) > 0) << "dangling refQosData " << ref;
  }
}

TEST(QosDataGeneration, PrecedenceIsInThePaBand) {
  MediaComponent mc;
  SmPolicyDecision decision;
  qos_context qos_ctx;
  fake_qos_reference_store store;
  QosData out;
  create_qos_data_from_media_component(mc, "s", decision, qos_ctx, store, out);

  EXPECT_GE(only_pcc_rule(decision).getPrecedence(), 1000);
  EXPECT_LT(only_pcc_rule(decision).getPrecedence(), 100000);
}

TEST(QosDataGeneration, LedgerMirrorsTheDecisionIds) {
  MediaComponent mc;
  SmPolicyDecision decision;
  qos_context qos_ctx;
  fake_qos_reference_store store;
  QosData out;
  create_qos_data_from_media_component(mc, "s", decision, qos_ctx, store, out);

  EXPECT_EQ(to_set(qos_ctx.owned_qos_ids()), qos_data_ids(decision));
  EXPECT_EQ(to_set(qos_ctx.owned_rule_ids()), pcc_rule_ids(decision));
}

TEST(QosDataGeneration, NoLatencyYieldsBestEffort5qi) {
  MediaComponent mc;  // no desMaxLatency, no GBR
  SmPolicyDecision decision;
  qos_context qos_ctx;
  fake_qos_reference_store store;
  QosData out;
  create_qos_data_from_media_component(mc, "s", decision, qos_ctx, store, out);

  EXPECT_EQ(only_qos_data(decision).getR5qi(), 9);
}

// --- Bandwidth mapping (TS 29.513 Table 7.3.3-1/-2) ---

TEST(QosDataBandwidth, ComponentLevelMbrIsUsedWhenNoSubComponents) {
  MediaComponent mc;
  mc.setMarBwUl("10 Mbps");
  mc.setMarBwDl("20 Mbps");
  SmPolicyDecision decision;
  qos_context qos_ctx;
  fake_qos_reference_store store;
  QosData out;
  create_qos_data_from_media_component(mc, "s", decision, qos_ctx, store, out);

  const QosData& qos = only_qos_data(decision);
  EXPECT_EQ(qos.getMaxbrUl(), "10 Mbps");
  EXPECT_EQ(qos.getMaxbrDl(), "20 Mbps");
}

TEST(QosDataBandwidth, PerSdfMbrIsSummedAcrossSubComponents) {
  // TS 29.513 Table 7.3.3-2: Maximum Authorized Data Rate = sum over SDFs.
  MediaComponent mc;
  std::map<std::string, MediaSubComponent> subs;
  subs["1"] = make_sub(1, {"permit out ip from any to assigned"}, "1 Mbps");
  subs["2"] = make_sub(2, {"permit out ip from any to assigned"}, "2 Mbps");
  mc.setMedSubComps(subs);
  SmPolicyDecision decision;
  qos_context qos_ctx;
  fake_qos_reference_store store;
  QosData out;
  create_qos_data_from_media_component(mc, "s", decision, qos_ctx, store, out);

  EXPECT_EQ(only_qos_data(decision).getMaxbrUl(), "3 Mbps");
}

TEST(QosDataBandwidth, GbrDerivedOnlyWhenMinimumRateRequested) {
  MediaComponent mc;
  mc.setMarBwUl("10 Mbps");
  mc.setMirBwUl("4 Mbps");  // requests a guaranteed rate -> GBR flow
  SmPolicyDecision decision;
  qos_context qos_ctx;
  fake_qos_reference_store store;
  QosData out;
  create_qos_data_from_media_component(mc, "s", decision, qos_ctx, store, out);

  const QosData& qos = only_qos_data(decision);
  EXPECT_TRUE(qos.gbrUlIsSet());
  EXPECT_EQ(qos.getGbrUl(), "4 Mbps");
}

TEST(QosDataBandwidth, NoGbrWhenNoMinimumRateRequested) {
  MediaComponent mc;
  mc.setMarBwUl("10 Mbps");  // MBR only, no mirBw
  SmPolicyDecision decision;
  qos_context qos_ctx;
  fake_qos_reference_store store;
  QosData out;
  create_qos_data_from_media_component(mc, "s", decision, qos_ctx, store, out);

  EXPECT_FALSE(only_qos_data(decision).gbrUlIsSet());
}

// --- fStatus (TS 29.513 Table 7.3.3-1: REMOVED -> 0 / excluded) ---

TEST(QosDataFlowStatus, RemovedSubComponentIsExcludedFromBandwidthSum) {
  MediaComponent mc;
  std::map<std::string, MediaSubComponent> subs;
  subs["1"] = make_sub(1, {"permit out ip from any to assigned"}, "1 Mbps");
  subs["2"] = make_sub(2, {"permit out ip from any to assigned"}, "5 Mbps",
                       /*removed=*/true);
  mc.setMedSubComps(subs);
  SmPolicyDecision decision;
  qos_context qos_ctx;
  fake_qos_reference_store store;
  QosData out;
  create_qos_data_from_media_component(mc, "s", decision, qos_ctx, store, out);

  // Only the active flow's 1 Mbps counts; the removed 5 Mbps flow contributes 0.
  EXPECT_EQ(only_qos_data(decision).getMaxbrUl(), "1 Mbps");
}

// --- SDF filters (TS 29.512 §4.1.4.2.1) ---

TEST(QosDataSdf, FlowFiltersAreBuiltFromSubComponentDescriptions) {
  MediaComponent mc;
  std::map<std::string, MediaSubComponent> subs;
  subs["1"] = make_sub(1, {"permit out ip from 1.2.3.4 to assigned",
                           "permit in ip from assigned to 1.2.3.4"});
  mc.setMedSubComps(subs);
  SmPolicyDecision decision;
  qos_context qos_ctx;
  fake_qos_reference_store store;
  QosData out;
  create_qos_data_from_media_component(mc, "s", decision, qos_ctx, store, out);

  const auto& flows = only_pcc_rule(decision).getFlowInfos();
  ASSERT_EQ(flows.size(), 2u);
  std::set<std::string> descs;
  for (const auto& f : flows) descs.insert(f.getFlowDescription());
  EXPECT_TRUE(descs.count("permit out ip from 1.2.3.4 to assigned") > 0);
  EXPECT_TRUE(descs.count("permit in ip from assigned to 1.2.3.4") > 0);
}

TEST(QosDataSdf, PermitAllFallbackWhenNoSubComponents) {
  MediaComponent mc;
  SmPolicyDecision decision;
  qos_context qos_ctx;
  fake_qos_reference_store store;
  QosData out;
  create_qos_data_from_media_component(mc, "s", decision, qos_ctx, store, out);

  const auto& flows = only_pcc_rule(decision).getFlowInfos();
  ASSERT_EQ(flows.size(), 1u);
  EXPECT_EQ(flows.front().getFlowDescription(),
            "permit out ip from any to assigned");
}

TEST(QosDataSdf, FlowFiltersAlwaysHaveAnExplicitDirection) {
  MediaComponent mc;
  std::map<std::string, MediaSubComponent> subs;
  subs["1"] = make_sub(1, {"permit out ip from any to assigned"});
  mc.setMedSubComps(subs);
  SmPolicyDecision decision;
  qos_context qos_ctx;
  fake_qos_reference_store store;
  QosData out;
  create_qos_data_from_media_component(mc, "s", decision, qos_ctx, store, out);

  for (const auto& f : only_pcc_rule(decision).getFlowInfos()) {
    EXPECT_NE(f.getFlowDirection().getEnumValue(),
              FlowDirection_anyOf::eFlowDirection_anyOf::
                  INVALID_VALUE_OPENAPI_GENERATED);
  }
}

// --- qosReference lookup (TS 29.513 §7.3.3) ---

TEST(QosDataReference, PreconfiguredSetIsAppliedWhenReferenceResolves) {
  auto preset = std::make_shared<QosData>();
  preset->setR5qi(5);  // operator-chosen, differs from any latency derivation
  preset->setMaxbrUl("99 Mbps");
  oai::model::common::Arp arp;
  arp.setPriorityLevel(3);
  preset->setArp(arp);

  fake_qos_reference_store store;
  store.insert("voice-ref", preset);

  MediaComponent mc;
  mc.setQosReference("voice-ref");
  mc.setDesMaxLatency(30.0f);  // would derive 5QI!=5 if not for the reference
  SmPolicyDecision decision;
  qos_context qos_ctx;
  QosData out;
  create_qos_data_from_media_component(mc, "s", decision, qos_ctx, store, out);

  const QosData& qos = only_qos_data(decision);
  EXPECT_EQ(qos.getR5qi(), 5);
  EXPECT_EQ(qos.getMaxbrUl(), "99 Mbps");
}

TEST(QosDataReference, FallsBackToDerivationWhenReferenceUnknown) {
  fake_qos_reference_store store;  // empty
  MediaComponent mc;
  mc.setQosReference("does-not-exist");
  SmPolicyDecision decision;
  qos_context qos_ctx;
  QosData out;
  create_qos_data_from_media_component(mc, "s", decision, qos_ctx, store, out);

  // Still produces a valid QosData (derived, best-effort default).
  EXPECT_EQ(only_qos_data(decision).getR5qi(), 9);
}

// ---------------------------------------------------------------------------
// create_qos_characteristics (TS 29.512 §4.2.6.6.3)
// ---------------------------------------------------------------------------

TEST(QosCharacteristics, StandardizedQfiProducesNoEntry) {
  QosData qos;
  qos.setR5qi(9);  // standardized
  SmPolicyDecision decision;
  auto result = create_qos_characteristics(qos, decision);

  ASSERT_TRUE(result.status.has_value());
  EXPECT_EQ(result.status.value(), status_code::OK);
  EXPECT_TRUE(decision.getQosChars().empty());
}

TEST(QosCharacteristics, DynamicQfiProducesAnEntryKeyedByThe5qi) {
  QosData qos;
  qos.setR5qi(128);  // dynamic / non-standardized
  qos.setPacketDelayBudget(75);
  qos.setPacketErrorRate("1E-4");
  SmPolicyDecision decision;
  auto result = create_qos_characteristics(qos, decision);

  ASSERT_TRUE(result.status.has_value());
  ASSERT_EQ(decision.getQosChars().size(), 1u);
  auto it = decision.getQosChars().find("128");
  ASSERT_NE(it, decision.getQosChars().end());
  EXPECT_EQ(it->second.getR5qi(), 128);
  EXPECT_EQ(it->second.getPacketDelayBudget(), 75);
  EXPECT_EQ(it->second.getPacketErrorRate(), "1E-4");
}

TEST(QosCharacteristics, DynamicGbrQfiHasGbrResourceType) {
  QosData qos;
  qos.setR5qi(130);
  qos.setGbrUl("5 Mbps");  // presence of GBR => GBR resource type
  qos.setPacketDelayBudget(50);
  qos.setPacketErrorRate("1E-5");
  SmPolicyDecision decision;
  create_qos_characteristics(qos, decision);

  auto it = decision.getQosChars().find("130");
  ASSERT_NE(it, decision.getQosChars().end());
  EXPECT_EQ(it->second.getResourceType().getEnumValue(),
            oai::model::common::QosResourceType_anyOf::eQosResourceType_anyOf::
                NON_CRITICAL_GBR);
}

// ---------------------------------------------------------------------------
// setup_qos_monitoring / validate_qos_authorization (unchanged stubs)
// ---------------------------------------------------------------------------

TEST(QosMonitoringSetup, SucceedsWithoutError) {
  SmPolicyDecision decision;
  auto result = setup_qos_monitoring(decision);
  ASSERT_TRUE(result.status.has_value());
  EXPECT_EQ(result.status.value(), status_code::OK);
}

TEST(QosAuthorization, DoesNotRejectTheHappyPath) {
  auto result = validate_qos_authorization();
  ASSERT_TRUE(result.status.has_value());
  EXPECT_EQ(result.status.value(), status_code::OK);
  EXPECT_FALSE(result.problem_details.has_value());
}

// ---------------------------------------------------------------------------
// handle_qos_requirements (orchestration)
// ---------------------------------------------------------------------------

TEST(QosRequirementsProcessing, ProducesAConsistentDecisionAndLedger) {
  MediaComponent mc;
  mc.setMarBwUl("5 Mbps");
  SmPolicyDecision decision;
  qos_context qos_ctx;
  fake_qos_reference_store store;

  auto result = handle_qos_requirements(mc, "sess-1", decision, qos_ctx, store);

  ASSERT_TRUE(result.status.has_value());
  EXPECT_EQ(result.status.value(), status_code::OK);
  ASSERT_GE(decision.getQosDecs().size(), 1u);
  ASSERT_GE(decision.getPccRules().size(), 1u);

  auto known = qos_data_ids(decision);
  for (const auto& [rule_id, rule] : decision.getPccRules()) {
    for (const auto& ref : rule.getRefQosData()) {
      EXPECT_TRUE(known.count(ref) > 0)
          << "PccRule " << rule_id << " references unknown QosData " << ref;
    }
  }
  EXPECT_EQ(to_set(qos_ctx.owned_qos_ids()), known);
  EXPECT_EQ(to_set(qos_ctx.owned_rule_ids()), pcc_rule_ids(decision));
}

TEST(QosRequirementsProcessing, DynamicReferenceAlsoEmitsQosCharacteristics) {
  auto preset = std::make_shared<QosData>();
  preset->setR5qi(140);  // dynamic
  preset->setPacketDelayBudget(60);
  preset->setPacketErrorRate("1E-4");
  oai::model::common::Arp arp;
  arp.setPriorityLevel(5);
  preset->setArp(arp);

  fake_qos_reference_store store;
  store.insert("dyn-ref", preset);

  MediaComponent mc;
  mc.setQosReference("dyn-ref");
  SmPolicyDecision decision;
  qos_context qos_ctx;

  handle_qos_requirements(mc, "s", decision, qos_ctx, store);

  EXPECT_EQ(decision.getQosDecs().size(), 1u);
  ASSERT_EQ(decision.getQosChars().size(), 1u);
  EXPECT_NE(decision.getQosChars().find("140"), decision.getQosChars().end());
}

// ---------------------------------------------------------------------------
// validate_and_merge_decision (already-implemented merge logic)
// ---------------------------------------------------------------------------

namespace {
PccRule make_pcc_rule(const std::string& id, int32_t precedence) {
  PccRule rule;
  rule.setPccRuleId(id);
  rule.setPrecedence(precedence);
  return rule;
}
}  // namespace

TEST(DecisionMerging, AssignsDefaultPrecedenceWhenRequestRuleHasNone) {
  SmPolicyDecision current;
  SmPolicyDecision request;
  auto rules  = request.getPccRules();
  rules["r1"] = make_pcc_rule("r1", 0);
  request.setPccRules(rules);

  auto result = validate_and_merge_decision(request, current, /*update=*/false);

  ASSERT_TRUE(result.status.has_value());
  EXPECT_EQ(result.status.value(), status_code::OK);
  auto merged = current.getPccRules();
  ASSERT_NE(merged.find("r1"), merged.end());
  EXPECT_EQ(merged["r1"].getPrecedence(), 256);
}

TEST(DecisionMerging, PreservesExplicitPrecedenceOnRequestRule) {
  SmPolicyDecision current;
  SmPolicyDecision request;
  auto rules  = request.getPccRules();
  rules["r1"] = make_pcc_rule("r1", 50);
  request.setPccRules(rules);

  validate_and_merge_decision(request, current, /*update=*/false);

  auto merged = current.getPccRules();
  ASSERT_NE(merged.find("r1"), merged.end());
  EXPECT_EQ(merged["r1"].getPrecedence(), 50);
}

TEST(DecisionMerging, AssignsPrecedenceAboveExistingHighest) {
  SmPolicyDecision current;
  auto current_rules   = current.getPccRules();
  current_rules["old"] = make_pcc_rule("old", 300);
  current.setPccRules(current_rules);

  SmPolicyDecision request;
  auto request_rules   = request.getPccRules();
  request_rules["new"] = make_pcc_rule("new", 0);
  request.setPccRules(request_rules);

  validate_and_merge_decision(request, current, /*update=*/false);

  auto merged = current.getPccRules();
  ASSERT_NE(merged.find("new"), merged.end());
  EXPECT_EQ(merged["new"].getPrecedence(), 301);
}

TEST(DecisionMerging, RejectsDuplicatePccRuleIdWhenNotUpdate) {
  SmPolicyDecision current;
  auto current_rules  = current.getPccRules();
  current_rules["r1"] = make_pcc_rule("r1", 10);
  current.setPccRules(current_rules);

  SmPolicyDecision request;
  auto request_rules  = request.getPccRules();
  request_rules["r1"] = make_pcc_rule("r1", 20);
  request.setPccRules(request_rules);

  auto result = validate_and_merge_decision(request, current, /*update=*/false);

  ASSERT_TRUE(result.status.has_value());
  EXPECT_EQ(result.status.value(), status_code::FORBIDDEN);
  ASSERT_TRUE(result.problem_details.has_value());
  EXPECT_EQ(result.problem_details.value(), "INVALID_SERVICE_INFORMATION");
  EXPECT_EQ(current.getPccRules().size(), 1u);
  EXPECT_EQ(current.getPccRules()["r1"].getPrecedence(), 10);
}

TEST(DecisionMerging, AllowsDuplicatePccRuleIdWhenUpdate) {
  SmPolicyDecision current;
  auto current_rules  = current.getPccRules();
  current_rules["r1"] = make_pcc_rule("r1", 10);
  current.setPccRules(current_rules);

  SmPolicyDecision request;
  auto request_rules  = request.getPccRules();
  request_rules["r1"] = make_pcc_rule("r1", 20);
  request.setPccRules(request_rules);

  auto result = validate_and_merge_decision(request, current, /*update=*/true);

  ASSERT_TRUE(result.status.has_value());
  EXPECT_EQ(result.status.value(), status_code::OK);
  // map::insert does not overwrite an existing key -> original precedence wins.
  EXPECT_EQ(current.getPccRules()["r1"].getPrecedence(), 10);
}

TEST(DecisionMerging, RejectsDuplicateTrafficControlIdWhenNotUpdate) {
  SmPolicyDecision current;
  auto current_tc   = current.getTraffContDecs();
  current_tc["tc1"] = TrafficControlData();
  current.setTraffContDecs(current_tc);

  SmPolicyDecision request;
  auto request_tc   = request.getTraffContDecs();
  request_tc["tc1"] = TrafficControlData();
  request.setTraffContDecs(request_tc);

  auto result = validate_and_merge_decision(request, current, /*update=*/false);

  ASSERT_TRUE(result.status.has_value());
  EXPECT_EQ(result.status.value(), status_code::FORBIDDEN);
  ASSERT_TRUE(result.problem_details.has_value());
  EXPECT_EQ(result.problem_details.value(), "INVALID_SERVICE_INFORMATION");
}

TEST(DecisionMerging, ClearsRefTcDataOnRulesWhoseTrafficControlIsMissing) {
  SmPolicyDecision current;
  auto rule = make_pcc_rule("r1", 10);
  rule.setRefTcData({"tc-missing"});
  auto current_rules  = current.getPccRules();
  current_rules["r1"] = rule;
  current.setPccRules(current_rules);

  SmPolicyDecision request;
  validate_and_merge_decision(request, current, /*update=*/true);

  auto merged = current.getPccRules();
  ASSERT_NE(merged.find("r1"), merged.end());
  EXPECT_TRUE(merged["r1"].getRefTcData().empty());
}

TEST(DecisionMerging, PreservesRefTcDataWhenTrafficControlIsPresent) {
  SmPolicyDecision current;
  auto rule = make_pcc_rule("r1", 10);
  rule.setRefTcData({"tc1"});
  auto current_rules  = current.getPccRules();
  current_rules["r1"] = rule;
  current.setPccRules(current_rules);
  auto current_tc   = current.getTraffContDecs();
  current_tc["tc1"] = TrafficControlData();
  current.setTraffContDecs(current_tc);

  SmPolicyDecision request;
  validate_and_merge_decision(request, current, /*update=*/true);

  auto merged = current.getPccRules();
  ASSERT_NE(merged.find("r1"), merged.end());
  ASSERT_EQ(merged["r1"].getRefTcData().size(), 1u);
  EXPECT_EQ(merged["r1"].getRefTcData().front(), "tc1");
}

TEST(DecisionMerging, MergesTrafficControlDataFromRequest) {
  SmPolicyDecision current;
  SmPolicyDecision request;
  auto request_tc   = request.getTraffContDecs();
  request_tc["tc1"] = TrafficControlData();
  request.setTraffContDecs(request_tc);

  auto result = validate_and_merge_decision(request, current, /*update=*/false);

  ASSERT_TRUE(result.status.has_value());
  EXPECT_EQ(result.status.value(), status_code::OK);
  EXPECT_NE(current.getTraffContDecs().find("tc1"),
            current.getTraffContDecs().end());
}
