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
//
// The tests are ordered by the primary 3GPP clause they exercise. Each test
// carries a short clause comment so the coverage can be traced back to the
// standards bundle under .vscode.

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
#include "PreemptionCapability.h"
#include "PreemptionVulnerability.h"
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

MediaSubComponent make_sub_with_bitrates(
    int32_t f_num, const std::vector<std::string>& fdescs,
    std::optional<std::string> mar_bw_ul,
    std::optional<std::string> mar_bw_dl,
    bool removed = false) {
  MediaSubComponent sub = make_sub(f_num, fdescs, mar_bw_ul, removed);
  if (mar_bw_dl) sub.setMarBwDl(*mar_bw_dl);
  return sub;
}

oai::model::common::PreemptionCapability make_preempt_capability(
    oai::model::common::PreemptionCapability_anyOf::
        ePreemptionCapability_anyOf value) {
  oai::model::common::PreemptionCapability cap;
  cap.setEnumValue(value);
  return cap;
}

oai::model::common::PreemptionVulnerability make_preempt_vulnerability(
    oai::model::common::PreemptionVulnerability_anyOf::
        ePreemptionVulnerability_anyOf value) {
  oai::model::common::PreemptionVulnerability vuln;
  vuln.setEnumValue(value);
  return vuln;
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

PccRule make_pcc_rule(const std::string& id, int32_t precedence) {
  PccRule rule;
  rule.setPccRuleId(id);
  rule.setPrecedence(precedence);
  return rule;
}

}  // namespace

/*
 * 3GPP TS 23.501 §5.7.4
 * Standardized 5QI classification.
 */

// TS 23.501 §5.7.4 Table 5.7.4-1: the full standardized 5QI catalogue shall
// be recognized as preconfigured rather than treated as dynamic.
TEST(Is5qiStandardized, KnownStandardizedValuesAreRecognized) {
  for (int32_t v : {1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
                    65, 66, 67, 69, 70, 71, 72, 73, 74, 75,
                    76, 79, 80, 82, 83, 84, 85, 86, 87}) {
    EXPECT_TRUE(is_standardized_5qi(v)) << "5QI " << v;
  }
}

// TS 23.501 §5.7.4 Table 5.7.4-1: values outside the standardized set shall
// be treated as dynamic or non-standardized 5QIs.
TEST(Is5qiStandardized, DynamicRangeValuesAreNotStandardized) {
  for (int32_t v : {0, 11, 64, 68, 77, 78, 81, 88, 100, 128, 200}) {
    EXPECT_FALSE(is_standardized_5qi(v)) << "5QI " << v;
  }
}

/*
 * 3GPP TS 23.503 §6.3.1
 * Dynamic PCC rule precedence and ordering.
 */

// TS 23.503 §6.3.1: PCC rule precedence shall be unambiguous; PA-derived rules
// stay inside the reserved PA precedence band.
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

// TS 23.503 §6.3.1: when a dynamic PCC rule is provisioned without an explicit
// precedence, the PCF assigns a deterministic default precedence.
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

// TS 23.503 §6.3.1: an explicitly supplied PCC rule precedence shall be kept
// unchanged when the rule is merged into the active decision.
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

// TS 23.503 §6.3.1: a newly added dynamic PCC rule shall sort above the
// currently highest precedence when no explicit precedence is provided.
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

/*
 * 3GPP TS 29.512 §4.1.4.2.1
 * PCC rules and service data flow templates.
 */

// TS 29.512 §4.1.4.2.1 and §4.2.6.6.2: authorized QoS per service data flow is
// provisioned as QosData and referenced by a dynamic PCC rule.
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

// TS 29.512 §4.1.4.2.1: dynamic PCC rules are identified within the PDU
// session; the PA implementation uses a stable PA-QOS session-scoped prefix.
TEST(QosDataGeneration, IdsUseThePaQosSessionScopedConvention) {
  MediaComponent mc;
  SmPolicyDecision decision;
  qos_context qos_ctx;
  fake_qos_reference_store store;
  QosData out;
  create_qos_data_from_media_component(
      mc, "sess-42", decision, qos_ctx, store, out);

  EXPECT_EQ(
      only_qos_data(decision).getQosId().rfind("PA-QOS-sess-42-", 0), 0u);
  EXPECT_EQ(
      only_pcc_rule(decision).getPccRuleId().rfind("PA-QOS-sess-42-", 0), 0u);
}

// TS 29.512 §4.1.4.2.1 and §5.6.2.6: every PCC rule that provisions
// authorized QoS shall reference the corresponding QosData entry via refQosData.
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

// TS 29.512 §4.1.4.2.1: the PCC rule SDF template shall contain the flow
// descriptions supplied by the AF media subcomponents.
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

// TS 29.512 §4.1.4.2.1: a PCC rule with an SDF template must carry at least
// one filter; the current implementation falls back to a permit-all filter.
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

// TS 29.512 §4.1.4.2.1: each flow filter in a PCC rule shall have an explicit
// packet flow direction so the SMF can interpret the SDF template correctly.
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

// TS 29.512 §4.1.4.2.1 together with TS 29.513 Table 7.3.3-1: a REMOVED
// service data flow shall not install an SDF filter in the generated PCC rule.
TEST(QosDataFlowStatus, RemovedSubComponentDoesNotCreateFlowInfo) {
  MediaComponent mc;
  std::map<std::string, MediaSubComponent> subs;
  subs["1"] = make_sub(1, {"permit out ip from any to assigned"}, "1 Mbps");
  subs["2"] = make_sub(2, {"permit in ip from assigned to any"}, "5 Mbps",
                       /*removed=*/true);
  mc.setMedSubComps(subs);
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

/*
 * 3GPP TS 29.512 §4.1.4.4.6
 * QoS monitoring policy data.
 */

// TS 29.512 §4.1.4.4.6: the current Phase 1 monitoring hook is a stub and
// shall return success until QosMonitoringData provisioning is implemented.
// TODO [QOS]: setup_qos_monitoring() currently returns success without creating
// monitoring state. Replace this stub expectation with assertions on created
// QosMonitoringData and refQosMon linkage once monitoring provisioning exists.
TEST(QosMonitoringSetup, SucceedsWithoutError) {
  SmPolicyDecision decision;
  auto result = setup_qos_monitoring(decision);
  ASSERT_TRUE(result.status.has_value());
  EXPECT_EQ(result.status.value(), status_code::OK);
}

/*
 * 3GPP TS 29.512 §4.2.6.2.3
 * Merging policy decisions into an existing SM policy association.
 */

// TS 29.512 §4.2.6.2.3: when creating new dynamic PCC rules, duplicate rule ids
// shall be rejected to keep the merged decision unambiguous.
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

// TS 29.512 §4.2.6.2.3: during update handling the existing PCC rule id may be
// retained, and map insertion shall keep the current rule instance in place.
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
  EXPECT_EQ(current.getPccRules()["r1"].getPrecedence(), 10);
}

// TS 29.512 §4.2.6.2.3: duplicate TrafficControlData identifiers shall be
// rejected when a non-update request would collide with the active decision.
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

// TS 29.512 §4.2.6.2.3: when referenced TrafficControlData disappears from the
// merged decision, dependent PCC rules shall no longer carry stale refTcData.
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

// TS 29.512 §4.2.6.2.3: if referenced TrafficControlData remains present after
// merge, the PCC rule shall preserve the existing refTcData linkage.
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

// TS 29.512 §4.2.6.2.3: new TrafficControlData entries supplied by the request
// shall be merged into the current active decision.
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

/*
 * 3GPP TS 29.512 §4.2.6.6.2
 * Provisioning authorized QoS per service data flow.
 */

// TS 29.512 §4.2.6.6.2: each authorized QoS decision shall provision at least
// the 5QI and ARP required for the service data flow.
TEST(QosDataGeneration, MandatoryQosFieldsAreSet) {
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

// TS 29.512 §4.2.6.6.2: ARP shall be explicitly signalled in the QosData, so
// pre-emption capability and vulnerability cannot remain invalid placeholders.
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

// TS 29.512 §4.2.6.6.2 together with TS 29.514 §5.6.2.7: when the AF provides
// pre-emption settings, the PCF shall propagate those exact values into ARP.
TEST(QosDataGeneration, ArpUsesRequestPreemptionValues) {
  MediaComponent mc;
  mc.setPreemptCap(make_preempt_capability(
      oai::model::common::PreemptionCapability_anyOf::
          ePreemptionCapability_anyOf::MAY_PREEMPT));
  mc.setPreemptVuln(make_preempt_vulnerability(
      oai::model::common::PreemptionVulnerability_anyOf::
          ePreemptionVulnerability_anyOf::PREEMPTABLE));
  SmPolicyDecision decision;
  qos_context qos_ctx;
  fake_qos_reference_store store;
  QosData out;
  create_qos_data_from_media_component(mc, "s", decision, qos_ctx, store, out);

  const auto& arp = only_qos_data(decision).getArp();
  EXPECT_EQ(arp.getPreemptCap().getEnumValue(),
            oai::model::common::PreemptionCapability_anyOf::
                ePreemptionCapability_anyOf::MAY_PREEMPT);
  EXPECT_EQ(arp.getPreemptVuln().getEnumValue(),
            oai::model::common::PreemptionVulnerability_anyOf::
                ePreemptionVulnerability_anyOf::PREEMPTABLE);
}

// TS 29.512 §4.2.6.6.2: the PCC rule to QosData linkage must remain internally
// consistent; the session-local ledger mirrors the provisioned ids for lifecycle
// operations on the same authorized QoS objects.
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

// TS 29.512 §4.2.6.6.2: standardized 5QI authorization may still carry
// signalled priority level, averaging window, and maximum data burst overrides.
TEST(QosDataReference, StandardizedReferencePreservesStandardizedOverrides) {
  auto preset = std::make_shared<QosData>();
  preset->setR5qi(9);
  preset->setPriorityLevel(6);
  preset->setAverWindow(200);
  preset->setMaxDataBurstVol(4096);
  oai::model::common::Arp arp;
  arp.setPriorityLevel(4);
  preset->setArp(arp);

  fake_qos_reference_store store;
  store.insert("std-ref", preset);

  MediaComponent mc;
  mc.setQosReference("std-ref");
  SmPolicyDecision decision;
  qos_context qos_ctx;
  QosData out;
  create_qos_data_from_media_component(mc, "s", decision, qos_ctx, store, out);

  const QosData& qos = only_qos_data(decision);
  EXPECT_EQ(qos.getR5qi(), 9);
  ASSERT_TRUE(qos.priorityLevelIsSet());
  EXPECT_EQ(qos.getPriorityLevel(), 6);
  ASSERT_TRUE(qos.averWindowIsSet());
  EXPECT_EQ(qos.getAverWindow(), 200);
  ASSERT_TRUE(qos.maxDataBurstVolIsSet());
  EXPECT_EQ(qos.getMaxDataBurstVol(), 4096);
}

/*
 * 3GPP TS 29.512 §4.2.6.6.3
 * Provisioning explicitly signalled QoS characteristics.
 */

// TS 29.512 §4.2.6.6.3: explicitly signalled QoS characteristics are only
// required for non-standardized or non-configured 5QIs.
TEST(QosCharacteristics, StandardizedQfiProducesNoEntry) {
  QosData qos;
  qos.setR5qi(9);
  SmPolicyDecision decision;
  auto result = create_qos_characteristics(qos, decision);

  ASSERT_TRUE(result.status.has_value());
  EXPECT_EQ(result.status.value(), status_code::OK);
  EXPECT_TRUE(decision.getQosChars().empty());
}

// TS 29.512 §4.2.6.6.3: each dynamic 5QI shall create a QosCharacteristics
// entry keyed by the assigned 5QI value.
TEST(QosCharacteristics, DynamicQfiProducesAnEntryKeyedByThe5qi) {
  QosData qos;
  qos.setR5qi(128);
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

// TS 29.512 §4.2.6.6.3 and §5.6.2.16: a dynamic 5QI that carries GBR
// information shall advertise a GBR resource type in QosCharacteristics.
TEST(QosCharacteristics, DynamicGbrQfiHasGbrResourceType) {
  QosData qos;
  qos.setR5qi(130);
  qos.setGbrUl("5 Mbps");
  qos.setPacketDelayBudget(50);
  qos.setPacketErrorRate("1E-5");
  SmPolicyDecision decision;
  create_qos_characteristics(qos, decision);

  auto it = decision.getQosChars().find("130");
  ASSERT_NE(it, decision.getQosChars().end());
  EXPECT_EQ(it->second.getResourceType().getEnumValue(),
            oai::model::common::QosResourceType_anyOf::
                eQosResourceType_anyOf::NON_CRITICAL_GBR);
}

// TS 29.512 §4.2.6.6.3 and §5.6.2.16: a dynamic 5QI without GBR information
// shall be signalled as a NON_GBR resource type.
TEST(QosCharacteristics, DynamicNonGbrQfiHasNonGbrResourceType) {
  QosData qos;
  qos.setR5qi(131);
  qos.setPacketDelayBudget(80);
  qos.setPacketErrorRate("1E-4");
  SmPolicyDecision decision;
  create_qos_characteristics(qos, decision);

  auto it = decision.getQosChars().find("131");
  ASSERT_NE(it, decision.getQosChars().end());
  EXPECT_EQ(it->second.getResourceType().getEnumValue(),
            oai::model::common::QosResourceType_anyOf::
                eQosResourceType_anyOf::NON_GBR);
}

// TS 29.512 §4.2.6.6.3: dynamic QosCharacteristics shall always contain the
// mandatory priority level, packet delay budget, and packet error rate fields.
TEST(QosCharacteristics, DynamicQfiDefaultsMandatoryFieldsWhenReferenceOmitsThem) {
  QosData qos;
  qos.setR5qi(132);
  SmPolicyDecision decision;
  create_qos_characteristics(qos, decision);

  auto it = decision.getQosChars().find("132");
  ASSERT_NE(it, decision.getQosChars().end());
  EXPECT_EQ(it->second.getPriorityLevel(), 8);
  EXPECT_EQ(it->second.getPacketDelayBudget(), 300);
  EXPECT_EQ(it->second.getPacketErrorRate(), "1E-6");
}

// TS 29.512 §4.2.6.6.3 and §5.6.2.16: the averaging window is applicable to
// GBR-type dynamic characteristics when the operator supplies one.
TEST(QosCharacteristics, GbrDynamicQfiCarriesAveragingWindowWhenProvided) {
  QosData qos;
  qos.setR5qi(133);
  qos.setGbrUl("2 Mbps");
  qos.setPacketDelayBudget(50);
  qos.setPacketErrorRate("1E-5");
  qos.setAverWindow(80);
  SmPolicyDecision decision;
  create_qos_characteristics(qos, decision);

  auto it = decision.getQosChars().find("133");
  ASSERT_NE(it, decision.getQosChars().end());
  ASSERT_TRUE(it->second.averagingWindowIsSet());
  EXPECT_EQ(it->second.getAveragingWindow(), 80);
}

// TS 29.512 §4.2.6.6.3 and §5.6.2.16: the averaging window is not signalled for
// NON_GBR dynamic characteristics even if the source QosData carries one.
TEST(QosCharacteristics, NonGbrDynamicQfiOmitsAveragingWindow) {
  QosData qos;
  qos.setR5qi(134);
  qos.setPacketDelayBudget(80);
  qos.setPacketErrorRate("1E-4");
  qos.setAverWindow(120);
  SmPolicyDecision decision;
  create_qos_characteristics(qos, decision);

  auto it = decision.getQosChars().find("134");
  ASSERT_NE(it, decision.getQosChars().end());
  EXPECT_FALSE(it->second.averagingWindowIsSet());
}

/*
 * 3GPP TS 29.513 §7.3.3
 * Mapping AF service information to authorized QoS.
 */

// TS 29.513 §7.3.3 NOTE 15/17: absent latency hints fall back to the default
// best-effort 5QI when no more specific algorithm is available.
TEST(Derive5qi, DefaultsToBestEffortWhenNoLatency) {
  EXPECT_EQ(derive_5qi(std::nullopt, /*has_gbr=*/false), 9);
  EXPECT_EQ(derive_5qi(std::nullopt, /*has_gbr=*/true), 9);
}

// TS 29.513 §7.3.3 NOTE 15/17: the current operator-tunable GBR heuristic maps
// progressively looser latency budgets to progressively less stringent GBR 5QIs.
TEST(Derive5qi, GbrBandsByLatency) {
  EXPECT_EQ(derive_5qi(30.0f, /*has_gbr=*/true), 3);
  EXPECT_EQ(derive_5qi(120.0f, /*has_gbr=*/true), 2);
  EXPECT_EQ(derive_5qi(250.0f, /*has_gbr=*/true), 4);
}

// TS 29.513 §7.3.3 NOTE 15/17: the current operator-tunable non-GBR heuristic
// maps latency bands to standardized non-GBR 5QI values.
TEST(Derive5qi, NonGbrBandsByLatency) {
  EXPECT_EQ(derive_5qi(50.0f, /*has_gbr=*/false), 7);
  EXPECT_EQ(derive_5qi(200.0f, /*has_gbr=*/false), 6);
  EXPECT_EQ(derive_5qi(500.0f, /*has_gbr=*/false), 9);
}

// TS 29.513 §7.3.3 NOTE 15/17: boundary latency values shall be mapped
// deterministically so the same hint produces the same standardized 5QI.
TEST(Derive5qi, UsesLatencyThresholdBoundariesDeterministically) {
  EXPECT_EQ(derive_5qi(50.0f, /*has_gbr=*/true), 3);
  EXPECT_EQ(derive_5qi(50.1f, /*has_gbr=*/true), 2);
  EXPECT_EQ(derive_5qi(150.0f, /*has_gbr=*/true), 2);
  EXPECT_EQ(derive_5qi(150.1f, /*has_gbr=*/true), 4);

  EXPECT_EQ(derive_5qi(100.0f, /*has_gbr=*/false), 7);
  EXPECT_EQ(derive_5qi(100.1f, /*has_gbr=*/false), 6);
  EXPECT_EQ(derive_5qi(300.0f, /*has_gbr=*/false), 6);
  EXPECT_EQ(derive_5qi(300.1f, /*has_gbr=*/false), 9);
}

// TS 29.513 §7.3.3 NOTE 15/17 together with TS 23.501 §5.7.4: every 5QI value
// produced by the current latency heuristic shall remain standardized.
TEST(Derive5qi, AllDerivedValuesAreStandardized) {
  for (float ms : {10.0f, 80.0f, 120.0f, 250.0f, 400.0f}) {
    EXPECT_TRUE(is_standardized_5qi(derive_5qi(ms, true)));
    EXPECT_TRUE(is_standardized_5qi(derive_5qi(ms, false)));
  }
}

// TS 29.513 §7.3.3: if the AF provides neither latency nor GBR hints, the PCF
// shall fall back to the default best-effort 5QI.
TEST(QosDataGeneration, NoLatencyYieldsBestEffort5qi) {
  MediaComponent mc;
  SmPolicyDecision decision;
  qos_context qos_ctx;
  fake_qos_reference_store store;
  QosData out;
  create_qos_data_from_media_component(mc, "s", decision, qos_ctx, store, out);

  EXPECT_EQ(only_qos_data(decision).getR5qi(), 9);
}

// TS 29.513 Table 7.3.3-1/-2: when no service data flows are broken out, the
// component-level authorized maximum bit rates are used directly.
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

// TS 29.513 Table 7.3.3-2: the maximum authorized uplink data rate is the sum
// of the authorized uplink data rates across the service data flows.
TEST(QosDataBandwidth, PerSdfMbrIsSummedAcrossSubComponents) {
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

// TS 29.513 Table 7.3.3-2: the maximum authorized downlink data rate is the sum
// of the authorized downlink data rates across the service data flows.
TEST(QosDataBandwidth, PerSdfDlMbrIsSummedAcrossSubComponents) {
  MediaComponent mc;
  std::map<std::string, MediaSubComponent> subs;
  subs["1"] = make_sub_with_bitrates(
      1, {"permit out ip from any to assigned"}, std::nullopt, "1 Mbps");
  subs["2"] = make_sub_with_bitrates(
      2, {"permit out ip from any to assigned"}, std::nullopt, "2 Mbps");
  mc.setMedSubComps(subs);
  SmPolicyDecision decision;
  qos_context qos_ctx;
  fake_qos_reference_store store;
  QosData out;
  create_qos_data_from_media_component(mc, "s", decision, qos_ctx, store, out);

  EXPECT_EQ(only_qos_data(decision).getMaxbrDl(), "3 Mbps");
}

// TS 29.513 Table 7.3.3-1 NOTE 6: guaranteed bandwidth is only derived when
// the AF explicitly requests a minimum or guaranteed rate.
TEST(QosDataBandwidth, GbrDerivedOnlyWhenMinimumRateRequested) {
  MediaComponent mc;
  mc.setMarBwUl("10 Mbps");
  mc.setMirBwUl("4 Mbps");
  SmPolicyDecision decision;
  qos_context qos_ctx;
  fake_qos_reference_store store;
  QosData out;
  create_qos_data_from_media_component(mc, "s", decision, qos_ctx, store, out);

  const QosData& qos = only_qos_data(decision);
  EXPECT_TRUE(qos.gbrUlIsSet());
  EXPECT_EQ(qos.getGbrUl(), "4 Mbps");
}

// TS 29.513 Table 7.3.3-1 NOTE 6: downlink guaranteed bandwidth is derived in
// the same way as uplink when the AF provides mirBwDl.
TEST(QosDataBandwidth, ComponentLevelGbrDlIsDerivedFromMirBwDl) {
  MediaComponent mc;
  mc.setMarBwDl("10 Mbps");
  mc.setMirBwDl("4 Mbps");
  SmPolicyDecision decision;
  qos_context qos_ctx;
  fake_qos_reference_store store;
  QosData out;
  create_qos_data_from_media_component(mc, "s", decision, qos_ctx, store, out);

  const QosData& qos = only_qos_data(decision);
  EXPECT_TRUE(qos.gbrDlIsSet());
  EXPECT_EQ(qos.getGbrDl(), "4 Mbps");
}

// TS 29.513 Table 7.3.3-1 NOTE 6: if no minimum or guaranteed rate is
// requested, the authorized QoS remains non-GBR and no GBR attribute is signalled.
TEST(QosDataBandwidth, NoGbrWhenNoMinimumRateRequested) {
  MediaComponent mc;
  mc.setMarBwUl("10 Mbps");
  SmPolicyDecision decision;
  qos_context qos_ctx;
  fake_qos_reference_store store;
  QosData out;
  create_qos_data_from_media_component(mc, "s", decision, qos_ctx, store, out);

  EXPECT_FALSE(only_qos_data(decision).gbrUlIsSet());
}

// TS 29.513 Table 7.3.3-1: if a service data flow omits marBwUl, the component-
// level uplink maximum authorized bit rate is used for that flow.
TEST(QosDataBandwidth, SubComponentFallsBackToComponentBandwidthWhenSubRateMissing) {
  MediaComponent mc;
  mc.setMarBwUl("10 Mbps");
  std::map<std::string, MediaSubComponent> subs;
  subs["1"] = make_sub(1, {"permit out ip from any to assigned"});
  mc.setMedSubComps(subs);
  SmPolicyDecision decision;
  qos_context qos_ctx;
  fake_qos_reference_store store;
  QosData out;
  create_qos_data_from_media_component(mc, "s", decision, qos_ctx, store, out);

  EXPECT_EQ(only_qos_data(decision).getMaxbrUl(), "10 Mbps");
}

// TS 29.513 Table 7.3.3-1: a REMOVED service data flow contributes zero to the
// authorized bandwidth and is excluded from the aggregate MBR calculation.
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

  EXPECT_EQ(only_qos_data(decision).getMaxbrUl(), "1 Mbps");
}

// TS 29.513 §7.3.3: when qosReference resolves to a pre-defined QoS set, the
// PCF shall use the operator-configured QoS values rather than deriving them.
TEST(QosDataReference, PreconfiguredSetIsAppliedWhenReferenceResolves) {
  auto preset = std::make_shared<QosData>();
  preset->setR5qi(5);
  preset->setMaxbrUl("99 Mbps");
  oai::model::common::Arp arp;
  arp.setPriorityLevel(3);
  preset->setArp(arp);

  fake_qos_reference_store store;
  store.insert("voice-ref", preset);

  MediaComponent mc;
  mc.setQosReference("voice-ref");
  mc.setDesMaxLatency(30.0f);
  SmPolicyDecision decision;
  qos_context qos_ctx;
  QosData out;
  create_qos_data_from_media_component(mc, "s", decision, qos_ctx, store, out);

  const QosData& qos = only_qos_data(decision);
  EXPECT_EQ(qos.getR5qi(), 5);
  EXPECT_EQ(qos.getMaxbrUl(), "99 Mbps");
}

// TS 29.513 §7.3.3: if qosReference does not resolve, the PCF shall continue by
// deriving authorized QoS from the received service information.
TEST(QosDataReference, FallsBackToDerivationWhenReferenceUnknown) {
  fake_qos_reference_store store;
  MediaComponent mc;
  mc.setQosReference("does-not-exist");
  SmPolicyDecision decision;
  qos_context qos_ctx;
  QosData out;
  create_qos_data_from_media_component(mc, "s", decision, qos_ctx, store, out);

  EXPECT_EQ(only_qos_data(decision).getR5qi(), 9);
}

// TS 29.513 §7.3.3: for each handled MediaComponent the PCF shall build a
// decision whose PCC rules and QosData entries remain internally consistent.
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

// TS 29.513 §7.3.3: repeated handling of multiple MediaComponents for the same
// session shall accumulate distinct authorized QoS and PCC rule entries.
TEST(QosRequirementsProcessing, MultipleComponentsAccumulateDistinctDecisionEntries) {
  MediaComponent audio;
  audio.setMarBwUl("5 Mbps");
  MediaComponent video;
  video.setMarBwDl("9 Mbps");

  SmPolicyDecision decision;
  qos_context qos_ctx;
  fake_qos_reference_store store;

  auto first = handle_qos_requirements(audio, "sess-1", decision, qos_ctx, store);
  auto second =
      handle_qos_requirements(video, "sess-1", decision, qos_ctx, store);

  ASSERT_TRUE(first.status.has_value());
  ASSERT_TRUE(second.status.has_value());
  EXPECT_EQ(first.status.value(), status_code::OK);
  EXPECT_EQ(second.status.value(), status_code::OK);
  EXPECT_EQ(decision.getQosDecs().size(), 2u);
  EXPECT_EQ(decision.getPccRules().size(), 2u);
  EXPECT_EQ(qos_ctx.owned_qos_ids().size(), 2u);
  EXPECT_EQ(qos_ctx.owned_rule_ids().size(), 2u);
}

// TS 29.513 §7.3.3 together with TS 29.512 §4.2.6.6.3: when a dynamic
// operator-provided reference is selected, orchestration shall also emit the
// matching explicitly signalled QosCharacteristics entry.
TEST(QosRequirementsProcessing, DynamicReferenceAlsoEmitsQosCharacteristics) {
  auto preset = std::make_shared<QosData>();
  preset->setR5qi(140);
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

/*
 * 3GPP TS 29.514 §4.1.3.1
 * Authorization of Policy Authorization service requests.
 */

// TS 29.514 §4.1.3.1: until subscription and resource checks are implemented,
// the Phase 1 authorization stub shall not reject the QoS happy path.
// TODO [QOS]: validate_qos_authorization() currently always returns OK. Update
// this test to assert accepted and rejected authorization outcomes once
// subscription, slice, and resource-availability checks are implemented.
TEST(QosAuthorization, DoesNotRejectTheHappyPath) {
  auto result = validate_qos_authorization();
  ASSERT_TRUE(result.status.has_value());
  EXPECT_EQ(result.status.value(), status_code::OK);
  EXPECT_FALSE(result.problem_details.has_value());
}

/*
 * Deferred 3GPP QoS Coverage
 *
 * The following tests capture standards requirements that are not executable
 * against the current Phase 1 implementation, are blocked by generated model
 * limitations, or would intentionally fail until the corresponding production
 * code path is implemented. They are kept disabled so the backlog is visible in
 * the suite without destabilizing the current unit-test run.
 */

/*
 * Deferred: 3GPP TS 23.503 §6.1.3.7
 * Service prioritization and conflict handling.
 */

// TS 23.503 §6.1.3.7: the PCF may pre-empt lower priority services or reject a
// request when cumulative authorized QoS exceeds the subscribed guaranteed rate.
TEST(QosAuthorization,
  DISABLED_RejectsUnauthorizedOrConflictingRequestsAndPreemptsLowerPriorityWhenAllowed) {
  GTEST_SKIP() << "Blocked: validate_qos_authorization() is still a no-input mock";
}

/*
 * Deferred: 3GPP TS 23.503 §6.3.1
 * Dynamic PCC rule precedence uniqueness.
 */

// TS 23.503 §6.3.1: every dynamic PCC rule shall retain an unambiguous
// precedence value, including batches of newly inserted zero-precedence rules.
TEST(DecisionMerging,
  DISABLED_AssignsUniquePrecedenceToMultipleZeroPrecedenceRules) {
  SmPolicyDecision current;
  SmPolicyDecision request;
  auto rules   = request.getPccRules();
  rules["r1"]  = make_pcc_rule("r1", 0);
  rules["r2"]  = make_pcc_rule("r2", 0);
  request.setPccRules(rules);

  auto result = validate_and_merge_decision(request, current, /*update=*/false);

  ASSERT_TRUE(result.status.has_value());
  EXPECT_EQ(result.status.value(), status_code::OK);
  ASSERT_EQ(current.getPccRules().size(), 2u);
  EXPECT_EQ(current.getPccRules().at("r1").getPrecedence(), 256);
  EXPECT_EQ(current.getPccRules().at("r2").getPrecedence(), 257);
}

/*
 * Deferred: 3GPP TS 29.512 §4.2.6.2.1 and §4.2.6.2.3
 * QoS-aware decision merge semantics.
 */

// TS 29.512 §4.2.6.2.3: merged SM policy decisions shall carry forward qosDecs,
// qosChars, and qosMonDecs from the request decision.
TEST(DecisionMerging,
  DISABLED_MergesQosDataQosCharacteristicsAndQosMonitoringData) {
  SmPolicyDecision current;
  SmPolicyDecision request;

  QosData qos;
  qos.setQosId("q1");
  qos.setR5qi(128);
  auto qos_decs  = request.getQosDecs();
  qos_decs["q1"] = qos;
  request.setQosDecs(qos_decs);

  QosCharacteristics qos_char;
  qos_char.setR5qi(128);
  qos_char.setPriorityLevel(8);
  qos_char.setPacketDelayBudget(300);
  qos_char.setPacketErrorRate("1E-6");
  auto qos_chars    = request.getQosChars();
  qos_chars["128"] = qos_char;
  request.setQosChars(qos_chars);

  QosMonitoringData qos_mon;
  qos_mon.setQmId("qm1");
  auto qos_mon_decs   = request.getQosMonDecs();
  qos_mon_decs["qm1"] = qos_mon;
  request.setQosMonDecs(qos_mon_decs);

  auto result = validate_and_merge_decision(request, current, /*update=*/false);

  ASSERT_TRUE(result.status.has_value());
  EXPECT_EQ(result.status.value(), status_code::OK);
  EXPECT_EQ(current.getQosDecs().size(), 1u);
  EXPECT_EQ(current.getQosChars().size(), 1u);
  EXPECT_EQ(current.getQosMonDecs().size(), 1u);
}

// TS 29.512 §4.2.6.2.1 and §5.6.2.6: after a QoS-aware merge, every refQosData
// reference shall still resolve to a QosData decision inside the merged policy.
TEST(DecisionMerging,
     DISABLED_PreservesRefQosDataReferentialIntegrityAfterMerge) {
  SmPolicyDecision current;
  SmPolicyDecision request;

  QosData qos;
  qos.setQosId("q1");
  qos.setR5qi(9);
  auto qos_decs  = request.getQosDecs();
  qos_decs["q1"] = qos;
  request.setQosDecs(qos_decs);

  PccRule rule;
  rule.setPccRuleId("r1");
  rule.setRefQosData({"q1"});
  auto rules   = request.getPccRules();
  rules["r1"] = rule;
  request.setPccRules(rules);

  auto result = validate_and_merge_decision(request, current, /*update=*/false);

  ASSERT_TRUE(result.status.has_value());
  EXPECT_EQ(result.status.value(), status_code::OK);
  ASSERT_EQ(current.getPccRules().size(), 1u);
  auto known = qos_data_ids(current);
  for (const auto& ref : current.getPccRules().at("r1").getRefQosData()) {
    EXPECT_TRUE(known.count(ref) > 0) << "dangling refQosData " << ref;
  }
}

/*
 * Deferred: 3GPP TS 29.512 §4.2.6.2.8 and §4.2.6.2.9
 * Resource sharing and priority sharing.
 */

// TS 29.512 §4.2.6.2.8/§4.2.6.2.9: PCC rules that may share resources shall be
// provisioned with matching sharingKeyUl and or sharingKeyDl values.
TEST(QosDataGeneration, DISABLED_CopiesSharingKeysForResourceSharingRules) {
  GTEST_SKIP() << "Blocked: resource-sharing inputs are not modeled on the current QoS path";
}

/*
 * Deferred: 3GPP TS 29.512 §4.2.6.5.7
 * Reflective QoS control.
 */

// TS 29.512 §4.2.6.5.7: reflective QoS is allowed only for eligible non-GBR
// flows and shall not be attached to match-all or default-QoS-flow rules.
TEST(QosDataGeneration,
  DISABLED_EnablesReflectiveQosOnlyOnEligibleNonGbrFlows) {
  GTEST_SKIP() << "Blocked: reflective QoS controls are not implemented in create_qos_data_from_media_component()";
}

/*
 * Deferred: 3GPP TS 29.512 §4.2.6.6.2
 * Packet-loss authorization for 5QI 1.
 */

// TS 29.512 §4.2.6.6.2: maximum packet loss rate shall only be signalled when
// the authorized QoS corresponds to 5QI 1 and that value is explicitly derived.
TEST(QosDataGeneration, DISABLED_AuthorizesMaxPacketLossOnlyForAuthorized5qiOne) {
  GTEST_SKIP() << "Blocked: the current derivation path does not produce an executable 5QI=1 authorization scenario";
}

/*
 * Deferred: 3GPP TS 29.512 §4.1.4.4.6 and §4.2.3.25
 * QoS monitoring data creation and linkage.
 */

// TS 29.512 §4.1.4.4.6 and §4.2.3.25: QoS monitoring policy shall create
// QosMonitoringData and reference it from the affected PCC rule via refQosMon.
TEST(QosMonitoringSetup,
  DISABLED_CreatesQosMonitoringDataAndLinksRefQosMon) {
  GTEST_SKIP() << "Blocked: setup_qos_monitoring() is still a success-only stub";
}

/*
 * Deferred: 3GPP TS 29.512 §4.2.6.2.1 and 3GPP TS 29.514 §4.2.2.32 / §4.2.3.30
 * Alternative QoS parameter sets.
 */

// TS 29.512 §4.2.6.2.1 and TS 29.514 §4.2.2.32/§4.2.3.30: alternative service
// requirements shall yield ordered refAltQosParams plus matching QosData sets.
TEST(QosRequirementsProcessing,
  DISABLED_CreatesOrderedAlternativeQosParameterSets) {
  GTEST_SKIP() << "Blocked: alternative QoS parameter-set modeling is not implemented on the current QoS path";
}

/*
 * Deferred: 3GPP TS 29.513 §7.3.3
 * RTCP-specific mapping rules and edge cases.
 */

// TS 29.513 Table 7.3.3-1: RTCP flows use the rsBw and rrBw-specific rate
// derivation path. The generated FlowUsage model is currently opaque in C++.
TEST(QosDataBandwidth, DISABLED_RtcpFlowUsageAppliesSpecialBandwidthRules) {
  GTEST_SKIP() << "Blocked: FlowUsage does not expose RTCP-specific values in the generated C++ model";
}

// TS 29.513 Table 7.3.3-1: when one traffic direction has no flow description,
// the corresponding authorized data rate for that direction shall be zero.
TEST(QosDataBandwidth, DISABLED_DirectionWithoutFlowDescriptionGetsZeroRate) {
  GTEST_SKIP() << "Blocked: direction-specific zero-rate handling is not implemented in the current bandwidth aggregator";
}

// TS 29.513 Table 7.3.3-1 together with TS 29.512 §4.1.4.2.1: when every
// subcomponent is REMOVED, no permit-all fallback rule should be installed.
TEST(QosDataFlowStatus, DISABLED_AllRemovedSubComponentsDoNotInstallPermitAllFallback) {
  MediaComponent mc;
  std::map<std::string, MediaSubComponent> subs;
  subs["1"] = make_sub(1, {"permit out ip from any to assigned"}, "1 Mbps",
                       /*removed=*/true);
  mc.setMedSubComps(subs);
  SmPolicyDecision decision;
  qos_context qos_ctx;
  fake_qos_reference_store store;
  QosData out;

  auto result = create_qos_data_from_media_component(
      mc, "sess-removed", decision, qos_ctx, store, out);

  ASSERT_TRUE(result.status.has_value());
  EXPECT_EQ(result.status.value(), status_code::OK);
  EXPECT_TRUE(only_pcc_rule(decision).getFlowInfos().empty());
}

/*
 * Deferred: 3GPP TS 29.514 §4.2.3.2
 * Session modification and QoS update handling.
 */

// TS 29.514 §4.2.3.2: modifying media-component QoS shall update or remove the
// app-session-owned QosData and PCC rule entries instead of recreating blindly.
TEST(QosRequirementsProcessing,
  DISABLED_UpdatesOwnedQosEntriesOnSessionModification) {
  GTEST_SKIP() << "Blocked: session-modification QoS update handling is not implemented yet";
}
