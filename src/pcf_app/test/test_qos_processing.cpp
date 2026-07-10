/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include <gtest/gtest.h>

#include <set>
#include <vector>

#include "Arp.h"
#include "PccRule.h"
#include "PreemptionCapability.h"
#include "PreemptionVulnerability.h"
#include "QosData.h"
#include "SmPolicyDecision.h"
#include "TrafficControlData.h"
#include "app_session.hpp"
#include "qos_context.hpp"

using namespace oai::pcf::app::policy_auth;
using namespace oai::model::pcf;

namespace {

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

}  // namespace

// ---------------------------------------------------------------------------
// create_qos_data_from_media_component
// ---------------------------------------------------------------------------

TEST(QosDataGeneration, CreatesAtLeastOneQosDataEntry) {
  SmPolicyDecision decision;
  qos_context qos_ctx;

  auto result = create_qos_data_from_media_component(decision, qos_ctx);

  ASSERT_TRUE(result.status.has_value());
  EXPECT_EQ(result.status.value(), status_code::OK);
  EXPECT_FALSE(result.problem_details.has_value());
  EXPECT_GE(decision.getQosDecs().size(), 1u);
}

TEST(QosDataGeneration, QosDataEntriesHaveTheirMandatoryFieldsSet) {
  // 5QI, ARP and priority level are mandatory for the SMF to enforce the QoS
  // flow.
  SmPolicyDecision decision;
  qos_context qos_ctx;
  create_qos_data_from_media_component(decision, qos_ctx);

  ASSERT_GE(decision.getQosDecs().size(), 1u);
  for (const auto& [id, qos_data] : decision.getQosDecs()) {
    EXPECT_TRUE(qos_data.r5qiIsSet()) << "qosId=" << id;
    EXPECT_TRUE(qos_data.arpIsSet()) << "qosId=" << id;
    EXPECT_TRUE(qos_data.priorityLevelIsSet()) << "qosId=" << id;
  }
}

TEST(QosDataGeneration, ArpPreemptionFieldsAreExplicitlySet) {
  // Both preemption capability and vulnerability must be a real value, never
  // left at the OpenAPI-generated "unset" sentinel.
  SmPolicyDecision decision;
  qos_context qos_ctx;
  create_qos_data_from_media_component(decision, qos_ctx);

  ASSERT_GE(decision.getQosDecs().size(), 1u);
  for (const auto& [id, qos_data] : decision.getQosDecs()) {
    const oai::model::common::Arp& arp = qos_data.getArp();
    EXPECT_NE(
        arp.getPreemptCap().getEnumValue(),
        oai::model::common::PreemptionCapability_anyOf::
            ePreemptionCapability_anyOf::INVALID_VALUE_OPENAPI_GENERATED)
        << "qosId=" << id;
    EXPECT_NE(
        arp.getPreemptVuln().getEnumValue(),
        oai::model::common::PreemptionVulnerability_anyOf::
            ePreemptionVulnerability_anyOf::INVALID_VALUE_OPENAPI_GENERATED)
        << "qosId=" << id;
  }
}

TEST(QosDataGeneration, CreatesAtLeastOnePccRule) {
  SmPolicyDecision decision;
  qos_context qos_ctx;
  create_qos_data_from_media_component(decision, qos_ctx);

  EXPECT_GE(decision.getPccRules().size(), 1u);
}

TEST(QosDataGeneration, PccRulesOnlyReferenceQosDataThatWasCreated) {
  // Referential integrity: every id a PccRule lists in refQosData must exist
  // as a key in the decision's QosData map, regardless of naming scheme.
  SmPolicyDecision decision;
  qos_context qos_ctx;
  create_qos_data_from_media_component(decision, qos_ctx);

  auto known_qos_ids = qos_data_ids(decision);
  ASSERT_FALSE(known_qos_ids.empty());

  for (const auto& [rule_id, rule] : decision.getPccRules()) {
    for (const auto& ref : rule.getRefQosData()) {
      EXPECT_TRUE(known_qos_ids.count(ref) > 0)
          << "PccRule " << rule_id << " references unknown QosData " << ref;
    }
  }
}

TEST(QosDataGeneration, PccRuleFlowFiltersAreWellFormedWhenPresent) {
  // SDF filters will eventually be derived from the request's
  // medSubComponents rather than a fixed placeholder; whatever filters exist,
  // each must have a non-empty description and an explicit direction.
  SmPolicyDecision decision;
  qos_context qos_ctx;
  create_qos_data_from_media_component(decision, qos_ctx);

  for (const auto& [rule_id, rule] : decision.getPccRules()) {
    for (const auto& flow_info : rule.getFlowInfos()) {
      EXPECT_FALSE(flow_info.getFlowDescription().empty())
          << "PccRule " << rule_id << " has a flow filter with no description";
      EXPECT_NE(
          flow_info.getFlowDirection().getEnumValue(),
          FlowDirection_anyOf::eFlowDirection_anyOf::
              INVALID_VALUE_OPENAPI_GENERATED)
          << "PccRule " << rule_id << " has a flow filter with no direction";
    }
  }
}

TEST(QosDataGeneration, LedgerTracksExactlyTheQosDataAndPccRuleIdsInTheDecision) {
  // Whatever ids get generated, the app-session's ledger must mirror them
  // exactly so PATCH/DELETE can later edit precisely what this session owns.
  SmPolicyDecision decision;
  qos_context qos_ctx;
  create_qos_data_from_media_component(decision, qos_ctx);

  EXPECT_EQ(to_set(qos_ctx.owned_qos_ids()), qos_data_ids(decision));
  EXPECT_EQ(to_set(qos_ctx.owned_rule_ids()), pcc_rule_ids(decision));
}

// ---------------------------------------------------------------------------
// create_qos_characteristics / setup_qos_monitoring
// ---------------------------------------------------------------------------
//
// Neither step currently derives anything from the request; both must still
// (a) succeed on the happy path and (b) never clobber the QosData/PccRule
// state a prior step already established, regardless of what they end up
// adding to qosChars/qosMonDecs in the future.

TEST(QosCharacteristicsProcessing, SucceedsWithoutError) {
  SmPolicyDecision decision;
  auto result = create_qos_characteristics(decision);

  ASSERT_TRUE(result.status.has_value());
  EXPECT_EQ(result.status.value(), status_code::OK);
}

TEST(QosCharacteristicsProcessing, DoesNotAlterQosDataOrPccRulesFromEarlierSteps) {
  SmPolicyDecision decision;
  qos_context qos_ctx;
  create_qos_data_from_media_component(decision, qos_ctx);
  auto qos_ids_before  = qos_data_ids(decision);
  auto rule_ids_before = pcc_rule_ids(decision);

  create_qos_characteristics(decision);

  EXPECT_EQ(qos_data_ids(decision), qos_ids_before);
  EXPECT_EQ(pcc_rule_ids(decision), rule_ids_before);
}

TEST(QosMonitoringSetup, SucceedsWithoutError) {
  SmPolicyDecision decision;
  auto result = setup_qos_monitoring(decision);

  ASSERT_TRUE(result.status.has_value());
  EXPECT_EQ(result.status.value(), status_code::OK);
}

TEST(QosMonitoringSetup, DoesNotAlterQosDataOrPccRulesFromEarlierSteps) {
  SmPolicyDecision decision;
  qos_context qos_ctx;
  create_qos_data_from_media_component(decision, qos_ctx);
  auto qos_ids_before  = qos_data_ids(decision);
  auto rule_ids_before = pcc_rule_ids(decision);

  setup_qos_monitoring(decision);

  EXPECT_EQ(qos_data_ids(decision), qos_ids_before);
  EXPECT_EQ(pcc_rule_ids(decision), rule_ids_before);
}

// ---------------------------------------------------------------------------
// validate_qos_authorization
// ---------------------------------------------------------------------------
//
// The gate takes no parameters yet, so there is no input to express a
// subscription/slice/resource rejection scenario against -- this only
// documents that the happy path is not rejected. It will need real cases
// (and real parameters) once subscription/resource checks are wired in.

TEST(QosAuthorization, DoesNotRejectTheHappyPath) {
  auto result = validate_qos_authorization();

  ASSERT_TRUE(result.status.has_value());
  EXPECT_EQ(result.status.value(), status_code::OK);
  EXPECT_FALSE(result.problem_details.has_value());
}

// ---------------------------------------------------------------------------
// handle_qos_requirements (orchestrates the steps above)
// ---------------------------------------------------------------------------

TEST(QosRequirementsProcessing, ProducesAConsistentQosDecisionAndLedger) {
  SmPolicyDecision decision;
  qos_context qos_ctx;

  auto result = handle_qos_requirements(decision, qos_ctx);

  ASSERT_TRUE(result.status.has_value());
  EXPECT_EQ(result.status.value(), status_code::OK);

  auto known_qos_ids = qos_data_ids(decision);
  ASSERT_GE(known_qos_ids.size(), 1u);
  ASSERT_GE(decision.getPccRules().size(), 1u);

  for (const auto& [rule_id, rule] : decision.getPccRules()) {
    for (const auto& ref : rule.getRefQosData()) {
      EXPECT_TRUE(known_qos_ids.count(ref) > 0)
          << "PccRule " << rule_id << " references unknown QosData " << ref;
    }
  }

  EXPECT_EQ(to_set(qos_ctx.owned_qos_ids()), known_qos_ids);
  EXPECT_EQ(to_set(qos_ctx.owned_rule_ids()), pcc_rule_ids(decision));
}

// ---------------------------------------------------------------------------
// validate_and_merge_decision
// ---------------------------------------------------------------------------
// This is the PCC-rule/traffic-control merge and precedence-assignment
// algorithm that commits a processed decision (including the QoS entries
// above) into the association's current decision. Unlike QoS parameter
// derivation, this logic is already fully implemented (not a placeholder),
// so it is tested against its actual specified behavior.

namespace {
PccRule make_pcc_rule(const std::string& id, int32_t precedence) {
  PccRule rule;
  rule.setPccRuleId(id);
  rule.setPrecedence(precedence);
  return rule;
}
}  // namespace

TEST(DecisionMerging, AssignsDefaultPrecedenceWhenRequestRuleHasNone) {
  SmPolicyDecision current;  // no existing PCC rules
  SmPolicyDecision request;
  auto rules = request.getPccRules();
  rules["r1"] = make_pcc_rule("r1", /*precedence=*/0);
  request.setPccRules(rules);

  auto result = validate_and_merge_decision(request, current, /*update=*/false);

  ASSERT_TRUE(result.status.has_value());
  EXPECT_EQ(result.status.value(), status_code::OK);
  auto merged = current.getPccRules();
  ASSERT_NE(merged.find("r1"), merged.end());
  // No existing rules -> highest_precedence defaults to 255, so an
  // unset-precedence request rule is assigned 256.
  EXPECT_EQ(merged["r1"].getPrecedence(), 256);
}

TEST(DecisionMerging, PreservesExplicitPrecedenceOnRequestRule) {
  SmPolicyDecision current;
  SmPolicyDecision request;
  auto rules = request.getPccRules();
  rules["r1"] = make_pcc_rule("r1", /*precedence=*/50);
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

  // Rejected before any merging happens -- current decision is untouched.
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
  // Documents current behaviour: the merge uses map::insert(), which does not
  // overwrite an existing key, so the ORIGINAL precedence (10) survives even
  // though the request asked for 20.
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
  // No matching "tc-missing" entry in TraffContDecs.

  SmPolicyDecision request;  // empty request: merge is a pure cleanup pass

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

  SmPolicyDecision request;  // empty request

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
  EXPECT_NE(current.getTraffContDecs().find("tc1"), current.getTraffContDecs().end());
}
