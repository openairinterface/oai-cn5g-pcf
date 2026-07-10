/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <vector>

#include "PccRule.h"
#include "QosData.h"
#include "SmPolicyDecision.h"
#include "qos_context.hpp"

using namespace oai::pcf::app::policy_auth;

namespace {
bool contains(const std::vector<std::string>& v, const std::string& needle) {
  return std::find(v.begin(), v.end(), needle) != v.end();
}
}  // namespace

TEST(QosContext, StartsEmpty) {
  qos_context qc;
  EXPECT_TRUE(qc.owned_qos_ids().empty());
  EXPECT_TRUE(qc.owned_rule_ids().empty());
}

TEST(QosContext, RecordQosFlowAddsToOwnedIds) {
  qos_context qc;
  qc.record_qos_flow("qos-1");

  auto ids = qc.owned_qos_ids();
  ASSERT_EQ(ids.size(), 1u);
  EXPECT_TRUE(contains(ids, "qos-1"));
  EXPECT_TRUE(qc.owned_rule_ids().empty());
}

TEST(QosContext, RecordPccRuleAddsToOwnedRuleIds) {
  qos_context qc;
  qc.record_pcc_rule("rule-1", 100, {"qos-1"});

  auto ids = qc.owned_rule_ids();
  ASSERT_EQ(ids.size(), 1u);
  EXPECT_TRUE(contains(ids, "rule-1"));
  EXPECT_TRUE(qc.owned_qos_ids().empty());
}

TEST(QosContext, RecordingMultipleEntriesAccumulates) {
  qos_context qc;
  qc.record_qos_flow("qos-1");
  qc.record_qos_flow("qos-2");
  qc.record_pcc_rule("rule-1", 100, {"qos-1"});
  qc.record_pcc_rule("rule-2", 101, {"qos-2"});

  auto qos_ids  = qc.owned_qos_ids();
  auto rule_ids = qc.owned_rule_ids();
  EXPECT_EQ(qos_ids.size(), 2u);
  EXPECT_EQ(rule_ids.size(), 2u);
  EXPECT_TRUE(contains(qos_ids, "qos-1"));
  EXPECT_TRUE(contains(qos_ids, "qos-2"));
  EXPECT_TRUE(contains(rule_ids, "rule-1"));
  EXPECT_TRUE(contains(rule_ids, "rule-2"));
}

TEST(QosContext, RecordingSameIdTwiceDoesNotDuplicate) {
  qos_context qc;
  qc.record_qos_flow("qos-1");
  qc.record_qos_flow("qos-1");

  EXPECT_EQ(qc.owned_qos_ids().size(), 1u);
}

TEST(QosContext, EraseOwnedFromRemovesExactlyTheOwnedEntries) {
  qos_context qc;
  qc.record_qos_flow("qos-owned");
  qc.record_pcc_rule("rule-owned", 100, {"qos-owned"});

  oai::model::pcf::SmPolicyDecision decision;

  oai::model::pcf::QosData owned_qos;
  owned_qos.setQosId("qos-owned");
  oai::model::pcf::QosData other_qos;
  other_qos.setQosId("qos-other");
  auto qos_map = decision.getQosDecs();
  qos_map["qos-owned"] = owned_qos;
  qos_map["qos-other"] = other_qos;
  decision.setQosDecs(qos_map);

  oai::model::pcf::PccRule owned_rule;
  owned_rule.setPccRuleId("rule-owned");
  oai::model::pcf::PccRule other_rule;
  other_rule.setPccRuleId("rule-other");
  auto rule_map = decision.getPccRules();
  rule_map["rule-owned"] = owned_rule;
  rule_map["rule-other"] = other_rule;
  decision.setPccRules(rule_map);

  qc.erase_owned_from(decision);

  auto remaining_qos   = decision.getQosDecs();
  auto remaining_rules = decision.getPccRules();
  EXPECT_EQ(remaining_qos.size(), 1u);
  EXPECT_TRUE(remaining_qos.find("qos-other") != remaining_qos.end());
  EXPECT_TRUE(remaining_qos.find("qos-owned") == remaining_qos.end());

  EXPECT_EQ(remaining_rules.size(), 1u);
  EXPECT_TRUE(remaining_rules.find("rule-other") != remaining_rules.end());
  EXPECT_TRUE(remaining_rules.find("rule-owned") == remaining_rules.end());
}

TEST(QosContext, EraseOwnedFromOnEmptyLedgerLeavesDecisionUnchanged) {
  qos_context qc;
  oai::model::pcf::SmPolicyDecision decision;
  oai::model::pcf::QosData qos;
  qos.setQosId("qos-1");
  auto qos_map = decision.getQosDecs();
  qos_map["qos-1"] = qos;
  decision.setQosDecs(qos_map);

  qc.erase_owned_from(decision);

  EXPECT_EQ(decision.getQosDecs().size(), 1u);
}

TEST(QosContext, SnapshotAndRestoreRoundTrip) {
  qos_context qc;
  qc.record_qos_flow("qos-1");
  qc.record_pcc_rule("rule-1", 100, {"qos-1"});

  auto snapshot = qc.snapshot();

  qos_context restored;
  restored.restore(snapshot);

  EXPECT_EQ(restored.owned_qos_ids().size(), 1u);
  EXPECT_EQ(restored.owned_rule_ids().size(), 1u);
  EXPECT_TRUE(contains(restored.owned_qos_ids(), "qos-1"));
  EXPECT_TRUE(contains(restored.owned_rule_ids(), "rule-1"));
}
