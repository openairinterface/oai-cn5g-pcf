/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include <gtest/gtest.h>

#include <optional>
#include <string>

#include "AppSessionContextReqData.h"
#include "app_session.hpp"

using namespace oai::pcf::app::policy_auth;

TEST(AppSession, ConstructorSetsIdAndAssociationId) {
  oai::_3gpp::model::AppSessionContextReqData ctx;
  app_session session("sess-1", ctx, std::optional<std::string>("assoc-1"));

  EXPECT_EQ(session.id(), "sess-1");
  ASSERT_TRUE(session.association_id().has_value());
  EXPECT_EQ(session.association_id().value(), "assoc-1");
}

TEST(AppSession, ConstructorWithoutAssociationIdLeavesItUnset) {
  oai::_3gpp::model::AppSessionContextReqData ctx;
  app_session session("sess-1", ctx, std::nullopt);

  EXPECT_FALSE(session.association_id().has_value());
}

TEST(AppSession, InitialStateIsPending) {
  oai::_3gpp::model::AppSessionContextReqData ctx;
  app_session session("sess-1", ctx, std::nullopt);

  EXPECT_EQ(session.state(), app_session_state::pending);
}

TEST(AppSession, SetStateChangesState) {
  oai::_3gpp::model::AppSessionContextReqData ctx;
  app_session session("sess-1", ctx, std::nullopt);

  session.set_state(app_session_state::established);
  EXPECT_EQ(session.state(), app_session_state::established);

  session.set_state(app_session_state::released);
  EXPECT_EQ(session.state(), app_session_state::released);
}

TEST(AppSession, NextVersionIncrementsMonotonically) {
  oai::_3gpp::model::AppSessionContextReqData ctx;
  app_session session("sess-1", ctx, std::nullopt);

  EXPECT_EQ(session.version(), 0u);
  EXPECT_EQ(session.next_version(), 1u);
  EXPECT_EQ(session.next_version(), 2u);
  EXPECT_EQ(session.version(), 2u);
}

TEST(AppSession, ContextSnapshotReturnsStoredContext) {
  oai::_3gpp::model::AppSessionContextReqData ctx;
  ctx.setSupi("imsi-001");
  ctx.setDnn("internet");
  app_session session("sess-1", ctx, std::nullopt);

  auto snapshot = session.context_snapshot();
  EXPECT_EQ(snapshot.getSupi(), "imsi-001");
  EXPECT_EQ(snapshot.getDnn(), "internet");
}

TEST(AppSession, UpdateContextReplacesStoredContext) {
  oai::_3gpp::model::AppSessionContextReqData ctx;
  ctx.setSupi("imsi-001");
  app_session session("sess-1", ctx, std::nullopt);

  oai::_3gpp::model::AppSessionContextReqData updated;
  updated.setSupi("imsi-002");
  session.update_context(updated);

  EXPECT_EQ(session.context_snapshot().getSupi(), "imsi-002");
}

TEST(AppSession, QosAccessorReturnsPersistentLedgerAcrossCalls) {
  oai::_3gpp::model::AppSessionContextReqData ctx;
  app_session session("sess-1", ctx, std::nullopt);

  session.qos().record_qos_flow("qos-1");

  EXPECT_EQ(session.qos().owned_qos_ids().size(), 1u);
}

TEST(AppSession, ToRecordProjectsIdStateBindingAndLedger) {
  oai::_3gpp::model::AppSessionContextReqData ctx;
  ctx.setSupi("imsi-001");
  ctx.setDnn("internet");
  ctx.setUeIpv4("10.0.0.1");
  app_session session("sess-1", ctx, std::optional<std::string>("assoc-1"));
  session.set_state(app_session_state::established);
  session.qos().record_qos_flow("qos-1");
  session.qos().record_pcc_rule("rule-1", 100, {"qos-1"});

  auto record = session.to_record();

  EXPECT_EQ(record.app_session_id, "sess-1");
  ASSERT_TRUE(record.association_id.has_value());
  EXPECT_EQ(record.association_id.value(), "assoc-1");
  EXPECT_EQ(record.state, app_session_state::established);
  EXPECT_EQ(record.supi, "imsi-001");
  EXPECT_EQ(record.dnn, "internet");
  EXPECT_EQ(record.ue_ipv4, "10.0.0.1");
  EXPECT_EQ(record.owned_qos_ids.size(), 1u);
  EXPECT_EQ(record.owned_pcc_rule_ids.size(), 1u);
}
