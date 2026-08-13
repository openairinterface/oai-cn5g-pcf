/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// Tests for the http_send seam injected into pcf_smpc
// A fake http_send exercises the FULL production wiring --
// Policy Authorization's create -> pcf_smpc's optimistic apply -> SMF notify
// -> classification -> (on a permanent rejection) the SM->PA
// sm_policy_update_failed signal -> Policy Authorization's compensating
// rollback -> a second notify -- with no real HTTP client and no mocking of
// the non-virtual http_client submodule type.

#include <gtest/gtest.h>

#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "AppSessionContext.h"
#include "AppSessionContextReqData.h"
#include "SmPolicyContextData.h"
#include "SmPolicyControl.h"
#include "SmPolicyDecision.h"
#include "crud_store.hpp"
#include "http_definitions.hpp"
#include "pcf_event.hpp"
#include "pcf_policy_authorization.hpp"
#include "pcf_sm_policy_control.hpp"
#include "policy_auth/app_session_storage.hpp"
#include "policy_auth/policy_auth_context.hpp"
#include "policy_auth/qos_reference_store.hpp"
#include "sm_policy/policy_decision.hpp"
#include "sm_policy/policy_storage.hpp"

using oai::common::sbi::http_status_code;
using oai::common::sbi::method_e;
using oai::http::request;
using oai::http::response;
using oai::_3gpp::model::AppSessionContext;
using oai::_3gpp::model::AppSessionContextReqData;
using oai::_3gpp::model::SmPolicyContextData;
using oai::_3gpp::model::SmPolicyControl;
using oai::_3gpp::model::SmPolicyDecision;
using oai::pcf::app::http_send_fn;
using oai::pcf::app::pcf_event;
using oai::pcf::app::pcf_policy_authorization;
using oai::pcf::app::pcf_smpc;
using oai::pcf::app::policy_auth::app_session_storage;
using oai::pcf::app::policy_auth::policy_auth_context;
using oai::pcf::app::policy_auth::qos_reference_store;
using oai::pcf::app::sm_policy::policy_decision;
using oai::pcf::app::sm_policy::policy_storage;
using oai::pcf::app::sm_policy::status_code;

namespace {

// Minimal fake of the policy_storage interface: one preconfigured decision,
// and a supi -> association_id map populated by insert_associations (the
// same call create_sm_policy_handler makes) so find_association resolves the
// binding pcf_policy_authorization's session-binding lookup needs.
class fake_policy_storage : public policy_storage {
 public:
  explicit fake_policy_storage(
      const std::shared_ptr<policy_decision>& decision)
      : m_decision(decision) {}

  std::shared_ptr<oai::pcf::app::sm_policy::policy_decision> find_policy(
      const SmPolicyContextData&) override {
    return m_decision;
  }
  void subscribe_to_decision_change(
      std::function<void(std::shared_ptr<oai::pcf::app::sm_policy::
                              policy_decision>&)>) override {}
  void insert_supi_decision(
      const std::string&, const SmPolicyDecision&) override {}
  void insert_dnn_decision(
      const std::string&, const SmPolicyDecision&) override {}
  void insert_slice_decision(
      const oai::_3gpp::model::Snssai&,
      const SmPolicyDecision&) override {}
  void insert_associations(
      const SmPolicyContextData& context,
      const std::string& association_id) override {
    m_supi_to_assoc[context.getSupi()] = association_id;
  }
  void insert_ip_association(
      const std::string&, const std::string&) override {}
  void insert_supi_association(
      const std::string&, const std::string&) override {}
  void insert_dnn_association(
      const std::string&, const std::string&) override {}
  std::shared_ptr<std::string> find_association(
      const std::optional<std::string>&,
      const std::optional<std::string>& supi,
      const std::optional<std::string>&) override {
    if (supi.has_value()) {
      auto it = m_supi_to_assoc.find(supi.value());
      if (it != m_supi_to_assoc.end()) {
        return std::make_shared<std::string>(it->second);
      }
    }
    return nullptr;
  }

 private:
  std::shared_ptr<oai::pcf::app::sm_policy::policy_decision> m_decision;
  std::unordered_map<std::string, std::string> m_supi_to_assoc;
};

// One recorded call the fixture's fake http_send received.
struct recorded_send {
  method_e method;
  std::string uri;
};

struct fixture {
  pcf_event ev;
  std::shared_ptr<fake_policy_storage> storage;
  std::vector<recorded_send> sent;
  std::deque<response> canned_responses;
  std::shared_ptr<pcf_smpc> smpc;
  std::shared_ptr<policy_auth_context> pa_context;
  std::shared_ptr<pcf_policy_authorization> pa;

  explicit fixture(const SmPolicyDecision& initial_decision) {
    storage = std::make_shared<fake_policy_storage>(
        std::make_shared<policy_decision>(initial_decision));

    http_send_fn http_send = [this](
                                  method_e m, const request& r) -> response {
      sent.push_back({m, r.uri});
      response resp = canned_responses.front();
      canned_responses.pop_front();
      return resp;
    };

    smpc = std::make_shared<pcf_smpc>(storage, ev, oai::pcf::app::operator_qos_policy{},
        oai::pcf::app::notify_failure_recovery_policy{}, http_send);

    auto app_sessions = std::make_shared<app_session_storage>(
        std::make_shared<
            oai::utils::crud_store_memory<oai::pcf::app::policy_auth::app_session>>());
    auto qos_refs = std::make_shared<
        oai::utils::crud_store_memory<const oai::_3gpp::model::QosData>>();
    pa_context = std::make_shared<policy_auth_context>(app_sessions, qos_refs);
    pa = std::make_shared<pcf_policy_authorization>(pa_context, ev);
  }

  // Creates the SM policy association (SUPI "imsi-test") and, via
  // pcf_policy_authorization::post_app_sessions_handler, drives one push
  // through the full production wiring: decision_applier's CAS commit (via
  // pcf_smpc::handle_commit_decision_request) -> push_decision_change's
  // notify step (pcf_smpc::handle_notify_committed_decision_request ->
  // send_sm_policy_control_update_notify -> the fake http_send ->
  // classify_smf_notify_response) -> whatever that outcome triggers
  // (nothing, a retry-queue enqueue, or an inline compensate_if_pending ->
  // PA's compensating rollback, which itself runs a SECOND notify through
  // the same fake).
  oai::pcf::app::policy_auth::status_code create_association_and_push(
      std::string& association_id) {
    SmPolicyContextData ctx;
    ctx.setSupi("imsi-test");
    ctx.setNotificationUri("http://smf.example.com/callback");

    SmPolicyDecision decision_out;
    std::string problem_details;
    const auto res = smpc->create_sm_policy_handler(
        ctx, decision_out, association_id, problem_details);
    EXPECT_EQ(res, status_code::CREATED);

    AppSessionContextReqData req_data;
    req_data.setSupi("imsi-test");
    req_data.setNotifUri("http://af.example.com/notify");
    req_data.setSuppFeat("0");
    AppSessionContext context;
    context.setAscReqData(req_data);

    std::string app_session_id;
    std::string pa_problem_details;
    return pa->post_app_sessions_handler(
        context, app_session_id, pa_problem_details);
  }
};

response applied_response() {
  return {http_status_code::OK, "{}", {}};
}

response permanent_rejection_response() {
  return {http_status_code::BAD_REQUEST, R"({"cause":"PCC_RULE_EVENT"})", {}};
}

response temporary_rejection_response() {
  return {http_status_code::FORBIDDEN, "{}", {}};
}

}  // namespace

TEST(SmNotifySend, AppliedResponseSendsOnceAndCommits) {
  fixture f{SmPolicyDecision{}};
  f.canned_responses.push_back(applied_response());

  std::string association_id;
  const auto result = f.create_association_and_push(association_id);

  EXPECT_EQ(result, oai::pcf::app::policy_auth::status_code::CREATED);
  ASSERT_EQ(f.sent.size(), 1u);
  EXPECT_EQ(f.sent[0].method, method_e::POST);
  EXPECT_NE(f.sent[0].uri.find("/update"), std::string::npos);
}

TEST(SmNotifySend, PermanentRejectionTriggersASecondNotifyForTheRollback) {
  fixture f{SmPolicyDecision{}};
  // First call: the original push, permanently rejected by the fake SMF.
  f.canned_responses.push_back(permanent_rejection_response());
  // Second call: PA's compensating rollback, which the fake SMF applies.
  f.canned_responses.push_back(applied_response());

  std::string association_id;
  const auto result = f.create_association_and_push(association_id);

  // The CAS commit itself succeeded before the notify ever ran, so PA's
  // handler reports success regardless of the SMF's notify outcome -- only
  // the rollback path (triggered asynchronously in this same call, since the
  // fake http_send runs synchronously) differs.
  EXPECT_EQ(result, oai::pcf::app::policy_auth::status_code::CREATED);
  ASSERT_EQ(f.sent.size(), 2u);
  EXPECT_EQ(f.sent[1].uri, f.sent[0].uri);

  // The rollback compensated an empty delta (no QoS was ever added), so the
  // association's decision is unchanged from its initial state.
  SmPolicyControl control;
  std::string problem_details;
  const auto get_res =
      f.smpc->get_sm_policy_handler(association_id, control, problem_details);
  EXPECT_EQ(get_res, oai::pcf::app::sm_policy::status_code::OK);
  EXPECT_TRUE(control.getPolicy().getQosDecs().empty());
}

TEST(SmNotifySend, TemporaryRejectionDoesNotTriggerARollbackNotify) {
  fixture f{SmPolicyDecision{}};
  f.canned_responses.push_back(temporary_rejection_response());

  std::string association_id;
  const auto result = f.create_association_and_push(association_id);

  EXPECT_EQ(result, oai::pcf::app::policy_auth::status_code::CREATED);
  // Retry-only outcome: deferred to the retry-drain queue (already covered
  // by test_retry_drain_queue.cpp), not a synchronous second notify.
  EXPECT_EQ(f.sent.size(), 1u);
}
