/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// Tests for the lifetime of the pcf_event signal connections. Policy
// Authorization and SM Policy Control talk through signals of a shared
// pcf_event; a service that is destroyed must leave no slot bound to it, or
// the next signal calls into a destroyed object (C++ Core Guidelines R.1).

#include <gtest/gtest.h>

#include <memory>
#include <string>

#include "AppSessionContext.h"
#include "AppSessionContextReqData.h"
#include "SmPolicyContextData.h"
#include "SmPolicyDecision.h"
#include "crud_store.hpp"
#include "http_definitions.hpp"
#include "pcf_event.hpp"
#include "pcf_policy_authorization.hpp"
#include "pcf_sm_policy_control.hpp"
#include "policy_auth/app_session_storage.hpp"
#include "policy_auth/policy_auth_context.hpp"
#include "sm_policy/policy_storage_yaml.hpp"

using oai::_3gpp::model::AppSessionContext;
using oai::_3gpp::model::AppSessionContextReqData;
using oai::_3gpp::model::SmPolicyContextData;
using oai::_3gpp::model::SmPolicyDecision;
using oai::common::sbi::http_status_code;
using oai::common::sbi::method_e;
using oai::http::request;
using oai::http::response;
using oai::pcf::app::http_send_fn;
using oai::pcf::app::pcf_event;
using oai::pcf::app::pcf_policy_authorization;
using oai::pcf::app::pcf_smpc;
using oai::pcf::app::policy_auth::app_session_storage;
using oai::pcf::app::policy_auth::policy_auth_context;
using oai::pcf::app::sm_policy::policy_storage_yaml;

namespace pa = oai::pcf::app::policy_auth;
namespace sm = oai::pcf::app::sm_policy;

// SM Policy Control is destroyed while the policy storage and Policy
// Authorization live on: session binding finds no slot and fails cleanly
// (500 PDU_SESSION_NOT_AVAILABLE), instead of running the destroyed object's
// handler.
TEST(EventConnections, DestroyedSmPolicyControlNoLongerAnswersBinding) {
  pcf_event ev;
  auto storage = std::make_shared<policy_storage_yaml>();
  storage->set_default_decision(SmPolicyDecision{});

  auto app_sessions = std::make_shared<app_session_storage>(
      std::make_shared<oai::utils::crud_store_memory<
          oai::pcf::app::policy_auth::app_session>>());
  auto qos_refs = std::make_shared<
      oai::utils::crud_store_memory<const oai::_3gpp::model::QosData>>();
  auto pa_context =
      std::make_shared<policy_auth_context>(app_sessions, qos_refs);
  auto pa = std::make_shared<pcf_policy_authorization>(pa_context, ev);

  {
    http_send_fn http_send = [](method_e, const request&) -> response {
      return {http_status_code::OK, "{}", {}};
    };
    pcf_smpc smpc(
        storage, ev, oai::pcf::app::operator_qos_policy{},
        oai::pcf::app::notify_failure_recovery_policy{}, http_send);

    SmPolicyContextData ctx;
    ctx.setIpv4Address("10.0.0.5");
    ctx.setSupi("imsi-1");
    ctx.setDnn("oai");
    ctx.setNotificationUri("http://smf.example.com/oai");
    SmPolicyDecision decision;
    std::string id;
    std::string problem_details;
    ASSERT_EQ(
        smpc.create_sm_policy_handler(ctx, decision, id, problem_details),
        sm::status_code::CREATED);
  }

  AppSessionContextReqData req;
  req.setUeIpv4("10.0.0.5");
  req.setSupi("imsi-1");
  req.setDnn("oai");
  req.setNotifUri("http://af.example.com/notify");
  req.setSuppFeat("0");
  AppSessionContext context;
  context.setAscReqData(req);
  std::string app_session_id;
  std::string problem_details;

  EXPECT_EQ(
      pa->post_app_sessions_handler(context, app_session_id, problem_details),
      pa::status_code::PDU_SESSION_NOT_AVAILABLE);
  EXPECT_EQ(problem_details, "PDU_SESSION_NOT_AVAILABLE");
}
