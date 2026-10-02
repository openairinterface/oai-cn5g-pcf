/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// Tests for how pcf_smpc keeps the IP/SUPI/DNN association index in step with
// the SM policy lifecycle, and how session binding treats what the index
// returns. They drive the real handlers (create/update/delete, and Policy
// Authorization's POST /app-sessions) over a real policy_storage_yaml.
//
// What the standards mandate, and what these tests check:
//  - When the UE IPv4 address changes, the SMF reports "UE_IP_CH" with the new
//    address in "ipv4Address" and the released one in "relIpv4Address"
//    [TS 29.512 §4.2.4.2, §5.6.3.6]. The PCF then updates its binding
//    information for the PDU session [TS 29.513 §5.2.2.3 steps 16 to 21].
//  - On termination, the PCF removes every binding information it holds for
//    the PDU session [TS 29.512 §4.2.5.2, TS 29.513 §5.2.3.1 step 14, NOTE 2].
//  - Session binding associates the AF session with an existing PDU session
//    [TS 29.513 §6.2]. If binding fails, the PCF rejects
//    Npcf_PolicyAuthorization_Create with HTTP "500 Internal Server Error" and
//    cause "PDU_SESSION_NOT_AVAILABLE" [TS 29.514 §4.2.2.2, Table 5.7.3-1].
//
// References are to Release 18: TS 29.512 V18.13.0, TS 29.513 V18.7.0,
// TS 29.514 V18.7.0.

#include <gtest/gtest.h>

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "AppSessionContext.h"
#include "AppSessionContextReqData.h"
#include "PolicyControlRequestTrigger.h"
#include "SmPolicyContextData.h"
#include "SmPolicyDecision.h"
#include "SmPolicyDeleteData.h"
#include "SmPolicyUpdateContextData.h"
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
using oai::_3gpp::model::PolicyControlRequestTrigger;
using oai::_3gpp::model::PolicyControlRequestTrigger_anyOf;
using oai::_3gpp::model::SmPolicyContextData;
using oai::_3gpp::model::SmPolicyDecision;
using oai::_3gpp::model::SmPolicyDeleteData;
using oai::_3gpp::model::SmPolicyUpdateContextData;
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
using oai::pcf::app::sm_policy::status_code;

namespace {

// policy_storage_yaml whose index always answers with an association id that
// pcf_smpc does not hold. This is what session binding sees when the index is
// stale (an entry left behind by a delete) or ahead of the store (a create
// that has indexed but not yet stored its association).
class stale_index_storage : public policy_storage_yaml {
 public:
  std::shared_ptr<std::string> find_association(
      const std::optional<std::string>&, const std::optional<std::string>&,
      const std::optional<std::string>&) override {
    return std::make_shared<std::string>("no-such-association");
  }
};

struct fixture {
  pcf_event ev;
  std::shared_ptr<policy_storage_yaml> storage;
  std::vector<std::string> sent_uris;
  std::shared_ptr<pcf_smpc> smpc;
  std::shared_ptr<policy_auth_context> pa_context;
  std::shared_ptr<pcf_policy_authorization> pa;

  explicit fixture(std::shared_ptr<policy_storage_yaml> s) : storage(s) {
    // Set before pcf_smpc subscribes, so no policy-change push is triggered.
    storage->set_default_decision(SmPolicyDecision{});

    http_send_fn http_send = [this](method_e, const request& r) -> response {
      sent_uris.push_back(r.uri);
      return {http_status_code::OK, "{}", {}};
    };
    smpc = std::make_shared<pcf_smpc>(
        storage, ev, oai::pcf::app::operator_qos_policy{},
        oai::pcf::app::notify_failure_recovery_policy{}, http_send);

    auto app_sessions = std::make_shared<app_session_storage>(
        std::make_shared<oai::utils::crud_store_memory<
            oai::pcf::app::policy_auth::app_session>>());
    auto qos_refs = std::make_shared<
        oai::utils::crud_store_memory<const oai::_3gpp::model::QosData>>();
    pa_context = std::make_shared<policy_auth_context>(app_sessions, qos_refs);
    pa         = std::make_shared<pcf_policy_authorization>(pa_context, ev);
  }

  std::string create(const std::string& ipv4, const std::string& supi) {
    SmPolicyContextData ctx;
    ctx.setIpv4Address(ipv4);
    ctx.setSupi(supi);
    ctx.setDnn("oai");
    ctx.setNotificationUri("http://smf.example.com/callback");

    SmPolicyDecision decision;
    std::string id;
    std::string problem_details;
    EXPECT_EQ(
        smpc->create_sm_policy_handler(ctx, decision, id, problem_details),
        status_code::CREATED);
    return id;
  }
};

std::optional<std::string> find_by_ip(
    policy_storage_yaml& storage, const std::string& ip) {
  auto found = storage.find_association(ip, std::nullopt, std::nullopt);
  return found ? std::optional<std::string>(*found) : std::nullopt;
}

// The SMF's report of a UE IPv4 address change: "UE_IP_CH" with the newly
// allocated address and the released one [TS 29.512 §5.6.3.6].
SmPolicyUpdateContextData ue_ip_change(
    const std::string& released_ipv4, const std::string& new_ipv4) {
  PolicyControlRequestTrigger trigger;
  trigger.setEnumValue(PolicyControlRequestTrigger_anyOf::
                           ePolicyControlRequestTrigger_anyOf::UE_IP_CH);
  SmPolicyUpdateContextData update;
  update.setRepPolicyCtrlReqTriggers({trigger});
  update.setIpv4Address(new_ipv4);
  update.setRelIpv4Address(released_ipv4);
  return update;
}

AppSessionContext app_session_request(
    const std::string& ue_ipv4, const std::string& supi) {
  AppSessionContextReqData req;
  req.setUeIpv4(ue_ipv4);
  req.setSupi(supi);
  req.setDnn("oai");
  req.setNotifUri("http://af.example.com/notify");
  req.setSuppFeat("0");
  AppSessionContext context;
  context.setAscReqData(req);
  return context;
}

}  // namespace

// After a UE_IP_CH, termination must still remove all binding information of
// the PDU session [TS 29.513 §5.2.3.1 step 14, NOTE 2], including what was
// recorded for the address the session was created with. UE_IP_CH rewrites
// the stored context's IPv4 in place, so a delete keyed on the current context
// misses the original entry and the old IP keeps resolving to a deleted
// association.
TEST(SmPolicyAssociationIndex, DeleteAfterUeIpChangeReclaimsOriginalIpEntry) {
  fixture f{std::make_shared<policy_storage_yaml>()};
  const std::string id = f.create("10.0.0.5", "imsi-1");
  ASSERT_EQ(find_by_ip(*f.storage, "10.0.0.5"), id);

  SmPolicyDecision decision;
  std::string problem_details;
  ASSERT_EQ(
      f.smpc->update_sm_policy_handler(
          id, ue_ip_change("10.0.0.5", "10.0.0.9"), decision, problem_details),
      status_code::OK)
      << problem_details;

  ASSERT_EQ(
      f.smpc->delete_sm_policy_handler(
          id, SmPolicyDeleteData{}, problem_details),
      status_code::OK);

  EXPECT_FALSE(find_by_ip(*f.storage, "10.0.0.5").has_value());
  EXPECT_FALSE(find_by_ip(*f.storage, "10.0.0.9").has_value());
}

// When the SMF reports a new and a released IPv4 address, the PCF updates its
// binding information [TS 29.513 §5.2.2.3 steps 16 to 21]: the released
// address no longer binds and the new one does, since binding compares the AF's
// "ueIpv4" with the PDU session's UE address [TS 29.513 §6.2 a)].
TEST(SmPolicyAssociationIndex, UeIpChangeReindexesTheNewAddress) {
  fixture f{std::make_shared<policy_storage_yaml>()};
  const std::string id = f.create("10.0.0.5", "imsi-1");

  SmPolicyDecision decision;
  std::string problem_details;
  ASSERT_EQ(
      f.smpc->update_sm_policy_handler(
          id, ue_ip_change("10.0.0.5", "10.0.0.9"), decision, problem_details),
      status_code::OK)
      << problem_details;

  EXPECT_EQ(find_by_ip(*f.storage, "10.0.0.9"), id);
  EXPECT_FALSE(find_by_ip(*f.storage, "10.0.0.5").has_value());
}

// No PDU session matches the AF request: session binding fails, and the PCF
// rejects the request with HTTP 500 and cause "PDU_SESSION_NOT_AVAILABLE"
// [TS 29.514 §4.2.2.2, Table 5.7.3-1; TS 29.513 §6.2]. The API handler maps
// policy_auth::status_code::PDU_SESSION_NOT_AVAILABLE to that response.
TEST(SmPolicyAssociationIndex, AppSessionWithoutPduSessionIsRejected) {
  fixture f{std::make_shared<policy_storage_yaml>()};

  std::string app_session_id;
  std::string problem_details;
  const auto result = f.pa->post_app_sessions_handler(
      app_session_request("10.0.0.5", "imsi-1"), app_session_id,
      problem_details);

  EXPECT_EQ(
      result,
      oai::pcf::app::policy_auth::status_code::PDU_SESSION_NOT_AVAILABLE);
  EXPECT_EQ(problem_details, "PDU_SESSION_NOT_AVAILABLE");
  EXPECT_TRUE(f.sent_uris.empty());
  EXPECT_TRUE(f.pa_context->app_sessions().find_all().empty());
}

// Binding is to an existing PDU session [TS 29.513 §6.2]. When the index hands
// back an id pcf_smpc does not hold (a stale entry, or a create that indexed
// before storing), binding has failed. Session binding must not hand Policy
// Authorization that id with an empty decision. The AF gets the same rejection
// as for any binding failure [TS 29.514 §4.2.2.2], and nothing is allocated or
// pushed to the SMF.
TEST(SmPolicyAssociationIndex, AppSessionIsNotBoundToAnUnknownAssociation) {
  fixture f{std::make_shared<stale_index_storage>()};

  std::string app_session_id;
  std::string problem_details;
  const auto result = f.pa->post_app_sessions_handler(
      app_session_request("10.0.0.5", "imsi-1"), app_session_id,
      problem_details);

  EXPECT_EQ(
      result,
      oai::pcf::app::policy_auth::status_code::PDU_SESSION_NOT_AVAILABLE);
  EXPECT_EQ(problem_details, "PDU_SESSION_NOT_AVAILABLE");
  EXPECT_TRUE(app_session_id.empty())
      << "an app-session id was allocated for a request that never bound";
  EXPECT_TRUE(f.sent_uris.empty());
  EXPECT_TRUE(f.pa_context->app_sessions().find_all().empty());
}
