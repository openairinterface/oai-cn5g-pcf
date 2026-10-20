/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// Tests for how pcf_smpc keeps the IP/SUPI/DNN association index in step with
// the SM policy lifecycle, how session binding treats what the index returns,
// and how Policy Authorization finds the PDU session of an existing AF session.
// They drive the real handlers (SM policy create/update/delete, and Policy
// Authorization's POST/PATCH/DELETE /app-sessions) over a real
// policy_storage_yaml.
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
//  - An AF session is bound to one and only one PDU session
//    [TS 23.503 §6.1.3.2.2]. On termination the PCF acts on the PDU session
//    "where PCC rules related with this AF session are installed"
//    [TS 29.513 §5.2.2.2.2.3 step 2], and a modification cannot change the
//    binding attributes [TS 29.514 §4.2.3.2], so modification and termination
//    use the binding made at creation instead of binding again.
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
#include "AppSessionContextUpdateData.h"
#include "AppSessionContextUpdateDataPatch.h"
#include "MediaComponent.h"
#include "MediaComponentRm.h"
#include "MediaSubComponent.h"
#include "PccRule.h"
#include "PolicyControlRequestTrigger.h"
#include "SmPolicyContextData.h"
#include "SmPolicyControl.h"
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
using oai::_3gpp::model::AppSessionContextUpdateData;
using oai::_3gpp::model::AppSessionContextUpdateDataPatch;
using oai::_3gpp::model::MediaComponent;
using oai::_3gpp::model::MediaComponentRm;
using oai::_3gpp::model::MediaSubComponent;
using oai::_3gpp::model::PccRule;
using oai::_3gpp::model::PolicyControlRequestTrigger;
using oai::_3gpp::model::PolicyControlRequestTrigger_anyOf;
using oai::_3gpp::model::SmPolicyContextData;
using oai::_3gpp::model::SmPolicyControl;
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

namespace pa = oai::pcf::app::policy_auth;

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

  std::string create(
      const std::string& ipv4, const std::string& supi,
      const std::string& dnn = "oai") {
    SmPolicyContextData ctx;
    ctx.setIpv4Address(ipv4);
    ctx.setSupi(supi);
    ctx.setDnn(dnn);
    // Per-DNN callback, so the notify URI shows which PDU session was updated.
    ctx.setNotificationUri("http://smf.example.com/" + dnn);

    SmPolicyDecision decision;
    std::string id;
    std::string problem_details;
    EXPECT_EQ(
        smpc->create_sm_policy_handler(ctx, decision, id, problem_details),
        status_code::CREATED);
    return id;
  }

  void delete_sm_policy(const std::string& id) {
    std::string problem_details;
    ASSERT_EQ(
        smpc->delete_sm_policy_handler(
            id, SmPolicyDeleteData{}, problem_details),
        status_code::OK);
  }

  // Ids of the PCC rules installed on an SM policy association.
  std::vector<std::string> pcc_rule_ids(const std::string& association_id) {
    SmPolicyControl control;
    std::string problem_details;
    EXPECT_EQ(
        smpc->get_sm_policy_handler(association_id, control, problem_details),
        status_code::OK);
    std::vector<std::string> ids;
    for (const auto& [id, rule] : control.getPolicy().getPccRules()) {
      ids.push_back(id);
    }
    return ids;
  }

  std::size_t pcc_rules(const std::string& association_id) {
    return pcc_rule_ids(association_id).size();
  }

  // POST /app-sessions with one video media component; returns its id.
  std::string post_video(const AppSessionContext& request) {
    std::string app_session_id;
    std::string problem_details;
    EXPECT_EQ(
        pa->post_app_sessions_handler(request, app_session_id, problem_details),
        pa::status_code::CREATED)
        << problem_details;
    return app_session_id;
  }

  // PATCH /app-sessions/{id}: raise the video's downlink bitrate.
  pa::status_code patch_video_bitrate(
      const std::string& app_session_id, std::string& problem_details) {
    MediaComponentRm video;
    video.setMedCompN(1);
    video.setMarBwDl("10 Mbps");
    AppSessionContextUpdateData update;
    update.setMedComponents({{"1", video}});
    AppSessionContextUpdateDataPatch patch;
    patch.setAscReqData(update);

    AppSessionContext out;
    return pa->mod_app_session_handler(
        app_session_id, patch, out, problem_details);
  }

  pa::status_code delete_app_session(const std::string& app_session_id) {
    std::string problem_details;
    return pa->delete_app_session_handler(app_session_id, problem_details);
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

// The SMF's report that the UE IPv4 address was released and none allocated
// in its place [TS 29.512 §5.6.3.6].
SmPolicyUpdateContextData ue_ip_release(const std::string& released_ipv4) {
  PolicyControlRequestTrigger trigger;
  trigger.setEnumValue(PolicyControlRequestTrigger_anyOf::
                           ePolicyControlRequestTrigger_anyOf::UE_IP_CH);
  SmPolicyUpdateContextData update;
  update.setRepPolicyCtrlReqTriggers({trigger});
  update.setRelIpv4Address(released_ipv4);
  return update;
}

AppSessionContext app_session_request(
    const std::string& ue_ipv4, const std::string& supi,
    const std::string& dnn = "oai") {
  AppSessionContextReqData req;
  if (!ue_ipv4.empty()) req.setUeIpv4(ue_ipv4);
  req.setSupi(supi);
  if (!dnn.empty()) req.setDnn(dnn);
  req.setNotifUri("http://af.example.com/notify");
  req.setSuppFeat("0");
  AppSessionContext context;
  context.setAscReqData(req);
  return context;
}

// The same request with one video media component, which installs one PCC rule
// on the bound PDU session.
AppSessionContext video_request(
    const std::string& ue_ipv4, const std::string& supi,
    const std::string& dnn = "oai") {
  MediaSubComponent flow;
  flow.setFNum(1);
  flow.setFDescs(
      {"permit out ip from 198.51.100.10 to assigned",
       "permit in ip from assigned to 198.51.100.10"});
  MediaComponent video;
  video.setMedCompN(1);
  video.setMarBwDl("5 Mbps");
  video.setMarBwUl("1 Mbps");
  video.setMedSubComps({{"1", flow}});

  AppSessionContext context    = app_session_request(ue_ipv4, supi, dnn);
  AppSessionContextReqData req = context.getAscReqData();
  req.setMedComponents({{"1", video}});
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

// A released IPv4 address with no new one: the PCF deregisters the address
// from its binding information [TS 29.513 §5.2.2.3 step 18], so it no longer
// binds, while the PDU session stays bindable by the SUPI [TS 29.513 §6.2 b)].
TEST(SmPolicyAssociationIndex, UeIpReleaseUnbindsTheReleasedAddress) {
  fixture f{std::make_shared<policy_storage_yaml>()};
  const std::string id = f.create("10.0.0.5", "imsi-1");

  SmPolicyDecision decision;
  std::string problem_details;
  ASSERT_EQ(
      f.smpc->update_sm_policy_handler(
          id, ue_ip_release("10.0.0.5"), decision, problem_details),
      status_code::OK)
      << problem_details;

  EXPECT_FALSE(find_by_ip(*f.storage, "10.0.0.5").has_value());
  auto by_supi = f.storage->find_association("", "imsi-1", "oai");
  ASSERT_TRUE(by_supi);
  EXPECT_EQ(*by_supi, id);
}

// An AF request whose "ueIpv4", "supi" and "dnn" all match a PDU session binds
// to it [TS 29.513 §6.2], and the AF session is created [TS 29.514 §4.2.2.2].
TEST(SmPolicyAssociationIndex, AppSessionBindsToItsPduSession) {
  fixture f{std::make_shared<policy_storage_yaml>()};
  f.create("10.0.0.5", "imsi-1");

  std::string app_session_id;
  std::string problem_details;
  const auto result = f.pa->post_app_sessions_handler(
      app_session_request("10.0.0.5", "imsi-1"), app_session_id,
      problem_details);

  EXPECT_EQ(result, oai::pcf::app::policy_auth::status_code::CREATED)
      << problem_details;
  EXPECT_FALSE(app_session_id.empty());
  EXPECT_EQ(f.sent_uris.size(), 1u);
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

// --- Modification and termination of an existing AF session ----------------

// After a UE_IP_CH the AF session's creation-time "ueIpv4" no longer matches
// its PDU session, and a PATCH cannot update it [TS 29.514 §4.2.3.2]. The
// modification still applies to the PDU session the AF session was bound to
// [TS 29.513 §5.2.2.2.2.2, TS 23.503 §6.1.3.2.2], instead of failing a fresh
// binding on the stale address.
TEST(SmPolicyAssociationIndex, PatchAfterUeIpChangeReachesItsPduSession) {
  fixture f{std::make_shared<policy_storage_yaml>()};
  const std::string id = f.create("10.0.0.5", "imsi-1");
  const std::string app_session_id =
      f.post_video(video_request("10.0.0.5", "imsi-1"));
  ASSERT_EQ(f.sent_uris.size(), 1u);

  SmPolicyDecision decision;
  std::string problem_details;
  ASSERT_EQ(
      f.smpc->update_sm_policy_handler(
          id, ue_ip_change("10.0.0.5", "10.0.0.9"), decision, problem_details),
      status_code::OK)
      << problem_details;

  EXPECT_EQ(
      f.patch_video_bitrate(app_session_id, problem_details),
      pa::status_code::OK)
      << problem_details;
  EXPECT_EQ(f.sent_uris.size(), 2u) << "the SMF was not notified of the PATCH";
  EXPECT_EQ(f.pcc_rules(id), 1u);
}

// On termination the PCF removes the AF session's PCC rules from the PDU
// session where they are installed [TS 29.513 §5.2.2.2.2.3 step 2], even after
// a UE_IP_CH made the AF session's creation-time "ueIpv4" stale.
TEST(SmPolicyAssociationIndex, DeleteAfterUeIpChangeRemovesItsPccRules) {
  fixture f{std::make_shared<policy_storage_yaml>()};
  const std::string id = f.create("10.0.0.5", "imsi-1");
  const std::string app_session_id =
      f.post_video(video_request("10.0.0.5", "imsi-1"));
  ASSERT_EQ(f.pcc_rules(id), 1u);

  SmPolicyDecision decision;
  std::string problem_details;
  ASSERT_EQ(
      f.smpc->update_sm_policy_handler(
          id, ue_ip_change("10.0.0.5", "10.0.0.9"), decision, problem_details),
      status_code::OK)
      << problem_details;

  EXPECT_EQ(f.delete_app_session(app_session_id), pa::status_code::OK);
  EXPECT_EQ(f.pcc_rules(id), 0u) << "the AF session's PCC rule was left behind";
  EXPECT_TRUE(f.pa_context->app_sessions().find_all().empty());
}

// The AF session stays on the PDU session it was bound to. Here it was bound by
// SUPI alone; when the UE then opens a second PDU session, a fresh binding on
// the same attributes would pick the newer one [TS 23.503 §6.1.3.2.2]. The
// PATCH must be committed to, and notified on, the first PDU session.
TEST(SmPolicyAssociationIndex, PatchStaysOnTheBoundSessionWhenUeOpensAnother) {
  fixture f{std::make_shared<policy_storage_yaml>()};
  f.create("10.0.0.5", "imsi-1", "oai");
  const std::string app_session_id =
      f.post_video(video_request("", "imsi-1", ""));
  const std::string second = f.create("10.0.0.6", "imsi-1", "ims");
  const auto sent_before   = f.sent_uris.size();

  std::string problem_details;
  EXPECT_EQ(
      f.patch_video_bitrate(app_session_id, problem_details),
      pa::status_code::OK)
      << problem_details;
  ASSERT_EQ(f.sent_uris.size(), sent_before + 1);
  EXPECT_EQ(f.sent_uris.back().rfind("http://smf.example.com/oai/", 0), 0u)
      << "the PATCH was applied to another PDU session: " << f.sent_uris.back();
  EXPECT_EQ(f.pcc_rules(second), 0u) << "the PATCH changed another PDU session";
}

// The PDU session has ended but the AF session is still stored (this PCF does
// not yet tell the AF to terminate [TS 29.513 §5.2.3.1 step 4]). A PATCH is
// rejected cleanly with "PDU_SESSION_NOT_AVAILABLE" (the API handler answers
// HTTP 500), and nothing is pushed to the SMF. TS 29.514 defines no cause for
// this case; Table 5.7.3-1 lists PDU_SESSION_NOT_AVAILABLE for POST.
TEST(SmPolicyAssociationIndex, PatchAfterPduSessionEndedIsRejected) {
  fixture f{std::make_shared<policy_storage_yaml>()};
  const std::string id = f.create("10.0.0.5", "imsi-1");
  const std::string app_session_id =
      f.post_video(video_request("10.0.0.5", "imsi-1"));
  f.delete_sm_policy(id);
  const auto sent_before = f.sent_uris.size();

  std::string problem_details;
  EXPECT_EQ(
      f.patch_video_bitrate(app_session_id, problem_details),
      pa::status_code::PDU_SESSION_NOT_AVAILABLE);
  EXPECT_EQ(problem_details, "PDU_SESSION_NOT_AVAILABLE");
  EXPECT_EQ(f.sent_uris.size(), sent_before);
}

// The PDU session has ended, so its PCC rules are already gone. Deleting the
// AF session still succeeds and removes it [TS 29.514 §4.2.4.2].
TEST(SmPolicyAssociationIndex, DeleteAfterPduSessionEndedRemovesAppSession) {
  fixture f{std::make_shared<policy_storage_yaml>()};
  const std::string id = f.create("10.0.0.5", "imsi-1");
  const std::string app_session_id =
      f.post_video(video_request("10.0.0.5", "imsi-1"));
  f.delete_sm_policy(id);

  EXPECT_EQ(f.delete_app_session(app_session_id), pa::status_code::OK);
  EXPECT_TRUE(f.pa_context->app_sessions().find_all().empty());
}

// --- Scope of AF-derived PCC rules ------------------------------------------
//
// PCC rules derived from an AF session belong to the one PDU session it is
// bound to [TS 23.503 §6.1.3.2.2, TS 29.513 §5.2.2.2.2.1 step 5] and are
// removed when the AF session ends [TS 29.513 §5.2.2.2.2.3 step 2]. They must
// not leak into the policies the PCF provisions for the UE's other or later PDU
// sessions.

// A UE's next PDU session starts from the provisioned policy, without the PCC
// rules of an AF session bound to its first PDU session.
TEST(SmPolicyProvisionedDecision, NewPduSessionDoesNotInheritAfRules) {
  fixture f{std::make_shared<policy_storage_yaml>()};
  const std::string first = f.create("10.0.0.5", "imsi-1", "oai");
  f.post_video(video_request("10.0.0.5", "imsi-1", "oai"));
  ASSERT_EQ(f.pcc_rules(first), 1u);

  const std::string second = f.create("10.0.0.6", "imsi-1", "ims");

  EXPECT_EQ(f.pcc_rules(second), 0u)
      << "the new PDU session inherited the AF session's PCC rule";
}

// Once the AF session and its PDU session have ended, a new PDU session of the
// same UE on the same DNN carries none of the old AF session's PCC rules.
TEST(SmPolicyProvisionedDecision, AfRulesDoNotOutliveTheAfSession) {
  fixture f{std::make_shared<policy_storage_yaml>()};
  const std::string first = f.create("10.0.0.5", "imsi-1");
  const std::string app_session_id =
      f.post_video(video_request("10.0.0.5", "imsi-1"));
  ASSERT_EQ(f.delete_app_session(app_session_id), pa::status_code::OK);
  f.delete_sm_policy(first);

  const std::string next = f.create("10.0.0.5", "imsi-1");

  EXPECT_EQ(f.pcc_rules(next), 0u)
      << "the deleted AF session's PCC rule came back";
}

// The operator's provisioned DNN policy still applies to the UE's PDU session
// on that DNN after an AF session on another of the UE's PDU sessions committed
// QoS; the AF commit does not create a per-SUPI policy that takes precedence.
TEST(SmPolicyProvisionedDecision, ProvisionedDnnPolicyStillApplies) {
  fixture f{std::make_shared<policy_storage_yaml>()};
  PccRule operator_rule;
  operator_rule.setPccRuleId("operator-ims");
  operator_rule.setPrecedence(100);
  SmPolicyDecision ims_policy;
  ims_policy.setPccRules({{"operator-ims", operator_rule}});
  f.storage->insert_dnn_decision("ims", ims_policy);

  f.create("10.0.0.5", "imsi-1", "oai");
  f.post_video(video_request("10.0.0.5", "imsi-1", "oai"));

  const std::string ims = f.create("10.0.0.6", "imsi-1", "ims");

  EXPECT_EQ(f.pcc_rule_ids(ims), std::vector<std::string>{"operator-ims"});
}
