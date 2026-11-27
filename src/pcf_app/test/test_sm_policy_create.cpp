/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// Tests for the answer of Npcf_SMPolicyControl_Create (pcf_smpc's
// create_sm_policy_handler). The SmPolicyDecision of the answer carries the
// negotiated features: "This parameter shall be supplied by the PCF in the
// response to the POST request that requested the creation of an individual
// SM policy resource" [TS 29.512 V17.6.0 §5.6.2.4]. They are the features both
// ends support [TS 29.500 V17.16.0 §6.6.2]; this PCF supports no optional
// Npcf_SMPolicyControl feature [TS 29.512 §5.8].

#include <gtest/gtest.h>

#include <memory>
#include <optional>
#include <string>

#include "SmPolicyContextData.h"
#include "SmPolicyControl.h"
#include "SmPolicyDecision.h"
#include "http_definitions.hpp"
#include "pcf_event.hpp"
#include "pcf_sm_policy_control.hpp"
#include "sm_policy/policy_storage_yaml.hpp"

using oai::_3gpp::model::SmPolicyContextData;
using oai::_3gpp::model::SmPolicyControl;
using oai::_3gpp::model::SmPolicyDecision;
using oai::common::sbi::http_status_code;
using oai::common::sbi::method_e;
using oai::http::request;
using oai::http::response;
using oai::pcf::app::http_send_fn;
using oai::pcf::app::pcf_event;
using oai::pcf::app::pcf_smpc;
using oai::pcf::app::sm_policy::policy_storage_yaml;
using oai::pcf::app::sm_policy::status_code;

namespace {

struct created_policy {
  std::string id;
  SmPolicyDecision decision;
};

created_policy create(
    pcf_smpc& smpc, const std::optional<std::string>& smf_supp_feat) {
  SmPolicyContextData ctx;
  ctx.setSupi("imsi-1");
  ctx.setDnn("oai");
  ctx.setNotificationUri("http://smf.example.com/oai");
  if (smf_supp_feat) ctx.setSuppFeat(*smf_supp_feat);

  created_policy created;
  std::string problem_details;
  EXPECT_EQ(
      smpc.create_sm_policy_handler(
          ctx, created.decision, created.id, problem_details),
      status_code::CREATED)
      << problem_details;
  return created;
}

}  // namespace

TEST(SmPolicyCreate, AnswerCarriesTheNegotiatedFeatures) {
  pcf_event ev;
  auto storage = std::make_shared<policy_storage_yaml>();
  storage->set_default_decision(SmPolicyDecision{});
  http_send_fn http_send = [](method_e, const request&) -> response {
    return {http_status_code::OK, "{}", {}};
  };
  pcf_smpc smpc(
      storage, ev, oai::pcf::app::operator_qos_policy{},
      oai::pcf::app::notify_failure_recovery_policy{}, http_send);

  for (const auto& smf_supp_feat :
       {std::optional<std::string>{}, std::optional<std::string>{"0"},
        std::optional<std::string>{"ffffffff"}}) {
    const created_policy created = create(smpc, smf_supp_feat);

    ASSERT_TRUE(created.decision.suppFeatIsSet())
        << "SMF suppFeat: " << smf_supp_feat.value_or("<absent>");
    EXPECT_EQ(created.decision.getSuppFeat(), "0");

    // The stored resource holds the same decision [TS 29.512 §5.6.2.2].
    SmPolicyControl control;
    std::string problem_details;
    ASSERT_EQ(
        smpc.get_sm_policy_handler(created.id, control, problem_details),
        status_code::OK);
    EXPECT_EQ(control.getPolicy().getSuppFeat(), "0");
  }
}
