/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// Tests for classify_smf_notify_response: the TS 29.512 Table 5.7.3-2 /
// clause 4.2.3.2 cause taxonomy for an SMF Npcf_SMPolicyControl_UpdateNotify
// response.

#include <gtest/gtest.h>

#include <nlohmann/json.hpp>

#include "3gpp_29.500.h"
#include "sm_policy/smf_notify_response_classifier.hpp"

using oai::common::sbi::http_status_code;
using oai::pcf::app::sm_policy::classify_smf_notify_response;
using oai::pcf::app::sm_policy::smf_notify_outcome;
using oai::pcf::app::sm_policy::status_code;

TEST(SmfNotifyResponseClassifier, Applied200WithEmptyBody) {
  const auto result = classify_smf_notify_response(http_status_code::OK, {});

  EXPECT_EQ(result.outcome, smf_notify_outcome::applied);
  EXPECT_EQ(result.response, status_code::CREATED);
  EXPECT_EQ(result.partial_failure_entries, 0u);
}

TEST(SmfNotifyResponseClassifier, Applied204NoContent) {
  const auto result =
      classify_smf_notify_response(http_status_code::NO_CONTENT, {});

  EXPECT_EQ(result.outcome, smf_notify_outcome::applied);
  EXPECT_EQ(result.response, status_code::CREATED);
}

TEST(SmfNotifyResponseClassifier, Applied200WithUnrelatedObjectBody) {
  // A single object (e.g. UeCampingRep, per the oneOf in TS 29.512
  // §4.2.3.2's Figure 4.2.3.2-1) is unrelated to failure -- not an array, so
  // it's plain success.
  const nlohmann::json body = {{"ueCampingInfo", "something"}};
  const auto result = classify_smf_notify_response(http_status_code::OK, body);

  EXPECT_EQ(result.outcome, smf_notify_outcome::applied);
  EXPECT_EQ(result.response, status_code::CREATED);
}

TEST(SmfNotifyResponseClassifier, PartialFailureWithPermanentCauseIsRollbackEligible) {
  const nlohmann::json body =
      nlohmann::json::array({{{"failureCause", "PCC_RULE_EVENT"}}});

  const auto result = classify_smf_notify_response(http_status_code::OK, body);

  EXPECT_EQ(result.outcome, smf_notify_outcome::permanent_rejection);
  EXPECT_EQ(result.response, status_code::OK);
  EXPECT_EQ(result.partial_failure_entries, 1u);
}

TEST(SmfNotifyResponseClassifier, PartialFailureWithOnlyTemporaryCauseIsRetryOnly) {
  const nlohmann::json body =
      nlohmann::json::array({{{"failureCause", "PCC_QOS_FLOW_EVENT"}}});

  const auto result = classify_smf_notify_response(http_status_code::OK, body);

  EXPECT_EQ(result.outcome, smf_notify_outcome::temporary_rejection);
  EXPECT_EQ(result.response, status_code::OK);
}

TEST(SmfNotifyResponseClassifier, PartialFailureIsPermanentIfAnyEntryIsPermanent) {
  const nlohmann::json body = nlohmann::json::array(
      {{{"failureCause", "PCC_QOS_FLOW_EVENT"}},
       {{"failureCause", "PCC_RULE_EVENT"}}});

  const auto result = classify_smf_notify_response(http_status_code::OK, body);

  EXPECT_EQ(result.outcome, smf_notify_outcome::permanent_rejection);
  EXPECT_EQ(result.partial_failure_entries, 2u);
}

// Known, pre-existing gap surfaced (not introduced) by this extraction: TS
// 29.512 §4.2.3.2's oneOf also allows a 200 body of array<
// PolicyDecisionFailureCode> (plain strings, not objects) signaling a FULL
// failure. classify_smf_notify_response's partial-failure detection requires
// an OBJECT with a "failureCause" key, so a string array falls through to
// "no partial-failure report" and is misclassified as applied. Documented
// here as current behavior, not endorsed -- worth revisiting.
TEST(
    SmfNotifyResponseClassifier,
    KnownGap_PolicyDecisionFailureCodeArrayIsCurrentlyMisclassifiedAsApplied) {
  const nlohmann::json body = nlohmann::json::array({"QOS_DECS_ERR"});

  const auto result = classify_smf_notify_response(http_status_code::OK, body);

  EXPECT_EQ(result.outcome, smf_notify_outcome::applied);
}

TEST(SmfNotifyResponseClassifier, Forbidden403IsRetryEligibleNotTerminal) {
  const auto result =
      classify_smf_notify_response(http_status_code::FORBIDDEN, {});

  EXPECT_EQ(result.outcome, smf_notify_outcome::temporary_rejection);
  EXPECT_EQ(result.response, status_code::CONTEXT_DENIED);
}

TEST(SmfNotifyResponseClassifier, BadRequestUserUnknown) {
  const nlohmann::json body = {{"cause", "USER_UNKNOWN"}};
  const auto result =
      classify_smf_notify_response(http_status_code::BAD_REQUEST, body);

  EXPECT_EQ(result.response, status_code::USER_UNKOWN);
  EXPECT_EQ(result.outcome, smf_notify_outcome::temporary_rejection);
}

TEST(SmfNotifyResponseClassifier, BadRequestPccRuleEventIsThePermanentCause) {
  const nlohmann::json body = {{"cause", "PCC_RULE_EVENT"}};
  const auto result =
      classify_smf_notify_response(http_status_code::BAD_REQUEST, body);

  EXPECT_EQ(result.response, status_code::INVALID_PARAMETERS);
  EXPECT_EQ(result.outcome, smf_notify_outcome::permanent_rejection);
}

TEST(SmfNotifyResponseClassifier, BadRequestPccQosFlowEventIsTemporary) {
  const nlohmann::json body = {{"cause", "PCC_QOS_FLOW_EVENT"}};
  const auto result =
      classify_smf_notify_response(http_status_code::BAD_REQUEST, body);

  EXPECT_EQ(result.response, status_code::INVALID_PARAMETERS);
  EXPECT_EQ(result.outcome, smf_notify_outcome::temporary_rejection);
}

TEST(SmfNotifyResponseClassifier, BadRequestUnrecognizedCauseDefaultsToTemporary) {
  const nlohmann::json body = {{"cause", "SOME_FUTURE_CAUSE"}};
  const auto result =
      classify_smf_notify_response(http_status_code::BAD_REQUEST, body);

  EXPECT_EQ(result.response, status_code::INVALID_PARAMETERS);
  EXPECT_EQ(result.outcome, smf_notify_outcome::temporary_rejection);
}

// Locks in a deliberate design choice: despite
// RULE_PERMANENT_ERROR's name suggesting it's a permanent-cause synonym for
// PCC_RULE_EVENT the doc's own axonomy table deliberately buckets it
// under "any other/unrecognized cause" -> temporary/retry-only, since it's
// unreachable while kPcfSupportedFeatures == 0x0ULL and the safer default
// when a codepath can never be exercised for real is "retry", not "assume
// terminal and roll back". This test guards against "helpfully" reclassifying
// it as permanent later without re-deriving that decision deliberately.
TEST(SmfNotifyResponseClassifier, BadRequestFeatureGatedCausesDefaultToTemporary) {
  for (const std::string cause :
       {"RULE_PERMANENT_ERROR", "RULE_TEMPORARY_ERROR", "PENDING_TRANSACTION"}) {
    const nlohmann::json body = {{"cause", cause}};
    const auto result =
        classify_smf_notify_response(http_status_code::BAD_REQUEST, body);

    EXPECT_EQ(result.outcome, smf_notify_outcome::temporary_rejection)
        << "cause=" << cause;
  }
}

// Directly re-validates the earlier bugfix: the response body for a 400 here
// is an ErrorReport, {error: {cause, detail}, ruleReports: ...} -- cause must
// be read from the nested "error" object, not the top level.
TEST(SmfNotifyResponseClassifier, NestedErrorReportShapeExtractsCauseAndDetail) {
  const nlohmann::json body = {
      {"error", {{"cause", "PCC_RULE_EVENT"}, {"detail", "nested"}}},
      {"ruleReports", nlohmann::json::array()}};

  const auto result =
      classify_smf_notify_response(http_status_code::BAD_REQUEST, body);

  EXPECT_EQ(result.outcome, smf_notify_outcome::permanent_rejection);
  EXPECT_EQ(result.cause, "PCC_RULE_EVENT");
  EXPECT_EQ(result.detail, "nested");
}

// Some responses (e.g. the generic 403 shape) are flat ProblemDetails, not
// ErrorReport -- cause/detail must also be read correctly from the top level
// when there's no "error" wrapper.
TEST(SmfNotifyResponseClassifier, FlatProblemDetailsShapeExtractsCauseAndDetail) {
  const nlohmann::json body = {
      {"cause", "PCC_RULE_EVENT"}, {"detail", "flat"}};

  const auto result =
      classify_smf_notify_response(http_status_code::BAD_REQUEST, body);

  EXPECT_EQ(result.outcome, smf_notify_outcome::permanent_rejection);
  EXPECT_EQ(result.cause, "PCC_RULE_EVENT");
  EXPECT_EQ(result.detail, "flat");
}

TEST(SmfNotifyResponseClassifier, EmptyBodyOnBadRequestDoesNotCrash) {
  const auto result =
      classify_smf_notify_response(http_status_code::BAD_REQUEST, {});

  EXPECT_EQ(result.cause, "");
  EXPECT_EQ(result.detail, "");
  EXPECT_EQ(result.outcome, smf_notify_outcome::temporary_rejection);
}

TEST(SmfNotifyResponseClassifier, InternalServerError500IsTransportAmbiguous) {
  // TS 29.512 Table 5.7.3-2 doesn't model any 5xx for this operation, so
  // there's no basis to treat it as a confirmed rejection.
  const auto result =
      classify_smf_notify_response(http_status_code::INTERNAL_SERVER_ERROR, {});

  EXPECT_EQ(result.outcome, smf_notify_outcome::transport_ambiguous);
  EXPECT_EQ(result.response, status_code::INTERNAL_SERVER_ERROR);
}

TEST(SmfNotifyResponseClassifier, NoResponseAtAllIsTransportAmbiguous) {
  // status_code 0: connection failure/timeout/gateway failure -- no HTTP
  // response was ever received to classify.
  const auto result =
      classify_smf_notify_response(http_status_code::NO_RESPONSE, {});

  EXPECT_EQ(result.outcome, smf_notify_outcome::transport_ambiguous);
}

TEST(SmfNotifyResponseClassifier, UnmodeledStatusCodeIsTransportAmbiguous) {
  const auto result = classify_smf_notify_response(404, {});

  EXPECT_EQ(result.outcome, smf_notify_outcome::transport_ambiguous);
  EXPECT_EQ(result.response, status_code::INTERNAL_SERVER_ERROR);
}
