/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "smf_notify_response_classifier.hpp"

#include "3gpp_29.500.h"

namespace oai::pcf::app::sm_policy {

using oai::common::sbi::http_status_code;

smf_notify_classification classify_smf_notify_response(
    int http_status, const nlohmann::json& body_json) {
  smf_notify_classification result;

  if (http_status == http_status_code::OK ||
      http_status == http_status_code::NO_CONTENT) {
    // A 200 can still carry a PartialSuccessReport array [TS 29.512 §4.2.3.2]
    // even though the top-level HTTP status is success, so classify from the
    // body instead of assuming success outright.
    if (body_json.is_array() && !body_json.empty() &&
        body_json.front().is_object() &&
        body_json.front().contains("failureCause")) {
      // array<PartialSuccessReport>. Phase 2 only reads each report's
      // top-level failureCause to route retry-vs-rollback; per-rule/
      // session-rule ruleReports/sessRuleReports extraction is deferred
      bool any_permanent = false;
      for (const auto& report : body_json) {
        if (report.value("failureCause", std::string{}) == "PCC_RULE_EVENT") {
          any_permanent = true;
          break;
        }
      }
      result.outcome  = any_permanent ? smf_notify_outcome::permanent_rejection
                                        : smf_notify_outcome::temporary_rejection;
      result.response = status_code::OK;
      result.partial_failure_entries = body_json.size();
      result.info =
          "SM Policy Update Notification: SMF returned a partial-failure "
          "report";
      return result;
    }

    // No partial-failure report: plain success (204, or a 200 body unrelated
    // to failure e.g. UeCampingRep).
    result.outcome  = smf_notify_outcome::applied;
    result.response = status_code::CREATED;
    result.info     = "Successful SM Policy Update Notification";
    return result;
  }

  // Failure case. body_json may be an ErrorReport ({error: {cause, detail,
  // ...}, ruleReports: ..., ...} [TS 29.512 §4.2.3.2]) or a flat
  // ProblemDetails ({cause, detail, ...}, e.g. the generic 403 response),
  // depending on the status; read "cause"/"detail" from whichever shape is
  // present instead of assuming one. Guard with is_object(): body_json can
  // legitimately be null (an error response with no body at all, or one
  // get_json() couldn't parse) -- nlohmann::json::value() throws
  // type_error.306 on a non-object receiver, and an SMF rejection is an
  // expected outcome here, not an exceptional one to crash the process over.
  const nlohmann::json& error_obj =
      body_json.contains("error") ? body_json.at("error") : body_json;
  result.cause =
      error_obj.is_object() ? error_obj.value("cause", std::string{}) : "";
  result.detail =
      error_obj.is_object() ? error_obj.value("detail", std::string{}) : "";

  if (http_status == http_status_code::FORBIDDEN) {
    result.info     = "SM Policy Update Notification Forbidden";
    result.response = status_code::CONTEXT_DENIED;
    // Not modeled by TS 29.512 Table 5.7.3-2 for this operation; kept
    // retry-eligible rather than assumed terminal.
    result.outcome = smf_notify_outcome::temporary_rejection;
  } else if (http_status == http_status_code::BAD_REQUEST) {
    // TS 29.512 Table 5.7.3-2: PCC_RULE_EVENT is the only cause that proves
    // the SMF won't apply this on retry ("should not be attempted again").
    // Everything else -- including PCC_QOS_FLOW_EVENT and the feature-gated
    // RULE_PERMANENT_ERROR/RULE_TEMPORARY_ERROR/PENDING_TRANSACTION
    // (unreachable while kPcfSupportedFeatures == 0x0ULL) -- defaults to
    // retry-only per §5.1's "when ambiguous, don't rollback" posture.
    if (result.cause == "USER_UNKNOWN") {
      result.response = status_code::USER_UNKOWN;
      result.info     = "SM Policy Association Creation: Unknown User";
      result.outcome  = smf_notify_outcome::temporary_rejection;
    } else if (result.cause == "PCC_RULE_EVENT") {
      result.response = status_code::INVALID_PARAMETERS;
      result.info     = "SM Policy Update Notification: permanently rejected";
      result.outcome  = smf_notify_outcome::permanent_rejection;
    } else {
      result.response = status_code::INVALID_PARAMETERS;
      result.info     = "SM Policy Update Notification: Bad Request";
      result.outcome  = smf_notify_outcome::temporary_rejection;
    }
  } else if (http_status == http_status_code::INTERNAL_SERVER_ERROR) {
    result.response = status_code::INTERNAL_SERVER_ERROR;
    result.info     = "SM Policy Update Notification: Internal Error";
    // TS 29.512 Table 5.7.3-2 doesn't model any 5xx for this operation -- no
    // basis to treat it as a confirmed rejection (N5_QoS_Phase2_§2.8 §5.1).
    result.outcome = smf_notify_outcome::transport_ambiguous;
  } else {
    result.response = status_code::INTERNAL_SERVER_ERROR;
    result.info =
        "SM Policy Update Notification: Unknown Error Code from SMF: " +
        std::to_string(http_status);
    // status_code == 0 covers a connection failure/timeout/gateway failure
    // (no HTTP response at all); any other unrecognized status is equally
    // unmodeled, so stay conservative.
    result.outcome = smf_notify_outcome::transport_ambiguous;
  }

  return result;
}

}  // namespace oai::pcf::app::sm_policy
