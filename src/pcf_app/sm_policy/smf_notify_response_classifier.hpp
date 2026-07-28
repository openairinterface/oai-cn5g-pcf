/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_SMF_NOTIFY_RESPONSE_CLASSIFIER_HPP_SEEN
#define FILE_SMF_NOTIFY_RESPONSE_CLASSIFIER_HPP_SEEN

#include <cstddef>
#include <string>

#include <nlohmann/json.hpp>

#include "sm_policy/pcf_smpc_status_code.hpp"
#include "sm_policy/smf_notify_outcome.hpp"

namespace oai::pcf::app::sm_policy {

// TS 29.512 Table 5.7.3-2 ("Application errors when NF service consumer acts
// as a server to receive a notification") causes classify_smf_notify_response
// actually distinguishes. Named so a typo becomes a compile error (unknown
// identifier) instead of a silently-always-false string comparison -- the
// same failure mode as the APPLICATION_SESSION_CONTEXT_NOT_FOUND.
inline constexpr const char* kCausePccRuleEvent = "PCC_RULE_EVENT";
inline constexpr const char* kCauseUserUnknown  = "USER_UNKNOWN";

/**
 * @brief Everything a caller needs to log and act on a classified SMF
 * UpdateNotify response.
 *
 * `info`/`cause`/`detail` mirror what send_sm_policy_control_update_notify
 * logged inline before this was extracted -- populated uniformly across
 * every branch so the caller can log a consistent summary line regardless of
 * outcome. `partial_failure_entries` is only nonzero for the 200 +
 * PartialSuccessReport-array case.
 */
struct smf_notify_classification {
  status_code response              = status_code::INTERNAL_SERVER_ERROR;
  smf_notify_outcome outcome         = smf_notify_outcome::transport_ambiguous;
  std::string info;
  std::string cause;
  std::string detail;
  std::size_t partial_failure_entries = 0;
};

/**
 * @brief Classify an SMF Npcf_SMPolicyControl_UpdateNotify response into
 * (status_code, smf_notify_outcome) per TS 29.512 Table 5.7.3-2 / clause
 * 4.2.3.2.
 *
 * Pure: takes only the raw HTTP status and the already-parsed JSON body (see
 * oai::http::response::get_json(), which safely returns {} on a parse
 * failure) -- no HTTP client, no association state -- specifically so this
 * taxonomy, is directly unit-testable without mocking HTTP.
 */
[[nodiscard]] smf_notify_classification classify_smf_notify_response(
    int http_status, const nlohmann::json& body_json);

}  // namespace oai::pcf::app::sm_policy

#endif  // FILE_SMF_NOTIFY_RESPONSE_CLASSIFIER_HPP_SEEN
