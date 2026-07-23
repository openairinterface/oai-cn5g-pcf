/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_SMF_NOTIFY_CAUSES_HPP_SEEN
#define FILE_SMF_NOTIFY_CAUSES_HPP_SEEN

namespace oai::pcf::app::sm_policy {

// TS 29.512 Table 5.7.3-2 ("Application errors when NF service consumer acts
// as a server to receive a notification") causes classify_smf_notify_response
// actually distinguishes. Named so a typo becomes a compile error (unknown
// identifier) instead of a silently-always-false string comparison -- the
// same failure mode as the APPLICATION_SESSION_CONTEXT_NOT_FOUND.
inline constexpr const char* kCausePccRuleEvent = "PCC_RULE_EVENT";
inline constexpr const char* kCauseUserUnknown  = "USER_UNKNOWN";

}  // namespace oai::pcf::app::sm_policy

#endif  // FILE_SMF_NOTIFY_CAUSES_HPP_SEEN
