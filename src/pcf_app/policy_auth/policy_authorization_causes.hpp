/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_POLICY_AUTHORIZATION_CAUSES_HPP_SEEN
#define FILE_POLICY_AUTHORIZATION_CAUSES_HPP_SEEN

namespace oai::pcf::app::policy_auth {

// TS 29.514 Table 5.7.3-1 ("Application errors") cause used on persistent
// version-CAS contention (apply_decision_with_retry's retry-exhaustion path).
// Named so a typo becomes a compile error instead of a silently-always-false
// string comparison -- the same failure mode as the
// APPLICATION_SESSION_CONTEXT_NOT_FOUND typo this mirrors.
inline constexpr const char* kCauseRequestedServiceTemporarilyNotAuthorized =
    "REQUESTED_SERVICE_TEMPORARILY_NOT_AUTHORIZED";

}  // namespace oai::pcf::app::policy_auth

#endif  // FILE_POLICY_AUTHORIZATION_CAUSES_HPP_SEEN
