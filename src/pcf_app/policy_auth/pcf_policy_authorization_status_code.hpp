/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_PCF_PA_STATUS_CODE_H_SEEN
#define FILE_PCF_PA_STATUS_CODE_H_SEEN

#include <optional>
#include <string>

namespace oai::pcf::app::policy_auth {

enum class status_code {
  CREATED,
  USER_UNKOWN,
  INVALID_PARAMETERS,
  CONTEXT_DENIED,
  NOT_FOUND,
  PDU_SESSION_NOT_AVAILABLE,
  REQUESTED_SERVICE_NOT_AUTHORIZED,
  OK,
  BAD_REQUEST,
  INTERNAL_SERVER_ERROR,
  FORBIDDEN
};

struct handler_result {
  std::optional<status_code> status;
  std::optional<std::string> problem_details;
};

// TS 29.514 Table 5.7.3-1 ("Application errors") cause used on persistent
// version-CAS contention (decision_applier::apply's retry-exhaustion path).
// Named so a typo becomes a compile error instead of a silently-always-false
// string comparison -- the same failure mode as the
// APPLICATION_SESSION_CONTEXT_NOT_FOUND typo this mirrors.
inline constexpr const char* kCauseRequestedServiceTemporarilyNotAuthorized =
    "REQUESTED_SERVICE_TEMPORARILY_NOT_AUTHORIZED";

}  // namespace oai::pcf::app::policy_auth
#endif
