/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*! \file pcf_policy_authorization_status_code.hpp
 \brief
 \author  Tariro Mukute
 \company University of Cape Town
 \date 2024
 \email: mkttar001@myuct.ac.za
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

}  // namespace oai::pcf::app::policy_auth
#endif
