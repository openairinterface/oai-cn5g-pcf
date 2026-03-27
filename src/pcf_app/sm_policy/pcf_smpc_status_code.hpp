/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*! \file pcf_sm_policy_control_errors.hpp
 \brief
 \author  Stefan Spettel
 \company Openairinterface Software Allianse
 \date 2022
 \email: stefan.spettel@eurecom.fr
 */

#ifndef FILE_PCF_SMPC_STATUS_CODE_H_SEEN
#define FILE_PCF_SMPC_STATUS_CODE_H_SEEN

namespace oai::pcf::app::sm_policy {

enum class status_code {
  CREATED,
  USER_UNKOWN,
  INVALID_PARAMETERS,
  CONTEXT_DENIED,
  NOT_FOUND,
  INTERNAL_SERVER_ERROR,
  OK,
};
}  // namespace oai::pcf::app::sm_policy
#endif
