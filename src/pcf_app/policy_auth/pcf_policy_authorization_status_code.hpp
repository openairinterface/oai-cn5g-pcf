/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
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
