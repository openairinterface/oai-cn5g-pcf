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

/*! \file pcscf_restoration_indication_api_handler.h
 \brief
 \author  Tariro Mukute
 \company University of Cape Town
 \date 2024
 \email: mkttar001@myuct.ac.za
 */

#pragma once

#include "PcscfRestorationRequestData.h"
#include "api_response.h"
#include "pcf_policy_authorization.hpp"
#include "SmPolicyDeleteData.h"
// #include "SmPolicyUpdateContextData.h"

namespace oai::pcf::api {

class pcscf_restoration_indication_api_handler {
 public:
  explicit pcscf_restoration_indication_api_handler(
      const std::shared_ptr<oai::pcf::app::pcf_policy_authorization>&
          pcf_policy_authorization) {
    m_pa_service = pcf_policy_authorization;
  }
  /**
   * Indicates P-CSCF restoration
   * @param pcscf_restoration_request_data
   * @return api_response
   */
  api_response pcscf_restoration(
      const oai::model::pcf::PcscfRestorationRequestData&
          pcscf_restoration_request_data);

 private:
  std::shared_ptr<oai::pcf::app::pcf_policy_authorization> m_pa_service;
};

}  // namespace oai::pcf::api