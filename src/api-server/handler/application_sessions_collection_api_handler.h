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

/*! \file application_sessions_collection_api_handler.h
 \brief
 \author  Tariro Mukute
 \company University of Cape Town
 \date 2024
 \email: mkttar001@myuct.ac.za
 */

#pragma once

#include "AppSessionContext.h"
#include "Ambr.h"
#include "api_response.h"
#include "pcf_policy_authorization.hpp"

namespace oai::pcf::api {

class application_sessions_collection_api_handler {
 public:
  explicit application_sessions_collection_api_handler(
      const std::shared_ptr<oai::pcf::app::pcf_policy_authorization>&
          pcf_policy_authorization,
      const std::string& address) {
    m_pa_service = pcf_policy_authorization;
    m_address    = address;
  }
  /**
   * Creates a new Individual Application Session Context resource
   * @param app_session_context
   * @return api_response
   */
  api_response post_app_sessions(
      const oai::model::pcf::AppSessionContext& app_session_context);

 private:
  std::shared_ptr<oai::pcf::app::pcf_policy_authorization> m_pa_service;
  std::string m_address;
};

}  // namespace oai::pcf::api