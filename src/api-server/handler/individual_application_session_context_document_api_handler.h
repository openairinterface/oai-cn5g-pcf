
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

/*! \file individual_application_session_context_document_api_handler.h
 \brief
 \author  Tariro Mukute
 \company University of Cape Town
 \date 2024
 \email: mkttar001@myuct.ac.za
 */

#pragma once

#include "AppSessionContextUpdateDataPatch.h"
#include "EventsSubscReqData.h"
#include "api_response.h"
#include "pcf_policy_authorization.hpp"

namespace oai::pcf::api {

class individual_application_session_context_document_api_handler {
 public:
  explicit individual_application_session_context_document_api_handler(
      const std::shared_ptr<oai::pcf::app::pcf_policy_authorization>&
          pcf_policy_authorization) {
    m_pa_service = pcf_policy_authorization;
  }
  /**
   * Delete Individual Application Session Context based on ID
   * @param app_session_id
   * @param events_subsc_req_data
   * @return api_response
   */
  api_response delete_app_session(
      const std::string& app_session_id,
      const oai::model::pcf::EventsSubscReqData& events_subsc_req_data);

  /**
   * Delete Individual Application Session Context based on ID
   * @param app_session_id
   * @param events_subsc_req_data
   * @return api_response
   */
  api_response get_app_session(const std::string& app_session_id);

  /**
   * Delete Individual Application Session Context based on ID
   * @param app_session_id
   * @param app_session_context_update_data_patch
   * @return api_response
   */
  api_response mod_app_session(
      const std::string& app_session_id,
      const oai::model::pcf::AppSessionContextUpdateDataPatch&
          app_session_context_update_data_patch);

 private:
  std::shared_ptr<oai::pcf::app::pcf_policy_authorization> m_pa_service;
};

}  // namespace oai::pcf::api