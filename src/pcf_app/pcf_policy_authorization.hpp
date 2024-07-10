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

/*! \file pcf_policy_authorization.hpp
 \brief
 \author  Tariro Mukute
 \company University of Cape Town
 \date 2024
 \email: mkttar001@myuct.ac.za
 */

#ifndef FILE_PCF_POLICY_AUTHORIZATION_SEEN
#define FILE_PCF_POLICY_AUTHORIZATION_SEEN

#include <string>
#include <unordered_map>
#include <shared_mutex>
#include <memory>

#include "AppSessionContext.h"
#include "AppSessionContextUpdateDataPatch.h"
#include "policy_auth/pcf_pa_status_code.hpp"
#include "uint_generator.hpp"

namespace oai::pcf::app {

/**
 * @brief Service class to handle Session Management Policies
 *
 */
class pcf_pa {
 public:
  explicit pcf_pa();
  pcf_pa(pcf_pa const&) = delete;
  void operator=(pcf_pa const&) = delete;

  virtual ~pcf_pa();

  /**
   * @brief Handler for receiving service policy requests, as defined in
   * 3GPP TS 29.514 Chapter 4.2.2
   * It creates an application session context in the PCF. The result
   * returns an update context created.
   *
   * @param context input: context from the request
   * provisioning
   * @return policy_auth::status_code
   */
  policy_auth::status_code post_app_sessions_handler(
      const oai::model::pcf::AppSessionContext& context,
      std::string& problem_details);

  /**
   * @brief Handler for receiving service policy requests to update application
   * session context, as defined in 3GPP TS 29.514 Chapter 4.2.3
   *
   * @param app_session_id input: context from the request
   * @param app_session_context_update_data_patch input: context from the
   * request
   * @param context output: the applications session context that has been
   * updated provisioning
   * @return policy_auth::status_code
   */
  policy_auth::status_code mod_app_session_handler(
      const std::string& app_session_id,
      const oai::model::pcf::AppSessionContextUpdateDataPatch&
          app_session_context_update_data_patch,
      const oai::model::pcf::AppSessionContext& context,
      std::string& problem_details);
};
}  // namespace oai::pcf::app
#endif /* FILE_PCF_POLICY_AUTHORIZATION_SEEN */
