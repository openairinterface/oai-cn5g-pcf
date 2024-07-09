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

#include "SmPolicyContextData.h"
#include "SmPolicyDecision.h"
#include "SmPolicyDeleteData.h"
#include "SmPolicyControl.h"
#include "SmPolicyUpdateContextData.h"
#include "sm_policy/pcf_pa_status_code.hpp"
#include "sm_policy/individual_sm_association.hpp"
#include "uint_generator.hpp"
#include "sm_policy/policy_storage.hpp"

namespace oai::pcf::app {

/**
 * @brief Service class to handle Session Management Policies
 *
 */
class pcf_pa {
 public:
  explicit pcf_pa(
      const std::shared_ptr<oai::pcf::app::sm_policy::policy_storage>&
          policy_storage);
  pcf_pa(pcf_pa const&) = delete;
  void operator=(pcf_pa const&) = delete;

  virtual ~pcf_pa();

  /**
   * @brief Handler for receiving create sm policy requests, as defined in
   * 3GPP TS 29.512 Chapter 4.2.2
   * The result depends on pre-configured policy rules based on supi, dnn,
   * snssai and default rules in that order
   *
   * @param context input: context from the request
   * @param decision output: policy decision based on context and local
   * provisioning
   * @return sm_policy::status_code
   */
  sm_policy::status_code post_app_sessions_handler(
      const oai::model::pcf::AppSessionContext& context,
      std::string& problem_details);

};
}  // namespace oai::pcf::app
#endif /* FILE_PCF_POLICY_AUTHORIZATION_SEEN */
