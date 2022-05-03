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

/*! \file pcf_sm_policy_control.hpp
 \brief
 \author  Rohan Kharade
 \company Openairinterface Software Allianse
 \date 2021
 \email: rohan.kharade@openairinterface.org
 */

#ifndef FILE_PCF_SM_POLICY_CONTROL_SEEN
#define FILE_PCF_SM_POLICY_CONTROL_SEEN

#include <string>
#include <unordered_map>
#include <shared_mutex>
#include <memory>

#include "SmPolicyContextData.h"
#include "SmPolicyDecision.h"
#include "sm_policy/pcf_smpc_status_code.hpp"
#include "sm_policy/individual_sm_association.hpp"
#include "sm_policy/policy_decision.hpp"
#include "sm_policy/slice_policy_decision.hpp"
#include "sm_policy/supi_policy_decision.hpp"
#include "sm_policy/dnn_policy_decision.hpp"
#include "sm_policy/snssai_hasher.hpp"
#include "uint_generator.hpp"

namespace oai::pcf::app {

/**
 * @brief Service class to handle Session Management Policies
 *
 */
class pcf_smpc {
 public:
  explicit pcf_smpc();
  pcf_smpc(pcf_smpc const&) = delete;
  void operator=(pcf_smpc const&) = delete;

  virtual ~pcf_smpc();

  /**
   * @brief Handler for receiving create sm policy requests
   *
   * @param context input: context from the request
   * @param decision output: policy decision based on context and local
   * provisioning
   * @return sm_policy::status_code
   */
  sm_policy::status_code create_sm_policy_handler(
      const oai::pcf::model::SmPolicyContextData& context,
      oai::pcf::model::SmPolicyDecision& decision, std::string& association_id,
      std::string& problem_details);

 private:
  /**
   * @brief Finds a policy based on the existing supi, dnn, slice and default
   * policies in that order.
   * PRECONDITION: Lock all mutexes for the maps
   *
   * @param context  The policy context containing supi, dnn and snssai
   * @param chosen_decision pointer to the object implementing the chosen
   * decision base class
   * @return true if policy found
   * @return false if no policy found
   */
  bool find_policy(
      const oai::pcf::model::SmPolicyContextData& context,
      oai::pcf::app::sm_policy::policy_decision** chosen_decision);

  util::uint_generator<uint32_t> m_association_id_generator;

  std::unordered_map<
      std::string, oai::pcf::app::sm_policy::individual_sm_association>
      m_associations;
  std::unordered_map<
      oai::pcf::model::Snssai, oai::pcf::app::sm_policy::slice_policy_decision,
      oai::pcf::app::sm_policy::snssai_hasher>
      m_slice_policy_decisions;

  std::unordered_map<std::string, oai::pcf::app::sm_policy::dnn_policy_decision>
      m_dnn_policy_decisions;

  std::unordered_map<
      std::string, oai::pcf::app::sm_policy::supi_policy_decision>
      m_supi_policy_decisions;

  std::unique_ptr<oai::pcf::app::sm_policy::policy_decision> default_decision;

  mutable std::shared_mutex m_associations_mutex;
  mutable std::shared_mutex m_slice_policy_decisions_mutex;
  mutable std::shared_mutex m_dnn_policy_decisions_mutex;
  mutable std::shared_mutex m_supi_policy_decisions_mutex;
};
}  // namespace oai::pcf::app
#endif /* FILE_PCF_SM_POLICY_CONTROL_SEEN */
