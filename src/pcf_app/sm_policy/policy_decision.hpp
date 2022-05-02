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

/*! \file individual_sm_association.hpp
 \brief
 \author  Stefan Spettel
 \company Openairinterface Software Allianse
 \date 2022
 \email: stefan.spettel@eurecom.fr
 */

#ifndef FILE_POLICY_DECISION_SEEN
#define FILE_POLICY_DECISION_SEEN

#include "SmPolicyContextData.h"
#include "SmPolicyDecision.h"
#include "pcf_sm_policy_control_errors.hpp"

namespace oai::pcf::app::sm_policy {

/**
 * @brief Abstract base class for policy decisions. All sub classes need to
 * implement the decide function
 *
 */
class policy_decision {
 public:
  /**
   * @brief Decides based on context on a policy. In case the return code is !=
   * CREATED, the decision reference may be undefined
   *
   * @param context input: The context of the individual sm policy association
   * @param decision output: The decision based on the context
   * @return oai::pcf::app::sm_policy::pcf_smpc_error_code   CREATED in case of
   * success
   */
  virtual oai::pcf::app::sm_policy::pcf_smpc_error_code decide(
      const oai::pcf::model::SmPolicyContextData& context,
      oai::pcf::model::SmPolicyDecision& decision) const = 0;
};
}  // namespace oai::pcf::app::sm_policy
#endif
