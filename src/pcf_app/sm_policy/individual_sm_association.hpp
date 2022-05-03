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

#ifndef FILE_INDIVIDUAL_SM_ASSOCIATION_SEEN
#define FILE_INDIVIDUAL_SM_ASSOCIATION_SEEN

#include "SmPolicyContextData.h"
#include "SmPolicyDecision.h"

#include <memory.h>

namespace oai::pcf::app::sm_policy {

class individual_sm_association {
 public:
  explicit individual_sm_association(
      oai::pcf::model::SmPolicyContextData context,
      oai::pcf::model::SmPolicyDecision decision, std::string id) {
    m_decision = decision;
    m_context  = context;
    m_id       = id;
  }

  virtual ~individual_sm_association() = default;

  oai::pcf::model::SmPolicyContextData get_sm_policy_context_data() const;
  oai::pcf::model::SmPolicyDecision get_sm_policy_decision() const;

  void set_sm_policy_context_data(
      oai::pcf::model::SmPolicyContextData& context);
  void set_sm_policy_decision(oai::pcf::model::SmPolicyDecision& decision);

  std::string get_id() const;

 private:
  oai::pcf::model::SmPolicyContextData m_context;
  oai::pcf::model::SmPolicyDecision m_decision;
  std::string m_id;
};
}  // namespace oai::pcf::app::sm_policy
#endif
