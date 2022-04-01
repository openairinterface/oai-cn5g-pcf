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

#include "common_root_types.h"
#include <boost/atomic.hpp>
#include <string>

#include "3gpp_29.500.h"
#include "pcf.h"
#include "3gpp_29.510.h"
#include "PatchItem.h"
#include "SmPolicyContextData.h"
#include "SmPolicyDecision.h"
#include "ProblemDetails.h"
#include "SmPolicyControl.h"
#include "SmPolicyDecision.h"
#include "SmPolicyDeleteData.h"
#include "SmPolicyUpdateContextData.h"

namespace oai::pcf::app {

class pcf_smpc {
public:
  explicit pcf_smpc();
  pcf_smpc(pcf_smpc const&) = delete;
  void operator=(pcf_smpc const&) = delete;

  virtual ~pcf_smpc();

  /*
   * Start event nf heartbeat procedure
   * @param [void]
   * @return void
   */
  void create_sm_policy_handler();

    // void delete_sm_policy(const std::string &smPolicyId, const SmPolicyDeleteData &smPolicyDeleteData);
    void get_sm_policy(const std::string &smPolicyId);
    //void update_sm_policy(const std::string &smPolicyId, const SmPolicyUpdateContextData &smPolicyUpdateContextData);

  private:

}; 
}// namespace pcf
#endif /* FILE_PCF_SM_POLICY_CONTROL_SEEN */

