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

/*! \file dnn_policy_decisions_handler.h
 \brief
 \author  Lukas Rotheneder
 \company phine.tech
 \date 2024
 \email: lukas.rotheneder@phine.tech
 */

#pragma once

#include <string>
#include <vector>
#include "api_response.h"
#include "DnnPolicyDecision.h"
#include "handler_base.hpp"

namespace oai::pcf::provisioning::api {

class dnn_policy_decisions_handler : public handler_base {
 public:
  /**
   * delete dnn policy decision for dnn
   * @param dnn
   * @return api_response
   */
  oai::pcf::api::api_response dnn_policy_decision_dnn_delete(
      const std::string& dnn);

  /**
   * get policy decision for dnn
   * @param dnn
   * @return api_response
   */
  oai::pcf::api::api_response dnn_policy_decision_dnn_get(
      const std::string& dnn);

  /**
   * update policy decision for dnn
   * @param dnn
   * @param dnnPolicyDecision
   * @return api_response
   */
  oai::pcf::api::api_response dnn_policy_decision_dnn_put(
      const std::string& dnn,
      const oai::pcf::provisioning::model::DnnPolicyDecision&
          dnnPolicyDecision);

  /**
   * create new dnn policy decision
   * @param dnnPolicyDecision
   * @return api_response
   */
  oai::pcf::api::api_response dnn_policy_decision_post(
      const oai::pcf::provisioning::model::DnnPolicyDecision&
          dnnPolicyDecision);

  /**
   * get all policy decisions
   * @return api_response
   */
  oai::pcf::api::api_response dnn_policy_decisions_get();
};
}  // namespace oai::pcf::provisioning::api
