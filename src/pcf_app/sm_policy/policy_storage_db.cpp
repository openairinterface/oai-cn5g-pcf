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

/*! \file policy_storage_db.cpp
 \brief
 \author  Lukas Rotheneder
 \company phine.tech
 \date 2024
 \email: lukas.rotheneder@phine.tech
 */

#include "policy_storage_db.hpp"
#include "sm_policy/database/database_wrapper.hpp"
#include <string>
#include <sstream>
#include "SupiPolicyDecision.h"
#include "supi_policy_decision.hpp"
#include "dnn_policy_decision.hpp"
#include "slice_policy_decision.hpp"

using namespace oai::pcf::app::sm_policy;
using namespace oai::model::pcf;
using namespace oai::model::common;
using namespace oai::pcf::provisioning::model;
using namespace oai::pcf::app;

extern std::unique_ptr<database_wrapper_abstraction> db_connector;

std::shared_ptr<policy_decision> policy_storage_db::find_policy(
    const SmPolicyContextData& context) {
  std::string msg_base = "SM Policy request from SUPI:";
  std::string supi     = context.getSupi();

  try {
    // First, check based on SUPI, then DNN, then Slice, then global default
    // rule.
    try {
      SupiPolicyDecision supiDecision =
          db_connector->getSupiPolicyDecision(supi);

      Logger::pcf_app().debug("%s Decide based on SUPI", msg_base);
      SmPolicyDecision smPolicyDecision =
          db_connector->getSmPolicyDecision(supiDecision.getPccRuleIds());
      return std::make_shared<supi_policy_decision>(supi, smPolicyDecision);
    } catch (const NotFoundException& e) {
      Logger::pcf_app().debug(
          "%s %s - Did not find SUPI policy", msg_base, supi);
    }

    try {
      std::string dnn               = context.getDnn();
      DnnPolicyDecision dnnDecision = db_connector->getDnnPolicyDecision(dnn);

      Logger::pcf_app().debug("%s Decide based on DNN", msg_base);
      SmPolicyDecision smPolicyDecision =
          db_connector->getSmPolicyDecision(dnnDecision.getPccRuleIds());
      return std::make_shared<dnn_policy_decision>(dnn, smPolicyDecision);
    } catch (const NotFoundException& e) {
      Logger::pcf_app().debug(
          "%s %s - Did not find DNN policy", msg_base, supi);
    }

    try {
      Snssai slice = context.getSliceInfo();
      SlicePolicyDecision sliceDecision =
          db_connector->getSlicePolicyDecision(context.getSliceInfo());

      Logger::pcf_app().debug("%s Decide based on slice", msg_base);
      SmPolicyDecision smPolicyDecision =
          db_connector->getSmPolicyDecision(sliceDecision.getPccRuleIds());
      return std::make_shared<slice_policy_decision>(slice, smPolicyDecision);

    } catch (const NotFoundException& e) {
      Logger::pcf_app().debug(
          "%s %s - Did not find slice policy", msg_base, supi);
    }

    try {
      std::vector<std::string> defaultPccRules =
          db_connector->getDefaultPolicyDecision();

      Logger::pcf_app().debug("%s Decide based on default policy", msg_base);
      SmPolicyDecision smPolicyDecision =
          db_connector->getSmPolicyDecision(defaultPccRules);
      return std::make_shared<policy_decision>(smPolicyDecision);
    } catch (const NotFoundException& e) {
      Logger::pcf_app().debug(
          "%s %s - Did not find default policy", msg_base, supi);
      return nullptr;
    }
  } catch (const std::exception& e) {
    Logger::pcf_app().error(
        "%s %s - Error during requesting decisions from DB: %e", msg_base, supi,
        e.what());
    return nullptr;
  }
}

void policy_storage_db::subscribe_to_decision_change(
    std::function<void(std::shared_ptr<policy_decision>&)> callback) {
  // TODO
}
