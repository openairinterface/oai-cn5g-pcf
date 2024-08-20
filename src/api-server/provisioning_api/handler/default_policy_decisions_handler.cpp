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

/*! \file default_policy_decisions_handler.cpp
 \brief
 \author  Lukas Rotheneder
 \company phine.tech
 \date 2024
 \email: lukas.rotheneder@phine.tech
 */

#include "default_policy_decisions_handler.h"
#include "database_wrapper_abstraction.hpp"
#include <nlohmann/json.hpp>

extern std::unique_ptr<oai::pcf::app::database_wrapper_abstraction>
    db_connector;

namespace oai::pcf::provisioning::api {

using namespace oai::pcf::api;
using namespace oai::common::sbi;

api_response default_policy_decisions_handler::default_decision_get() {
  return handle_request_with_error_handling_json_body([&]() -> nlohmann::json {
    nlohmann::json json_data = db_connector->getDefaultPolicyDecision();
    Logger::pcf_db().info(
        "Default policy rules successfully retrieved: %s", json_data.dump());
    return json_data;
  });
}

api_response default_policy_decisions_handler::default_decision_put(
    const std::vector<std::string>& pccRules) {
  nlohmann::json json_data = pccRules;
  return handle_request_with_error_handling([&]() -> bool {
    Logger::pcf_db().info("Set default policy rules: %s", json_data.dump());
    return db_connector->setDefaultPolicyDecision(pccRules);
  });
}

}  // namespace oai::pcf::provisioning::api