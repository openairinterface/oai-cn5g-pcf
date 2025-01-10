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

/*! \file pcc_rules_handler.cpp
 \brief
 \author  Lukas Rotheneder
 \company phine.tech
 \date 2024
 \email: lukas.rotheneder@phine.tech
 */

#include "pcc_rules_handler.h"
#include <nlohmann/json.hpp>
#include "database_wrapper_abstraction.hpp"

extern std::unique_ptr<oai::pcf::app::database_wrapper_abstraction>
    db_connector;

namespace oai::pcf::provisioning::api {

using namespace oai::pcf::api;
using namespace oai::common::sbi;

oai::pcf::api::api_response pcc_rules_handler::pcc_rule_pcc_rule_id_delete(
    const std::string& pccRuleId) {
  return handle_request_with_error_handling([&]() -> bool {
    Logger::pcf_db().info("Deleting PccRule with id %s", pccRuleId);
    return db_connector->deletePccRule(pccRuleId);
  });
}

oai::pcf::api::api_response pcc_rules_handler::pcc_rule_pcc_rule_id_get(
    const std::string& pccRuleId) {
  return handle_request_with_error_handling_json_body([&]() -> nlohmann::json {
    nlohmann::json json_data = db_connector->getPccRule(pccRuleId);
    Logger::pcf_db().info(
        "PccRule successfully retrieved: %s", json_data.dump());
    return json_data;
  });
}

oai::pcf::api::api_response pcc_rules_handler::pcc_rule_pcc_rule_id_put(
    const std::string& pccRuleId, const oai::model::pcf::PccRule& pccRule) {
  if (pccRuleId != pccRule.getPccRuleId()) {
    api_response response;
    response.status_code = http_status_code::BAD_REQUEST;
    response.body        = "PCC Rule and Id do not match";
    return response;
  }

  return handle_request_with_error_handling([&]() -> bool {
    nlohmann::json json_data = pccRule;
    Logger::pcf_db().info("Updating PccRule %s", json_data.dump());
    return db_connector->updatePccRule(pccRule);
  });
}

oai::pcf::api::api_response pcc_rules_handler::pcc_rule_post(
    const oai::model::pcf::PccRule& pccRule) {
  return handle_request_with_error_handling([&]() -> bool {
    nlohmann::json json_data = pccRule;
    Logger::pcf_db().info("Creating PccRule: %s", json_data.dump());
    return db_connector->createPccRule(pccRule);
  });
}

oai::pcf::api::api_response pcc_rules_handler::pcc_rules_get() {
  return handle_request_with_error_handling_json_body([&]() -> nlohmann::json {
    nlohmann::json json_data = db_connector->getAllPccRules();
    Logger::pcf_db().info(
        "All PccRules successfully retrieved: %s", json_data.dump());
    return json_data;
  });
}
}  // namespace oai::pcf::provisioning::api