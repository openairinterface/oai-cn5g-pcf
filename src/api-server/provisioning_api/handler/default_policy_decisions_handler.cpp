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
#include <nlohmann/json.hpp>

namespace oai::pcf::provisioning::api {

using namespace oai::pcf::api;
using namespace oai::common::sbi;

api_response default_policy_decisions_handler::default_decision_get() {
  std::string content_type = "application/problem+json";
  api_response response;

  nlohmann::json json_data;
  json_data = m_pccRules;

  response.headers.add<Pistache::Http::Header::ContentType>(
      Pistache::Http::Mime::MediaType(content_type));
  response.body        = json_data.dump();
  response.status_code = http_status_code::OK;

  return response;
}

api_response default_policy_decisions_handler::default_decision_put(
    const std::vector<std::string>& pccRules) {
  api_response response;

  m_pccRules = pccRules;

  response.status_code = http_status_code::OK;

  return response;
}
}  // namespace oai::pcf::provisioning::api