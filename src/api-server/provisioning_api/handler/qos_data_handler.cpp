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

/*! \file qos_rules_handler.cpp
 \brief
 \author  Lukas Rotheneder
 \company phine.tech
 \date 2024
 \email: lukas.rotheneder@phine.tech
 */

#include "qos_data_handler.h"
#include <nlohmann/json.hpp>

namespace oai::pcf::provisioning::api {

using namespace oai::pcf::api;
using namespace oai::common::sbi;

oai::pcf::api::api_response qos_data_handler::qos_data_qos_id_delete(
    const std::string& qosId) {
  api_response response;
  response.status_code = http_status_code::NOT_IMPLEMENTED;
  return response;
}

oai::pcf::api::api_response qos_data_handler::qos_data_qos_id_get(
    const std::string& qosId) {
  api_response response;
  response.status_code = http_status_code::NOT_IMPLEMENTED;
  return response;
}

oai::pcf::api::api_response qos_data_handler::qos_data_qos_id_put(
    const std::string& qosId, const oai::model::pcf::QosData& qosData) {
  api_response response;
  response.status_code = http_status_code::NOT_IMPLEMENTED;
  return response;
}

oai::pcf::api::api_response qos_data_handler::qos_data_post(
    const oai::model::pcf::QosData& qosData) {
  api_response response;
  response.status_code = http_status_code::NOT_IMPLEMENTED;
  return response;
}

oai::pcf::api::api_response qos_data_handler::qos_data_get() {
  api_response response;
  response.status_code = http_status_code::NOT_IMPLEMENTED;
  return response;
}
}  // namespace oai::pcf::provisioning::api