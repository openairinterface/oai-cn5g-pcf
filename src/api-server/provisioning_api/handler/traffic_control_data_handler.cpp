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

/*! \file traffic_control_data_handler.cpp
 \brief
 \author  Lukas Rotheneder
 \company phine.tech
 \date 2024
 \email: lukas.rotheneder@phine.tech
 */

#include "traffic_control_data_handler.h"
#include <nlohmann/json.hpp>
#include "database_wrapper_abstraction.hpp"

extern std::unique_ptr<oai::pcf::app::database_wrapper_abstraction>
    db_connector;

namespace oai::pcf::provisioning::api {

using namespace oai::pcf::api;
using namespace oai::common::sbi;

oai::pcf::api::api_response
traffic_control_data_handler::traffic_control_data_tc_id_delete(
    const std::string& tcId) {
  return handle_request_with_error_handling([&]() -> bool {
    Logger::pcf_db().info("Deleting TrafficControlData with id %s", tcId);
    return db_connector->deleteTrafficControlData(tcId);
  });
}

oai::pcf::api::api_response
traffic_control_data_handler::traffic_control_data_tc_id_put(
    const std::string& tcId,
    const oai::model::pcf::TrafficControlData& trafficControlData) {
  if (tcId != trafficControlData.getTcId()) {
    api_response response;
    response.status_code = http_status_code::BAD_REQUEST;
    response.body        = "Traffic control data and Id do not match";
    return response;
  }

  return handle_request_with_error_handling([&]() -> bool {
    nlohmann::json json_data = trafficControlData;
    Logger::pcf_db().info("Updating TrafficControlData %s", json_data.dump());
    return db_connector->updateTrafficControlData(trafficControlData);
  });
}

oai::pcf::api::api_response
traffic_control_data_handler::traffic_control_data_tc_id_get(
    const std::string& tcId) {
  return handle_request_with_error_handling_json_body([&]() -> nlohmann::json {
    nlohmann::json json_data = db_connector->getTrafficControlData(tcId);
    Logger::pcf_db().info(
        "TrafficControlData successfully retrieved: %s", json_data.dump());
    return json_data;
  });
}

oai::pcf::api::api_response
traffic_control_data_handler::traffic_control_data_post(
    const oai::model::pcf::TrafficControlData& trafficControlData) {
  return handle_request_with_error_handling([&]() -> bool {
    nlohmann::json json_data = trafficControlData;
    Logger::pcf_db().info("Creating TrafficControlData: %s", json_data.dump());
    return db_connector->createTrafficControlData(trafficControlData);
  });
}

oai::pcf::api::api_response
traffic_control_data_handler::traffic_control_data_get() {
  return handle_request_with_error_handling_json_body([&]() -> nlohmann::json {
    nlohmann::json json_data = db_connector->getAllTrafficControlData();
    Logger::pcf_db().info(
        "All TrafficControlData successfully retrieved: %s", json_data.dump());
    return json_data;
  });
}
}  // namespace oai::pcf::provisioning::api