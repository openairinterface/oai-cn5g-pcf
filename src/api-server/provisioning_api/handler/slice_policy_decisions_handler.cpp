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

/*! \file slice_policy_decisions_handler.cpp
 \brief
 \author  Lukas Rotheneder
 \company phine.tech
 \date 2024
 \email: lukas.rotheneder@phine.tech
 */

#include "slice_policy_decisions_handler.h"
#include "database_wrapper_abstraction.hpp"
#include <nlohmann/json.hpp>

extern std::unique_ptr<oai::pcf::app::database_wrapper_abstraction>
    db_connector;

namespace oai::pcf::provisioning::api {

using namespace oai::pcf::api;
using namespace oai::common::sbi;
using namespace oai::pcf::provisioning::model;
using namespace oai::model::common;

oai::pcf::api::api_response
slice_policy_decisions_handler::slice_policy_decision_get(
    const std::optional<int32_t>& sst, const std::optional<std::string>& sd) {
  if (sst.has_value()) {
    Snssai slice(sst.value());
    if (sd.has_value()) {
      slice.setSd(sd.value());
    }
    return handle_request_with_error_handling_json_body(
        [&]() -> nlohmann::json {
          nlohmann::json json_data =
              db_connector->getSlicePolicyDecision(slice);
          Logger::pcf_db().info(
              "Slice policy decision successfully retrieved: %s",
              json_data.dump());
          return json_data;
        });
  } else {
    api_response response;
    response.status_code = http_status_code::BAD_REQUEST;
    response.body        = "SST is mandatory";
    return response;
  }
}

oai::pcf::api::api_response
slice_policy_decisions_handler::slice_policy_decision_delete(
    const std::optional<int32_t>& sst, const std::optional<std::string>& sd) {
  if (sst.has_value()) {
    Snssai slice(sst.value());
    if (sd.has_value()) {
      slice.setSd(sd.value());
    }
    return handle_request_with_error_handling([&]() -> bool {
      nlohmann::json json_data = slice;
      Logger::pcf_db().info(
          "Deleting slice policy decision with slice %s", json_data.dump());
      return db_connector->deleteSlicePolicyDecision(slice);
      ;
    });
  } else {
    api_response response;
    response.status_code = http_status_code::BAD_REQUEST;
    response.body        = "SST is mandatory";
    return response;
  }
}

oai::pcf::api::api_response
slice_policy_decisions_handler::slice_policy_decision_put(
    const std::optional<int32_t>& sst, const std::optional<std::string>& sd,
    const oai::pcf::provisioning::model::SlicePolicyDecision&
        slicePolicyDecision) {
  if (sst.has_value()) {
    Snssai slice(sst.value());
    if (sd.has_value()) {
      slice.setSd(sd.value());
    }
    if (slice != slicePolicyDecision.getSnssai()) {
      api_response response;
      response.status_code = http_status_code::BAD_REQUEST;
      response.body        = "Decision and slice do not match";
      return response;
    }
    return handle_request_with_error_handling([&]() -> bool {
      nlohmann::json json_data = slicePolicyDecision;
      Logger::pcf_db().info(
          "Updating slice policy decision: %s", json_data.dump());
      return db_connector->updateSlicePolicyDecision(slicePolicyDecision);
    });
  } else {
    api_response response;
    response.status_code = http_status_code::BAD_REQUEST;
    response.body        = "SST is mandatory";
    return response;
  }
}

oai::pcf::api::api_response
slice_policy_decisions_handler::slice_policy_decision_post(
    const oai::pcf::provisioning::model::SlicePolicyDecision&
        slicePolicyDecision) {
  return handle_request_with_error_handling([&]() -> bool {
    nlohmann::json json_data = slicePolicyDecision;
    Logger::pcf_db().info(
        "Creating slice policy decision: %s", json_data.dump());
    return db_connector->createSlicePolicyDecision(slicePolicyDecision);
  });
}

oai::pcf::api::api_response
slice_policy_decisions_handler::slice_policy_decisions_get() {
  return handle_request_with_error_handling_json_body([&]() -> nlohmann::json {
    nlohmann::json json_data = db_connector->getAllSlicePolicyDecisions();
    Logger::pcf_db().info(
        "All slice policy decisions successfully retrieved: %s",
        json_data.dump());
    return json_data;
  });
}
}  // namespace oai::pcf::provisioning::api