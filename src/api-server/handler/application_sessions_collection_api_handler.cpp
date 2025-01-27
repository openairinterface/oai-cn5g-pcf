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

/*! \file application_sessions_collection_api_handler.cpp
 \brief
 \author  Tariro Mukute
 \company University of Cape Town
 \date 2024
 \email: mkttar001@myuct.ac.za
 */

#include "application_sessions_collection_api_handler.h"
#include "ProblemDetails.h"
#include "logger.hpp"
#include "api_defs.h"

namespace oai::pcf::api {

using namespace oai::model::pcf;
using namespace oai::model::common;
using namespace oai::common::sbi;
using namespace oai::pcf::app::policy_auth;

api_response application_sessions_collection_api_handler::post_app_sessions(
    const AppSessionContext& app_session_context) {
  api_response response;

  ProblemDetails problem_details;
  std::string problem_description;
  std::string content_type = "application/problem+json";
  std::string location;
  std::string app_session_id;
  nlohmann::json json_data;
  uint16_t http_code;

  status_code res = m_pa_service->post_app_sessions_handler(
      app_session_context, app_session_id, problem_description);

  problem_details.setDetail(problem_description);

  switch (res) {
    case status_code::CREATED:
      content_type = "application/json";
      location  = m_address + app_sessions::get_route() + "/" + app_session_id;
      http_code = http_status_code::OK;
      break;
    default:
      problem_details.setCause("INTERNAL_ERROR");
      http_code = http_status_code::INTERNAL_SERVER_ERROR;
  }

  if (res == status_code::OK) {
    to_json(json_data, app_session_context);
  } else {
    to_json(json_data, problem_details);
  }

  // TODO: set Location header
  Logger::pcf_app().info(fmt::format("Location: {}", location));

  response.headers.add<Pistache::Http::Header::ContentType>(
      Pistache::Http::Mime::MediaType(content_type));
  response.body        = json_data.dump();
  response.status_code = http_code;
  return response;
}

}  // namespace oai::pcf::api