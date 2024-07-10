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

/*! \file pcscf_restoration_indication_api_handler.cpp
 \brief
 \author  Tariro Mukute
 \company University of Cape Town
 \date 2024
 \email: mkttar001@myuct.ac.za
 */

#include "pcscf_restoration_indication_api_handler.h"

namespace oai::pcf::api {

using namespace oai::model::pcf;
using namespace oai::model::common;
using namespace oai::common::sbi;
using namespace oai::pcf::app::policy_auth;

api_response pcscf_restoration_indication_api_handler::pcscf_restoration(
    const PcscfRestorationRequestData& pcscf_restoration_request_data) {
  api_response response;
  std::string content_type = "application/problem+json";

  nlohmann::json json_data;

  json_data["error"] = "API endpoint not implemented";

  response.headers.add<Pistache::Http::Header::ContentType>(
      Pistache::Http::Mime::MediaType(content_type));
  response.body        = json_data.dump();
  response.status_code = http_status_code::NOT_FOUND;
  ;
  return response;
}

}  // namespace oai::pcf::api