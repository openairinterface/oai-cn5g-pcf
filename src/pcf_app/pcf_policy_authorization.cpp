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

/*! \file pcf_policy_authorization.cpp
 \brief
 \author  Tariro Mukute
 \company University of Cape Town
 \date 2024
 \email: mkttar001@myuct.ac.za
 */

#include "pcf_policy_authorization.hpp"
#include "logger.hpp"
#include "pcf_config.hpp"

#include <boost/uuid/uuid_io.hpp>
#include <unordered_map>
#include <map>
#include <memory>
#include <string>

using namespace oai::pcf::app;
using namespace oai::pcf::app::policy_auth;
using namespace oai::config::pcf;
using namespace oai::model::pcf;

using namespace std;

//------------------------------------------------------------------------------
pcf_pa::pcf_pa() {}

//------------------------------------------------------------------------------
status_code pcf_pa::post_app_sessions_handler(
    const SmPolicyContextData& context, std::string& problem_details) {
  Logger::pcf_app().warn("App session, but not implemented!");

  return status_code::NOT_FOUND;
}

//------------------------------------------------------------------------------
policy_auth::status_code pcf_pa::mod_app_session_handler(
    const std::string& app_session_id,
    const oai::model::pcf::AppSessionContextUpdateDataPatch&
        app_session_context_update_data_patch,
    const oai::model::pcf::AppSessionContext& context,
    std::string& problem_details) {
  Logger::pcf_app().warn("App session, but not implemented!");

  return status_code::NOT_FOUND;
}

//------------------------------------------------------------------------------
pcf_pa::~pcf_pa() {
  Logger::pcf_app().debug("Delete PCF PA instance...");
}
