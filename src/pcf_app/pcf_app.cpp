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

/*! \file pcf_app.cpp
 \brief
 \author  Rohan Kharade
 \company Openairinterface Software Allianse
 \date 2021
 \email: rohan.kharade@openairinterface.org
 */

#include "pcf_app.hpp"
#include "pcf_nrf.hpp"
#include "conversions.hpp"
#include "logger.hpp"
#include "pcf.h"
#include "pcf_config.hpp"
#include "pcf_client.hpp"
#include "Snssai.h"

#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <stdexcept>

using namespace oai::pcf::app;
using namespace oai::pcf::config;
using namespace oai::pcf::model;

using namespace std;

extern pcf_app* pcf_app_inst;
extern pcf_config pcf_cfg;
pcf_nrf* pcf_nrf_inst;

//------------------------------------------------------------------------------
pcf_app::pcf_app(const std::string& config_file, pcf_event& ev)
    : event_sub(ev) {
  Logger::pcf_app().startup("Starting...");
  // Register to NRF
  if (pcf_cfg.pcf_features.register_nrf) {
    try {
      pcf_nrf_inst = new pcf_nrf(ev);
      pcf_nrf_inst->register_to_nrf();
      Logger::pcf_app().info("NRF TASK Created ");
    } catch (std::exception& e) {
      Logger::pcf_app().error("Cannot create NRF TASK: %s", e.what());
      throw;
    }
  }

  pcf_smpc_service = std::make_shared<pcf_smpc>();
}

//------------------------------------------------------------------------------
pcf_app::~pcf_app() {
  Logger::pcf_app().debug("Delete PCF_APP instance...");
  pcf_smpc_service = nullptr;
}

std::shared_ptr<pcf_smpc> pcf_app::get_pcf_smpc_service() {
  return pcf_smpc_service;
}