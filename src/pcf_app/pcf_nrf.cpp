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

/*! \file pcf_nrf.cpp
 \brief
 \author  Rohan Kharade
 \company Openairinterface Software Allianse
 \date 2021
 \email: rohan.kharade@openairinterface.org
 */

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
using namespace boost::placeholders;
using namespace std;

extern std::unique_ptr<pcf_config> pcf_cfg;

//------------------------------------------------------------------------------
pcf_nrf::pcf_nrf(pcf_event& ev) : event_sub(ev) {
  pcf_instance_id = to_string(boost::uuids::random_generator()());
  generate_nrf_api_url();
  generate_pcf_profile();

  pcf_client_inst = std::make_unique<pcf_client>();
}

//------------------------------------------------------------------------------
void pcf_nrf::generate_nrf_api_url() {
  nrf_url = "";
  nrf_url.append(conv::toString(pcf_cfg->nrf_addr.ipv4_addr))
      .append(":")
      .append(to_string(pcf_cfg->nrf_addr.port))
      .append(NNRF_NFM_BASE)
      .append(pcf_cfg->nrf_addr.api_version)
      .append(NNRF_DISC_INSTANCES)
      .append(pcf_instance_id);
}

//---------------------------------------------------------------------------------------------
void pcf_nrf::generate_pcf_profile() {
  // TODO: remove hardcoded values
  // generate UUID
  nf_instance_profile.set_nf_instance_id(pcf_instance_id);
  nf_instance_profile.set_nf_instance_name("OAI-PCF");
  nf_instance_profile.set_nf_type("PCF");
  nf_instance_profile.set_nf_status("REGISTERED");
  nf_instance_profile.set_nf_heartBeat_timer(50);
  nf_instance_profile.set_nf_priority(1);
  nf_instance_profile.set_nf_capacity(100);
  nf_instance_profile.add_nf_ipv4_addresses(pcf_cfg->sbi.addr4);

  // NF services
  nf_service_t nf_service        = {};
  nf_service.service_instance_id = SM_POLICY_API_NAME;
  nf_service.service_name        = SM_POLICY_API_NAME;
  nf_service_version_t version   = {};
  version.api_version_in_uri     = pcf_cfg->sbi_api_version;
  version.api_full_version       = "1.0.0";  // TODO: to be updated
  nf_service.versions.push_back(version);
  nf_service.scheme            = "http";
  nf_service.nf_service_status = "REGISTERED";
  // IP Endpoint
  ip_endpoint_t endpoint = {};
  // TODO: use only one IP address from cfg for now
  endpoint.ipv4_address = pcf_cfg->sbi.addr4;
  endpoint.transport    = "TCP";
  endpoint.port         = pcf_cfg->sbi.http1_port;
  if (pcf_cfg->pcf_features.use_http2) endpoint.port = pcf_cfg->sbi.http2_port;
  nf_service.ip_endpoints.push_back(endpoint);

  nf_instance_profile.add_nf_service(nf_service);

  // PCF info
  pcf_info_t pcf_info_item;
  pcf_info_item.groupid = "oai-pcf-testgroupid";
  pcf_info_item.dnn_list.emplace_back("default");
  pcf_info_item.dnn_list.emplace_back("oai");
  pcf_info_item.dnn_list.emplace_back("oai.ipv4");
  pcf_info_item.dnn_list.emplace_back("ims");
  supi_range_pcf_info_item_t supi_ranges;
  supi_ranges.supi_range.start   = "208950000000031";
  supi_ranges.supi_range.pattern = "^imsi-20895[31-131]{10}$";
  supi_ranges.supi_range.end     = "208950000000131";
  pcf_info_item.supi_ranges.push_back(supi_ranges);
  identity_range_pcf_info_item_t gpsi_ranges;
  gpsi_ranges.identity_range.start   = "752740000";
  gpsi_ranges.identity_range.pattern = "^gpsi-75274[0-9]{4}$";
  gpsi_ranges.identity_range.end     = "752749999";
  pcf_info_item.gpsi_ranges.push_back(gpsi_ranges);
  nf_instance_profile.set_pcf_info(pcf_info_item);
  // ToDo: rxDiamHost, rxDiamRealm, v2xSupportInd.
  // Display the profile
  nf_instance_profile.display();
}

//---------------------------------------------------------------------------------------------
void pcf_nrf::register_to_nrf() {
  nlohmann::json response_data = {};

  nlohmann::json body{};
  nf_instance_profile.to_json(body);

  std::string resp_body;
  std::string resp_headers;

  Logger::pcf_sbi().info("Sending NF registration request");
  http_response_codes_e res =
      pcf_client_inst->send_put(nrf_url, body.dump(), resp_body, resp_headers);

  if (res == http_response_codes_e::HTTP_RESPONSE_CODE_CREATED or
      res == http_response_codes_e::HTTP_RESPONSE_CODE_OK) {
    try {
      if (resp_body.find("REGISTERED") != 0) {
        start_event_nf_heartbeat(nrf_url);
      }
      Logger::pcf_sbi().debug("NF registration successful");
    } catch (nlohmann::json::exception& e) {
      Logger::pcf_sbi().warn("NF registration procedure failed");
    }
  } else {
    Logger::pcf_sbi().warn(
        "NF registration failed: Wrong response code: %d", res);
  }
}
//------------------------------------------------------------------------------
void pcf_nrf::start_event_nf_heartbeat(std::string& remoteURI) {
  // get current time
  uint64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count();
  const uint64_t interval = HEART_BEAT_TIMER * 1000;  // ms

  task_connection = event_sub.subscribe_task_nf_heartbeat(
      boost::bind(&pcf_nrf::trigger_nf_heartbeat_procedure, this, _1), interval,
      ms + interval);
}

//---------------------------------------------------------------------------------------------
void pcf_nrf::trigger_nf_heartbeat_procedure(uint64_t ms) {
  _unused(ms);
  oai::pcf::model::PatchItem patch_item = {};
  std::vector<oai::pcf::model::PatchItem> patch_items;
  //{"op":"replace","path":"/nfStatus", "value": "REGISTERED"}
  patch_item.setOp("replace");
  patch_item.setPath("/nfStatus");
  patch_item.setValue("REGISTERED");
  patch_items.push_back(patch_item);
  Logger::pcf_sbi().info("Sending NF heartbeat request");

  std::string body_response;
  std::string response_headers;

  nlohmann::json j;
  to_json(j, patch_item);

  http_response_codes_e res = pcf_client_inst->send_patch(
      nrf_url, j.dump(), body_response, response_headers);

  if (res == http_response_codes_e::HTTP_RESPONSE_CODE_OK or
      res == http_response_codes_e::HTTP_RESPONSE_CODE_NO_CONTENT) {
    Logger::pcf_sbi().debug("NF heartbeat request successful");
  } else {
    // TODO what should we do in this case?
    // We disconnect, but we dont trigger anything else
    Logger::pcf_sbi().warn(
        "NF heartbeat request failed. Wrong response code %d", res);
    task_connection.disconnect();
  }
}
//------------------------------------------------------------------------------
pcf_nrf::~pcf_nrf() {
  Logger::pcf_sbi().debug("Delete PCF_NRF instance...");
}
