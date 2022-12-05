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
using namespace oai::model::common;
using namespace boost::placeholders;
using namespace std;

extern pcf_nrf* pcf_nrf_inst;
extern std::unique_ptr<pcf_config> pcf_cfg;
pcf_client* pcf_client_instance = nullptr;

//------------------------------------------------------------------------------
pcf_nrf::pcf_nrf(pcf_event& ev) : event_sub(ev) {}

//---------------------------------------------------------------------------------------------
void pcf_nrf::get_pcf_api_root(std::string& api_root) {
  api_root = std::string(
                 inet_ntoa(*((struct in_addr*) &pcf_cfg->nrf_addr.ipv4_addr))) +
             ":" + std::to_string(pcf_cfg->nrf_addr.port) + NNRF_NFM_BASE +
             pcf_cfg->nrf_addr.api_version;
}

//---------------------------------------------------------------------------------------------
void pcf_nrf::generate_pcf_profile(
    pcf_profile& pcf_nf_profile, std::string& pcf_instance_id) {
  // TODO: remove hardcoded values
  // generate UUID
  pcf_nf_profile.set_nf_instance_id(pcf_instance_id);
  pcf_nf_profile.set_nf_instance_name("OAI-PCF");
  pcf_nf_profile.set_nf_type("PCF");
  pcf_nf_profile.set_nf_status("REGISTERED");
  pcf_nf_profile.set_nf_heartBeat_timer(50);
  pcf_nf_profile.set_nf_priority(1);
  pcf_nf_profile.set_nf_capacity(100);
  pcf_nf_profile.add_nf_ipv4_addresses(pcf_cfg->sbi.addr4);

  // NF services
  nf_service_t nf_service        = {};
  nf_service.service_instance_id = "npcf-smpolicycontrol";
  nf_service.service_name        = "npcf-smpolicycontrol";
  nf_service_version_t version   = {};
  version.api_version_in_uri     = "v1";
  version.api_full_version       = "1.0.0";  // TODO: to be updated
  nf_service.versions.push_back(version);
  nf_service.scheme            = "http";
  nf_service.nf_service_status = "REGISTERED";
  // IP Endpoint
  ip_endpoint_t endpoint = {};
  std::vector<struct in_addr> addrs;
  pcf_nf_profile.get_nf_ipv4_addresses(addrs);
  endpoint.ipv4_address = addrs[0];  // TODO: use first IP ADDR for now
  endpoint.transport    = "TCP";
  endpoint.port         = pcf_cfg->sbi.http1_port;
  if (pcf_cfg->pcf_features.use_http2) endpoint.port = pcf_cfg->sbi.http2_port;
  nf_service.ip_endpoints.push_back(endpoint);

  pcf_nf_profile.add_nf_service(nf_service);

  // PCF info
  pcf_info_t pcf_info_item;
  pcf_info_item.groupid = "oai-pcf-testgroupid";
  pcf_info_item.dnn_list.push_back("default");
  pcf_info_item.dnn_list.push_back("oai");
  pcf_info_item.dnn_list.push_back("oai.ipv4");
  pcf_info_item.dnn_list.push_back("ims");
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
  pcf_nf_profile.set_pcf_info(pcf_info_item);
  // ToDo: rxDiamHost, rxDiamRealm, v2xSupportInd.
  // Display the profile
  pcf_nf_profile.display();
}

//---------------------------------------------------------------------------------------------
void pcf_nrf::register_to_nrf() {
  // Generate UUID
  pcf_instance_id              = to_string(boost::uuids::random_generator()());
  nlohmann::json response_data = {};

  // Generate NF Profile
  pcf_profile pcf_nf_profile;
  generate_pcf_profile(pcf_nf_profile, pcf_instance_id);

  // Send NF registeration request
  std::string pcf_api_root = {};
  std::string response     = {};
  std::string method       = {"PUT"};
  get_pcf_api_root(pcf_api_root);
  std::string remoteUri = pcf_api_root + NNRF_DISC_INSTANCES + pcf_instance_id;
  nlohmann::json json_data = {};
  pcf_nf_profile.to_json(json_data);

  Logger::pcf_app().info("Sending NF registeration request");
  pcf_client_instance->curl_http_client(
      remoteUri, method, response, json_data.dump().c_str());

  try {
    response_data = nlohmann::json::parse(response);
    if (response.find("REGISTERED") != 0) {
      start_event_nf_heartbeat(remoteUri);
    }
  } catch (nlohmann::json::exception& e) {
    Logger::pcf_app().info("NF registeration procedure failed");
  }
}
//------------------------------------------------------------------------------
void pcf_nrf::start_event_nf_heartbeat(std::string& remoteURI) {
  // get current time
  uint64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count();
  struct itimerspec its;
  its.it_value.tv_sec  = HEART_BEAT_TIMER;  // seconds
  its.it_value.tv_nsec = 0;                 // 100 * 1000 * 1000; //100ms
  const uint64_t interval =
      its.it_value.tv_sec * 1000 +
      its.it_value.tv_nsec / 1000000;  // convert sec, nsec to msec

  task_connection = event_sub.subscribe_task_nf_heartbeat(
      boost::bind(&pcf_nrf::trigger_nf_heartbeat_procedure, this, _1), interval,
      ms + interval);
}

//---------------------------------------------------------------------------------------------
void pcf_nrf::trigger_nf_heartbeat_procedure(uint64_t ms) {
  _unused(ms);
  PatchItem patch_item = {};
  std::vector<PatchItem> patch_items;
  PatchOperation op;
  op.setEnumValue(PatchOperation_anyOf::ePatchOperation_anyOf::REPLACE);
  patch_item.setOp(op);
  patch_item.setPath("/nfStatus");
  patch_item.setValue("REGISTERED");
  patch_items.push_back(patch_item);
  Logger::pcf_app().info("Sending NF heartbeat request");

  std::string response     = {};
  std::string method       = {"PATCH"};
  nlohmann::json json_data = nlohmann::json::array();
  for (auto i : patch_items) {
    nlohmann::json item = {};
    to_json(item, i);
    json_data.push_back(item);
  }

  std::string pcf_api_root = {};
  get_pcf_api_root(pcf_api_root);
  std::string remoteUri = pcf_api_root + NNRF_DISC_INSTANCES + pcf_instance_id;
  pcf_client_instance->curl_http_client(
      remoteUri, method, response, json_data.dump().c_str());
  if (!response.empty()) task_connection.disconnect();
}
//------------------------------------------------------------------------------
pcf_nrf::~pcf_nrf() {
  Logger::pcf_app().debug("Delete PCF_NRF instance...");
}
