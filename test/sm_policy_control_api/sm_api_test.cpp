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

/*! \file sm_api_test_fixture.cpp
 \brief
 \author  Stefan Spettel
 \company Openairinterface Software Allianse
 \date 2022
 \email: stefan.spettel@eurecom.fr
 */

#include "gtest/gtest.h"
#include "pistache/endpoint.h"
#include "pcf-api-server.h"
#include "pcf_app.hpp"
#include "pcf_config.hpp"
#include "test_common.h"
#include "test_rest_client.hpp"
#include "PduSessionType_anyOf.h"
#include "PduSessionType.h"
#include "SmPolicyContextData.h"

#include <thread>
#include <chrono>
#include <memory>
#include <nlohmann/json.hpp>

using namespace oai::pcf;

extern config::pcf_config pcf_cfg;  // defined in main

namespace oai::pcf::test {

class SMApiTest : public ::testing::Test {
 protected:
  config::pcf_config pcf_cfg;
  std::unique_ptr<PCFApiServer> pcf_api_server_1;
  std::unique_ptr<app::pcf_app> pcf_app_inst = nullptr;
  std::thread pcf_http1_manager;
  std::string base_url;

  std::unique_ptr<TestRestClient> rest_client;

  void SetUp() override {
    pcf_event ev;

    // Config
    pcf_cfg.load(pcf_config_path);

    // PCF application layer
    pcf_app_inst = std::make_unique<pcf_app>(pcf_config_path, ev);

    // hack to increment ports to prevent address already in use due to bad
    // shutdown routine
    int port = pcf_cfg.sbi.http1_port + port_inc;
    port_inc++;
    Pistache::Address addr(Pistache::Ipv4::any(), port);
    base_url = fmt::format("127.0.0.1:{}/npcf-smpolicycontrol/v1/", port);

    pcf_api_server_1 = std::make_unique<PCFApiServer>(addr, pcf_app_inst.get());

    pcf_api_server_1->init(2);
    std::thread temp_thread(&PCFApiServer::start, pcf_api_server_1.get());
    pcf_http1_manager.swap(temp_thread);

    rest_client = std::make_unique<TestRestClient>();
  }

  void TearDown() override {
    bool fail = false;
    if (pcf_api_server_1) {
      // pistache has a race condition here when called too quickly after init
      for (int i = 0; i < 5; i++) {
        try {
          pcf_api_server_1->shutdown();
        } catch (std::runtime_error e) {
          std::cout << "Pistache invalid object state, try again after 500ms"
                    << std::endl;
          if (i == 4) {
            fail = true;
            std::cout << "Could not shutdown Pistache after 2 seconds. Fail"
                      << std::endl;
          }
          std::this_thread::sleep_for(std::chrono::milliseconds(500ms));
        }
      }
      if (!fail) {
        pcf_http1_manager.join();
      }
      pcf_api_server_1.release();
    }
    pcf_app_inst.release();

    rest_client.release();

    if (fail) {
      GTEST_SKIP();
    }
  }
};

}  // namespace oai::pcf::test
