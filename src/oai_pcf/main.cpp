/*
 * Copyright (c) 2019 EURECOM
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "common_defs.h"
#include "logger.hpp"
#include "pcf-api-server.hpp"
#include "pcf-http2-server.hpp"
#include "pcf_app.hpp"
#include "pcf_config.hpp"
#include "options.hpp"
#include "pid_file.hpp"
#include "pistache/http.h"

#include <algorithm>
#include <iostream>
#include <csignal>
#include <thread>

using namespace util;
using namespace std;
using namespace oai::pcf::app;
using namespace oai::pcf::config;

std::unique_ptr<pcf_app> pcf_app_inst;
// TODO Stefan: I am not happy with these global variables
// We could make a singleton getInstance in config
// or we handle everything in smf_app init and have a reference to config there
std::unique_ptr<pcf_config> pcf_cfg = std::make_unique<pcf_config>();
std::unique_ptr<PCFApiServer> pcf_api_server_1;
std::unique_ptr<pcf_http2_server> pcf_api_server_2;

//------------------------------------------------------------------------------
void my_app_signal_handler(int s) {
  std::cout << "Caught signal " << s << std::endl;
  Logger::system().startup("exiting");
  std::cout << "Shutting down HTTP servers..." << std::endl;

  if (pcf_api_server_1) {
    pcf_api_server_1->shutdown();
  }
  if (pcf_api_server_2) {
    pcf_api_server_2->stop();
  }
}

//------------------------------------------------------------------------------
int main(int argc, char** argv) {
  // Command line options
  if (!oai::utils::options::parse(argc, argv)) {
    std::cout << "Options::parse() failed" << std::endl;
    return 1;
  }

  // Logger
  Logger::init(
      "pcf", oai::utils::options::getlogStdout(),
      oai::utils::options::getlogRotFilelog());

  // PID file
  string pid_file_name = get_exe_absolute_path("/var/run", 0);
  if (!is_pid_file_lock_success(pid_file_name.c_str())) {
    Logger::pcf_app().error("Lock PID file %s failed\n", pid_file_name.c_str());
    exit(-EDEADLK);
  }

  std::signal(SIGINT, my_app_signal_handler);

  // Event subsystem
  pcf_event ev;

  // Config
  if (pcf_cfg->load(oai::utils::options::getlibconfigConfig()) == RETURNerror) {
    exit(-1);
  }
  pcf_cfg->display();

  // PCF application layer
  pcf_app_inst = std::make_unique<pcf_app>(ev);

  std::string v4_address = conv::toString(pcf_cfg->sbi.addr4);

  // PCF Pistache API server (HTTP1)
  Pistache::Address addr(v4_address, Pistache::Port(pcf_cfg->sbi.http1_port));
  PCFApiServer test(addr, pcf_app_inst);

  pcf_api_server_1 = std::make_unique<PCFApiServer>(addr, pcf_app_inst);
  pcf_api_server_1->init(2);
  std::thread pcf_http1_manager(&PCFApiServer::start, pcf_api_server_1.get());

  // PCF NGHTTP API server (HTTP2)
  pcf_api_server_2 = std::make_unique<pcf_http2_server>(
      v4_address, pcf_cfg->sbi.http2_port, pcf_app_inst);
  std::thread pcf_http2_manager(
      &pcf_http2_server::start, pcf_api_server_2.get());

  pcf_http1_manager.join();
  pcf_http2_manager.join();

  Logger::pcf_app().info("HTTP servers successfully stopped. Exiting");

  return 0;
}
