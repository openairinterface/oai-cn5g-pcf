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
#include "pistache/endpoint.h"
#include "pistache/http.h"
#include "pistache/router.h"

#include <algorithm>
#include <boost/asio.hpp>
#include <iostream>
#include <csignal>
#include <cstdint>
#include <thread>
#include <unistd.h>  // get_pid(), pause()
#include <vector>

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/split.hpp>

using namespace util;
using namespace std;
using namespace oai::pcf::app;
using namespace oai::pcf::config;

std::unique_ptr<pcf_app> pcf_app_inst;
// TODO Stefan: I am not happy with these global variables
// We could make a singleton getInstance in config
// or we handle everything in smf_app init and have a reference to config there
std::unique_ptr<pcf_config> pcf_cfg = std::make_unique<pcf_config>();
;
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
  exit(0);
}
//------------------------------------------------------------------------------
// We are doing a check to see if an existing process already runs this program.
// We have seen that running at least twice this program in a container may lead
// to the container host to crash.
bool check_redundant_process(const std::string& exec_name) {
  FILE* fp;
  int result     = 0;
  size_t retSize = 0;

  // Retrieving only the executable name
  std::string prog_name =
      exec_name.substr(exec_name.rfind("/", 0), exec_name.length());

  std::string cmd = "ps aux | grep -v grep | grep -v nohup | grep -c ";
  cmd.append(prog_name);

  fp = popen(cmd.c_str(), "r");

  char buf[64];
  retSize = fread(buf, 1, sizeof(buf), fp);
  pclose(fp);
  // if something is wrong, then we cannot know
  if (retSize == 0) {
    return false;
  }
  try {
    stoi(buf);
  } catch (invalid_argument& ex) {
    cout << "ERROR: Could not read how many processes are running" << std::endl;
    return false;
  }

  return true;
}
//------------------------------------------------------------------------------
int main(int argc, char** argv) {
  // Checking if another instance of pcf is running
  if (!check_redundant_process(argv[0])) {
    std::cout << "An instance of " << argv[0] << " is maybe already called!"
              << std::endl;
    return -1;
  }

  // Command line options
  if (!Options::parse(argc, argv)) {
    std::cout << "Options::parse() failed" << std::endl;
    return 1;
  }

  // Logger
  Logger::init("pcf", Options::getlogStdout(), Options::getlogRotFilelog());

  struct sigaction sigIntHandler {};
  sigIntHandler.sa_handler = my_app_signal_handler;
  sigemptyset(&sigIntHandler.sa_mask);
  sigIntHandler.sa_flags = 0;
  sigaction(SIGINT, &sigIntHandler, nullptr);

  // Event subsystem
  pcf_event ev;

  // Config
  if (pcf_cfg->load(Options::getlibconfigConfig()) == RETURNerror) {
    exit(-1);
  }
  pcf_cfg->display();

  // PCF application layer
  pcf_app_inst = std::make_unique<pcf_app>(ev);

  // PID file
  // Currently hard-coded value. TODO: add as config option.
  string pid_file_name = get_exe_absolute_path("/var/run", pcf_cfg->instance);
  if (!is_pid_file_lock_success(pid_file_name.c_str())) {
    Logger::pcf_app().error("Lock PID file %s failed\n", pid_file_name.c_str());
    exit(-EDEADLK);
  }

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
  std::cout << " after join server" << std::endl;

  FILE* fp             = nullptr;
  std::string filename = fmt::format("/tmp/pcf_{}.status", getpid());
  fp                   = fopen(filename.c_str(), "w+");
  fprintf(fp, "STARTED\n");
  fflush(fp);
  fclose(fp);

  pause();
  return 0;
}
