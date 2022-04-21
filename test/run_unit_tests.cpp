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

/*! \file run_unit_tests.cpp
 \brief
 \author  Stefan Spettel
 \company Openairinterface Software Allianse
 \date 2022
 \email: stefan.spettel@eurecom.fr
 */

#include "gtest/gtest.h"
#include "test_common.h"
#include "logger.hpp"
#include "pcf_config.hpp"

std::string pcf_config_path; 
int port_inc = 0;

oai::pcf::config::pcf_config pcf_cfg;

int main(int argc, char* argv[]) {
  ::testing::InitGoogleTest(&argc, argv);

  if (argc != 2)
  {
    std::cout << "You need to specify the PCF config file path" << std::endl;
    return -1;
  } 
  pcf_config_path = argv[1];
  //TODO logger should not be here, but apparently singleton does not work
  //Thus, when called in SetUp, we get multiple lines per test
  Logger::init("pcf_tests", true, false);

  return RUN_ALL_TESTS();
}