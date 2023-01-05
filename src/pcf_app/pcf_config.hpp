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

/*! \file pcf_config.hpp
 \brief
 \author  Rohan Kharade, Stefan Spettel
 \company OpenAirInterface Software Alliance
 \date 2022
 \email: rohan.kharade@openairinterface.org
*/

#pragma once

#include "config.hpp"

namespace oai::pcf::config {

const std::string NAME_DEFAULT_VALUE  = "PCF";
const bool REGISTER_NRF_DEFAULT_VALUE = false;
const bool USE_HTTP2_DEFAULT_VALUE    = false;

const std::string PCF_CONFIG_STRING_REGISTER_NRF  = "register_nrf";
const std::string PCF_CONFIG_STRING_USE_HTTP2     = "use_http2";
const std::string PCF_CONFIG_STRING_NAME          = "name";
const std::string PCF_CONFIG_STRING_PCC_RULES_DIR = "pcc_rules_directory";
const std::string PCF_CONFIG_STRING_POLICY_DECISIONS_DIR =
    "policy_decisions_directory";
const std::string PCF_CONFIG_STRING_TRAFFIC_RULES_DIR =
    "traffic_rules_directory";
const std::string PCF_CONFIG_STRING_SBI_IFACE = "local_sbi_interface";
const std::string PCF_CONFIG_STRING_SBI_IFACE_HTTP2 =
    "local_sbi_interface_http2";
const std::string PCF_CONFIG_STRING_NRF = "nrf";

struct support_features {
  bool register_nrf;
  bool use_http2;
};

class pcf_config {
 public:
  oai::config::local_sbi_interface sbi;
  oai::config::local_sbi_interface sbi_http2;
  std::string pcc_rules_path;
  std::string policy_decisions_path;
  std::string traffic_rules_path;

  oai::config::sbi_interface nrf_addr;

  support_features pcf_features;

  explicit pcf_config(
      const std::string& config_path, bool log_stdout, bool log_rot_file)
      : pcf_features() {
    m_cfg =
        std::make_unique<oai::config::config>("pcf", log_stdout, log_rot_file);
    m_config_path = config_path;
  };

  /**
   * Initializes the configuration, sets mandatory values for validation, sets
   * default values, reads YAML configuration file and validates the
   * configuration
   * @return True on success
   */
  bool init();

  void display();

 private:
  std::unique_ptr<oai::config::config_iface> m_cfg;
  std::string m_config_path;

  void set_direct_variables();
};
}  // namespace oai::pcf::config
