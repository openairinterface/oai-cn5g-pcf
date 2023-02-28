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

/*! \file pcf_config.cpp
 \brief
 \author  Rohan Kharade, Stefan Spettel
 \company OpenAirInterface Software Alliance
 \date 2022
 \email: rohan.kharade@openairinterface.org
*/

#include <config_yaml_file.hpp>
#include "pcf_config.hpp"

using namespace oai::config;

bool oai::pcf::config::pcf_config::init() {
  // Default configuration
  std::unique_ptr<config_type> client_http_version =
      std::make_unique<uint8_config_value>(
          factory::get_uint8_config(CLIENT_HTTP2_VERSION_DEFAULT_VALUE));
  std::unique_ptr<config_type> register_nrf =
      std::make_unique<option_config_value>(
          factory::get_option_config(REGISTER_NRF_DEFAULT_VALUE));
  std::unique_ptr<config_type> pcf_name = std::make_unique<string_config_value>(
      factory::get_string_config(NAME_DEFAULT_VALUE));

  m_cfg->set_configuration(
      PCF_CONFIG_STRING_CLIENT_HTTP_VERSION, std::move(client_http_version));
  m_cfg->set_configuration(
      PCF_CONFIG_STRING_REGISTER_NRF, std::move(register_nrf));
  m_cfg->set_configuration(PCF_CONFIG_STRING_NAME, std::move(pcf_name));

  m_cfg->set_configuration_mandatory(PCF_CONFIG_STRING_TRAFFIC_RULES_DIR);
  m_cfg->set_configuration_mandatory(PCF_CONFIG_STRING_POLICY_DECISIONS_DIR);
  m_cfg->set_configuration_mandatory(PCF_CONFIG_STRING_PCC_RULES_DIR);

  m_cfg->set_configuration_mandatory(PCF_CONFIG_STRING_SBI_IFACE);

  yaml_file file;
  try {
    file.read_from_file(m_config_path, *m_cfg);
  } catch (std::runtime_error& err) {
    return false;
  }
  // this is only mandatory when REGISTER_NRF is set
  if (m_cfg->get_support_feature(PCF_CONFIG_STRING_REGISTER_NRF)) {
    m_cfg->set_configuration_mandatory(PCF_CONFIG_STRING_NRF);
  }
  set_validation_constraints();

  bool validated = m_cfg->validate();
  if (!validated) {
    logger::logger_registry::get_logger(LOGGER_NAME)
        .error("Configuration validation not successful!");
    return false;
  }
  set_direct_variables();
  return true;
}

void oai::pcf::config::pcf_config::set_direct_variables() {
  sbi = m_cfg->get_local_sbi_interface(PCF_CONFIG_STRING_SBI_IFACE);

  nrf_addr       = m_cfg->get_sbi_interface(PCF_CONFIG_STRING_NRF);
  pcc_rules_path = m_cfg->get_base_conf_val(PCF_CONFIG_STRING_PCC_RULES_DIR);
  policy_decisions_path =
      m_cfg->get_base_conf_val(PCF_CONFIG_STRING_POLICY_DECISIONS_DIR);
  traffic_rules_path =
      m_cfg->get_base_conf_val(PCF_CONFIG_STRING_TRAFFIC_RULES_DIR);

  pcf_features.register_nrf =
      m_cfg->get_support_feature(PCF_CONFIG_STRING_REGISTER_NRF);
  pcf_features.client_http_version =
      m_cfg->get_uint8_conf_val(PCF_CONFIG_STRING_CLIENT_HTTP_VERSION);
}

void oai::pcf::config::pcf_config::display() {
  m_cfg->display();
}

void oai::pcf::config::pcf_config::set_validation_constraints() {
  std::unique_ptr<uint8_config_value> http_client_version_ptr =
      std::make_unique<uint8_config_value>(
          m_cfg->get_uint8_conf(PCF_CONFIG_STRING_CLIENT_HTTP_VERSION));
  http_client_version_ptr->set_validation_max_value(2);
  http_client_version_ptr->set_validation_min_value(1);

  m_cfg->set_configuration(
      PCF_CONFIG_STRING_CLIENT_HTTP_VERSION,
      std::move(http_client_version_ptr));
}
