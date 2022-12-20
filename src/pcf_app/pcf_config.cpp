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
  std::unique_ptr<config_type> use_http2 =
      std::make_unique<option_config_value>(
          factory::get_option_config(USE_HTTP2_DEFAULT_VALUE));
  std::unique_ptr<config_type> register_nrf =
      std::make_unique<option_config_value>(
          factory::get_option_config(REGISTER_NRF_DEFAULT_VALUE));
  std::unique_ptr<config_type> pcf_name = std::make_unique<string_config_value>(
      factory::get_string_config(NAME_DEFAULT_VALUE));

  m_cfg->set_configuration(PCF_CONFIG_STRING_USE_HTTP2, std::move(use_http2));
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
  try {
    sbi_http2 =
        m_cfg->get_local_sbi_interface(PCF_CONFIG_STRING_SBI_IFACE_HTTP2);
  } catch (std::invalid_argument&) {
  }

  nrf_addr       = m_cfg->get_sbi_interface(PCF_CONFIG_STRING_NRF);
  pcc_rules_path = m_cfg->get_base_conf_val(PCF_CONFIG_STRING_PCC_RULES_DIR);
  policy_decisions_path =
      m_cfg->get_base_conf_val(PCF_CONFIG_STRING_POLICY_DECISIONS_DIR);
  traffic_rules_path =
      m_cfg->get_base_conf_val(PCF_CONFIG_STRING_TRAFFIC_RULES_DIR);

  pcf_features.register_nrf =
      m_cfg->get_support_feature(PCF_CONFIG_STRING_REGISTER_NRF);
  pcf_features.use_http2 =
      m_cfg->get_support_feature(PCF_CONFIG_STRING_USE_HTTP2);
}

void oai::pcf::config::pcf_config::display() {
  m_cfg->display();
}
