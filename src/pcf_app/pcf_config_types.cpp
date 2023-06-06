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

/*! \file pcf_config_types.cpp
 \brief
 \author  Stefan Spettel
 \company phine.tech
 \date 2023
 \email: stefan.spettel@phine.tech
*/

#include "pcf_config_types.hpp"

#include <utility>
#include "config.hpp"

using namespace oai::config;
using namespace oai::config::pcf;

policy_config::policy_config(
    const std::string& policy_decisions_path, const std::string& pcc_rules_path,
    const std::string& traffic_rules_path) {
  m_config_name = "Policy";
  m_traffic_rules_path =
      string_config_value("Traffic Rules", traffic_rules_path);
  m_pcc_rules_path = string_config_value("PCC Rules", pcc_rules_path);
  m_policy_decisions_path =
      string_config_value("Policy Decisions", policy_decisions_path);
  m_set = true;
}

void policy_config::from_yaml(const YAML::Node& node) {
  if (node["policy_decisions_path"]) {
    m_policy_decisions_path.from_yaml(node["policy_decisions_path"]);
  }
  if (node["pcc_rules_path"]) {
    m_pcc_rules_path.from_yaml(node["pcc_rules_path"]);
  }
  if (node["traffic_rules_path"]) {
    m_traffic_rules_path.from_yaml(node["traffic_rules_path"]);
  }
}

std::string policy_config::to_string(const std::string& indent) const {
  if (!m_set) return "";
  std::string out;
  unsigned int inner_width = get_inner_width(indent.length());
  out.append(m_config_name).append("\n");
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, OUTER_LIST_ELEM,
      m_policy_decisions_path.get_config_name(), inner_width,
      m_policy_decisions_path.get_value()));
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, OUTER_LIST_ELEM, m_pcc_rules_path.get_config_name(),
      inner_width, m_pcc_rules_path.get_value()));
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, OUTER_LIST_ELEM, m_traffic_rules_path.get_config_name(),
      inner_width, m_traffic_rules_path.get_value()));
  return out;
}

const std::string& policy_config::get_pcc_rules_path() const {
  return m_pcc_rules_path.get_value();
}

const std::string& policy_config::get_policy_decisions_path() const {
  return m_policy_decisions_path.get_value();
}

const std::string& policy_config::get_traffic_rules_path() const {
  return m_traffic_rules_path.get_value();
}

pcf_config_type::pcf_config_type(
    const std::string& name, const std::string& host, const sbi_interface& sbi,
    const policy_config& policy)
    : nf(name, host, sbi), m_policy_config(policy) {
  m_policy_config.set_config();
}

void pcf_config_type::from_yaml(const YAML::Node& node) {
  nf::from_yaml(node);
  if (node["local_policy"]) {
    m_policy_config.from_yaml(node["local_policy"]);
  }
}

std::string pcf_config_type::to_string(const std::string& indent) const {
  std::string out = nf::to_string("");
  out.append(m_policy_config.to_string(indent));

  return out;
}

void pcf_config_type::validate() {
  nf::validate();
  m_policy_config.validate();
}

const policy_config& pcf_config_type::get_policy_config() const {
  return m_policy_config;
}
