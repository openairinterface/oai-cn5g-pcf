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

/*! \file config_types.cpp
 \brief
 \author  Stefan Spettel
 \company phine.tech
 \date 2022
 \email: stefan.spettel@phine.tech
*/

#include "config_types.hpp"
#include "config.hpp"
#include "conversions.hpp"
#include "logger_base.hpp"
#include "if.hpp"
#include "common_defs.h"

#include <fmt/format.h>
#include <algorithm>
#include <regex>
#include <string>

using namespace oai::config;

const std::string INNER_LIST_ELEM = "+";

bool config_type::matches_regex(
    const std::string& value, const std::string& regex) {
  std::regex re(regex);

  if (!std::regex_match(value, re)) {
    logger::logger_registry::get_logger(LOGGER_NAME)
        .error("%s does not follow regex specification: %s", value, regex);
    return false;
  }
  return true;
}

bool config_type::is_set() const {
  return m_set;
}

config_type_e config_type::get_config_type() const {
  return config_type_e::invalid;
}

bool sbi_interface::validate() {
  if (!matches_regex(m_url, URL_REGEX)) {
    return false;
  }
  m_set = true;
  return true;
}

std::string sbi_interface::to_string(const std::string& indent) const {
  std::string out;
  unsigned int inner_width = COLUMN_WIDTH;
  if (indent.length() < COLUMN_WIDTH) {
    inner_width = COLUMN_WIDTH - indent.length();
  }

  out.append("SBI Interface\n");
  out.append(indent).append(
      fmt::format(BASE_FORMATTER, INNER_LIST_ELEM, "URL", inner_width, m_url));
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM, "API Version", inner_width,
      m_api_version));
  return out;
}

config_type_e sbi_interface::get_config_type() const {
  return config_type_e::sbi;
}

const std::string& sbi_interface::get_api_version() const {
  return m_api_version;
}

const std::string& sbi_interface::get_url() const {
  return m_url;
}

bool local_interface::validate() {
  unsigned int _mtu{};
  in_addr _addr4{};
  in_addr _netmask{};
  if (get_inet_addr_infos_from_iface(m_if_name, _addr4, _netmask, _mtu) ==
      RETURNerror) {
    logger::logger_registry::get_logger(LOGGER_NAME)
        .error(
            "Error in reading configuration from network interface %s",
            m_if_name);
    return false;
  }
  m_mtu   = _mtu;
  m_addr4 = _addr4;

  m_set = true;
  return true;
}

std::string local_interface::to_string(const std::string& indent) const {
  std::string out;
  unsigned int inner_width = COLUMN_WIDTH;
  if (indent.length() < COLUMN_WIDTH) {
    inner_width = COLUMN_WIDTH - indent.length();
  }

  out.append("Local Interface\n");
  std::string ip4 = conv::toString(m_addr4);
  std::string ip6 = conv::toString(m_addr6);

  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM, "IPv4 Address ", inner_width, ip4));
  if (ip6 != "::") {
    out.append(indent).append(fmt::format(
        BASE_FORMATTER, INNER_LIST_ELEM, "IPv6 Address", inner_width, ip6));
  }
  out.append(indent).append(
      fmt::format(BASE_FORMATTER, INNER_LIST_ELEM, "MTU", inner_width, m_mtu));
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM, "Interface name: ", inner_width,
      m_if_name));
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM, "Port", inner_width, m_port));

  return out;
}

config_type_e local_interface::get_config_type() const {
  return config_type_e::local;
}

const std::string& local_interface::get_if_name() const {
  return m_if_name;
}

const in_addr& local_interface::get_addr4() const {
  return m_addr4;
}

const in6_addr& local_interface::get_addr6() const {
  return m_addr6;
}

unsigned int local_interface::get_mtu() const {
  return m_mtu;
}

uint16_t local_interface::get_port() const {
  return m_port;
}

bool local_sbi_interface::validate() {
  bool sbi_validate = validate_sbi_api_version(m_api_version);
  if (!sbi_validate) {
    return false;
  }
  return local_interface::validate();
}

std::string local_sbi_interface::to_string(const std::string& indent) const {
  unsigned int inner_width = 0;
  if (indent.length() < COLUMN_WIDTH) {
    inner_width = COLUMN_WIDTH - indent.length();
  }

  std::string out = local_interface::to_string(indent);
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM, "API Version", inner_width,
      m_api_version));

  std::string http_version = m_use_http2 ? "2" : "1";

  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM, "HTTP Version", inner_width,
      http_version));

  return out;
}

const std::string& local_sbi_interface::get_api_version() const {
  return m_api_version;
}

bool local_sbi_interface::use_http2() const {
  return m_use_http2;
}

bool network_interface::validate_sbi_api_version(const std::string& v) {
  auto it =
      std::find(allowed_api_versions.begin(), allowed_api_versions.end(), v);
  if (it == allowed_api_versions.end()) {
    logger::logger_registry::get_logger(LOGGER_NAME)
        .error("API version %s not valid!", v);
    return false;
  }
  return true;
}

std::string string_config_value::to_string(const std::string&) const {
  std::string out;
  return out.append(m_value);
}

bool string_config_value::validate() {
  m_set = true;
  return true;
}

config_type_e string_config_value::get_config_type() const {
  return config_type_e::string;
}

const std::string& string_config_value::get_value() const {
  return m_value;
}

std::string option_config_value::to_string(const std::string&) const {
  std::string val = m_value ? "Yes" : "No";
  return val;
}

bool option_config_value::validate() {
  m_set = true;
  return true;
}

config_type_e option_config_value::get_config_type() const {
  return config_type_e::option;
}

bool option_config_value::get_value() const {
  return m_value;
}

option_config_value factory::get_option_config(bool val) {
  option_config_value v;
  v.m_value = val;
  return v;
}

string_config_value factory::get_string_config(const std::string& val) {
  string_config_value v;
  v.m_value = val;
  return v;
}
