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

/*! \file config_types.hpp
 \brief
 \author  Stefan Spettel
 \company phine.tech
 \date 2022
 \email: stefan.spettel@phine.tech
*/

#pragma once

#include "string"
#include <netinet/in.h>
#include <vector>
#include <memory>

namespace oai::config {

const std::vector<std::string> allowed_api_versions{"v1", "v2"};

// Only used for pretty-printing
enum class config_type_e { STRING, OPTION, SBI, LOCAL, INVALID };

class config_type {
 public:
  [[nodiscard]] virtual std::string to_string(
      const std::string& indent) const                        = 0;
  [[nodiscard]] virtual bool validate() const                 = 0;
  [[nodiscard]] virtual config_type_e get_config_type() const = 0;

  virtual ~config_type() = default;
};

class string_config_value : public config_type {
 public:
  std::string value;
  std::string regex;

  [[nodiscard]] std::string to_string(const std::string& indent) const override;
  [[nodiscard]] bool validate() const override;
  [[nodiscard]] config_type_e get_config_type() const override;

 private:
  config_type_e type = config_type_e::STRING;
};

class option_config_value : public config_type {
 public:
  bool value = false;

  [[nodiscard]] std::string to_string(const std::string& indent) const override;
  [[nodiscard]] bool validate() const override;
  [[nodiscard]] config_type_e get_config_type() const override;

 private:
  config_type_e type = config_type_e::OPTION;
};

class network_interface : public config_type {
 public:
  static bool validate_sbi_api_version(const std::string& v);
};

class sbi_interface : public network_interface {
 public:
  std::string api_version;
  std::string url;

  [[nodiscard]] bool validate() const override;
  [[nodiscard]] std::string to_string(const std::string& indent) const override;
  [[nodiscard]] config_type_e get_config_type() const override;

 private:
  config_type_e type = config_type_e::SBI;
};

class local_interface : public network_interface {
 public:
  std::string iface_name;
  in_addr addr4;
  in6_addr addr6;
  unsigned int mtu;
  uint16_t port;

  [[nodiscard]] bool validate() const override;
  [[nodiscard]] std::string to_string(const std::string& indent) const override;
  [[nodiscard]] config_type_e get_config_type() const override;

 private:
  config_type_e type = config_type_e::LOCAL;
};

class local_sbi_interface : public local_interface {
 public:
  std::string api_version;

  [[nodiscard]] bool validate() const override;
  [[nodiscard]] std::string to_string(const std::string& indent) const override;

 private:
  config_type_e type = config_type_e::LOCAL;
};

}  // namespace oai::config