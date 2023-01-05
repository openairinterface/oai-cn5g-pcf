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

const std::string URL_REGEX = "http://.*:[0-9]*";

// Only used for pretty-printing
enum class config_type_e { string, option, sbi, local, invalid };

class config_type {
 public:
  /**
   * Returns a string representation of the config. The indent is prepended at
   * each line
   * @param indent to be prepended
   * @return string representation
   */
  [[nodiscard]] virtual std::string to_string(
      const std::string& indent) const = 0;

  /**
   * Validates the configuration and marks the configuration as set if
   * successful
   * @return true if validation successful, false otherwise
   */
  [[nodiscard]] virtual bool validate() = 0;

  /**
   * Gets the config type of this config
   * @return config_type_e
   */
  [[nodiscard]] virtual config_type_e get_config_type() const = 0;

  /**
   * Checks if the configuration is set. Configuration is not set if it has not
   * been validated.
   * @return true if set, false otherwise
   */
  [[nodiscard]] virtual bool is_set() const;

  /**
   * Helper function to match a regex
   * @param value to match again
   * @param regex that is used for the matching
   * @return true if matched, false otherwise
   */
  static bool matches_regex(const std::string& value, const std::string& regex);

  virtual ~config_type() = default;

 protected:
  bool m_set = false;
};

class string_config_value : public config_type {
 public:
  std::string value;
  std::string regex;

  [[nodiscard]] std::string to_string(const std::string& indent) const override;
  [[nodiscard]] bool validate() override;
  [[nodiscard]] config_type_e get_config_type() const override;
};

class option_config_value : public config_type {
 public:
  bool value = false;

  [[nodiscard]] std::string to_string(const std::string& indent) const override;
  [[nodiscard]] bool validate() override;
  [[nodiscard]] config_type_e get_config_type() const override;
};

class network_interface : public config_type {
 public:
  static bool validate_sbi_api_version(const std::string& v);
};

class sbi_interface : public network_interface {
 public:
  std::string api_version;
  std::string url;

  [[nodiscard]] bool validate() override;
  [[nodiscard]] std::string to_string(const std::string& indent) const override;
  [[nodiscard]] config_type_e get_config_type() const override;
};

class local_interface : public network_interface {
 public:
  std::string if_name{};
  in_addr addr4{};
  in6_addr addr6{};
  unsigned int mtu{};
  uint16_t port{};

  [[nodiscard]] bool validate() override;
  [[nodiscard]] std::string to_string(const std::string& indent) const override;
  [[nodiscard]] config_type_e get_config_type() const override;
};

class local_sbi_interface : public local_interface {
 public:
  std::string api_version;
  bool use_http2 = false;

  [[nodiscard]] bool validate() override;
  [[nodiscard]] std::string to_string(const std::string& indent) const override;
};

class factory {
 public:
  static option_config_value get_option_config(bool val);

  static string_config_value get_string_config(const std::string& val);
};

}  // namespace oai::config