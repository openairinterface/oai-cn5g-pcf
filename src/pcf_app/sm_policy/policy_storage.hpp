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

/*! \file policy_storage.hpp
 \brief
 \author  Lukas Rotheneder
 \company phine.tech
 \date 2024
 \email: lukas.rotheneder@phine.tech
 */

#pragma once

#include <string>
#include <memory>
#include <shared_mutex>
#include <unordered_map>
#include <optional>

#include "SmPolicyDecision.h"
#include "SmPolicyContextData.h"
#include "policy_decision.hpp"

namespace oai::pcf::app::sm_policy {

class policy_storage {
 public:
  /**
   * @brief Finds a policy based on the existing supi, dnn, slice and default
   * policies in that order.
   *
   * @param context  The policy context containing supi or dnn or snssai
   * @param chosen_decision
   * decision base class
   * @return pointer to the object implementing the chosen, null in case no
   * decision can be found
   */
  virtual std::shared_ptr<policy_decision> find_policy(
      const oai::model::pcf::SmPolicyContextData& context) = 0;

  /**
   * @brief Calls the callback when any of the policies have been updated
   *
   * @param callback
   */
  virtual void subscribe_to_decision_change(
      std::function<void(std::shared_ptr<policy_decision>&)> callback) = 0;

  virtual void insert_supi_decision(
      const std::string& supi,
      const oai::model::pcf::SmPolicyDecision& decision) = 0;

  virtual void insert_dnn_decision(
      const std::string& dnn,
      const oai::model::pcf::SmPolicyDecision& decision) = 0;

  virtual void insert_slice_decision(
      const oai::model::common::Snssai&,
      const oai::model::pcf::SmPolicyDecision& decision) = 0;

  virtual void insert_associations(
      const oai::model::pcf::SmPolicyContextData& context,
      const std::string& association_id) = 0;

  virtual void insert_ip_association(
      const std::string& dnn, const std::string& association_id) = 0;

  virtual void insert_supi_association(
      const std::string& supi, const std::string& association_id) = 0;

  virtual void insert_dnn_association(
      const std::string& dnn, const std::string& association_id) = 0;

  virtual std::shared_ptr<std::string> find_association(
      const std::optional<std::string>& ipv4,
      const std::optional<std::string>& supi,
      const std::optional<std::string>& dnn) = 0;
};

}  // namespace oai::pcf::app::sm_policy