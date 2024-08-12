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

/*! \file policy_storage_hpp.cpp
 \brief
 \author  Lukas Rotheneder
 \company phine.tech
 \date 2024
 \email: lukas.rotheneder@phine.tech
 */

#pragma once

#include "policy_storage.hpp"

namespace oai::pcf::app::sm_policy {
/**
 * @brief Class connected to policies stored in the database, added through
 * provisioning requests.
 *
 */
class policy_storage_db : public policy_storage {
  std::shared_ptr<policy_decision> find_policy(
      const oai::model::pcf::SmPolicyContextData& context);

  void subscribe_to_decision_change(
      std::function<void(std::shared_ptr<policy_decision>&)> callback);
};

}  // namespace oai::pcf::app::sm_policy