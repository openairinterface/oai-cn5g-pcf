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

/*! \file qos_rules_handler.h
 \brief
 \author  Lukas Rotheneder
 \company phine.tech
 \date 2024
 \email: lukas.rotheneder@phine.tech
 */

#pragma once

#include <string>
#include <vector>
#include "api_response.h"
#include "QosData.h"
#include "handler_base.hpp"

namespace oai::pcf::provisioning::api {

class qos_data_handler : public handler_base {
 public:
  /**
   *
   * @return
   */
  oai::pcf::api::api_response qos_data_get();

  /**
   *
   * @param qosData
   * @return
   */
  oai::pcf::api::api_response qos_data_post(
      const oai::model::pcf::QosData& qosData);

  /**
   *
   * @param qosId
   * @return
   */
  oai::pcf::api::api_response qos_data_qos_id_delete(const std::string& qosId);

  /**
   *
   * @param qosId
   * @return
   */
  oai::pcf::api::api_response qos_data_qos_id_get(const std::string& qosId);

  /**
   *
   * @param qosId
   * @param qosData
   * @return
   */
  oai::pcf::api::api_response qos_data_qos_id_put(
      const std::string& qosId, const oai::model::pcf::QosData& qosData);
};
}  // namespace oai::pcf::provisioning::api
