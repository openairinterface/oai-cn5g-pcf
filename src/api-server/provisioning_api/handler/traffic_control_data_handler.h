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

/*! \file traffic_control_data_handler.h
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
#include "TrafficControlData.h"
#include "handler_base.hpp"

namespace oai::pcf::provisioning::api {

class traffic_control_data_handler : public handler_base {
 public:
  /**
   *
   * @return
   */
  oai::pcf::api::api_response traffic_control_data_get();

  /**
   *
   * @param trafficControlData
   * @return
   */
  oai::pcf::api::api_response traffic_control_data_post(
      const oai::model::pcf::TrafficControlData& trafficControlData);

  /**
   *
   * @param tcId
   * @return
   */
  oai::pcf::api::api_response traffic_control_data_tc_id_delete(
      const std::string& tcId);

  /**
   *
   * @param tcId
   * @return
   */
  oai::pcf::api::api_response traffic_control_data_tc_id_get(
      const std::string& tcId);

  /**
   *
   * @param tcId
   * @param trafficControlData
   * @return
   */
  oai::pcf::api::api_response traffic_control_data_tc_id_put(
      const std::string& tcId,
      const oai::model::pcf::TrafficControlData& trafficControlData);
};
}  // namespace oai::pcf::provisioning::api
