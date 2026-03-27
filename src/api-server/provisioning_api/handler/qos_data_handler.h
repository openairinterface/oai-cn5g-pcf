/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
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
