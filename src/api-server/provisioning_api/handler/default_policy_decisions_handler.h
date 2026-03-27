/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*! \file default_policy_decisions_handler.h
 \brief
 \author  Lukas Rotheneder
 \company phine.tech
 \date 2024
 \email: lukas.rotheneder@phine.tech
 */

#pragma once

#include <string>
#include <vector>
#include "handler_base.hpp"
#include "api_response.h"

namespace oai::pcf::provisioning::api {

class default_policy_decisions_handler : public handler_base {
 public:
  /**
   * get default decision
   * @return api_response
   */
  oai::pcf::api::api_response default_decision_get();

  /**
   * Update default decision
   * @param stdString
   * @returnapi_response
   */
  oai::pcf::api::api_response default_decision_put(
      const std::vector<std::string>& pccRules);
};
}  // namespace oai::pcf::provisioning::api
