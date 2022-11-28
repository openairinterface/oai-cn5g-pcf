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

/*! \file pcf_app.hpp
 \brief
 \author  Rohan Kharade
 \company Openairinterface Software Allianse
 \date 2021
 \email: rohan.kharade@openairinterface.org
 */

#ifndef FILE_PCF_APP_HPP_SEEN
#define FILE_PCF_APP_HPP_SEEN

#include "common_root_types.h"
#include <boost/atomic.hpp>
#include <string>

#include "3gpp_29.500.h"
#include "pcf.h"
#include "pcf_profile.hpp"
#include "pcf_event.hpp"
#include "3gpp_29.510.h"
#include "PatchItem.h"
#include "pcf_sm_policy_control.hpp"
#include "sm_policy/policy_storage.hpp"
#include "sm_policy/policy_provisioning_file.hpp"
#include "pcf_nrf.hpp"

namespace oai::pcf::app {

class pcf_app {
 public:
  explicit pcf_app(pcf_event& ev);
  pcf_app(pcf_app const&) = delete;
  void operator=(pcf_app const&) = delete;

  virtual ~pcf_app();

  std::shared_ptr<pcf_smpc> get_pcf_smpc_service();

  /**
   * Stops all the ongoing processes and procedures of the PCF APP layer,
   * deregisters at NRF
   */
  void stop();

 private:
  pcf_profile nf_instance_profile;  // PCF profile
  std::string pcf_instance_id;      // PCF instance id
  // for Event Handling
  pcf_event& event_sub;
  bs2::connection task_connection;

  std::shared_ptr<pcf_smpc> pcf_smpc_service;
  std::shared_ptr<oai::pcf::app::sm_policy::policy_storage> m_policy_storage;
  std::unique_ptr<oai::pcf::app::pcf_nrf> pcf_nrf_inst;

  std::shared_ptr<oai::pcf::app::sm_policy::policy_provisioning_file>
      provisioning_file;
};
}  // namespace oai::pcf::app
#endif /* FILE_PCF_APP_HPP_SEEN */
