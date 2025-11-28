/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include <boost/atomic.hpp>
#include <string>

#include "3gpp_29.500.h"
#include "pcf_profile.hpp"
#include "pcf_event.hpp"
#include "PatchItem.h"
#include "pcf_sm_policy_control.hpp"
#include "sm_policy/policy_storage.hpp"
#include "sm_policy/policy_storage_db.hpp"
#include "sm_policy/policy_storage_yaml.hpp"
#include "sm_policy/policy_provisioning_file.hpp"
#include "pcf_nrf.hpp"
#include "pcf_policy_authorization.hpp"
#include "sm_policy/database/database_wrapper.hpp"
#include "sm_policy/database/mysql_db.hpp"

namespace oai::pcf::app {

// TODO [QOS] PCF QoS Coordination Architecture Overview
// =====================================================
//
// This PCF implementation needs comprehensive QoS coordination between two main services:
// 1. Policy Authorization Service (pcf_policy_authorization) - Handles application QoS requests
// 2. SM Policy Control Service (pcf_sm_policy_control) - Handles session management QoS policies
//
// KEY QOS COORDINATION CHALLENGES TO ADDRESS:
//
// A. PCC RULE MANAGEMENT:
//    - Unique PCC rule ID generation across services (prefix-based: "pa-" for Policy Auth, "sm-" for SM)
//    - Precedence value coordination to avoid conflicts (Policy Auth: 1-100, SM Policy: 101-255)
//    - Rule lifecycle management and cleanup coordination
//
// B. QOS DATA CONSISTENCY:
//    - QosData merging between Policy Authorization and SM Policy decisions
//    - QosCharacteristics coordination for non-standard 5QI values
//    - QosMonitoringData synchronization across services
//
// C. RESOURCE MANAGEMENT:
//    - Bandwidth allocation tracking across both services
//    - QoS flow identifier allocation and management
//    - Priority level and ARP coordination
//
// D. NOTIFICATION COORDINATION:
//    - SMF notification consolidation for combined policy updates
//    - Event-driven coordination via pcf_event system
//    - Error handling and rollback mechanisms for failed updates
//
// E. VALIDATION AND AUTHORIZATION:
//    - Cross-service QoS requirement validation
//    - Subscription and slice policy compliance checking
//    - Resource availability verification
//
// IMPLEMENTATION APPROACH:
// - Use pcf_event system for real-time coordination between services
// - Implement shared QoS coordination functions in both service classes
// - Create unified PCC rule and QoS data management framework
// - Establish clear precedence and ID allocation schemes
// - Design comprehensive validation and conflict resolution mechanisms

class pcf_app {
 public:
  explicit pcf_app(pcf_event& ev);
  pcf_app(pcf_app const&) = delete;
  void operator=(pcf_app const&) = delete;

  virtual ~pcf_app();

  std::shared_ptr<pcf_smpc> get_pcf_smpc_service();
  std::shared_ptr<pcf_policy_authorization>
  get_pcf_policy_authorization_service();

  /**
   * Stop all the ongoing processes and procedures of the PCF APP layer,
   * deregisters at NRF
   */
  void stop();

 private:
  pcf_profile m_nf_instance_profile;  // PCF profile
  std::string m_pcf_instance_id;      // PCF instance id
  // for Event Handling
  pcf_event& m_event_sub;
  bs2::connection m_task_connection;

  std::shared_ptr<pcf_smpc> m_pcf_smpc_service;
  std::shared_ptr<oai::pcf::app::sm_policy::policy_storage> m_policy_storage;
  std::unique_ptr<oai::pcf::app::pcf_nrf> m_pcf_nrf_inst;

  std::shared_ptr<oai::pcf::app::sm_policy::policy_provisioning_file>
      m_provisioning_file;

  std::shared_ptr<pcf_policy_authorization> m_pcf_policy_authorization_service;
};
}  // namespace oai::pcf::app
