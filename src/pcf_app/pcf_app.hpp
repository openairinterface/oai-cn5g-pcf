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
#include "policy_auth/app_session_storage.hpp"
#include "sm_policy/database/database_wrapper.hpp"

namespace oai::pcf::app {

// TODO [QOS] PCF QoS Coordination Architecture Overview [TS 29.513 §5.2.2.2, TS 29.512 §4.2.6]
// =====================================================
//
// This PCF implementation needs comprehensive QoS coordination between two main services:
// 1. Policy Authorization Service (pcf_policy_authorization) - Handles application QoS requests [TS 29.514]
// 2. SM Policy Control Service (pcf_sm_policy_control) - Handles session management QoS policies [TS 29.512]
//
// KEY QOS COORDINATION CHALLENGES TO ADDRESS:
//
// A. PCC RULE MANAGEMENT [TS 23.503 §6.1.3.7, TS 29.512 §4.1.4.2]:
//    - Unique PCC rule ID generation across services (prefix-based: "PA-QOS-" for Policy Auth, "SM-" for SM) [TS 29.512 §4.1.4.2.1]
//    - Precedence value coordination to avoid conflicts (Policy Auth: 1000-1999, SM Policy: 2000-2999) [TS 23.503 §6.3.1]
//    - Rule lifecycle management and cleanup coordination [TS 29.512 §4.2.6.2.1]
//
// B. QOS DATA CONSISTENCY [TS 29.512 §4.2.6.6]:
//    - QosData merging between Policy Authorization and SM Policy decisions [TS 29.512 §4.2.6.6.2, §5.6.2.8]
//    - QosCharacteristics coordination for non-standard 5QI values [TS 29.512 §4.2.6.6.3, §5.6.2.16]
//    - QosMonitoringData synchronization across services [TS 29.512 §4.2.3.25, §5.6.2.40]
//
// C. RESOURCE MANAGEMENT [TS 29.512 §4.2.6.8, TS 23.503 §6.1.4]:
//    - Bandwidth allocation tracking across both services [TS 29.512 §4.2.6.8.2]
//    - QoS flow identifier allocation and management [TS 23.501 §5.7.1.1]
//    - Priority level and ARP coordination [TS 23.501 §5.7.3.3]
//
// D. NOTIFICATION COORDINATION [TS 29.512 §4.2.3.2, TS 29.513 §5.2.2.3]:
//    - SMF notification consolidation for combined policy updates [TS 29.512 §4.2.3.2]
//    - Event-driven coordination via pcf_event system (boost::signals2)
//    - Error handling and rollback mechanisms for failed updates [TS 29.500 §5.2.8]
//
// E. VALIDATION AND AUTHORIZATION [TS 29.514 §4.1.3.1, TS 23.503 §6.1.3.2.3]:
//    - Cross-service QoS requirement validation [TS 29.513 §7.3.3]
//    - Subscription and slice policy compliance checking [TS 29.512 §4.2.6.6.1, §4.2.6.7]
//    - Resource availability verification [TS 23.503 §6.1.3.2.3]
//
// IMPLEMENTATION APPROACH:
// - Use pcf_event system for real-time coordination between services
// - Implement shared QoS coordination functions in both service classes
// - Create unified PCC rule and QoS data management framework [TS 29.512 §4.2.6.2]
// - Establish clear precedence and ID allocation schemes [TS 23.503 §6.3.1]
// - Design comprehensive validation and conflict resolution mechanisms [TS 23.503 §6.1.3.7]

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

  std::shared_ptr<oai::pcf::app::policy_auth::app_session_storage>
      m_app_session_storage;
  std::shared_ptr<pcf_policy_authorization> m_pcf_policy_authorization_service;
};
}  // namespace oai::pcf::app
