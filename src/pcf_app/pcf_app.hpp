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

// QoS coordination between this PCF's two services
// (pcf_policy_authorization, N5 [TS 29.514]) and SM Policy Control (pcf_smpc,
// N7 [TS 29.512])interfacing runs over the pcf_event signal bus, both
// constructed here [TS 29.513 §5.2.2.2]:
//
//   sm_session_binding          locate the association, and read its decision +
//                               version so the caller can commit optimistically
//   sm_update_decision          commit an SmPolicyDelta under a version-CAS
//   notify_committed_decision   notify the SMF and return the classified outcome
//   sm_policy_update_failed     a permanent rejection found on a delayed retry
//   sm_get_association_decision fresh decision lookup by id (rollback path)
//
// PCC rule identity and precedence are kept disjoint by construction rather
// than negotiated: Policy Authorization owns the "PA-QOS-" id prefix and a
// reserved precedence band [TS 29.512 §4.1.4.2.1, TS 23.503 §6.3.1]. Active
// conflict detection and slice-level resource admission control are not
// implemented -- see the TODOs in pcf_sm_policy_control.hpp.

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

  std::shared_ptr<oai::pcf::app::policy_auth::policy_auth_context>
      m_policy_auth_context;
  std::shared_ptr<pcf_policy_authorization> m_pcf_policy_authorization_service;
};
}  // namespace oai::pcf::app
