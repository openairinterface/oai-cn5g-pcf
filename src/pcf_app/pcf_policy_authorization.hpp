/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_PCF_POLICY_AUTHORIZATION_SEEN
#define FILE_PCF_POLICY_AUTHORIZATION_SEEN

#include <string>
#include <memory>
#include <optional>

#include "SmPolicyContextData.h"
#include "SmPolicyDecision.h"
#include "TrafficControlData.h"
#include "AppSessionContext.h"
#include "AppSessionContextUpdateDataPatch.h"
#include "AppSessionContextReqData.h"
#include "policy_auth/pcf_policy_authorization_status_code.hpp"
#include "policy_auth/app_session.hpp"
#include "policy_auth/app_session_storage.hpp"
#include "pcf_event.hpp"

namespace oai::pcf::app {

/**
 * @brief Service class to handle Session Management Policies
 *
 */
class pcf_policy_authorization {
 public:
  explicit pcf_policy_authorization(
      std::shared_ptr<policy_auth::app_session_storage> app_session_storage,
      pcf_event& ev);
  pcf_policy_authorization(pcf_policy_authorization const&) = delete;
  void operator=(pcf_policy_authorization const&) = delete;

  virtual ~pcf_policy_authorization();

  /**
   * @brief Handler for receiving service policy requests, as defined in
   * 3GPP TS 29.514 Chapter 4.2.2
   * It creates an application session context in the PCF. The result
   * returns an update context created.
   *
   * @param context input: context from the request
   * provisioning
   * @return policy_auth::status_code
   */
  policy_auth::status_code post_app_sessions_handler(
      const oai::_3gpp::model::AppSessionContext& context,
      std::string& app_session_id, std::string& problem_details);

  /**
   * @brief Handler for receiving service policy requests to update application
   * session context, as defined in 3GPP TS 29.514 Chapter 4.2.3
   *
   * @param app_session_id input: context from the request
   * @param app_session_context_update_data_patch input: context from the
   * request
   * @param context output: the applications session context that has been
   * updated provisioning
   * @return policy_auth::status_code
   */
  policy_auth::status_code mod_app_session_handler(
      const std::string& app_session_id,
      const oai::_3gpp::model::AppSessionContextUpdateDataPatch&
          app_session_context_update_data_patch,
      const oai::_3gpp::model::AppSessionContext& context,
      std::string& problem_details);

  /**
   * @brief Handler for terminating an application session context, as defined
   * in 3GPP TS 29.514 Chapter 4.2.4.
   *
   * Removes the QoS entries this app-session contributed from the bound SM
   * policy association's decision (using the session's ledger), notifies the
   * SMF, and drops the session from storage.
   *
   * @param app_session_id  input: id of the session to terminate
   * @param problem_details output: additional information in case of an error
   * @return policy_auth::status_code::OK on success, NOT_FOUND if the session
   * does not exist
   */
  policy_auth::status_code delete_app_session_handler(
      const std::string& app_session_id, std::string& problem_details);

 private:
  // Repository for app-session working state + binding persistence (injected;
  // in-memory backend now, DB backend later). Owns app-session id generation.
  std::shared_ptr<policy_auth::app_session_storage> m_app_session_storage;

  // for Event Handling
  pcf_event& m_event_sub;
};

}  // namespace oai::pcf::app
#endif /* FILE_PCF_POLICY_AUTHORIZATION_SEEN */
