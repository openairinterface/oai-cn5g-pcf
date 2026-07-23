/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_PCF_POLICY_AUTHORIZATION_SEEN
#define FILE_PCF_POLICY_AUTHORIZATION_SEEN

#include <cstdint>
#include <functional>
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
#include "policy_auth/policy_auth_context.hpp"
#include "pcf_event.hpp"
#include "sm_policy/smf_notify_outcome.hpp"
#include "sm_policy_delta.hpp"

namespace oai::pcf::app {

/**
 * @brief Service class to handle Session Management Policies
 *
 */
class pcf_policy_authorization {
 public:
  explicit pcf_policy_authorization(
      std::shared_ptr<policy_auth::policy_auth_context> context, pcf_event& ev);
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
      oai::_3gpp::model::AppSessionContext& app_session_context,
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

  /**
   * @brief Handler for reading an Individual Application Session Context, as
   * defined in 3GPP TS 29.514 Chapter 4.2.5.
   *
   * Returns the stored AppSessionContext for the given id. Read-only: it does
   * not touch the bound SM policy association or the SMF.
   *
   * @param app_session_id      input: id of the session to read
   * @param app_session_context output: the session context on success
   * @param problem_details     output: additional information in case of an
   * error
   * @return policy_auth::status_code::OK on success, NOT_FOUND if the session
   * does not exist (or has been released)
   */
  policy_auth::status_code get_app_session_handler(
      const std::string& app_session_id,
      oai::model::pcf::AppSessionContext& app_session_context,
      std::string& problem_details);

  /**
   * @brief Build the AppSessionContextRespData returned to the AF, negotiating
   * supported features against the request [TS 29.514 §4.2.2.2, §5.8;
   * TS 29.500 §6.6.2]. Phase 1 advertises no optional Npcf_PolicyAuthorization
   * features, so the negotiated feature set is empty ("0"). Static so both the
   * create (collection) and read (document) API paths produce a consistent
   * ascRespData.
   */
  static oai::model::pcf::AppSessionContextRespData build_response_data(
      const oai::model::pcf::AppSessionContextReqData& req);

 private:
  /**
   * @brief Push a request's decision change to the bound association with
   * optimistic concurrency + bounded retry. Thin wrapper around
   * policy_auth::apply_decision_with_retry (apply_decision_with_retry.hpp) --
   * the CAS-retry/conflict/exhaustion mechanics are extracted there as a
   * free, dependency-injected function specifically so they're directly
   * unit-tested without pcf_event/pcf_smpc, since every PA handler
   * (create/modify/delete/rollback) depends on this being correct.
   *
   * `derive` is invoked once per attempt with the current base decision; it must
   * copy-and-mutate `working` into this request's intended decision and return
   * an empty handler_result, or a set handler_result for a *deterministic*
   * failure (403/400/...) that no retry can fix. The delta (base -> working) is
   * applied to the association only if it is still at the base's version; on a
   * version conflict `derive` is re-run against the freshly committed decision.
   *
   * On success returns status_code::OK and fills `committed_delta` (the delta
   * that was applied -- callers use it to update the session ledger as a
   * post-commit side-effect). On a deterministic failure returns that failure.
   * On retry exhaustion returns FORBIDDEN with problem_details =
   * REQUESTED_SERVICE_TEMPORARILY_NOT_AUTHORIZED [TS 29.514 Table 5.7.3-1].
   */
  policy_auth::status_code apply_with_retry(
      std::optional<std::string>& association_id,
      const oai::model::pcf::SmPolicyDecision& initial_base,
      std::uint64_t initial_version,
      const std::function<policy_auth::handler_result(
          const oai::model::pcf::SmPolicyDecision& base,
          oai::model::pcf::SmPolicyDecision& working)>& derive,
      oai::pcf::app::sm_policy_delta& committed_delta,
      std::string& problem_details, const std::string& app_session_id);

  /**
   * @brief Handler for a definitively "permanent" SMF notify rejection.
   * Consumes (try_take) the matching
   * pending_rollback_tracker entry, if still tracked, then delegates the
   * fetch-live-decision-then-apply-with-retry orchestration to
   * policy_auth::perform_compensating_rollback (rollback_orchestration.hpp) --
   * extracted as a free, dependency-injected function specifically so that
   * "always fetch live state, never reuse the tracker's stale pre-commit
   * snapshot" is unit-tested in isolation. Also fires the §5.7 AF-notify stub
   * either way (rollback committed, not committed, or the association no
   * longer existing to roll back at all).
   */
  void handle_sm_policy_update_failed(
      const std::string& association_id, std::uint64_t version,
      oai::pcf::app::sm_policy::smf_notify_outcome reason);

  // Aggregate of the injected Policy Authorization stores (app-session working
  // set + binding index, and the operator-preconfigured QoS reference sets).
  // New stores are added on policy_auth_context, not here.
  std::shared_ptr<policy_auth::policy_auth_context> m_context;

  // for Event Handling
  pcf_event& m_event_sub;
  bs2::connection m_sm_policy_update_failed_connection;

  // TODO [QOS-SUB] Application Function notification infrastructure [TS 29.514 §4.2.5, TS 29.500 §6.2]
  // Add data structures and methods for AF monitoring and notifications as per 3GPP TS 29.514:
  //
  // 1. AF NOTIFICATION CLIENT [TS 29.500 §5.2.6, TS 29.514 §4.2.5]:
  //    - std::unique_ptr<af_notification_client> m_af_notif_client;
  //    - HTTP/2 client for sending notifications to Application Functions [TS 29.500 §5.2.6]
  //    - Support for both secured (HTTPS) and unsecured (HTTP) connections [TS 33.501 §13.1.0]
  //    - Connection pooling and retry mechanisms for AF endpoints [TS 29.500 §5.2.8]
  //
  // 2. SUBSCRIPTION MANAGEMENT [TS 29.514 §4.2.6, §5.3.4.1]:
  //    - std::unordered_map<std::string, af_subscription> m_af_subscriptions;
  //    - Maps session_id to AF notification subscription details
  //    - std::unordered_map<std::string, af_endpoint_info> m_af_endpoints;
  //    - AF endpoint health monitoring and authentication credentials [TS 29.500 §5.2.6]
  //
  // 3. NOTIFICATION QUEUE SYSTEM [TS 29.500 §6.8]:
  //    - std::queue<af_notification_event> m_notification_queue;
  //    - std::queue<af_notification_event> m_priority_notification_queue; [TS 29.500 §6.8.2]
  //    - std::queue<af_notification_event> m_failed_notification_queue; [TS 29.500 §5.2.8]
  //    - Asynchronous notification processing with priority handling [TS 29.500 §6.8.5]
  //
  // 4. MONITORING EVENT HANDLERS [TS 29.514 §4.2.5]:
  //    - void handle_qos_flow_update(session_id, qos_flow_info);
  //    - void handle_pdu_session_event(session_id, session_event);
  //    - void handle_monitoring_report(session_id, monitoring_data);
  //    - void handle_policy_decision_update(session_id, policy_changes);
  //
  // 5. AF NOTIFICATION METHODS [TS 29.514 §4.2.5]:
  //    - status_code notify_af_qos_status(af_endpoint, qos_notification); [TS 29.514 §4.2.5.4]
  //    - status_code notify_af_session_event(af_endpoint, session_notification); [TS 29.514 §4.2.5.22]
  //    - status_code notify_af_monitoring_report(af_endpoint, monitoring_report); [TS 29.514 §4.2.5.14]
  //    - status_code notify_af_policy_update(af_endpoint, policy_notification); [TS 29.514 §4.2.5.2]
  //
  // 6. SUBSCRIPTION LIFECYCLE [TS 29.514 §4.2.6]:
  //    - status_code register_af_subscription(session_id, af_subscription_info); [TS 29.514 §4.2.6.2]
  //    - status_code update_af_subscription(session_id, subscription_updates);
  //    - status_code remove_af_subscription(session_id); [TS 29.514 §4.2.7.1]
  //    - void cleanup_expired_subscriptions();
  //
  // TODO [QOS-MON] QoS monitoring infrastructure [TS 29.512 §4.1.4.4.6, TS 23.503 §6.1.3.21]
  // Add comprehensive QoS monitoring framework:
  //
  // 7. MONITORING INFRASTRUCTURE [TS 29.512 §4.2.3.25, TS 23.503 §6.1.3.21]:
  //    - std::unordered_map<std::string, qos_monitoring_context> m_qos_monitors;
  //    - Timer-based monitoring report generation for subscribed sessions [TS 29.512 §5.6.2.40]
  //    - Threshold-based event triggering for QoS violations and improvements [TS 29.514 §4.2.5.14]
};

}  // namespace oai::pcf::app
#endif /* FILE_PCF_POLICY_AUTHORIZATION_SEEN */
