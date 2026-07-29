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
#include "AppSessionContextUpdateData.h"
#include "AppSessionContextUpdateDataPatch.h"
#include "AppSessionContextReqData.h"
#include "policy_auth/pcf_policy_authorization_status_code.hpp"
#include "policy_auth/app_session.hpp"
#include "policy_auth/decision_applier.hpp"
#include "policy_auth/policy_auth_context.hpp"
#include "policy_auth/qos_deriver.hpp"
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
   * @brief Push a decision change through m_applier and, on commit, drive
   * the SMF notify + compensating-rollback-check as one operation, so no
   * caller can commit without also notifying.
   * Every handler
   * (POST/PATCH/DELETE/rollback) calls this instead of m_applier.apply()
   * directly.
   */
  policy_auth::status_code push_decision_change(
      policy_auth::decision_apply_request request,
      const std::function<policy_auth::handler_result(
          const oai::model::pcf::SmPolicyDecision& base,
          oai::model::pcf::SmPolicyDecision& working)>& derive,
      oai::pcf::app::sm_policy_delta& committed_delta,
      std::string& problem_details);

  /**
   * @brief Consumes (try_take) the matching pending_rollback_tracker entry,
   * if still tracked, then delegates the fetch-live-decision-then-apply-
   * with-retry orchestration to policy_auth::perform_compensating_rollback
   * (decision_applier.hpp) -- extracted as a free, dependency-injected
   * function specifically so that "always fetch live state, never reuse the
   * tracker's stale pre-commit snapshot" is unit-tested in isolation. Also
   * fires the §5.7 AF-notify stub either way (rollback committed, not
   * committed, or the association no longer existing to roll back at all).
   *
   * Called from two places: directly, right after push_decision_change's own
   * commit, when the SMF notify reports a permanent rejection inline on the
   * same attempt; and as the slot for sm_policy_update_failed_sig_t, when a
   * permanent rejection is instead discovered later via
   * retry_drain_queue's delayed path. Both cases reduce to the same
   * question -- "is there a pending commit for (association_id, version),
   * and if so, compensate it" -- so both share this one implementation.
   */
  void compensate_if_pending(
      const std::string& association_id, std::uint64_t version,
      oai::pcf::app::sm_policy::smf_notify_outcome reason);

  // Per-attempt recompute for POST /app-sessions's derive (called once per
  // apply() attempt against the current base): derives this request's QoS/SFC
  // into `working` (side-effect-free w.r.t. shared session state), authorizes,
  // merges and validates. Only per-request state remains as parameters --
  // the stable deps it used to thread (qos_ref_store, op_policy) are now
  // m_qos_deriver, reached via `this`.
  policy_auth::handler_result derive_post_app_session(
      const oai::model::pcf::AppSessionContext& context,
      const std::string& app_session_id,
      const std::shared_ptr<policy_auth::app_session>& session,
      oai::model::pcf::SmPolicyDecision& working);

  // Per-attempt recompute for PATCH /app-sessions/{id}'s derive: re-derives
  // this PATCH's changes -- SFC, QoS modify/add, and REMOVED deletions --
  // into `working`, authorizes, merges and validates, then applies the AF's
  // JSON Merge Patch onto `req_context` (rebuilt from the session snapshot on
  // every attempt; the committed attempt leaves the value used post-commit).
  policy_auth::handler_result derive_mod_app_session(
      const oai::model::pcf::AppSessionContextUpdateData& patch_asc,
      const std::string& app_session_id,
      const std::shared_ptr<policy_auth::app_session>& session,
      oai::model::pcf::AppSessionContextReqData& req_context,
      oai::model::pcf::SmPolicyDecision& working);

  // Aggregate of the injected Policy Authorization stores (app-session working
  // set + binding index, and the operator-preconfigured QoS reference sets).
  // New stores are added on policy_auth_context, not here.
  std::shared_ptr<policy_auth::policy_auth_context> m_context;

  // CAS-retry/conflict/exhaustion mechanics shared by every PA handler
  // (create/modify/delete/rollback). The stable deps (sm_update_decision
  // bridge to m_event_sub, this instance's rollback tracker, max retries)
  // are bound once here at construction instead of re-supplied per call.
  policy_auth::decision_applier m_applier;

  // The two never-varying deps the QoS-derivation functions used to thread
  // through every call (qos_ref_store, op_policy), bound once at construction.
  policy_auth::qos_deriver m_qos_deriver;

  // for Event Handling
  pcf_event& m_event_sub;
  bs2::connection m_sm_policy_update_failed_connection;

  // TODO [QOS-SUB] AF notification infrastructure (Phase 3) [TS 29.514 §4.2.5,
  // TS 29.500 §6.2]: an HTTP/2 notification client, a subscription registry
  // keyed by app-session, endpoint health tracking, and a
  // priority/dead-letter notification queue with retry. The notify_af_*()
  // entry points replace policy_auth::notify_af_qos_update_failed()'s stub.
  // New stores belong on policy_auth_context, and per-session AF state on
  // app_session as an af() aspect beside qos() -- not as fields here.
  //
  // TODO [QOS-MON] Monitoring infrastructure (Phase 4) [TS 29.512 §4.1.4.4.6,
  // TS 23.503 §6.1.3.21]: monitoring contexts with thresholds and a report
  // timer, added the same way (a mon() aspect + a store).
};

}  // namespace oai::pcf::app
#endif /* FILE_PCF_POLICY_AUTHORIZATION_SEEN */
