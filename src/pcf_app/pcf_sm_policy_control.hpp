/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_PCF_SM_POLICY_CONTROL_SEEN
#define FILE_PCF_SM_POLICY_CONTROL_SEEN

#include <functional>
#include <string>
#include <unordered_map>
#include <shared_mutex>
#include <memory>
#include <optional>

#include "SmPolicyContextData.h"
#include "SmPolicyDecision.h"
#include "SmPolicyDeleteData.h"
#include "SmPolicyControl.h"
#include "SmPolicyUpdateContextData.h"
// 3gpp_29.500.h (not the heavier http_definitions.hpp) is deliberate here:
// it's the lightweight header that declares method_e, with none of
// http_definitions.hpp's <cpr/cpr.h>/<curl/curl.h>/<fmt/format.h>/
// <nlohmann/json.hpp> pulled in. oai::http::request/response below are
// forward-declared instead of included for the same reason -- this header
// is included well beyond pcf_smpc's own .cpp (e.g. transitively via
// pcf_app.hpp into api-server sources), and those consumers have no need
// for (and, before this fix, no include path configured for) the full HTTP
// client dependency stack just to see this class's declaration.
#include "3gpp_29.500.h"
#include "sm_policy/pcf_smpc_status_code.hpp"
#include "sm_policy/smf_notify_outcome.hpp"
#include "sm_policy/individual_sm_association.hpp"
#include "sm_policy/retry_drain_queue.hpp"
#include "sm_policy_delta.hpp"
#include "uint_generator.hpp"
#include "sm_policy/policy_storage.hpp"
#include "pcf_event.hpp"
#include "pcf_runtime_policy.hpp"

namespace oai::http {
struct request;
struct response;
}  // namespace oai::http

namespace oai::pcf::app {

// A PCF-owned seam over the single blocking call pcf_smpc needs from
// http_client. http_client::send_http_request is NOT virtual (submodule,
// shared across every CN5G NF -- not ours to change), so injecting
// std::shared_ptr<http_client> alone would not give mockability; this
// std::function seam does.
using http_send_fn = std::function<oai::http::response(
    oai::common::sbi::method_e, const oai::http::request&)>;

/**
 * @brief Service class to handle Session Management Policies
 *
 */
class pcf_smpc {
 public:
  explicit pcf_smpc(
      const std::shared_ptr<oai::pcf::app::sm_policy::policy_storage>&
          policy_storage,
      pcf_event& ev,
      oai::pcf::app::operator_qos_policy qos_authorization_policy         = {},
      oai::pcf::app::notify_failure_recovery_policy notify_failure_recovery = {},
      // The SMF-notify send seam. Empty
      // (the default) binds to the real http_client_inst global at
      // construction; tests inject a fake returning canned responses.
      http_send_fn http_send = {});
  pcf_smpc(pcf_smpc const&) = delete;
  void operator=(pcf_smpc const&) = delete;

  virtual ~pcf_smpc();

  /**
   * @brief Handler for receiving create sm policy requests, as defined in
   * 3GPP TS 29.512 Chapter 4.2.2
   * The result depends on pre-configured policy rules based on supi, dnn,
   * snssai and default rules in that order
   *
   * @param context input: context from the request
   * @param decision output: policy decision based on context and local
   * provisioning
   * @return sm_policy::status_code
   */
  sm_policy::status_code create_sm_policy_handler(
      const oai::_3gpp::model::SmPolicyContextData& context,
      oai::_3gpp::model::SmPolicyDecision& decision,
      std::string& association_id, std::string& problem_details);

  /**
   * @brief Handler for deleting an existing SM policy association, as defined
   * in 3GPP TS 29.512 Chapter 4.2.5
   *
   * @param id The ID of the existing association, if not exist return
   * status_code::NOT_FOUND
   * @param delete_data input: delete data from the request
   * @param problem_details output: additional information in case of an error
   * @return sm_policy::status_code
   */
  sm_policy::status_code delete_sm_policy_handler(
      const std::string& id,
      const oai::_3gpp::model::SmPolicyDeleteData& delete_data,
      std::string& problem_details);

  /**
   * @brief Handler for getting an existing SM policy association, as defined in
   * 3GPP TS 29.512 Annex A
   *
   * @param id The ID of the existing association, if not exist return
   * status_code::NOT_FOUND
   * @param control output: The SmPolicyControl data
   * @param problem_details output: additional information in case of an
   * error
   * @return sm_policy::status_code
   */
  sm_policy::status_code get_sm_policy_handler(
      const std::string& id, oai::_3gpp::model::SmPolicyControl& control,
      std::string& problem_details);

  /**
   * @brief Handler for updating the policy decision based on the provided
   * update context, as define in 3GPP TS 29.512 Chapter 4.2.4
   *
   * @param id The ID of the existing association, if not exist return
   * status_code::NOT_FOUND
   * @param update_context input: The context of the update
   * @param decision output: The SmPolicyDecision
   * @param problem_details output: additional information in case of an error
   * @return sm_policy::status_code
   */
  sm_policy::status_code update_sm_policy_handler(
      const std::string& id,
      const oai::_3gpp::model::SmPolicyUpdateContextData& update_context,
      oai::_3gpp::model::SmPolicyDecision& decision,
      std::string& problem_details);

 private:
  oai::utils::uint_generator<uint32_t> m_association_id_generator;

  std::unordered_map<
      std::string, oai::pcf::app::sm_policy::individual_sm_association>
      m_associations;

  mutable std::shared_mutex m_associations_mutex;

  std::shared_ptr<oai::pcf::app::sm_policy::policy_storage> m_policy_storage;

  // Operator QoS authorization limits used when authorizing the subscribed
  // Session-AMBR / default QoS into a SessionRule [TS 29.512 §4.2.6.6.1].
  // Injected at construction (default = permissive); populated from config in a
  // later step (see N5_QoS_Phase1_§1.4 plan §7.4).
  oai::pcf::app::operator_qos_policy m_qos_authorization_policy;

  // Bounded retry-drain queue for temporary/ambiguous SMF notify outcomes
  // Drained on the task_tick heartbeat (see
  // m_task_tick_connection); TTL/cap/retry-count/backoff come from config via
  // notify_failure_recovery.
  oai::pcf::app::sm_policy::retry_drain_queue m_retry_drain_queue;

  // The SMF-notify send seam (constructor-bound; see http_send_fn above).
  http_send_fn m_http_send;

  // Drains due entries from m_retry_drain_queue: re-fetches each association's
  // live decision + context under lock immediately before the attempt
  // (never resend a frozen snapshot), notifies off-lock [CP.22],
  // and reports the outcome back to the queue. Fires the SM->PA
  // sm_policy_update_failed signal on a permanent rejection discovered here
  // -- unlike a rejection discovered inline on the first attempt (reported
  // directly via handle_notify_committed_decision_request's return value,
  // not this signal) since nothing is synchronously waiting for this
  // delayed retry.
  void drain_retry_queue(std::uint64_t tick_ms);

  void handle_policy_change(
      const std::shared_ptr<oai::pcf::app::sm_policy::policy_decision>&
          decision);

  // Notify the SMF of a decision. Takes an immutable snapshot + the context
  // (SUPI/DNN/notifUri) captured under the association lock, so the caller can
  // release the lock before this blocking SMF round-trip [CP.22]. `outcome`
  // carries the TS 29.512 Table 5.7.3-2 classification (permanent/temporary/
  // transport-ambiguous/etc.) that `status_code` alone can't express.
  sm_policy::status_code send_sm_policy_control_update_notify(
      const oai::_3gpp::model::SmPolicyContextData& context,
      const std::shared_ptr<const oai::_3gpp::model::SmPolicyDecision>& decision,
      sm_policy::smf_notify_outcome& outcome);

  void handle_session_binding_request(
      const std::optional<std::string>& ipv4,
      const std::optional<std::string>& supi,
      const std::optional<std::string>& dnn,
      std::optional<std::string>& assoc_id,
      oai::_3gpp::model::SmPolicyDecision& decision, std::uint64_t& version);

  // Looks up an association's CURRENT decision + version directly by its
  // already-known association_id.
  // Unlike handle_session_binding_request, takes no (ipv4, supi, dnn) --
  // the caller already has the association_id and just wants a fresh
  // snapshot, e.g. immediately before Policy Authorization's own
  // apply_with_retry call for a compensating rollback.
  void handle_get_association_decision(
      const std::string& association_id, bool& found,
      oai::_3gpp::model::SmPolicyDecision& decision, std::uint64_t& version);

  // Optimistic, version-checked commit ONLY -- no persist-triggered notify,
  // no signal. Applies
  // `delta` if the association is still at `expected_version`; otherwise
  // reports a conflict (with the current version/decision) via `out` for the
  // caller to retry against. Persists the committed decision (cheap/local)
  // before returning. The caller (decision_applier, via
  // pcf_policy_authorization::push_decision_change) is responsible for
  // calling handle_notify_committed_decision_request afterward if this
  // committed -- splitting the two steps this way means nothing here needs
  // to invoke anything the caller handed in.
  void handle_commit_decision_request(
      std::optional<std::string>& association_id, std::uint64_t expected_version,
      const oai::pcf::app::sm_policy_delta& delta,
      oai::pcf::app::decision_apply_result& out);

  // Notify the SMF of a decision this same PA instance just committed (via
  // handle_commit_decision_request) and return the classified outcome
  // directly. Re-fetches the association's live decision + context under
  // lock immediately before sending (same discipline drain_retry_queue's
  // delayed path uses -- never resend a frozen snapshot). Does not fire
  // sm_policy_update_failed -- that signal is reserved for
  // drain_retry_queue's delayed-discovery path; the caller here is already
  // synchronously waiting for the answer.
  void handle_notify_committed_decision_request(
      const std::string& association_id, std::uint64_t version,
      oai::pcf::app::sm_policy::smf_notify_outcome& outcome);

  // TODO [QOS] Cross-service coordination still to build on this side
  // [TS 29.513 §5.2.2.2]: active PCC-rule conflict detection and an SM-side
  // id/precedence-band convention [TS 23.503 §6.1.3.7, TS 29.512 §4.1.4.2.1],
  // and network-slice resource admission control [TS 29.512 §4.2.6.8,
  // TS 23.503 §6.1.4]. Today collisions are avoided by construction (the PA
  // side's id prefix + reserved precedence band) and the only capacity gate is
  // the per-session cumulative Session-AMBR check in validate_qos_authorization().

  // TODO [QOS-MON] Monitoring coordination (Phase 4) [TS 29.512 §4.2.3.25].

  // for Event Handling
  pcf_event& m_event_sub;
  bs2::connection m_sm_session_binding_connection;
  bs2::connection m_sm_update_decision_connection;
  bs2::connection m_notify_committed_decision_connection;
  bs2::connection m_task_tick_connection;
  bs2::connection m_get_association_decision_connection;
};
}  // namespace oai::pcf::app
#endif /* FILE_PCF_SM_POLICY_CONTROL_SEEN */
