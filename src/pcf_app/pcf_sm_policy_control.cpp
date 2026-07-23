/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "pcf_sm_policy_control.hpp"
#include "logger.hpp"
#include "pcf_config.hpp"
#include "sm_policy/policy_decision.hpp"
#include "sm_policy/qos_session_authorization.hpp"
#include "sm_policy/smf_notify_response_classifier.hpp"
#include "SmPolicyDecision.h"

#include <boost/uuid/uuid_io.hpp>
#include <unordered_map>
#include <map>
#include <memory>
#include <string>
#include <optional>
#include "nlohmann/json.hpp"
#include "3gpp_29.500.h"
#include "http_client.hpp"

using namespace oai::pcf::app;
using namespace oai::pcf::app::sm_policy;
using namespace oai::config::pcf;
using namespace oai::_3gpp::model;
using namespace oai::_3gpp::model;
using namespace oai::http;

using namespace std;

extern std::shared_ptr<oai::http::http_client> http_client_inst;

namespace {
// Retry-drain heartbeat period [N5_QoS_Phase2_§2.8 plan §5.2] -- well above
// task_tick's raw 1ms rate, since nothing here needs finer granularity than
// the backoff schedule itself. An internal polling detail, not an operator
// policy choice, so unlike TTL/cap/retry-count/backoff it isn't config-driven.
constexpr std::uint64_t kRetryDrainCheckPeriodMs = 1000;
}  // namespace

//------------------------------------------------------------------------------
pcf_smpc::pcf_smpc(
    const std::shared_ptr<oai::pcf::app::sm_policy::policy_storage>&
        policy_storage,
    pcf_event& ev, oai::pcf::app::operator_qos_policy qos_authorization_policy,
    oai::pcf::app::notify_failure_recovery_policy notify_failure_recovery)
    : m_retry_drain_queue(
          notify_failure_recovery.retry_drain_ttl,
          notify_failure_recovery.retry_drain_max_entries,
          notify_failure_recovery.max_notify_retries,
          notify_failure_recovery.retry_backoff_initial),
      m_event_sub(ev) {
  m_policy_storage           = policy_storage;
  m_qos_authorization_policy = std::move(qos_authorization_policy);

  std::function<void(const std::shared_ptr<policy_decision>& decision)> f =
      std::bind(&pcf_smpc::handle_policy_change, this, std::placeholders::_1);

  m_policy_storage->subscribe_to_decision_change(f);

  m_sm_session_binding_connection =
      m_event_sub.subscribe_sm_session_binding(boost::bind(
          &pcf_smpc::handle_session_binding_request, this,
          boost::placeholders::_1, boost::placeholders::_2,
          boost::placeholders::_3, boost::placeholders::_4,
          boost::placeholders::_5, boost::placeholders::_6));

  m_sm_update_decision_connection =
      m_event_sub.subscribe_sm_update_decision(boost::bind(
          &pcf_smpc::handle_update_decision_request, this,
          boost::placeholders::_1, boost::placeholders::_2,
          boost::placeholders::_3, boost::placeholders::_4));

  m_task_tick_connection = m_event_sub.subscribe_task_nf_heartbeat(
      boost::bind(
          &pcf_smpc::drain_retry_queue, this, boost::placeholders::_1),
      kRetryDrainCheckPeriodMs);

  m_get_association_decision_connection =
      m_event_sub.subscribe_sm_get_association_decision(boost::bind(
          &pcf_smpc::handle_get_association_decision, this,
          boost::placeholders::_1, boost::placeholders::_2,
          boost::placeholders::_3, boost::placeholders::_4));
}

void pcf_smpc::handle_policy_change(
    const std::shared_ptr<policy_decision>& /* decision */) {
  Logger::pcf_app().warn("Policy changed, but not implemented!");
}

sm_policy::status_code pcf_smpc::send_sm_policy_control_update_notify(
    const oai::model::pcf::SmPolicyContextData& context,
    const std::shared_ptr<const oai::model::pcf::SmPolicyDecision>& decision,
    smf_notify_outcome& outcome) {
  // Safe default: if some future edit adds a path below that forgets to set
  // `outcome`, fail toward "ambiguous, retry-only" rather than toward
  // "applied" or an unset value -- consistent with §5.1's "when ambiguous,
  // don't rollback" posture.
  outcome = smf_notify_outcome::transport_ambiguous;
  // Notifies the SMF with the FULL decision (the SMF diffs it itself). Operates
  // on an immutable snapshot captured under the association lock, so this
  // blocking round-trip runs off-lock [CP.22].
  //
  // TODO [QOS-SMF] Populate QosMonDecs (Phase 4) and any TraffContDecs the SMF
  // needs for QoS steering [TS 29.512 §5.6.2.40, §5.6.2.3]; qosChars and QoS
  // PccRules/QosData are already carried.

  const oai::model::pcf::SmPolicyDecision& dec = *decision;
  std::string uri = context.getNotificationUri() + "/update";
  nlohmann::json json_data;
  nlohmann::json decision_json;
  to_json(decision_json, dec);

  json_data["smPolicyDecision"] = decision_json;

  const std::string& supi = context.getSupi();

  Logger::pcf_app().info(
      "Sending SM Policy Update Notification for SUPI %s: uri -> %s",
      supi.c_str(), uri.c_str());

  Logger::pcf_app().debug(
      "SM Policy Update Notification payload: %zu PCC rule(s), %zu QosData, "
      "%zu QosChars, %zu QosMonDecs, %zu TraffContDecs",
      dec.getPccRules().size(), dec.getQosDecs().size(),
      dec.getQosChars().size(), dec.getQosMonDecs().size(),
      dec.getTraffContDecs().size());
  const std::string request_body = json_data.dump();
  Logger::pcf_app().trace(
      "SM Policy Update Notification request body -> SMF: %s",
      request_body.c_str());

  request req   = http_client_inst->prepare_json_request(uri, request_body);
  response resp = http_client_inst->send_http_request(method_e::POST, req);

  // TODO [QOS][ROLLBACK] Deferred: resp has
  // no way to distinguish a connection/gateway failure from a timeout -- both
  // leave status_code at 0. Telling them apart needs oai-cn5g-common-src's
  // http_client to surface cpr::Response::error.code (shared across every
  // CN5G NF; a separate, cross-repo change deferred for now). Until that
  // lands, treat any status_code == 0 outcome as the more conservative of the
  // two -- bounded retry, never rollback -- consistent with §5.1's "when
  // ambiguous, don't rollback" posture.
  Logger::pcf_app().debug(
      "SM Policy Update Notification response from SMF for SUPI %s: HTTP %d",
      supi.c_str(), resp.status_code);
  Logger::pcf_app().trace(
      "SM Policy Update Notification response body <- SMF: %s",
      resp.body.c_str());

  // Classification (TS 29.512 Table 5.7.3-2 / clause 4.2.3.2) is a pure
  // function of (http status, parsed body) -- extracted so it's directly
  // unit-tested without mocking HTTP [N5_QoS_Phase2_§2.8 plan §5.1].
  // (Previously this parsed resp.body -- a std::string -- directly as a
  // nlohmann::json via from_json(resp.body, problem_details):
  // nlohmann::json's implicit std::string constructor builds a JSON *string
  // scalar*, not a parsed object, so `cause`/`detail` were never actually
  // populated -- the USER_UNKNOWN branch had never fired against a real SMF
  // response. get_json() parses properly.)
  const auto classification =
      classify_smf_notify_response(resp.status_code, resp.get_json());
  outcome = classification.outcome;

  if (classification.outcome == smf_notify_outcome::applied) {
    // TODO [PAS] check if for required headers
    Logger::pcf_app().info(
        "%s for SUPI %s", classification.info.c_str(), supi.c_str());

    // TODO [QOS-SUB] Coordinate Application Function notifications after successful SMF update [TS 29.513 §5.2.2.3, TS 29.514 §4.2.5]
    // Following successful SMF notification, trigger AF notifications as per 3GPP TS 29.514:
    //
    // 1. EXTRACT AF NOTIFICATION TARGETS [TS 29.513 §5.2.2.2.2]:
    //    - Identify AF applications affected by the policy update
    //    - Retrieve AF notification URIs from associated application sessions [TS 29.514 §5.6.2.6]
    //    - Determine notification event types required by each AF [TS 29.514 §5.6.2.6]
    //
    // 2. PREPARE AF NOTIFICATION DATA [TS 29.514 §4.2.5]:
    //    - Extract QoS status changes from the policy decision [TS 29.514 §5.6.2.15]
    //    - Compile monitoring measurements if available from UPF reports [TS 29.514 §5.6.2.37]
    //    - Prepare session context updates for AF consumption [TS 29.514 §5.6.2.9]
    //
    // 3. TRIGGER ASYNCHRONOUS AF NOTIFICATIONS [TS 29.500 §6.2]:
    //    - Emit events to Policy Authorization service for AF notification delivery
    //    - Include session binding information to correlate AF applications
    //    - Schedule retry for failed AF notifications with appropriate backoff [TS 29.500 §5.2.8]
    //
    // 4. LOG COORDINATION STATUS:
    //    - Track successful AF notification triggers
    //    - Log any coordination failures for troubleshooting
    //    - Update AF subscription health status [TS 29.500 §5.2.6]
    //
    // Example coordination:
    // std::string supi = association.get_sm_policy_context_data().getSupi();
    // std::string dnn = association.get_sm_policy_context_data().getDnn();
    // m_event_sub.coordinate_af_notifications(supi, dnn, association.get_sm_policy_decision_dto());

    return classification.response;
  }

  if (classification.partial_failure_entries > 0) {
    Logger::pcf_app().warn(
        "%s for SUPI %s: HTTP %d (%zu entries) -- outcome=%s",
        classification.info.c_str(), supi.c_str(), resp.status_code,
        classification.partial_failure_entries, to_string(outcome));
    return classification.response;
  }

  Logger::pcf_app().warn(
      "%s -- Details: %s - %s", classification.info.c_str(),
      classification.cause.c_str(), classification.detail.c_str());
  return classification.response;
}

void pcf_smpc::handle_session_binding_request(
    const std::optional<std::string>& ipv4,
    const std::optional<std::string>& supi,
    const std::optional<std::string>& dnn, std::optional<std::string>& assoc_id,
    oai::_3gpp::model::SmPolicyDecision& decision, std::uint64_t& version) {
  // TODO [QOS] Handle QoS requirements during session binding [TS 29.513 §5.2.2.1, TS 29.512 §4.2.2]
  // When Policy Authorization requests session binding, provide comprehensive QoS context:
  //
  // 1. QOS CONTEXT RETRIEVAL [TS 29.512 §4.2.2.2, TS 23.503 §6.1.3.2]:
  //    - Retrieve existing QoS policies for this SUPI/DNN combination
  //    - Include base QoS characteristics from subscription profile [TS 29.512 §4.2.6.6.1]
  //    - Provide network slice-specific QoS limits and policies [TS 29.512 §4.2.6.7, TS 23.503 §6.1.4]
  //
  // 2. QOS BASELINE ESTABLISHMENT [TS 29.512 §4.2.2.2, TS 23.503 §6.1.3.2.3]:
  //    - Set baseline QoS parameters that Policy Authorization can build upon
  //    - Ensure default QoS flows are properly configured [TS 23.501 §5.7.1.1]
  //    - Provide QoS rule precedence ranges available for Policy Auth use [TS 23.503 §6.3.1]
  //
  // 3. RESOURCE AVAILABILITY [TS 29.512 §4.2.6.8, TS 23.503 §6.1.4]:
  //    - Include current QoS resource utilization information
  //    - Provide available bandwidth and priority level ranges [TS 29.512 §4.2.6.8.2]
  //    - Share network congestion status affecting QoS decisions

  // TODO: support multiple sessions

  std::shared_ptr<std::string> association_id =
      m_policy_storage->find_association(ipv4, supi, dnn);

  if (!association_id) {
    Logger::pcf_app().debug(
        fmt::format("handle_session_binding_request, association_id is null"));
    return;
  }

  assoc_id = association_id->c_str();

  std::unique_lock lock_assocations(m_associations_mutex);
  auto iter = m_associations.find(association_id->c_str());
  if (iter == m_associations.end()) {
    Logger::pcf_app().info(fmt::format(
        "Could not find policy association: ID {} not found",
        association_id->c_str()));
    return;
  }

  // Hand back the decision and the version it was read at, under the same lock,
  // so Policy Authorization can later present that version for an optimistic
  // (version-checked) apply.
  decision = iter->second.get_sm_policy_decision_dto();
  version  = iter->second.decision_version();

  // Get PCC from decision
}

//------------------------------------------------------------------------------
void pcf_smpc::handle_get_association_decision(
    const std::string& association_id, bool& found,
    oai::model::pcf::SmPolicyDecision& decision, std::uint64_t& version) {
  found = false;

  std::shared_lock lock_associations(m_associations_mutex);
  auto iter = m_associations.find(association_id);
  if (iter == m_associations.end()) {
    Logger::pcf_app().info(fmt::format(
        "handle_get_association_decision: association {} not found",
        association_id));
    return;
  }

  found    = true;
  decision = iter->second.get_sm_policy_decision_dto();
  version  = iter->second.decision_version();
}

void pcf_smpc::handle_update_decision_request(
    std::optional<std::string>& association_id, std::uint64_t expected_version,
    const oai::pcf::app::sm_policy_delta& delta,
    oai::pcf::app::decision_apply_result& out) {
  // TODO [QOS] Process QoS policy updates from Policy Authorization Service [TS 29.513 §5.2.2.2.2, TS 29.512 §4.2.3.2]
  // This function receives updated policy decisions from pcf_policy_authorization
  // containing QoS requirements that need to be integrated with existing SM policies:
  //
  // 1. CONFLICT RESOLUTION [TS 23.503 §6.1.3.7]:
  //    - Check for PCC rule ID conflicts between Policy Auth and SM Policy Control [TS 29.512 §4.1.4.2.1]
  //    - Ensure QoS rule precedence values don't overlap with existing SM rules [TS 29.512 §5.6.2.6]
  //    - Resolve conflicts between Policy Auth QoS requirements and SM QoS policies [TS 23.503 §6.1.3.7]
  //
  // 2. QOS DATA INTEGRATION [TS 29.512 §4.2.6.6.2]:
  //    - Merge QosData entries from Policy Authorization with existing SM QoS data [TS 29.512 §5.6.2.8]
  //    - Validate QoS parameters against subscription and network slice limits [TS 29.512 §4.2.6.6.1, TS 23.503 §6.1.4]
  //    - Update QoS Characteristics for new or modified 5QI values [TS 29.512 §4.2.6.6.3, §5.6.2.16]
  //
  // 3. PCC RULE COORDINATION [TS 29.512 §4.2.6.2.1]:
  //    - Generate unique PCC rule IDs that don't conflict across services [TS 29.512 §4.1.4.2.1]
  //    - Assign appropriate precedence values considering both Policy Auth and SM rules [TS 23.503 §6.3.1]
  //    - Ensure QoS enforcement actions are consistent across rule sets [TS 23.503 §6.1.3.7]

  // Optimistic, version-checked apply. Under the association lock we commit the
  // delta copy-on-write ONLY IF the association is still at the version the
  // caller read; on a mismatch we return the current version+decision so the
  // caller re-derives against it and retries. This serialises concurrent
  // updates to one association, closing both the lost-update race and the
  // stale-cumulative-limit race (the retrying caller re-validates against the
  // committed base) -- see the retry loop in pcf_policy_authorization.cpp.
  //
  // First-come-first-served / last-committer-wins: serialisation orders the
  // commits, it does NOT merge conflicting intents. Two requests changing the
  // SAME key (same app-session + medCompN) still resolve by whoever commits
  // last -- the loser re-derives on top and overwrites. That is the intended
  // semantics for concurrent modification of one resource; cross-session
  // updates (disjoint keys) all survive because the delta only carries the
  // keys its request actually changed.
  oai::_3gpp::model::SmPolicyContextData context;
  {
    std::unique_lock lock_associations(m_associations_mutex);
    auto iter = m_associations.find(association_id.value());
    if (iter == m_associations.end()) {
      // Association gone (e.g. PDU session released concurrently); no retry
      // helps, so report a terminal (non-committed) result.
      Logger::pcf_app().info(fmt::format(
          "Could not update policy association: ID {} not found",
          association_id.value()));
      out = {false, 0, nullptr};
      return;
    }

    const std::uint64_t current = iter->second.decision_version();
    if (current != expected_version) {
      // Someone committed since the caller read its base. Hand back the current
      // state; nothing is applied, persisted, or notified. The caller retries.
      out = {false, current, iter->second.snapshot_decision()};
      Logger::pcf_app().debug(fmt::format(
          "Update rejected for association {}: version {} != expected {} "
          "(concurrent update); caller will re-derive and retry",
          association_id.value(), current, expected_version));
      return;
    }

    iter->second.apply_delta(delta);  // copy-on-write + version bump
    out = {true, iter->second.decision_version(),
           iter->second.snapshot_decision()};
    // Capture the context under the lock so persist/notify run off-lock
    // [CP.22: never hold a lock across a blocking/foreign call].
    context = iter->second.get_sm_policy_context_data();
  }  // m_associations_mutex released

  // TODO [PAS] confirm if the storage should be updated
  /**
   * The changes from the update policy authorisation request should be
   * be for an existing policy association for an existing PDU session.
   * THe SMF gets the updated policy decision from the PCF for which the
   * PCF reads the new decision from the policy storage. However the policy
   * storage persists over new UE connections.
   *
   * The TODO is to confirm if the policy storage should be updated with the
   * new decision and to look for an alternative way to store the updates for
   * the policy decisions that are not persisted.
   */
  // Reached only on commit (conflicts/not-found returned above). Persist +
  // notify against the immutable post-commit snapshot.
  if (!context.getSupi().empty()) {
    m_policy_storage->insert_supi_decision(context.getSupi(), *out.decision);
  } else if (!context.getDnn().empty()) {
    m_policy_storage->insert_dnn_decision(context.getDnn(), *out.decision);
  } else {
    Logger::pcf_app().error("Failed to update policy decision");
  }

  // Notify the SMF against the immutable snapshot, off-lock. The notification
  // still carries the full decision (the SMF diffs it itself); only PCF-internal
  // application is incremental.
  smf_notify_outcome outcome = smf_notify_outcome::applied;
  auto ret = send_sm_policy_control_update_notify(context, out.decision, outcome);
  if (ret != status_code::CREATED) {
    Logger::pcf_app().error(
        "Policy update notification failed for association %s: outcome=%s",
        association_id.value_or("<none>").c_str(), to_string(outcome));

    switch (outcome) {
      case smf_notify_outcome::permanent_rejection:
        // TS 29.512 Table 5.7.3-2: the SMF has told us, unambiguously, that
        // it will not apply this change -- the only outcome Policy
        // Authorization may act on with a compensating rollback
        // [N5_QoS_Phase2_§2.8 plan §5.3]. `out.version` is the same
        // post-commit version PA's apply_with_retry recorded this commit's
        // pending_rollback_tracker entry under.
        m_event_sub.sm_policy_update_failed(
            association_id.value(), out.version, outcome);
        break;
      case smf_notify_outcome::temporary_rejection:
      case smf_notify_outcome::transport_ambiguous:
        // Bounded retry, never rollback [§5.1/§5.2] -- drained off task_tick
        // (m_task_tick_connection, this class's constructor).
        m_retry_drain_queue.enqueue(association_id.value(), out.version);
        break;
      default:
        // applied/partial_failure never reach here: applied returns CREATED
        // above, and this classifier never produces partial_failure on its
        // own (it already routes 200-with-partial-report straight to
        // permanent/temporary_rejection per §5.1).
        break;
    }
  }
}

//------------------------------------------------------------------------------
void pcf_smpc::drain_retry_queue(std::uint64_t /*tick_ms*/) {
  const auto now = std::chrono::steady_clock::now();
  m_retry_drain_queue.sweep_expired(now);

  for (const auto& [association_id, version] : m_retry_drain_queue.due_entries(now)) {
    // Re-fetch the association's LIVE decision + context under lock
    // immediately before this attempt (finding J) -- never resend a frozen
    // snapshot, since an unrelated disjoint-key commit may have landed on
    // this association since it was queued.
    std::shared_ptr<const oai::model::pcf::SmPolicyDecision> decision;
    oai::model::pcf::SmPolicyContextData context;
    bool association_found;
    {
      std::shared_lock lock_associations(m_associations_mutex);
      auto iter          = m_associations.find(association_id);
      association_found  = iter != m_associations.end();
      if (association_found) {
        decision = iter->second.snapshot_decision();
        context  = iter->second.get_sm_policy_context_data();
      }
    }  // m_associations_mutex released [CP.22]

    if (!association_found) {
      // Association gone (e.g. PDU session released concurrently); nothing
      // left to retry.
      m_retry_drain_queue.report_attempt(association_id, version, true, now);
      continue;
    }

    smf_notify_outcome outcome = smf_notify_outcome::applied;
    send_sm_policy_control_update_notify(context, decision, outcome);

    if (outcome == smf_notify_outcome::permanent_rejection) {
      // Discovered on a retry rather than the first attempt -- fires the
      // same SM->PA event either way [§5.3].
      m_event_sub.sm_policy_update_failed(association_id, version, outcome);
    }

    // applied and permanent_rejection are both terminal for this queue (one
    // resolved cleanly, the other now owned by Policy Authorization);
    // temporary_rejection/transport_ambiguous reschedule with backoff, or
    // exhaust (report_attempt logs the exhaustion itself).
    const bool resolved = outcome == smf_notify_outcome::applied ||
                           outcome == smf_notify_outcome::permanent_rejection;
    m_retry_drain_queue.report_attempt(association_id, version, resolved, now);
  }
}

//------------------------------------------------------------------------------
status_code pcf_smpc::create_sm_policy_handler(
    const SmPolicyContextData& context, SmPolicyDecision& decision,
    std::string& association_id, std::string& problem_details) {
  std::shared_ptr<policy_decision> chosen_decision =
      m_policy_storage->find_policy(context);

  if (!chosen_decision) {
    problem_details = fmt::format(
        "SM policy request from SUPI {}: No policies found", context.getSupi());
    Logger::pcf_app().debug(fmt::format(problem_details));
    return status_code::CONTEXT_DENIED;
  }

  association_id = std::to_string(m_association_id_generator.get_uid());

  individual_sm_association assoc(context, *chosen_decision, association_id);

  status_code res = assoc.decide_policy(decision);

  // XXX: Perform session binding
  m_policy_storage->insert_associations(context, association_id);

  if (res != status_code::CREATED) {
    problem_details = fmt::format(
        "SM Policy request from SUPI {}: Invalid policy decision provisioned",
        context.getSupi());
    Logger::pcf_app().debug(fmt::format(problem_details));
  } else {
    // Authorize the subscribed Session-AMBR / default 5QI/ARP (forwarded by the
    // SMF in the context) into a SessionRule on the decision [TS 29.512
    // §4.2.6.6.1]. Done here -- after decide_policy, before storing -- so it
    // applies uniformly across every policy_decision subclass and lands in both
    // the decision returned to the SMF and the copy persisted on the
    // association (so a later sm_session_binding serves it to Policy
    // Authorization for QoS validation, TS 29.514 §4.1.3.1).
    sm_policy::authorize_session_rule_into(
        decision, context, association_id, m_qos_authorization_policy);
    assoc.set_sm_policy_decision(decision);

    std::unique_lock lock_assocations(m_associations_mutex);
    m_associations.insert(std::make_pair(association_id, assoc));

    Logger::pcf_app().info(fmt::format(
        "Created Policy Decision for SUPI {} with ID {}", context.getSupi(),
        association_id));
  }
  return res;
}

//------------------------------------------------------------------------------
sm_policy::status_code pcf_smpc::delete_sm_policy_handler(
    const std::string& id, const SmPolicyDeleteData& /* delete_data */,
    std::string& problem_details) {
  // TODO for now, just delete, ignore the delete_data
  std::unique_lock lock_associations(m_associations_mutex);
  auto iter = m_associations.find(id);
  if (iter == m_associations.end()) {
    problem_details =
        fmt::format("Could not delete policy association: ID {} not found", id);
    Logger::pcf_app().info(problem_details);
    return status_code::NOT_FOUND;
  }
  m_associations.erase(iter);
  Logger::pcf_app().info(
      fmt::format("Deleted policy association with ID {}", id));

  // TODO [PAS]: Perform session binding delete

  return status_code::OK;
}

//------------------------------------------------------------------------------
sm_policy::status_code pcf_smpc::get_sm_policy_handler(
    const std::string& id, SmPolicyControl& control,
    std::string& problem_details) {
  Logger::pcf_app().debug(fmt::format("get_sm_policy_handler: ID {}", id));
  std::shared_lock lock_associations(m_associations_mutex);
  auto iter = m_associations.find(id);
  if (iter == m_associations.end()) {
    problem_details = fmt::format(
        "Could not retrieve policy association: ID {} not found", id);
    Logger::pcf_app().info(problem_details);
    return status_code::NOT_FOUND;
  }
  control.setContext(iter->second.get_sm_policy_context_data());
  control.setPolicy(iter->second.get_sm_policy_decision_dto());

  Logger::pcf_app().info(
      fmt::format("Retrieved policy association with ID {}", id));

  return status_code::OK;
}

//------------------------------------------------------------------------------
sm_policy::status_code pcf_smpc::update_sm_policy_handler(
    const std::string& id, const SmPolicyUpdateContextData& update_context,
    SmPolicyDecision& decision, std::string& problem_details) {
  Logger::pcf_app().info("Entering update_sm_policy_handler");
  std::unique_lock lock_associations(m_associations_mutex);
  auto iter = m_associations.find(id);

  if (iter == m_associations.end()) {
    problem_details =
        fmt::format("Could not update policy association: ID {} not found", id);
    Logger::pcf_app().info(problem_details);
    return status_code::NOT_FOUND;
  }

  // TODO [PAS]: Perform session binding update

  SmPolicyDecision new_decision;

  return iter->second.redecide_policy(
      update_context, decision, problem_details);
}

//------------------------------------------------------------------------------
pcf_smpc::~pcf_smpc() {
  Logger::pcf_app().debug("Delete PCF SMPC instance...");
}
