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
    oai::pcf::app::notify_failure_recovery_policy notify_failure_recovery,
    http_send_fn http_send)
    : m_retry_drain_queue(
          notify_failure_recovery.retry_drain_ttl,
          notify_failure_recovery.retry_drain_max_entries,
          notify_failure_recovery.max_notify_retries,
          notify_failure_recovery.retry_backoff_initial),
      m_http_send(
          http_send ? std::move(http_send)
                    : http_send_fn([](method_e m, const request& r) {
                        return http_client_inst->send_http_request(m, r);
                      })),
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
          &pcf_smpc::handle_commit_decision_request, this,
          boost::placeholders::_1, boost::placeholders::_2,
          boost::placeholders::_3, boost::placeholders::_4));

  m_notify_committed_decision_connection =
      m_event_sub.subscribe_notify_committed_decision(boost::bind(
          &pcf_smpc::handle_notify_committed_decision_request, this,
          boost::placeholders::_1, boost::placeholders::_2,
          boost::placeholders::_3));

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
    const oai::_3gpp::model::SmPolicyContextData& context,
    const std::shared_ptr<const oai::_3gpp::model::SmPolicyDecision>& decision,
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

  const oai::_3gpp::model::SmPolicyDecision& dec = *decision;
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
  response resp = m_http_send(method_e::POST, req);

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

    // TODO [QOS-SUB] Coordinate AF notifications once the SMF has applied the
    // update (Phase 3, §2.6) [TS 29.513 §5.2.2.3, TS 29.514 §4.2.5]: find the
    // app-sessions bound to this association
    // (app_session_storage::find_by_association), then emit
    // SUCCESSFUL_RESOURCES_ALLOCATION to those that subscribed [§4.2.5.8].

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
  // The decision handed back below already carries the QoS baseline Policy
  // Authorization needs: the authorized Session-AMBR / default 5QI-ARP that
  // create_sm_policy_handler() put in a SessionRule [TS 29.512 §4.2.6.6.1], plus
  // every PCC rule and QosData currently installed. Slice-level resource
  // utilisation is not included -- see the admission-control TODO in the header.

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
}

//------------------------------------------------------------------------------
void pcf_smpc::handle_get_association_decision(
    const std::string& association_id, bool& found,
    oai::_3gpp::model::SmPolicyDecision& decision, std::uint64_t& version) {
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

void pcf_smpc::handle_commit_decision_request(
    std::optional<std::string>& association_id, std::uint64_t expected_version,
    const oai::pcf::app::sm_policy_delta& delta,
    oai::pcf::app::decision_apply_result& out) {
  // Merging is the delta apply itself: upsert-by-key over qosDecs/pccRules/
  // qosChars/traffContDecs [TS 29.512 §4.2.6.6.2]. Authorization against
  // operator policy and the subscribed Session-AMBR already ran on the Policy
  // Authorization side against this same base [TS 29.512 §4.2.6.6.1], and
  // referential integrity was checked pre-notification, so nothing is
  // re-validated here. Conflict detection and slice admission control remain --
  // see the TODOs in the header.

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
      // state; nothing is applied or persisted. The caller retries.
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
    // Capture the context under the lock so persist runs off-lock
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
  // Reached only on commit (conflicts/not-found returned above). Persist
  // against the immutable post-commit snapshot.
  if (!context.getSupi().empty()) {
    m_policy_storage->insert_supi_decision(context.getSupi(), *out.decision);
  } else if (!context.getDnn().empty()) {
    m_policy_storage->insert_dnn_decision(context.getDnn(), *out.decision);
  } else {
    Logger::pcf_app().error("Failed to update policy decision");
  }
}

void pcf_smpc::handle_notify_committed_decision_request(
    const std::string& association_id, std::uint64_t version,
    smf_notify_outcome& outcome) {
  // Re-fetch the association's LIVE decision + context under lock
  // immediately before this attempt (same discipline drain_retry_queue's
  // delayed path uses -- never resend a frozen snapshot; an unrelated
  // disjoint-key commit may have landed on this association since PA's
  // commit call returned).
  //
  //  PA already  can be configured to run multiple HTTP workers
  // so a DIFFERENT concurrent request bound to the SAME
  // association can acquire m_associations_mutex and commit its own delta
  // in the gap between this request's own commit releasing the lock and
  // this re-fetch reacquiring it. "Same thread, same request, nothing else
  // ran in between" does not imply "no other thread touched this
  // association in between" -- the mutex serializes individual
  // acquisitions, it does not serialize across two acquisitions made by the
  // same caller. Skipping this would silently resend a stale snapshot.
  std::shared_ptr<const oai::_3gpp::model::SmPolicyDecision> decision;
  oai::_3gpp::model::SmPolicyContextData context;
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
    // Association gone (e.g. concurrently deleted) in the narrow window
    // between PA's commit call returning and this call -- nothing to
    // notify. Conservative: don't claim a confirmed outcome either way.
    outcome = smf_notify_outcome::transport_ambiguous;
    return;
  }

  outcome = smf_notify_outcome::applied;
  auto ret = send_sm_policy_control_update_notify(context, decision, outcome);
  if (ret != status_code::CREATED) {
    Logger::pcf_app().error(
        "Policy update notification failed for association %s: outcome=%s",
        association_id.c_str(), to_string(outcome));

    switch (outcome) {
      case smf_notify_outcome::permanent_rejection:
        // TS 29.512 Table 5.7.3-2: the SMF has told us, unambiguously, that
        // it will not apply this change -- the only outcome Policy
        // Authorization may act on with a compensating rollback.
        // Reported directly via `outcome`
        // to the caller (Policy Authorization, already synchronously
        // waiting for this call to return) -- no signal fired here.
        break;
      case smf_notify_outcome::temporary_rejection:
      case smf_notify_outcome::transport_ambiguous:
        // Bounded retry, never rollback [§5.1/§5.2] -- drained off task_tick
        // (m_task_tick_connection, this class's constructor).
        m_retry_drain_queue.enqueue(association_id, version);
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
    std::shared_ptr<const oai::_3gpp::model::SmPolicyDecision> decision;
    oai::_3gpp::model::SmPolicyContextData context;
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
      const auto drain_outcome =
          m_retry_drain_queue.report_attempt(association_id, version, true, now);
      Logger::pcf_app().debug(
          "drain_retry_queue: association %s version %lu gone -> %s",
          association_id.c_str(), version, to_string(drain_outcome));
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
    // exhaust (report_attempt logs the exhaustion itself at ERROR -- this
    // debug line traces every attempt's outcome, not just the terminal one).
    const bool resolved = outcome == smf_notify_outcome::applied ||
                           outcome == smf_notify_outcome::permanent_rejection;
    const auto drain_outcome = m_retry_drain_queue.report_attempt(
        association_id, version, resolved, now);
    Logger::pcf_app().debug(
        "drain_retry_queue: association %s version %lu -> %s",
        association_id.c_str(), version, to_string(drain_outcome));
  }
}

//------------------------------------------------------------------------------
status_code pcf_smpc::create_sm_policy_handler(
    const SmPolicyContextData& context, SmPolicyDecision& decision,
    std::string& association_id, std::string& problem_details) {
  // The QoS baseline for this association is established below by
  // authorize_session_rule_into() (subscribed Session-AMBR / default 5QI-ARP ->
  // SessionRule) [TS 29.512 §4.2.6.6.1]. Slice bandwidth reservation is not
  // done -- see the admission-control TODO in the header.

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

  // TODO [QOS] This is where the SMF's own PCC rule error reports arrive
  // ("ruleReports"/"sessRuleReports" in SmPolicyUpdateContextData) [TS 29.512
  // §4.2.4.15, §4.2.4.7]. They are currently NOT read: redecide() only switches
  // on repPolicyCtrlReqTriggers, so a rule the SMF failed to install -- or a QoS
  // flow it later terminated -- leaves this PCF believing the QoS is active,
  // with no compensating rollback and no AF notification.

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
