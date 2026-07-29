/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "pcf_policy_authorization.hpp"
#include "logger.hpp"
#include "pcf_config.hpp"
#include "pcf_event.hpp"
#include "sm_policy_delta.hpp"
#include "AppSessionContext.h"
#include "AppSessionContextReqData.h"
#include "AppSessionContextUpdateDataPatch.h"
#include "MediaComponentRm.h"
#include "FlowStatus.h"
#include "policy_auth/af_notify.hpp"
#include "policy_auth/app_session.hpp"
#include "policy_auth/decision_applier.hpp"

#include "AppSessionContextRespData.h"

#include <boost/uuid/uuid_io.hpp>
#include <exception>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>

using namespace oai::pcf::app;
using namespace oai::pcf::app::policy_auth;
using namespace oai::config::pcf;
using namespace oai::model::pcf;

using namespace std;

namespace {
// Bounded retries for the optimistic (version-checked) association apply. The
// contention window is only derive+validate, so a handful of attempts is ample;
// exhaustion surfaces as an error the AF can retry.
constexpr int kMaxApplyRetries = 3;

// Bitwise intersection of the AF's supported features with the PCF's, formatted
// as a 3GPP SupportedFeatures hex string [TS 29.500 §6.6.2, TS 29.571 §5.2.2].
// Phase 1: the PCF advertises no optional Npcf_PolicyAuthorization features, so
// the negotiated set is empty ("0"). When the PCF starts supporting a feature,
// set the corresponding bit(s) in kPcfSupportedFeatures.
std::string negotiate_supported_features(const std::string& af_supp_feat) {
  static constexpr unsigned long long kPcfSupportedFeatures = 0x0ULL;
  unsigned long long af = 0;
  try {
    if (!af_supp_feat.empty())
      af = std::stoull(af_supp_feat, nullptr, /*base=*/16);
  } catch (const std::exception&) {
    af = 0;  // unparseable / out of range -> negotiate no features
  }
  std::stringstream ss;
  ss << std::hex << std::nouppercase << (af & kPcfSupportedFeatures);
  return ss.str();  // "0" today
}
}  // namespace

//------------------------------------------------------------------------------
pcf_policy_authorization::pcf_policy_authorization(
    std::shared_ptr<policy_auth::policy_auth_context> context, pcf_event& ev)
    : m_context(std::move(context)),
      m_applier(
          [this](
              std::optional<std::string>& assoc_id,
              std::uint64_t expected_version, const sm_policy_delta& delta,
              decision_apply_result& result) {
            m_event_sub.sm_update_decision(
                assoc_id, expected_version, delta, result);
          },
          m_context->rollback_tracker(), kMaxApplyRetries),
      m_qos_deriver(
          m_context->qos_references(), m_context->qos_authorization_policy()),
      m_event_sub(ev) {
  // Invariant: connect only once,
  // here at construction, before any HTTP thread starts.
  m_sm_policy_update_failed_connection =
      m_event_sub.subscribe_sm_policy_update_failed(boost::bind(
          &pcf_policy_authorization::compensate_if_pending, this,
          boost::placeholders::_1, boost::placeholders::_2,
          boost::placeholders::_3));

  // TODO [QOS-SUB] Initialize the AF notification client, subscription registry
  // and delivery queue here (Phase 3) [TS 29.514 §4.2.5, TS 29.500 §6.2, §6.8].
  // TODO [QOS-MON] Initialize monitoring contexts and the report timer here,
  // and subscribe to UPF measurement reports (Phase 4) [TS 29.512 §4.2.3.25,
  // TS 23.503 §6.1.3.21].
}

//------------------------------------------------------------------------------
// Wraps m_applier.apply() with the post-commit notify + rollback-check, so
// no caller can commit a decision change without also notifying the SMF and
// checking whether that notify came back as a confirmed permanent rejection.
// Every handler
// (POST/PATCH/DELETE/rollback) calls this instead of m_applier.apply()
// directly.
status_code pcf_policy_authorization::push_decision_change(
    decision_apply_request request,
    const std::function<handler_result(
        const oai::model::pcf::SmPolicyDecision&,
        oai::model::pcf::SmPolicyDecision&)>& derive,
    sm_policy_delta& committed_delta, std::string& problem_details) {
  std::uint64_t committed_version = 0;
  const status_code push = m_applier.apply(
      request, derive, committed_delta, problem_details, committed_version);
  if (push != status_code::OK) return push;

  // Ask SM to notify the SMF of the commit we just made and get the
  // classified outcome back directly -- a plain synchronous call/return,
  // not a signal, since we're already blocked waiting for the answer.
  sm_policy::smf_notify_outcome outcome = sm_policy::smf_notify_outcome::applied;
  m_event_sub.notify_committed_decision(
      request.association_id.value(), committed_version, outcome);
  if (outcome == sm_policy::smf_notify_outcome::permanent_rejection) {
    // Discovered inline, on this same attempt -- nothing to race, since
    // m_applier.apply() already recorded this commit's pending_rollback_
    // tracker entry before returning OK, and this check runs synchronously
    // right after, on the same thread.
    compensate_if_pending(
        request.association_id.value(), committed_version, outcome);
  }
  return status_code::OK;
}

//------------------------------------------------------------------------------
// Optimistic-concurrency driver shared by POST/PATCH/DELETE, via m_applier
// (decision_applier.hpp). `derive` is the request's pure recompute
// (side-effect-free w.r.t. shared session state. It must derive into a
// throwaway scratch ledger, not the session's real ledger); the real
// ledger/context/version are updated by the caller only after this returns OK.
//
// Why the version-CAS (compare-and-swap) + re-derive is needed (worked
// examples). Binding hands PA
// a (decision, version) pair; PA derives a delta against that base, and the SM
// side applies it ONLY IF the association is still at that version.
//
//   1. Cross-session, disjoint keys -- always safe, even without retry.
//      Session S1 adds qos "..-S1-qos-1", S2 adds "..-S2-qos-1". The deltas
//      touch different keys, so applying them in either order yields the union.
//      A version conflict here just re-derives an identical (still-disjoint)
//      delta; the retry is harmless.
//
//   2. Cumulative Session-AMBR race -- the reason a per-key lock is NOT enough.
//      Authorized Session-AMBR = 100 Mbps. S1 and S2 both bind at version v,
//      each deriving a 60 Mbps non-GBR flow. Each validates fine against the
//      SAME stale base (60 <= 100). Without the CAS both commit -> 120 Mbps,
//      over the limit. WITH the CAS: S1 commits (v -> v+1); S2's apply is
//      rejected (v != v+1); S2 re-derives against the committed base, whose
//      cumulative is now 60, so validate_qos_authorization sees 60+60=120 > 100
//      and rejects S2 with 403. The over-subscription can no longer slip
//      through, because the cumulative check always runs against the base that
//      actually committed.
//
//   3. Same key, concurrent modify -- first-come-first-served / last-committer
//      -wins (a race that intentionally REMAINS). S1 and S2 both PATCH the same
//      medCompN (same qosId) at version v. Serialisation orders them: the first
//      commits, the second's CAS fails, it re-derives on top of the first and
//      overwrites it. No corruption, but the earlier writer's value is gone.
//      That is the intended semantics for concurrent modification of one
//      resource -- the delta only carries the keys a request changed, so nothing
//      *else* is lost; only the directly-contended field resolves last-wins.
//------------------------------------------------------------------------------
// Per-attempt recompute for POST /app-sessions (see the header for the
// contract): derive this request's QoS/SFC into `working`, authorize, merge
// and validate.
handler_result pcf_policy_authorization::derive_post_app_session(
    const oai::model::pcf::AppSessionContext& context,
    const std::string& app_session_id,
    const std::shared_ptr<policy_auth::app_session>& session,
    oai::model::pcf::SmPolicyDecision& working) {
  oai::model::pcf::SmPolicyDecision request_decision = {};  // SFC/QoS contributions
  policy_auth::qos_context scratch;  // throwaway: decouples the real ledger
  bool qos_flow_processed = false;

  if (context.getAscReqData().medComponentsIsSet()) {
    for (const auto& medComponent : context.getAscReqData().getMedComponents()) {
      const auto& med_component = medComponent.second;
      if (med_component.afSfcReqIsSet()) {
        handler_result r = policy_auth::handle_service_function_chaining(
            med_component.getAfSfcReq(), request_decision);
        if (r.problem_details.has_value()) return r;
        break;
      } else if (
          // Any MediaComponent bearing QoS intent [TS 29.513 §7.3.3].
          med_component.qosReferenceIsSet() ||
          med_component.medSubCompsIsSet() || med_component.marBwUlIsSet() ||
          med_component.marBwDlIsSet() || med_component.mirBwUlIsSet() ||
          med_component.mirBwDlIsSet()) {
        handler_result r = m_qos_deriver.handle_qos_requirements(
            med_component, app_session_id, working, scratch);
        if (r.problem_details.has_value()) return r;
        qos_flow_processed = true;
      }
    }
  } else if (context.getAscReqData().afSfcReqIsSet()) {
    handler_result r = policy_auth::handle_service_function_chaining(
        context.getAscReqData().getAfSfcReq(), request_decision);
    if (r.problem_details.has_value()) return r;
  }

  // Authorize against operator policy + the subscribed Session-AMBR. Owned =
  // this session's prior-committed ids (empty on create) + the ids just
  // derived into `scratch`; only owned flows are judged and summed
  // [TS 29.514 §4.1.3.1, TS 23.503 §6.1.3.2.3, TS 29.512 §4.2.6.6].
  if (qos_flow_processed) {
    std::vector<std::string> owned = session->qos().owned_qos_ids();
    const auto derived_ids         = scratch.owned_qos_ids();
    owned.insert(owned.end(), derived_ids.begin(), derived_ids.end());
    handler_result a = m_qos_deriver.validate_qos_authorization(working, owned);
    if (a.problem_details.has_value()) return a;
  }

  handler_result m = validate_and_merge_decision(request_decision, working);
  if (m.problem_details.has_value()) return m;

  // Pre-notification gate: never push a structurally/referentially
  // inconsistent decision [TS 29.512 §4.2.6.2, §5.6.2.4].
  handler_result v = policy_auth::validate_policy_decision(working);
  if (v.problem_details.has_value()) return v;

  return {};  // ok
}

//------------------------------------------------------------------------------
status_code pcf_policy_authorization::post_app_sessions_handler(
    const oai::model::pcf::AppSessionContext& context,
    std::string& app_session_id, std::string& problem_details) {
  // The decision session binding returns; base_decision snapshots it and the
  // per-attempt working copy is derived from it inside `derive` (below).
  oai::model::pcf::SmPolicyDecision current_decision = {};

  Logger::pcf_app().info("POST /app-sessions");

  const oai::model::pcf::AppSessionContextReqData reqContext =
      context.getAscReqData();
  std::optional<std::string> association_id = {};
  std::uint64_t bound_version               = 0;
  try {
    // Perform session binding (returns the association's decision + version).
    m_event_sub.sm_session_binding(
        reqContext.getUeIpv4(), reqContext.getSupi(), reqContext.getDnn(),
        association_id, current_decision, bound_version);
  } catch (const std::exception& e) {
    Logger::pcf_app().info(e.what());
    problem_details = "PDU_SESSION_NOT_AVAILABLE";
    return status_code::INTERNAL_SERVER_ERROR;
  }

  if (!association_id.has_value()) {
    Logger::pcf_app().debug("Failed to find session");
    return status_code::NOT_FOUND;
  }

  // Base the update on the decision + version session binding returned;
  // apply_with_retry re-derives against a newer base if a concurrent update
  // commits first, so this read-modify-write is serialisable [TS 29.512
  // §4.2.3.2].
  const oai::model::pcf::SmPolicyDecision base_decision = current_decision;

  // Authorise the service information (pure, base-independent) up front.
  handler_result auth_result = authorize_service_info(context.getAscReqData());
  if (auth_result.problem_details.has_value()) {
    problem_details = auth_result.problem_details.value();
    return auth_result.status.value();
  }

  // Create the app-session up front (storage-generated, restart-safe id) so the
  // derived QoS ids are stable across retries. Its ledger stays EMPTY until the
  // update commits (post-commit, below); derivation writes to a throwaway
  // scratch ledger, so a rejected/retried attempt leaves no trace on it.
  app_session_id = m_context->app_sessions().generate_id();
  auto session   = std::make_shared<policy_auth::app_session>(
      app_session_id, reqContext, association_id);

  // Per-attempt recompute (pure w.r.t. shared session state), called once per
  // apply() attempt against the current base; extracted as
  // derive_post_app_session since only genuinely per-request state (context,
  // app_session_id, session) remains to thread through it -- m_qos_deriver
  // holds the stable deps.
  auto derive = [this, &context, &app_session_id, &session](
                    const oai::model::pcf::SmPolicyDecision&,
                    oai::model::pcf::SmPolicyDecision& working)
      -> handler_result {
    return derive_post_app_session(context, app_session_id, session, working);
  };

  sm_policy_delta committed_delta;
  const status_code push = push_decision_change(
      {association_id, base_decision, bound_version, app_session_id}, derive,
      committed_delta, problem_details);
  if (push != status_code::OK) return push;

  // ---- post-commit side-effects (reached only once the delta committed) ----
  // Persist the app-session, reconcile its ledger with what actually committed,
  // and advance lifecycle. Deferred to here so a rejected/retried attempt has
  // no visible effect on shared state.
  m_context->app_sessions().insert(session);
  session->qos().apply_committed_delta(committed_delta);
  session->set_state(app_session_state::established);

  // TODO [QOS-SUB] Register the AF's notification endpoint and subscribed
  // events from reqContext here, then send the
  // SUCCESSFUL_RESOURCES_ALLOCATION notification if subscribed (Phase 3)
  // [TS 29.514 §4.2.6, §4.2.5.8].
  // TODO [QOS-MON] Configure monitoring thresholds from the request (Phase 4)
  // [TS 29.514 §4.2.2.23.1].

  // Return "201 Created" response to the HTTP POST request
  return status_code::CREATED;
}

//------------------------------------------------------------------------------
// Per-attempt recompute for PATCH /app-sessions/{id} (see the header for the
// contract): re-derive this PATCH's changes -- SFC, QoS modify/add, and
// REMOVED deletions -- into `working`, authorize, merge, validate, then apply
// the AF's JSON Merge Patch onto `req_context`. Ids are deterministic per
// medCompN, so re-deriving a component modifies its flow in place
// [TS 29.514 §4.2.3.2, TS 29.512 §4.2.6.2.1].
handler_result pcf_policy_authorization::derive_mod_app_session(
    const oai::model::pcf::AppSessionContextUpdateData& patch_asc,
    const std::string& app_session_id,
    const std::shared_ptr<policy_auth::app_session>& session,
    oai::model::pcf::AppSessionContextReqData& req_context,
    oai::model::pcf::SmPolicyDecision& working) {
  oai::model::pcf::SmPolicyDecision request_decision = {};  // SFC contributions
  policy_auth::qos_context scratch;  // throwaway: decouples the real ledger
  req_context             = session->context_snapshot();
  bool qos_flow_processed = false;

  if (patch_asc.medComponentsIsSet()) {
    for (const auto& [med_comp_key, med_component] :
         patch_asc.getMedComponents()) {
      // Service function chaining update [TS 29.514 §4.2.2.8].
      if (med_component.afSfcReqIsSet()) {
        handler_result r = policy_auth::handle_service_function_chaining_update(
            med_component.getAfSfcReq(), request_decision, req_context);
        if (r.problem_details.has_value()) return r;
        continue;
      }

      const int32_t med_comp_n = med_component.getMedCompN();
      const std::string qos_id =
          "PA-QOS-" + app_session_id + "-qos-" + std::to_string(med_comp_n);
      const std::string rule_id =
          "PA-QOS-" + app_session_id + "-" + std::to_string(med_comp_n);

      // Removal (fStatus=REMOVED): drop this flow + PCC rule from `working`.
      // The ledger removal is deferred -- apply_committed_delta() reconciles
      // it post-commit from the removals in the committed delta
      // [TS 29.514 §4.2.3.2].
      const bool removed =
          med_component.fStatusIsSet() &&
          med_component.getFStatus().getEnumValue() ==
              oai::model::pcf::FlowStatus_anyOf::eFlowStatus_anyOf::REMOVED;
      if (removed) {
        auto pcc_rules = working.getPccRules();
        auto qos_decs  = working.getQosDecs();
        pcc_rules.erase(rule_id);
        qos_decs.erase(qos_id);
        working.setPccRules(pcc_rules);
        working.setQosDecs(qos_decs);
        qos_flow_processed = true;
        continue;
      }

      // Modify / add: re-deriving with the same deterministic ids overwrites
      // an existing flow (upgrade/downgrade) or installs a new one
      // [TS 29.513 §7.3.3].
      if (med_component.qosReferenceIsSet() ||
          med_component.medSubCompsIsSet() || med_component.marBwUlIsSet() ||
          med_component.marBwDlIsSet() || med_component.mirBwUlIsSet() ||
          med_component.mirBwDlIsSet()) {
        handler_result r = m_qos_deriver.handle_qos_requirements(
            med_component, app_session_id, working, scratch);
        if (r.problem_details.has_value()) return r;
        qos_flow_processed = true;
      }
    }
  } else if (patch_asc.afSfcReqIsSet()) {
    handler_result r = policy_auth::handle_service_function_chaining_update(
        patch_asc.getAfSfcReq(), request_decision, req_context);
    if (r.problem_details.has_value()) return r;
  }

  // Authorize the modified/added QoS, same gate as create. Owned = prior
  // committed ids (removed flows still listed here are harmless -- they are
  // absent from `working` so the gate never inspects them) + this attempt's
  // scratch ids [TS 29.514 §4.1.3.1, TS 23.503 §6.1.3.2.3].
  if (qos_flow_processed) {
    std::vector<std::string> owned = session->qos().owned_qos_ids();
    const auto derived_ids         = scratch.owned_qos_ids();
    owned.insert(owned.end(), derived_ids.begin(), derived_ids.end());
    handler_result a = m_qos_deriver.validate_qos_authorization(working, owned);
    if (a.problem_details.has_value()) return a;
  }

  handler_result m =
      validate_and_merge_decision(request_decision, working, true);
  if (m.problem_details.has_value()) return m;

  // Pre-notification gate [TS 29.512 §4.2.6.2, §5.6.2.4].
  handler_result v = policy_auth::validate_policy_decision(working);
  if (v.problem_details.has_value()) return v;

  // Apply the AF's JSON Merge Patch (RFC 7396) onto the stored request data so
  // a subsequent GET reflects the modification: scalar fields replaced, media
  // components merged in place, added, or removed [TS 29.514 §4.2.3.2].
  req_context = policy_auth::merge_patch_context(req_context, patch_asc);
  return {};  // ok
}

//------------------------------------------------------------------------------
policy_auth::status_code pcf_policy_authorization::mod_app_session_handler(
    const std::string& app_session_id,
    const oai::model::pcf::AppSessionContextUpdateDataPatch&
        app_session_context_update_data_patch,
    oai::model::pcf::AppSessionContext& app_session_context,
    std::string& problem_details) {
  // Base decision from binding; the per-attempt working copy is derived from it
  // inside `derive` (below).
  oai::model::pcf::SmPolicyDecision current_decision = {};

  const oai::model::pcf::AppSessionContextUpdateData reqContext =
      app_session_context_update_data_patch.getAscReqData();
  std::optional<std::string> association_id = {};
  std::uint64_t bound_version               = 0;

  // Get app session
  auto session = m_context->app_sessions().find(app_session_id);
  if (!session) {
    Logger::pcf_app().error("App session not found");
    problem_details = "APPLICATION_SESSION_CONTEXT_NOT_FOUND";
    return status_code::NOT_FOUND;
  }
  // Zombie-session guard: abort if a concurrent DELETE released it.
  if (session->state() == app_session_state::released) {
    Logger::pcf_app().error("App session already released");
    problem_details = "APPLICATION_SESSION_CONTEXT_NOT_FOUND";
    return status_code::NOT_FOUND;
  }

  auto req_context = session->context_snapshot();

  try {
    // Perform session binding (returns the association's decision + version).
    m_event_sub.sm_session_binding(
        req_context.getUeIpv4(), req_context.getSupi(), req_context.getDnn(),
        association_id, current_decision, bound_version);
  } catch (const std::exception& e) {
    Logger::pcf_app().info(e.what());
    problem_details = "PDU_SESSION_NOT_AVAILABLE";
    return status_code::INTERNAL_SERVER_ERROR;
  }

  // Base this PATCH's update on the decision + version binding returned;
  // apply_with_retry re-derives against a newer base on a concurrent commit
  // [TS 29.512 §4.2.3.2].
  const oai::model::pcf::SmPolicyDecision base_decision = current_decision;

  // Per-attempt recompute (pure w.r.t. shared session state): re-derive this
  // PATCH's changes -- SFC, QoS modify/add, and REMOVED deletions -- into
  // `working`, authorize, merge and validate. Ids are deterministic per
  // medCompN, so re-deriving a component modifies its flow in place
  // [TS 29.514 §4.2.3.2, TS 29.512 §4.2.6.2.1]. On a version conflict
  // apply_with_retry re-invokes this against the freshly committed base.
  //
  // The stored-context projection `req_context` is rebuilt from the session
  // snapshot on every attempt (SFC routing mutates it, then RFC 7396 merges the
  // AF patch onto it); the committed attempt leaves the value used post-commit.
  const auto& patch_asc = app_session_context_update_data_patch.getAscReqData();
  auto derive = [this, &patch_asc, &app_session_id, &session, &req_context](
                    const oai::model::pcf::SmPolicyDecision&,
                    oai::model::pcf::SmPolicyDecision& working)
      -> handler_result {
    return derive_mod_app_session(
        patch_asc, app_session_id, session, req_context, working);
  };

  sm_policy_delta committed_delta;
  const status_code push = push_decision_change(
      {association_id, base_decision, bound_version, app_session_id}, derive,
      committed_delta, problem_details);
  if (push != status_code::OK) return push;

  // ---- post-commit side-effects (reached only once the delta committed) ----
  // Reconcile the ledger with what committed, persist the merged request
  // context, and advance lifecycle.
  session->qos().apply_committed_delta(committed_delta);
  session->update_context(req_context);
  session->next_version();
  session->set_state(app_session_state::modified);

  app_session_context.setAscReqData(req_context);
  app_session_context.setAscRespData(build_response_data(req_context));

  return status_code::OK;
}

//------------------------------------------------------------------------------
policy_auth::status_code pcf_policy_authorization::delete_app_session_handler(
    const std::string& app_session_id, std::string& problem_details) {
  Logger::pcf_app().info("DELETE /app-sessions/{}", app_session_id);

  auto session = m_context->app_sessions().find(app_session_id);
  if (!session) {
    Logger::pcf_app().error("App session not found");
    problem_details = "APPLICATION_SESSION_CONTEXT_NOT_FOUND";
    return status_code::NOT_FOUND;
  }
  if (session->state() == app_session_state::released) {
    Logger::pcf_app().error("App session already released");
    problem_details = "APPLICATION_SESSION_CONTEXT_NOT_FOUND";
    return status_code::NOT_FOUND;
  }

  // Mark released first so a concurrent PATCH aborts (plan §5.5).
  session->set_state(app_session_state::released);

  // Re-fetch the bound association's current decision (existing binding signal,
  // keyed by the session's stored context), remove exactly the entries this
  // session contributed (from its ledger), and push the reduced decision back
  // to the SM policy association (the single owner). CP.22: no storage lock is
  // held across the emits below.
  const auto app_session_context = session->context_snapshot();
  std::optional<std::string> association_id          = {};
  oai::model::pcf::SmPolicyDecision current_decision = {};
  std::uint64_t bound_version                        = 0;
  try {
    m_event_sub.sm_session_binding(
        app_session_context.getUeIpv4(), app_session_context.getSupi(),
        app_session_context.getDnn(), association_id, current_decision,
        bound_version);
  } catch (const std::exception& e) {
    // The PDU session/association may already be gone; still drop the
    // app-session from storage below.
    Logger::pcf_app().info(e.what());
  }

  if (association_id.has_value()) {
    // Removals-only recompute: strip exactly this session's owned entries from
    // the base decision. Idempotent, so re-deriving on a version conflict is
    // safe; the resulting delta leaves other sessions' entries untouched
    // [TS 29.512 §4.2.3.2].
    auto derive =
        [&](const oai::model::pcf::SmPolicyDecision& /*base*/,
            oai::model::pcf::SmPolicyDecision& working) -> handler_result {
      session->qos().erase_owned_from(working);
      return {};  // removals never fail
    };

    sm_policy_delta committed_delta;
    const status_code push = push_decision_change(
        {association_id, current_decision, bound_version, app_session_id},
        derive, committed_delta, problem_details);
    if (push != status_code::OK) {
      // Best-effort cleanup: the AF's session is being torn down regardless, so
      // proceed to drop it from storage even if persistent contention stopped
      // us from committing the removals. The association may retain this
      // session's stale entries until a later reconcile [TS 29.514 §4.2.4].
      Logger::pcf_app().warn(fmt::format(
          "DELETE {}: could not commit QoS removals to association {} "
          "(contention); proceeding with storage removal",
          app_session_id, association_id.value_or("<none>")));
    }
  } else {
    Logger::pcf_app().debug(
        "No SM policy association bound; skipping SMF decision update");
  }

  // TODO [QOS-SUB] If the DELETE carried an EventsSubscReqData, send the
  // termination EventsNotification to the AF here (Phase 3) [TS 29.514 §4.2.4].

  m_context->app_sessions().remove(app_session_id);

  return status_code::OK;
}

//------------------------------------------------------------------------------
policy_auth::status_code pcf_policy_authorization::get_app_session_handler(
    const std::string& app_session_id,
    oai::model::pcf::AppSessionContext& app_session_context,
    std::string& problem_details) {
  Logger::pcf_app().info("GET /app-sessions/{}", app_session_id);

  auto session = m_context->app_sessions().find(app_session_id);
  // A session mid-termination (marked released before storage removal) is
  // treated as gone, so GET never returns a context that is being torn down.
  if (!session || session->state() == app_session_state::released) {
    Logger::pcf_app().debug("App session '{}' not found", app_session_id);
    problem_details = "APPLICATION_SESSION_CONTEXT_NOT_FOUND";
    return status_code::NOT_FOUND;
  }

  // The resource representation is the AppSessionContext; PA stores the request
  // data (ascReqData) the AF created the session with [TS 29.514 §4.2.5.1], and
  // returns the negotiated response data (ascRespData) alongside it.
  const auto req_data = session->context_snapshot();
  app_session_context.setAscReqData(req_data);
  app_session_context.setAscRespData(build_response_data(req_data));
  return status_code::OK;
}

//------------------------------------------------------------------------------
oai::model::pcf::AppSessionContextRespData
pcf_policy_authorization::build_response_data(
    const oai::model::pcf::AppSessionContextReqData& req) {
  AppSessionContextRespData resp;
  // Negotiate supported features against the AF request (suppFeat is mandatory
  // in the request) [TS 29.514 §4.2.2.2, §5.8].
  resp.setSuppFeat(negotiate_supported_features(req.getSuppFeat()));
  return resp;
}

//------------------------------------------------------------------------------
pcf_policy_authorization::~pcf_policy_authorization() {
  Logger::pcf_app().debug("Delete PCF PA instance...");
}

//------------------------------------------------------------------------------
void pcf_policy_authorization::compensate_if_pending(
    const std::string& association_id, std::uint64_t version,
    sm_policy::smf_notify_outcome reason) {
  auto commit =
      m_context->rollback_tracker().try_take(association_id, version);
  if (!commit) {
    Logger::pcf_app().warn(
        "compensate_if_pending: no pending commit tracked for "
        "association %s version %lu (outcome=%s) -- expired, already taken, "
        "or never tracked; cannot attribute or notify an AF",
        association_id.c_str(), version, sm_policy::to_string(reason));
    return;
  }

  Logger::pcf_app().error(
      "compensate_if_pending: association %s version %lu "
      "permanently rejected by the SMF (outcome=%s) -- app-session %s's "
      "commit needs compensating rollback",
      association_id.c_str(), version, sm_policy::to_string(reason),
      commit->app_session_id.c_str());

  // Fetch-live-then-apply orchestration
  // extracted into perform_compensating_rollback (decision_applier.hpp)
  // -- the live-decision lookup and apply_with_retry are injected as
  // collaborators specifically so a test can assert this always feeds
  // apply_with_retry a freshly-looked-up live decision, never this commit's
  // own stale pre-commit base/post-commit version (a prior bug).
  auto lookup_live_decision = [this](
      const std::string& id, bool& found,
      oai::model::pcf::SmPolicyDecision& decision,
      std::uint64_t& out_version) {
    m_event_sub.sm_get_association_decision(
        id, found, decision, out_version);
  };
  auto apply_rollback_with_retry = [this](
      policy_auth::decision_apply_request request,
      const std::function<handler_result(
          const oai::model::pcf::SmPolicyDecision&,
          oai::model::pcf::SmPolicyDecision&)>& derive,
      sm_policy_delta& committed_delta, std::string& problem_details) {
    // Goes through push_decision_change (not m_applier.apply() directly) so
    // the rollback's own re-commit ALSO gets notified and, if THAT notify
    // is itself permanently rejected, ALSO gets its own compensate_if_pending
    // check -- exactly the same treatment every other commit gets, since
    // this is just another commit as far as push_decision_change is
    // concerned.
    return push_decision_change(
        request, derive, committed_delta, problem_details);
  };
  const status_code rollback_push = policy_auth::perform_compensating_rollback(
      association_id, version, *commit, lookup_live_decision,
      apply_rollback_with_retry);

  // AF notification [§5.7 stub; Phase 3 fills in the real body]. Affected ids
  // are this commit's own original footprint (what needed undoing), not the
  // filtered rollback_committed_delta -- an id §5.6 skipped as stale is still
  // an id the AF's QoS update failed for, whether or not PCF's own state
  // reverted for it.
  std::vector<std::string> affected_qos_ids;
  for (const auto& [id, unused] : commit->committed_delta.upsert_qos_decs) {
    (void)unused;
    affected_qos_ids.push_back(id);
  }
  for (const auto& id : commit->committed_delta.removed_qos_decs) {
    affected_qos_ids.push_back(id);
  }
  std::vector<std::string> affected_pcc_rule_ids;
  for (const auto& [id, unused] : commit->committed_delta.upsert_pcc_rules) {
    (void)unused;
    affected_pcc_rule_ids.push_back(id);
  }
  for (const auto& id : commit->committed_delta.removed_pcc_rules) {
    affected_pcc_rule_ids.push_back(id);
  }
  policy_auth::notify_af_qos_update_failed(
      commit->app_session_id, affected_qos_ids, affected_pcc_rule_ids, reason,
      rollback_push == status_code::OK);
}