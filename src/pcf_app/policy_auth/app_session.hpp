/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_APP_SESSION_SEEN
#define FILE_APP_SESSION_SEEN

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "AppSessionContext.h"
#include "AppSessionContextReqData.h"
#include "AppSessionContextUpdateData.h"
#include "MediaComponent.h"
#include "QosData.h"
#include "SmPolicyDecision.h"
#include "guarded.hpp"
#include "pcf_policy_authorization_status_code.hpp"
#include "qos_context.hpp"

namespace oai::pcf::app::policy_auth {

/**
 * @brief Durable, serializable projection of an app_session.
 *
 * Documents the future `app_session_binding` DB table and is the
 * (de)serialization contract for the future DB storage backend. The in-memory
 * backend stores live objects and does not need it; it is defined now so the
 * schema is fixed.
 *
 * association_id maps to an indexed foreign key that is NOT unique: a single SM
 * policy association can bind multiple app-sessions (1:N).
 */
struct app_session_record {
  std::string app_session_id;                 // primary key
  std::optional<std::string> association_id;  // indexed FK (non-unique)
  std::string supi;                           // binding lookup key (indexed)
  std::string dnn;
  std::string ue_ipv4;  // binding lookup key (indexed)
  std::string af_app_id;
  app_session_state state{app_session_state::pending};
  std::vector<std::string> owned_qos_ids;
  std::vector<std::string> owned_pcc_rule_ids;
  std::vector<std::string> owned_qos_mon_ids;
  std::string context_json;  // serialized AppSessionContextReqData
  std::chrono::system_clock::time_point created_at{};
  std::chrono::system_clock::time_point updated_at{};
  std::optional<std::chrono::system_clock::time_point> expires_at;
};

/**
 * @brief Aggregate root for an application session (3GPP TS 29.514).
 *
 * Deliberately thin: each cross-cutting concern is a self-contained "aspect"
 * object with its own lock (qos_context; AF-subscription and monitoring),
 * so this class never accretes unrelated state.
 * The full SmPolicyDecision is NOT stored here -- it is owned by the SM
 * policy association; this object keeps only a ledger (via qos_context) of the
 * ids it contributed, plus the app-session <-> association binding.
 *
 * AF-subscription and monitoring state become their own aspect classes,
 * added as one member line -- not fields on this class.
 */
class app_session {
 public:
  app_session(
      std::string id, const oai::_3gpp::model::AppSessionContextReqData& context,
      std::optional<std::string> association_id);

  app_session(const app_session&)            = delete;
  app_session& operator=(const app_session&) = delete;
  virtual ~app_session()                     = default;

  [[nodiscard]] const std::string& id() const { return m_id; }

  [[nodiscard]] app_session_state state() const { return m_state.load(); }
  void set_state(app_session_state state) { m_state.store(state); }

  // Monotonic version stamped on each update; lets stale notifications be
  // detected once cross-service coordination is delta-based (plan §4.7).
  uint64_t next_version() { return ++m_version; }
  [[nodiscard]] uint64_t version() const { return m_version.load(); }

  // app-session <-> SM policy association binding (set at construction).
  [[nodiscard]] const std::optional<std::string>& association_id() const {
    return m_association_id;
  }

  // QoS aspect (Phase 1). Phase 3 adds af(), Phase 4 adds mon() the same way.
  [[nodiscard]] qos_context& qos() { return m_qos; }
  [[nodiscard]] const qos_context& qos() const { return m_qos; }

  [[nodiscard]] oai::_3gpp::model::AppSessionContextReqData context_snapshot()
      const;
  void update_context(
      const oai::_3gpp::model::AppSessionContextReqData& context);

  // Durable projection (documents the app_session_binding schema). from_record()
  // ships with the future DB storage backend.
  [[nodiscard]] app_session_record to_record() const;

 private:
  const std::string m_id;
  const std::chrono::system_clock::time_point m_created_at;
  std::atomic<app_session_state> m_state{app_session_state::pending};
  std::atomic<uint64_t> m_version{0};
  oai::utils::guarded<oai::_3gpp::model::AppSessionContextReqData> m_context;
  std::optional<std::string> m_association_id;
  qos_context m_qos;
};

/**
 * Handlers for processing different App Session operation procedures
 *
 * 3GPP TS 29.514 4.2.x
 */

// Service function chaining (N6-LAN traffic steering, TS 29.514 §4.2.2.8) is
// not present anymore: see the TODO in app_session.cpp. There is currently no
// handle_service_function_chaining[_update] here -- callers must not derive
// SFC from oai::_3gpp::model::AfRoutingRequirement yet.

// QoS handling functions [TS 29.514 §4.2.2.2, TS 29.513 §7.3, TS 29.512 §4.2.6.6]

// Generate QoS characteristics for a non-standardized (dynamically assigned)
// 5QI [TS 29.512 §4.2.6.6.3, §5.6.2.16]. No-op for standardized 5QI values.
oai::pcf::app::policy_auth::handler_result create_qos_characteristics(
    const oai::_3gpp::model::QosData& qos_data,
    oai::_3gpp::model::SmPolicyDecision& decision);

// --- QoS mapping helpers (pure; unit-tested directly) ---

// True if `r5qi` is a standardized 5QI value per TS 23.501 §5.7.4 Table 5.7.4-1.
// A standardized 5QI carries preconfigured characteristics, so the PCF need not
// signal a QosCharacteristics entry for it [TS 29.512 §4.2.6.6.2].
[[nodiscard]] bool is_standardized_5qi(int32_t r5qi);

// Derive an authorized 5QI from the desired max latency and whether the flow is
// GBR. [TS 29.513 §7.3.3 NOTE 15/17: when desMaxLatency is present, 5QI mapping
// "may be done according to table 5.7.4-1 in TS 23.501"]. The authoritative
// latency->5QI table is not available in-repo, so this is an operator-tunable
// approximation that falls back to the best-effort default 5QI=9.
[[nodiscard]] int32_t derive_5qi(
    std::optional<float> des_max_latency_ms, bool has_gbr);

// No-op stub until Phase 4 -- see app_session.cpp for what it will do
// [TS 29.512 §4.1.4.4.6, TS 29.514 §4.2.2.23].
oai::pcf::app::policy_auth::handler_result setup_qos_monitoring(
    oai::_3gpp::model::SmPolicyDecision& decision);

// NOTE: there is no handle_qos_update()/diff step for a modification. A PATCH
// re-derives the same medCompN through handle_qos_requirements() above, which
// upserts the flow in place -- so modify/add/remove and QoS upgrade/downgrade
// all fall out of one code path, and that path stays safe to re-run under the
// commit's version-CAS retry [TS 29.514 §4.2.3.2, TS 29.512 §4.2.6.2.1]. The
// cost is that nothing reports *which* attributes changed; Phase 3 needs that
// for its EventsNotification and is the natural place to add it.

// TODO [QOS-SUB] AF notification handlers (Phase 3) [TS 29.514 §4.2.5]:
// notify_af_qos_status (§4.2.5.4), notify_af_pdu_session_event (§4.2.5.22),
// notify_af_policy_update (§4.2.5.2, §4.2.5.8) and register_af_subscription
// (§4.2.6). These replace af_notify.hpp's notify_af_qos_update_failed() stub.
// TODO [QOS-MON] configure_af_monitoring (§4.2.2.23.1) and
// notify_af_monitoring_report (§4.2.5.14) (Phase 4).

oai::pcf::app::policy_auth::handler_result authorize_service_info(
    const oai::_3gpp::model::AppSessionContextReqData& reqData);

oai::pcf::app::policy_auth::handler_result validate_and_merge_decision(
    const oai::_3gpp::model::SmPolicyDecision& request_decision,
    oai::_3gpp::model::SmPolicyDecision& current_decision, bool update = false);

// Final structural/semantic validation of a fully-merged SmPolicyDecision,
// run as a pre-notification gate before the decision is pushed to the SMF
// [TS 29.512 §4.2.6.2, §5.6.2.4]. Rejects (with diagnostics logged) on
// referential-integrity violations that the SMF cannot process -- a PCC rule
// referencing a missing QosData/TrafficControlData, or a non-standardized 5QI
// without a signalled QosCharacteristics [TS 29.512 §4.2.6.2.1, §5.6.2.6,
// §5.6.2.16]. PCC-rule well-formedness issues (missing precedence, no traffic
// identification) are logged as diagnostics but not fatal, since
// operator-provisioned/predefined rules may legitimately omit them. Returns OK
// when the decision is safe to notify.
oai::pcf::app::policy_auth::handler_result validate_policy_decision(
    const oai::_3gpp::model::SmPolicyDecision& decision);

// Apply a JSON Merge Patch (RFC 7396) of a modification's ascReqData onto the
// stored ascReqData, returning the merged request data [TS 29.514 §4.2.3.2].
//
// Fields the AF set add or replace the corresponding stored fields; the
// medComponents map (and the medSubComps within each component) merge entry by
// entry, so a partial update touches only the attributes it carries. Media
// components the AF flags with fStatus=REMOVED are deleted from the stored map:
// the generated *Rm model types cannot represent RFC 7396 null-removal, so 3GPP
// fStatus is the removal signal [TS 29.514 §4.2.3.2, §5.6.2.7].
oai::_3gpp::model::AppSessionContextReqData merge_patch_context(
    const oai::_3gpp::model::AppSessionContextReqData& stored,
    const oai::_3gpp::model::AppSessionContextUpdateData& patch);

}  // namespace oai::pcf::app::policy_auth

#endif  // FILE_APP_SESSION_SEEN
