/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_PCF_RUNTIME_POLICY_HPP_SEEN
#define FILE_PCF_RUNTIME_POLICY_HPP_SEEN

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>

/**
 * @file
 * @brief Runtime policy values derived once from the parsed config at startup
 * and shared by both PCF services.
 *
 * Two aggregates with one lifecycle: pcf_app builds both from pcf_cfg in its
 * constructor and injects both into pcf_smpc (SM Policy Control) and
 * policy_auth_context (Policy Authorization). The make_*() functions are the
 * only config-layer dependency here; the aggregates themselves are pure
 * runtime types.
 */

namespace oai::config::pcf {
class qos_authorization_config;
class notify_failure_recovery_config;
}  // namespace oai::config::pcf

namespace oai::pcf::app {

/**
 * @brief Operator-configurable QoS authorization limits.
 *
 * Shared by the SM Policy Control side (authorizing the subscribed Session-AMBR
 * / default QoS into a SessionRule -- TS 29.512 §4.2.6.6.1) and the Policy
 * Authorization side (validating AF-requested QoS -- TS 29.514 §4.1.3.1). Bit
 * rates are stored pre-parsed to bit/s so the hot path never re-parses 3GPP
 * BitRate strings.
 *
 * Defaults are deliberately permissive (empty allow-list = allow any 5QI;
 * nullopt caps = no clamp; fail-open on missing subscription) so a
 * default-constructed instance authorizes the subscribed values unchanged. The
 * operator tightens these via config.
 */
struct operator_qos_policy {
  // Dynamic (non-standardized) 5QIs the PCF may authorize. Empty => allow any.
  // Consumed by the Policy Authorization validator; not used SM-side (subscribed
  // default 5QIs are inherently authorized).
  std::set<int32_t> allowed_dynamic_5qi;

  // Per-service-data-flow MBR ceiling (Policy Authorization side). nullopt => no
  // cap. [TS 29.512 §4.2.6.6.2]
  std::optional<uint64_t> max_flow_mbr_ul_bps;
  std::optional<uint64_t> max_flow_mbr_dl_bps;

  // Authorized Session-AMBR ceiling (SM Policy Control side). nullopt => no
  // clamp. [TS 29.512 §4.2.6.6.1]
  std::optional<uint64_t> max_session_ambr_ul_bps;
  std::optional<uint64_t> max_session_ambr_dl_bps;

  // When true, the Policy Authorization validator rejects QoS if no subscribed
  // Session-AMBR is available to check against (fail-closed). Default false =
  // fail-open, per TS 29.512 §4.2.2.2 ("no Session-AMBR constraints apply unless
  // operator policies define any").
  bool reject_on_missing_subscription{false};
};

/**
 * @brief Runtime bounds for SMF notify-failure recovery
 *
 * Shared by the SM-side retry-drain queue (retry_drain_ttl/
 * retry_drain_max_entries/max_notify_retries/retry_backoff_initial) and the
 * PA-side pending_rollback_tracker (rollback_tracker_ttl/
 * rollback_tracker_max_entries). Neither TS 29.512 nor TS 29.514 prescribes
 * these values; defaults here mirror
 * notify_failure_recovery_config's YAML defaults so a default-constructed
 * instance behaves the same as an empty config block.
 */
struct notify_failure_recovery_policy {
  std::chrono::seconds retry_drain_ttl{30};
  std::size_t retry_drain_max_entries{10000};
  int max_notify_retries{3};
  std::chrono::milliseconds retry_backoff_initial{500};
  std::chrono::seconds rollback_tracker_ttl{30};
  std::size_t rollback_tracker_max_entries{10000};
};

/**
 * @brief Build the runtime operator_qos_policy from the parsed config.
 *
 * Translates the operator QoS-authorization config (3GPP BitRate strings) into
 * the runtime operator_qos_policy (bit/s), shared by the SM Policy Control side
 * (Session-AMBR authorization) and the Policy Authorization side (QoS
 * validation). Empty bitrate strings map to std::nullopt ("no cap")
 * [TS 29.514 §4.1.3.1, TS 29.512 §4.2.6.6].
 */
operator_qos_policy make_operator_qos_policy(
    const oai::config::pcf::qos_authorization_config& cfg);

/**
 * @brief Build the runtime notify_failure_recovery_policy from the parsed
 * config.
 */
notify_failure_recovery_policy make_notify_failure_recovery_policy(
    const oai::config::pcf::notify_failure_recovery_config& cfg);

}  // namespace oai::pcf::app

#endif  // FILE_PCF_RUNTIME_POLICY_HPP_SEEN
