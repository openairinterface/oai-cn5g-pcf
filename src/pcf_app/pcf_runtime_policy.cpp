/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "pcf_runtime_policy.hpp"

#include <cstdint>
#include <optional>
#include <string>

#include "bitrate.hpp"
#include "pcf_config_types.hpp"

namespace oai::pcf::app {

operator_qos_policy make_operator_qos_policy(
    const oai::config::pcf::qos_authorization_config& cfg) {
  operator_qos_policy policy;

  for (int32_t r5qi : cfg.get_allowed_dynamic_5qi()) {
    policy.allowed_dynamic_5qi.insert(r5qi);
  }

  const auto parse = [](const std::string& value) -> std::optional<uint64_t> {
    return value.empty() ? std::nullopt : oai::utils::bitrate::to_bps(value);
  };
  policy.max_flow_mbr_ul_bps     = parse(cfg.get_max_flow_mbr_ul());
  policy.max_flow_mbr_dl_bps     = parse(cfg.get_max_flow_mbr_dl());
  policy.max_session_ambr_ul_bps = parse(cfg.get_max_session_ambr_ul());
  policy.max_session_ambr_dl_bps = parse(cfg.get_max_session_ambr_dl());
  policy.reject_on_missing_subscription =
      cfg.get_reject_on_missing_subscription();

  return policy;
}

notify_failure_recovery_policy make_notify_failure_recovery_policy(
    const oai::config::pcf::notify_failure_recovery_config& cfg) {
  notify_failure_recovery_policy policy;
  policy.retry_drain_ttl =
      std::chrono::seconds(cfg.get_retry_drain_ttl_seconds());
  policy.retry_drain_max_entries =
      static_cast<std::size_t>(cfg.get_retry_drain_max_entries());
  policy.max_notify_retries = cfg.get_max_notify_retries();
  policy.retry_backoff_initial =
      std::chrono::milliseconds(cfg.get_retry_backoff_initial_ms());
  policy.rollback_tracker_ttl =
      std::chrono::seconds(cfg.get_rollback_tracker_ttl_seconds());
  policy.rollback_tracker_max_entries =
      static_cast<std::size_t>(cfg.get_rollback_tracker_max_entries());
  return policy;
}

}  // namespace oai::pcf::app
