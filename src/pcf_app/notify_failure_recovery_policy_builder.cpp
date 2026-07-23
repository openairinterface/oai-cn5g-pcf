/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "notify_failure_recovery_policy_builder.hpp"

#include <cstddef>

#include "pcf_config_types.hpp"

namespace oai::pcf::app {

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
