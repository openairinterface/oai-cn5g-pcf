/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_NOTIFY_FAILURE_RECOVERY_POLICY_HPP_SEEN
#define FILE_NOTIFY_FAILURE_RECOVERY_POLICY_HPP_SEEN

#include <chrono>
#include <cstddef>

namespace oai::pcf::app {

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

}  // namespace oai::pcf::app

#endif  // FILE_NOTIFY_FAILURE_RECOVERY_POLICY_HPP_SEEN
