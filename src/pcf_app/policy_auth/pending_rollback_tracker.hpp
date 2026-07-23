/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_PENDING_ROLLBACK_TRACKER_HPP_SEEN
#define FILE_PENDING_ROLLBACK_TRACKER_HPP_SEEN

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "SmPolicyDecision.h"
#include "guarded.hpp"
#include "sm_policy_delta.hpp"

namespace oai::pcf::app::policy_auth {

/**
 * @brief What would need to be undone if this commit is later reported as a
 * permanent SMF rejection.
 *
 * `base` reuses snapshot_decision()'s shape (individual_sm_association.hpp)
 * rather than a fresh full-decision copy.
 */
struct pending_commit {
  std::string app_session_id;
  oai::pcf::app::sm_policy_delta committed_delta;
  std::shared_ptr<const oai::model::pcf::SmPolicyDecision> base;
  std::chrono::steady_clock::time_point recorded_at;
};

/**
 * @brief PA-side tracking table: "which commit does this (association_id,
 * version) refer to".
 *
 * Populated at the exact point apply_with_retry currently discards this data
 * (pcf_policy_authorization.cpp, right where it commits and returns OK);
 * consumed when the SM->PA permanent-rejection event arrives. Bounded
 * by an explicit TTL (sweep_expired, meant to be driven by the task_tick
 * heartbeat) and a hard cap (record) -- "some retention window" isn't enough
 * on its own, or this is a slow leak under sustained SMF failures.
 *
 * Its own aspect class (own header, guarded<T> member, minimal focused
 * interface), rather than fields bolted onto pcf_policy_authorization.
 */
class pending_rollback_tracker {
 public:
  pending_rollback_tracker(std::chrono::seconds ttl, std::size_t max_entries);

  /**
   * @brief Record what would need to be undone for (association_id,
   * version). Silently drops the record (after a WARN log) once at capacity
   * -- a later permanent-rejection report for that commit becomes
   * unattributable rather than growing this table without bound.
   */
  void record(
      const std::string& association_id, std::uint64_t version,
      pending_commit commit);

  /**
   * @brief Consume and return the record for (association_id, version), if
   * still tracked. std::nullopt if never recorded, already taken, or
   * expired/evicted -- the caller should log at WARN and drop in that case,
   * it can no longer attribute or notify an AF that's untraceable.
   */
  [[nodiscard]] std::optional<pending_commit> try_take(
      const std::string& association_id, std::uint64_t version);

  /** @brief Evict every entry older than the configured TTL. */
  void sweep_expired(std::chrono::steady_clock::time_point now);

 private:
  using key_t = std::pair<std::string, std::uint64_t>;

  const std::chrono::seconds m_ttl;
  const std::size_t m_max_entries;
  oai::utils::guarded<std::map<key_t, pending_commit>> m_pending;
};

}  // namespace oai::pcf::app::policy_auth

#endif  // FILE_PENDING_ROLLBACK_TRACKER_HPP_SEEN
