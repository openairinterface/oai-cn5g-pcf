/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_RETRY_DRAIN_QUEUE_HPP_SEEN
#define FILE_RETRY_DRAIN_QUEUE_HPP_SEEN

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "guarded.hpp"

namespace oai::pcf::app::sm_policy {

/**
 * @brief Outcome of reporting a drain attempt back to the queue
 */
enum class drain_result {
  succeeded,   // notify succeeded; entry removed, nothing further happens
  rescheduled, // still temporary/ambiguous; entry re-armed with backoff
  exhausted,   // max_notify_retries reached; entry removed, log-only escalation
  not_found,   // (association_id, version) wasn't queued (already resolved,
               // expired, or evicted)
};

inline const char* to_string(drain_result result) {
  switch (result) {
    case drain_result::succeeded:
      return "succeeded";
    case drain_result::rescheduled:
      return "rescheduled";
    case drain_result::exhausted:
      return "exhausted";
    case drain_result::not_found:
      return "not_found";
  }
  return "unknown";
}

/**
 * @brief SM-owned retry-drain queue for temporary/ambiguous SMF notify
 * outcomes -- distinct from PA's pending_rollback_tracker.
 *
 * Holds only (association_id, version) + attempt count + next-eligible-time;
 * deliberately does NOT hold a frozen decision snapshot -- the
 * caller re-fetches the association's live decision immediately before each
 * drain attempt and calls send_sm_policy_control_update_notify off-lock with
 * that fresh snapshot, so a disjoint-key commit landing on the same
 * association in the meantime is never overwritten by a stale retry.
 *
 * due_entries() returns a plain copy so the caller does the actual blocking
 * re-fetch+notify per entry outside this queue's lock [CP.22], then reports
 * the result via report_attempt() (which re-locks only briefly). Never
 * surfaces a "permanent" outcome itself -- firing the event on a
 * permanent rejection is the caller's responsibility, both for entries
 * queued here and for a permanent rejection arriving directly on the first
 * attempt (which never enters this queue at all).
 *
 * Bounded by an explicit TTL (sweep_expired) and a hard cap (enqueue), same
 * discipline as pending_rollback_tracker.
 */
class retry_drain_queue {
 public:
  retry_drain_queue(
      std::chrono::seconds ttl, std::size_t max_entries, int max_retries,
      std::chrono::milliseconds backoff_initial);

  /**
   * @brief Enqueue (association_id, version) for future retry. Idempotent if
   * already queued (leaves its attempt count/backoff progress untouched).
   * Dropped (after a WARN log) if already at capacity.
   */
  void enqueue(const std::string& association_id, std::uint64_t version);

  /** @brief Entries whose next-eligible-time has passed, as of `now`. */
  [[nodiscard]] std::vector<std::pair<std::string, std::uint64_t>> due_entries(
      std::chrono::steady_clock::time_point now) const;

  /**
   * @brief Report the result of a drain attempt for (association_id,
   * version). `success` removes the entry outright. Otherwise: reschedules
   * with exponential backoff if attempts remain, or removes the entry and
   * returns drain_result::exhausted once max_notify_retries is reached.
   */
  [[nodiscard]] drain_result report_attempt(
      const std::string& association_id, std::uint64_t version, bool success,
      std::chrono::steady_clock::time_point now);

  /** @brief Evict every entry older than the configured TTL. */
  void sweep_expired(std::chrono::steady_clock::time_point now);

 private:
  using key_t = std::pair<std::string, std::uint64_t>;

  struct entry {
    int attempt = 0;
    std::chrono::steady_clock::time_point next_eligible_at;
    std::chrono::steady_clock::time_point recorded_at;
  };

  const std::chrono::seconds m_ttl;
  const std::size_t m_max_entries;
  const int m_max_retries;
  const std::chrono::milliseconds m_backoff_initial;

  oai::utils::guarded<std::map<key_t, entry>> m_entries;
};

}  // namespace oai::pcf::app::sm_policy

#endif  // FILE_RETRY_DRAIN_QUEUE_HPP_SEEN
