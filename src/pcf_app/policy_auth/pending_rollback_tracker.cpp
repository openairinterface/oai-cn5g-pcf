/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "pending_rollback_tracker.hpp"

#include "logger.hpp"

namespace oai::pcf::app::policy_auth {

pending_rollback_tracker::pending_rollback_tracker(
    std::chrono::seconds ttl, std::size_t max_entries)
    : m_ttl(ttl), m_max_entries(max_entries) {}

void pending_rollback_tracker::record(
    const std::string& association_id, std::uint64_t version,
    pending_commit commit) {
  auto pending = m_pending.write();
  if (pending->size() >= m_max_entries) {
    Logger::pcf_app().warn(
        "pending_rollback_tracker: at capacity (%zu entries) -- dropping "
        "record for association %s version %lu; a later permanent-rejection "
        "report for it won't be attributable",
        m_max_entries, association_id.c_str(), version);
    return;
  }
  commit.recorded_at = std::chrono::steady_clock::now();
  (*pending)[key_t{association_id, version}] = std::move(commit);
}

std::optional<pending_commit> pending_rollback_tracker::try_take(
    const std::string& association_id, std::uint64_t version) {
  auto pending = m_pending.write();
  auto it      = pending->find(key_t{association_id, version});
  if (it == pending->end()) return std::nullopt;
  pending_commit commit = std::move(it->second);
  pending->erase(it);
  return commit;
}

void pending_rollback_tracker::sweep_expired(
    std::chrono::steady_clock::time_point now) {
  auto pending = m_pending.write();
  for (auto it = pending->begin(); it != pending->end();) {
    if (now - it->second.recorded_at > m_ttl) {
      it = pending->erase(it);
    } else {
      ++it;
    }
  }
}

}  // namespace oai::pcf::app::policy_auth
