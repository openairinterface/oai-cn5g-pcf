/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "retry_drain_queue.hpp"

#include "logger.hpp"

namespace oai::pcf::app::sm_policy {

retry_drain_queue::retry_drain_queue(
    std::chrono::seconds ttl, std::size_t max_entries, int max_retries,
    std::chrono::milliseconds backoff_initial)
    : m_ttl(ttl),
      m_max_entries(max_entries),
      m_max_retries(max_retries),
      m_backoff_initial(backoff_initial) {}

void retry_drain_queue::enqueue(
    const std::string& association_id, std::uint64_t version) {
  auto entries  = m_entries.write();
  const key_t key{association_id, version};
  if (entries->find(key) != entries->end()) {
    // Already queued -- leave its attempt count/backoff progress untouched.
    return;
  }
  if (entries->size() >= m_max_entries) {
    Logger::pcf_app().warn(
        "retry_drain_queue: at capacity (%zu entries) -- dropping retry for "
        "association %s version %lu; no further retry will be attempted for "
        "it",
        m_max_entries, association_id.c_str(), version);
    return;
  }
  const auto now  = std::chrono::steady_clock::now();
  entry e;
  e.attempt          = 0;
  e.next_eligible_at = now + m_backoff_initial;
  e.recorded_at      = now;
  (*entries)[key]    = e;
}

std::vector<std::pair<std::string, std::uint64_t>>
retry_drain_queue::due_entries(
    std::chrono::steady_clock::time_point now) const {
  std::vector<key_t> due;
  auto entries = m_entries.read();
  for (const auto& [key, e] : *entries) {
    if (e.next_eligible_at <= now) due.push_back(key);
  }
  return due;
}

drain_result retry_drain_queue::report_attempt(
    const std::string& association_id, std::uint64_t version, bool success,
    std::chrono::steady_clock::time_point now) {
  auto entries = m_entries.write();
  auto it      = entries->find(key_t{association_id, version});
  if (it == entries->end()) return drain_result::not_found;

  if (success) {
    entries->erase(it);
    return drain_result::succeeded;
  }

  entry& e = it->second;
  ++e.attempt;
  if (e.attempt >= m_max_retries) {
    Logger::pcf_app().error(
        "retry_drain_queue: association %s version %lu exhausted %d "
        "retry(s); log-only escalation, no rollback",
        association_id.c_str(), version, m_max_retries);
    entries->erase(it);
    return drain_result::exhausted;
  }

  // Exponential backoff: initial * 2^attempt.
  e.next_eligible_at = now + (m_backoff_initial * (1 << e.attempt));
  return drain_result::rescheduled;
}

void retry_drain_queue::sweep_expired(
    std::chrono::steady_clock::time_point now) {
  auto entries = m_entries.write();
  for (auto it = entries->begin(); it != entries->end();) {
    if (now - it->second.recorded_at > m_ttl) {
      it = entries->erase(it);
    } else {
      ++it;
    }
  }
}

}  // namespace oai::pcf::app::sm_policy
