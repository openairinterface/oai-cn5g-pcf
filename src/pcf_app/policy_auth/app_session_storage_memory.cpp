/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "app_session_storage_memory.hpp"

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>

#include "app_session.hpp"

namespace oai::pcf::app::policy_auth {

std::string app_session_storage_memory::generate_id() {
  // random_generator is not thread-safe; guard it with the storage mutex.
  std::unique_lock lock(m_mutex);
  return boost::uuids::to_string(m_uuid_gen());
}

void app_session_storage_memory::insert(
    const std::shared_ptr<app_session>& session) {
  if (!session) return;
  std::unique_lock lock(m_mutex);
  m_sessions[session->id()] = session;
  if (session->association_id().has_value()) {
    m_by_association[session->association_id().value()].insert(session->id());
  }
}

std::shared_ptr<app_session> app_session_storage_memory::find(
    const std::string& app_session_id) {
  std::shared_lock lock(m_mutex);
  auto it = m_sessions.find(app_session_id);
  return it == m_sessions.end() ? nullptr : it->second;
}

std::vector<std::shared_ptr<app_session>>
app_session_storage_memory::find_by_association(
    const std::string& association_id) {
  std::vector<std::shared_ptr<app_session>> result;
  std::shared_lock lock(m_mutex);
  auto assoc_it = m_by_association.find(association_id);
  if (assoc_it == m_by_association.end()) return result;
  result.reserve(assoc_it->second.size());
  for (const auto& session_id : assoc_it->second) {
    auto session_it = m_sessions.find(session_id);
    if (session_it != m_sessions.end()) result.push_back(session_it->second);
  }
  return result;
}

void app_session_storage_memory::remove(const std::string& app_session_id) {
  std::unique_lock lock(m_mutex);
  auto it = m_sessions.find(app_session_id);
  if (it == m_sessions.end()) return;

  // Erase only this session's entry from the reverse index (1:N).
  if (it->second && it->second->association_id().has_value()) {
    auto assoc_it = m_by_association.find(it->second->association_id().value());
    if (assoc_it != m_by_association.end()) {
      assoc_it->second.erase(app_session_id);
      if (assoc_it->second.empty()) m_by_association.erase(assoc_it);
    }
  }
  m_sessions.erase(it);
}

}  // namespace oai::pcf::app::policy_auth
