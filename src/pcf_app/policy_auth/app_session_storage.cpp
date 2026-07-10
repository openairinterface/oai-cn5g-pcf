/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "app_session_storage.hpp"

#include <utility>

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>

#include "app_session.hpp"
#include "logger.hpp"

namespace oai::pcf::app::policy_auth {

app_session_storage::app_session_storage(
    std::shared_ptr<oai::utils::crud_store<app_session>> backend)
    : m_backend(std::move(backend)) {}

std::string app_session_storage::generate_id() {
  std::unique_lock lock(m_id_mutex);
  auto id = boost::uuids::to_string(m_uuid_gen());
  Logger::pcf_app().trace("app_session_storage: generated id %s", id.c_str());
  return id;
}

void app_session_storage::insert(const std::shared_ptr<app_session>& session) {
  if (!session) {
    Logger::pcf_app().warn("app_session_storage: ignoring insert of null session");
    return;
  }
  m_backend->insert(session->id(), session);
  if (session->association_id().has_value()) {
    std::unique_lock lock(m_index_mutex);
    m_by_association[session->association_id().value()].insert(session->id());
    Logger::pcf_app().debug(
        "app_session_storage: inserted session %s (association %s)",
        session->id().c_str(), session->association_id().value().c_str());
  } else {
    Logger::pcf_app().debug(
        "app_session_storage: inserted session %s (no association)",
        session->id().c_str());
  }
}

std::shared_ptr<app_session> app_session_storage::find(
    const std::string& app_session_id) const {
  auto session = m_backend->find(app_session_id);
  Logger::pcf_app().trace(
      "app_session_storage: find %s -> %s", app_session_id.c_str(),
      session ? "hit" : "miss");
  return session;
}

std::vector<std::shared_ptr<app_session>> app_session_storage::find_all() const {
  return m_backend->find_all();
}

std::vector<std::shared_ptr<app_session>>
app_session_storage::find_by_association(
    const std::string& association_id) const {
  std::vector<std::shared_ptr<app_session>> result;
  std::shared_lock lock(m_index_mutex);
  auto it = m_by_association.find(association_id);
  if (it == m_by_association.end()) return result;
  result.reserve(it->second.size());
  for (const auto& session_id : it->second) {
    // m_backend has its own lock (distinct from m_index_mutex) -- no deadlock.
    auto session = m_backend->find(session_id);
    if (session) result.push_back(session);
  }
  Logger::pcf_app().trace(
      "app_session_storage: find_by_association %s -> %zu session(s)",
      association_id.c_str(), result.size());
  return result;
}

void app_session_storage::remove(const std::string& app_session_id) {
  // Capture the session first so we know which association-index entry to prune.
  auto session = m_backend->find(app_session_id);
  if (!session) {
    Logger::pcf_app().trace(
        "app_session_storage: remove %s -> not found (no-op)",
        app_session_id.c_str());
    return;
  }
  m_backend->remove(app_session_id);
  Logger::pcf_app().debug(
      "app_session_storage: removed session %s", app_session_id.c_str());
  if (session->association_id().has_value()) {
    std::unique_lock lock(m_index_mutex);
    auto it = m_by_association.find(session->association_id().value());
    if (it == m_by_association.end()) return;
    it->second.erase(app_session_id);  // erase only this session's entry (1:N)
    if (it->second.empty()) m_by_association.erase(it);
  }
}

}  // namespace oai::pcf::app::policy_auth
