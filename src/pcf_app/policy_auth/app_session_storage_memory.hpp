/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_APP_SESSION_STORAGE_MEMORY_HPP_SEEN
#define FILE_APP_SESSION_STORAGE_MEMORY_HPP_SEEN

#include <memory>
#include <set>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <boost/uuid/uuid_generators.hpp>

#include "app_session_storage.hpp"

namespace oai::pcf::app::policy_auth {

/**
 * @brief In-memory implementation of app_session_storage.
 *
 * Holds the live app-session working set and a 1:N reverse index
 * (association_id -> {app_session_id}). Generates UUIDs for app-session ids
 * (restart-safe and non-guessable). A restart drops all sessions; durable
 * recovery is the job of the future DB backend (plan §6, §9).
 */
class app_session_storage_memory final : public app_session_storage {
 public:
  std::string generate_id() override;
  void insert(const std::shared_ptr<app_session>& session) override;
  std::shared_ptr<app_session> find(const std::string& app_session_id) override;
  std::vector<std::shared_ptr<app_session>> find_by_association(
      const std::string& association_id) override;
  void remove(const std::string& app_session_id) override;

 private:
  mutable std::shared_mutex m_mutex;
  std::unordered_map<std::string, std::shared_ptr<app_session>> m_sessions;
  std::unordered_map<std::string, std::set<std::string>> m_by_association;
  boost::uuids::random_generator m_uuid_gen;
};

}  // namespace oai::pcf::app::policy_auth

#endif  // FILE_APP_SESSION_STORAGE_MEMORY_HPP_SEEN
