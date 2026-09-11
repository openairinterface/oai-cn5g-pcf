/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_APP_SESSION_STORAGE_HPP_SEEN
#define FILE_APP_SESSION_STORAGE_HPP_SEEN

#include <memory>
#include <mutex>
#include <set>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <boost/uuid/uuid_generators.hpp>

#include "crud_store.hpp"

namespace oai::pcf::app::policy_auth {

class app_session;

/**
 * @brief Repository for app-session working state and binding persistence.
 *
 * A single concrete class: it composes an injected
 * generic oai::utils::crud_store<app_session> for the actual storage -- pass a
 * crud_store_memory now, a DB-backed crud_store later -- and adds the two
 * app-session-specific concerns that don't fit a plain keyed CRUD:
 *   - generate_id(): restart-safe UUID id generation;
 *   - find_by_association(): the 1:N app-session <-> SM-policy binding index,
 *     maintained here on insert/remove.
 *
 * Note: the index is updated as a separate step from the backend write (they
 * take different locks), so there is a brief window where a just-inserted
 * session is in the backend but not yet in the index (and vice versa on
 * remove). This is acceptable for the control-plane lookups that use it.
 */
class app_session_storage {
 public:
  explicit app_session_storage(
      std::shared_ptr<oai::utils::crud_store<app_session>> backend);

  /** Generate a restart-safe, non-guessable app-session id (UUID). */
  std::string generate_id();

  void insert(const std::shared_ptr<app_session>& session);

  /** @return the session, or nullptr if not found. */
  [[nodiscard]] std::shared_ptr<app_session> find(
      const std::string& app_session_id) const;

  [[nodiscard]] std::vector<std::shared_ptr<app_session>> find_all() const;

  /** @return all app-sessions bound to the association (1:N); empty if none. */
  [[nodiscard]] std::vector<std::shared_ptr<app_session>> find_by_association(
      const std::string& association_id) const;

  void remove(const std::string& app_session_id);

 private:
  std::shared_ptr<oai::utils::crud_store<app_session>> m_backend;

  // 1:N association_id -> {app_session_id} secondary index.
  mutable std::shared_mutex m_index_mutex;
  std::unordered_map<std::string, std::set<std::string>> m_by_association;

  // random_generator is not thread-safe; guard it.
  std::mutex m_id_mutex;
  boost::uuids::random_generator m_uuid_gen;
};

}  // namespace oai::pcf::app::policy_auth

#endif  // FILE_APP_SESSION_STORAGE_HPP_SEEN
