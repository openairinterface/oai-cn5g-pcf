/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_APP_SESSION_STORAGE_HPP_SEEN
#define FILE_APP_SESSION_STORAGE_HPP_SEEN

#include <memory>
#include <string>
#include <vector>

namespace oai::pcf::app::policy_auth {

class app_session;

/**
 * @brief Repository abstraction for app-session working state and binding
 * persistence.
 *
 * Mirrors sm_policy::policy_storage and is injected into
 * pcf_policy_authorization the same way policy_storage is injected into
 * pcf_smpc. A single interface lets the working set be backed by an in-memory
 * map now and a database later without touching the service.
 *
 * The backend also owns app-session ID generation (generate_id) so the strategy
 * can be backend-specific and restart-safe: a random UUID for the in-memory
 * backend, a DB-seeded id for the future DB backend.
 */
class app_session_storage {
 public:
  virtual ~app_session_storage() = default;

  /** Generate a backend-specific, restart-safe app-session id. */
  virtual std::string generate_id() = 0;

  virtual void insert(const std::shared_ptr<app_session>& session) = 0;

  /** @return the session, or nullptr if not found. */
  virtual std::shared_ptr<app_session> find(
      const std::string& app_session_id) = 0;

  /** @return all app-sessions bound to the association (1:N); empty if none. */
  virtual std::vector<std::shared_ptr<app_session>> find_by_association(
      const std::string& association_id) = 0;

  virtual void remove(const std::string& app_session_id) = 0;
};

}  // namespace oai::pcf::app::policy_auth

#endif  // FILE_APP_SESSION_STORAGE_HPP_SEEN
