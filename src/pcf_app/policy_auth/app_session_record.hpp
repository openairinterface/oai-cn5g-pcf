/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_APP_SESSION_RECORD_HPP_SEEN
#define FILE_APP_SESSION_RECORD_HPP_SEEN

#include <chrono>
#include <optional>
#include <string>
#include <vector>

#include "qos_types.hpp"

namespace oai::pcf::app::policy_auth {

/**
 * @brief Durable, serializable projection of an app_session.
 *
 * Documents the future `app_session_binding` DB table and is the
 * (de)serialization contract for the future DB storage backend. The in-memory
 * backend stores live objects and does not need it; it is defined now so the
 * schema is fixed.
 *
 * association_id maps to an indexed foreign key that is NOT unique: a single SM
 * policy association can bind multiple app-sessions (1:N).
 */
struct app_session_record {
  std::string app_session_id;                 // primary key
  std::optional<std::string> association_id;  // indexed FK (non-unique)
  std::string supi;                           // binding lookup key (indexed)
  std::string dnn;
  std::string ue_ipv4;  // binding lookup key (indexed)
  std::string af_app_id;
  app_session_state state{app_session_state::pending};
  std::vector<std::string> owned_qos_ids;
  std::vector<std::string> owned_pcc_rule_ids;
  std::vector<std::string> owned_qos_mon_ids;
  std::string context_json;  // serialized AppSessionContextReqData
  std::chrono::system_clock::time_point created_at{};
  std::chrono::system_clock::time_point updated_at{};
  std::optional<std::chrono::system_clock::time_point> expires_at;
};

}  // namespace oai::pcf::app::policy_auth

#endif  // FILE_APP_SESSION_RECORD_HPP_SEEN
