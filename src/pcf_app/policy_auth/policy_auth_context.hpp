/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_POLICY_AUTH_CONTEXT_HPP_SEEN
#define FILE_POLICY_AUTH_CONTEXT_HPP_SEEN

#include <memory>
#include <utility>

#include "app_session_storage.hpp"
#include "operator_qos_policy.hpp"
#include "qos_reference_store.hpp"

namespace oai::pcf::app::policy_auth {

/**
 * @brief Aggregates the stores the Policy Authorization service depends on.
 *
 * The service takes this single object instead of one constructor parameter per
 * store, so adding a store later (AF-subscription in Phase 3, monitoring in
 * Phase 4) is a member + accessor here rather than another parameter threaded
 * through pcf_app and the service constructor.
 *
 * The aggregated stores keep their own focused interfaces (a mutable runtime
 * working set for app-sessions, a read-only provisioned lookup for QoS
 * references), so unit tests continue to fake only the store they exercise.
 */
class policy_auth_context {
 public:
  policy_auth_context(
      std::shared_ptr<app_session_storage> app_sessions,
      std::shared_ptr<qos_reference_store> qos_references,
      operator_qos_policy qos_authorization_policy = {})
      : m_app_sessions(std::move(app_sessions)),
        m_qos_references(std::move(qos_references)),
        m_qos_authorization_policy(std::move(qos_authorization_policy)) {}

  // Mutable runtime working set of app-sessions (+ binding index, id-gen).
  [[nodiscard]] app_session_storage& app_sessions() const {
    return *m_app_sessions;
  }

  // Read-only operator-preconfigured QoS reference sets [TS 29.513 §7.3.3].
  [[nodiscard]] qos_reference_store& qos_references() const {
    return *m_qos_references;
  }

  // Operator QoS authorization limits used by validate_qos_authorization()
  // [TS 29.514 §4.1.3.1]. Defaults are permissive; populated from config in a
  // later step (see N5_QoS_Phase1_§1.4 plan §7.4).
  [[nodiscard]] const operator_qos_policy& qos_authorization_policy() const {
    return m_qos_authorization_policy;
  }

 private:
  std::shared_ptr<app_session_storage> m_app_sessions;
  std::shared_ptr<qos_reference_store> m_qos_references;
  operator_qos_policy m_qos_authorization_policy;
};

}  // namespace oai::pcf::app::policy_auth

#endif  // FILE_POLICY_AUTH_CONTEXT_HPP_SEEN
