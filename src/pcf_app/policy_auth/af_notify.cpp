/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "af_notify.hpp"

#include "logger.hpp"

namespace oai::pcf::app::policy_auth {

void notify_af_qos_update_failed(
    const std::string& app_session_id,
    const std::vector<std::string>& affected_qos_ids,
    const std::vector<std::string>& affected_pcc_rule_ids,
    oai::pcf::app::sm_policy::smf_notify_outcome smf_reason,
    bool rollback_applied) {
  Logger::pcf_app().warn(
      "notify_af_qos_update_failed: app-session %s -- would "
      "notify the AF of FAILED_RESOURCES_ALLOCATION [TS 29.514 §4.2.5.8 NOTE "
      "1] (reason=%s, rollback_applied=%s, %zu affected QoS id(s), %zu "
      "affected PCC rule id(s)); Phase 3 replaces this with an actual "
      "EventsNotification POST, gated on the AF having subscribed to this "
      "event",
      app_session_id.c_str(), oai::pcf::app::sm_policy::to_string(smf_reason),
      rollback_applied ? "true" : "false", affected_qos_ids.size(),
      affected_pcc_rule_ids.size());
}

}  // namespace oai::pcf::app::policy_auth
