/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_AF_NOTIFY_HPP_SEEN
#define FILE_AF_NOTIFY_HPP_SEEN

#include <string>
#include <vector>

#include "sm_policy/smf_notify_outcome.hpp"

namespace oai::pcf::app::policy_auth {

/**
 * @brief AF notification of a permanent SM policy update
 * rejection [TS 29.514 clause 4.2.5.8 NOTE 1:
 * "If the PCF detects that the PCC rules ... cannot be installed or modified
 * because there is a temporary network failure ... the PCF can notify the AF
 * of the event 'FAILED_RESOURCES_ALLOCATION'."].
 *
 * Logs only; TODO Phase 3 replaces the body with an actual POST of
 * EventsNotification to the app-session's notification URI, gated on the AF
 * having subscribed to this event ("if requested by the AF" -- clause
 * 4.2.5.8 NOTE 1). No evSubsc/subscription bookkeeping exists yet;
 *
 * `rollback_applied` matters even in the stub: if §5.6's per-key staleness
 * safeguard skipped some/all keys, Phase 3's real notify body needs to know
 * whether PCF's state actually reverted or only partially did.
 */
void notify_af_qos_update_failed(
    const std::string& app_session_id,
    const std::vector<std::string>& affected_qos_ids,
    const std::vector<std::string>& affected_pcc_rule_ids,
    oai::pcf::app::sm_policy::smf_notify_outcome smf_reason,
    bool rollback_applied);

}  // namespace oai::pcf::app::policy_auth

#endif  // FILE_AF_NOTIFY_HPP_SEEN
