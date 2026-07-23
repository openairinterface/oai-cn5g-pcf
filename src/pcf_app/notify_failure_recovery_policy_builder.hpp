/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_NOTIFY_FAILURE_RECOVERY_POLICY_BUILDER_HPP_SEEN
#define FILE_NOTIFY_FAILURE_RECOVERY_POLICY_BUILDER_HPP_SEEN

#include "notify_failure_recovery_policy.hpp"

namespace oai::config::pcf {
class notify_failure_recovery_config;
}

namespace oai::pcf::app {

/**
 * @brief Build the runtime notify_failure_recovery_policy from the parsed
 * config.
 *
 * A free function in its own translation unit (mirroring
 * make_operator_qos_policy) so the conversion is unit-testable in isolation
 * and pcf_app.cpp stays a thin composition root.
 */
notify_failure_recovery_policy make_notify_failure_recovery_policy(
    const oai::config::pcf::notify_failure_recovery_config& cfg);

}  // namespace oai::pcf::app

#endif  // FILE_NOTIFY_FAILURE_RECOVERY_POLICY_BUILDER_HPP_SEEN
