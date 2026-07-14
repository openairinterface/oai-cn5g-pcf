/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_OPERATOR_QOS_POLICY_BUILDER_HPP_SEEN
#define FILE_OPERATOR_QOS_POLICY_BUILDER_HPP_SEEN

#include "operator_qos_policy.hpp"

namespace oai::config::pcf {
class qos_authorization_config;
}

namespace oai::pcf::app {

/**
 * @brief Build the runtime operator_qos_policy from the parsed config.
 *
 * Translates the operator QoS-authorization config (3GPP BitRate strings) into
 * the runtime operator_qos_policy (bit/s), shared by the SM Policy Control side
 * (Session-AMBR authorization) and the Policy Authorization side (QoS
 * validation). Empty bitrate strings map to std::nullopt ("no cap")
 * [TS 29.514 §4.1.3.1, TS 29.512 §4.2.6.6].
 *
 * A free function in its own translation unit (mirroring
 * policy_auth::load_qos_references_from_directory) so the conversion is unit-
 * testable in isolation and pcf_app.cpp stays a thin composition root.
 */
operator_qos_policy make_operator_qos_policy(
    const oai::config::pcf::qos_authorization_config& cfg);

}  // namespace oai::pcf::app

#endif  // FILE_OPERATOR_QOS_POLICY_BUILDER_HPP_SEEN
