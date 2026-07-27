/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_QOS_DERIVER_HPP_SEEN
#define FILE_QOS_DERIVER_HPP_SEEN

#include <string>
#include <vector>

#include "QosData.h"
#include "SmPolicyDecision.h"
#include "operator_qos_policy.hpp"
#include "pcf_policy_authorization_status_code.hpp"
#include "qos_context.hpp"
#include "qos_reference_store.hpp"

namespace oai::pcf::app::policy_auth {

/**
 * @brief Holds the two never-varying dependencies the QoS-derivation
 * functions in app_session.cpp used to thread through every call --
 * `qos_ref_store` (operator-preconfigured QoS reference sets) and
 * `op_policy` (operator QoS authorization limits), both constant per
 * pcf_policy_authorization instance and re-supplied on every per-attempt
 * `derive` re-run. Constructor-injected here instead.
 */
class qos_deriver {
 public:
  qos_deriver(
      const qos_reference_store& qos_ref_store,
      const operator_qos_policy& op_policy);

  // Extract and process the QoS requirements of one MediaComponent,
  // orchestrating create_qos_data_from_media_component, QoS characteristics
  // and monitoring in sequence [TS 29.514 §4.2.2.2, TS 29.513 §7.3.3].
  // Templated on the media-component type so the SAME §7.3.3 mapping serves
  // both create (MediaComponent) and update (MediaComponentRm). Explicitly
  // instantiated for both in qos_deriver.cpp.
  template <typename MediaComponentT>
  [[nodiscard]] handler_result handle_qos_requirements(
      const MediaComponentT& media_component, const std::string& app_session_id,
      oai::model::pcf::SmPolicyDecision& decision, qos_context& qos_ctx);

  // Create the QosData + PccRule (with SDF filters) for one media component
  // [TS 29.512 §5.6.2.8, §4.1.4.2.1, TS 29.513 §7.3.3]. Returns the derived
  // QosData in `out_qos_data` so the caller can decide whether QoS
  // characteristics are required (non-standardized 5QI). Public
  // so the derivation logic stays directly unit-testable in isolation from
  // create_qos_characteristics/setup_qos_monitoring's side effects, matching
  // test_qos_processing.cpp's existing granular coverage.
  template <typename MediaComponentT>
  [[nodiscard]] handler_result create_qos_data_from_media_component(
      const MediaComponentT& media_component, const std::string& app_session_id,
      oai::model::pcf::SmPolicyDecision& decision, qos_context& qos_ctx,
      oai::model::pcf::QosData& out_qos_data);

  // Validate the QoS this app-session authorized against operator policy and
  // the subscribed envelope [TS 29.514 §4.1.3.1, TS 23.503 §6.1.3.2.3]. See
  // app_session.hpp's prior free-function declaration for the full contract
  // (allowed 5QI, ARP priority range, per-flow MBR ceiling, GBR<=MBR
  // structural sanity, cumulative Session-AMBR check).
  [[nodiscard]] handler_result validate_qos_authorization(
      const oai::model::pcf::SmPolicyDecision& decision,
      const std::vector<std::string>& owned_qos_ids);

 private:
  const qos_reference_store& m_qos_ref_store;
  const operator_qos_policy& m_op_policy;
};

}  // namespace oai::pcf::app::policy_auth

#endif  // FILE_QOS_DERIVER_HPP_SEEN
