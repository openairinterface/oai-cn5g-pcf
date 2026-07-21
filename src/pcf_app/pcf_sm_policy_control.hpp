/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_PCF_SM_POLICY_CONTROL_SEEN
#define FILE_PCF_SM_POLICY_CONTROL_SEEN

#include <string>
#include <unordered_map>
#include <shared_mutex>
#include <memory>
#include <optional>

#include "SmPolicyContextData.h"
#include "SmPolicyDecision.h"
#include "SmPolicyDeleteData.h"
#include "SmPolicyControl.h"
#include "SmPolicyUpdateContextData.h"
#include "sm_policy/pcf_smpc_status_code.hpp"
#include "sm_policy/individual_sm_association.hpp"
#include "sm_policy_delta.hpp"
#include "uint_generator.hpp"
#include "sm_policy/policy_storage.hpp"
#include "pcf_event.hpp"
#include "operator_qos_policy.hpp"

namespace oai::pcf::app {

/**
 * @brief Service class to handle Session Management Policies
 *
 */
class pcf_smpc {
 public:
  explicit pcf_smpc(
      const std::shared_ptr<oai::pcf::app::sm_policy::policy_storage>&
          policy_storage,
      pcf_event& ev,
      oai::pcf::app::operator_qos_policy qos_authorization_policy = {});
  pcf_smpc(pcf_smpc const&) = delete;
  void operator=(pcf_smpc const&) = delete;

  virtual ~pcf_smpc();

  /**
   * @brief Handler for receiving create sm policy requests, as defined in
   * 3GPP TS 29.512 Chapter 4.2.2
   * The result depends on pre-configured policy rules based on supi, dnn,
   * snssai and default rules in that order
   *
   * @param context input: context from the request
   * @param decision output: policy decision based on context and local
   * provisioning
   * @return sm_policy::status_code
   */
  sm_policy::status_code create_sm_policy_handler(
      const oai::_3gpp::model::SmPolicyContextData& context,
      oai::_3gpp::model::SmPolicyDecision& decision,
      std::string& association_id, std::string& problem_details);

  /**
   * @brief Handler for deleting an existing SM policy association, as defined
   * in 3GPP TS 29.512 Chapter 4.2.5
   *
   * @param id The ID of the existing association, if not exist return
   * status_code::NOT_FOUND
   * @param delete_data input: delete data from the request
   * @param problem_details output: additional information in case of an error
   * @return sm_policy::status_code
   */
  sm_policy::status_code delete_sm_policy_handler(
      const std::string& id,
      const oai::_3gpp::model::SmPolicyDeleteData& delete_data,
      std::string& problem_details);

  /**
   * @brief Handler for getting an existing SM policy association, as defined in
   * 3GPP TS 29.512 Annex A
   *
   * @param id The ID of the existing association, if not exist return
   * status_code::NOT_FOUND
   * @param control output: The SmPolicyControl data
   * @param problem_details output: additional information in case of an
   * error
   * @return sm_policy::status_code
   */
  sm_policy::status_code get_sm_policy_handler(
      const std::string& id, oai::_3gpp::model::SmPolicyControl& control,
      std::string& problem_details);

  /**
   * @brief Handler for updating the policy decision based on the provided
   * update context, as define in 3GPP TS 29.512 Chapter 4.2.4
   *
   * @param id The ID of the existing association, if not exist return
   * status_code::NOT_FOUND
   * @param update_context input: The context of the update
   * @param decision output: The SmPolicyDecision
   * @param problem_details output: additional information in case of an error
   * @return sm_policy::status_code
   */
  sm_policy::status_code update_sm_policy_handler(
      const std::string& id,
      const oai::_3gpp::model::SmPolicyUpdateContextData& update_context,
      oai::_3gpp::model::SmPolicyDecision& decision,
      std::string& problem_details);

 private:
  oai::utils::uint_generator<uint32_t> m_association_id_generator;

  std::unordered_map<
      std::string, oai::pcf::app::sm_policy::individual_sm_association>
      m_associations;

  mutable std::shared_mutex m_associations_mutex;

  std::shared_ptr<oai::pcf::app::sm_policy::policy_storage> m_policy_storage;

  // Operator QoS authorization limits used when authorizing the subscribed
  // Session-AMBR / default QoS into a SessionRule [TS 29.512 §4.2.6.6.1].
  // Injected at construction (default = permissive); populated from config in a
  // later step (see N5_QoS_Phase1_§1.4 plan §7.4).
  oai::pcf::app::operator_qos_policy m_qos_authorization_policy;

  void handle_policy_change(
      const std::shared_ptr<oai::pcf::app::sm_policy::policy_decision>&
          decision);

  // Notify the SMF of a decision. Takes an immutable snapshot + the context
  // (SUPI/DNN/notifUri) captured under the association lock, so the caller can
  // release the lock before this blocking SMF round-trip [CP.22].
  sm_policy::status_code send_sm_policy_control_update_notify(
      const oai::model::pcf::SmPolicyContextData& context,
      const std::shared_ptr<const oai::model::pcf::SmPolicyDecision>& decision);

  void handle_session_binding_request(
      const std::optional<std::string>& ipv4,
      const std::optional<std::string>& supi,
      const std::optional<std::string>& dnn,
      std::optional<std::string>& assoc_id,
      oai::_3gpp::model::SmPolicyDecision& decision, std::uint64_t& version);

  // Optimistic, version-checked apply. Applies `delta` and notifies the SMF
  // only if the association is still at `expected_version`; otherwise reports a
  // conflict (with the current version/decision) via `out` for the caller to
  // retry against.
  void handle_update_decision_request(
      std::optional<std::string>& association_id, std::uint64_t expected_version,
      const oai::pcf::app::sm_policy_delta& delta,
      oai::pcf::app::decision_apply_result& out);

  // TODO [QOS] Add QoS coordination functions between Policy Authorization and SM Policy Control [TS 29.513 §5.2.2.2, TS 29.512 §4.2.3]
  // Implement the following functions to ensure proper QoS policy coordination:

  // TODO [QOS] PCC rule conflict resolution and ID management [TS 23.503 §6.1.3.7, TS 29.512 §4.1.4.2.1]
  // void resolve_pcc_rule_conflicts(
  //     const oai::model::pcf::SmPolicyDecision& policy_auth_decision,
  //     oai::model::pcf::SmPolicyDecision& current_sm_decision);

  // TODO [QOS] QoS precedence and priority coordination [TS 29.512 §5.6.2.6, TS 23.503 §6.3.1]
  // bool validate_qos_precedence_ranges(
  //     const oai::model::pcf::SmPolicyDecision& new_decision,
  //     const std::string& association_id);

  // TODO [QOS] Generate unique identifiers for cross-service coordination [TS 29.512 §4.1.4.2.1]
  // std::string generate_unique_pcc_rule_id(const std::string& service_prefix);
  // uint32_t allocate_precedence_value(const std::string& association_id, uint32_t base_precedence);

  // TODO [QOS] QoS data validation and consistency checks [TS 29.512 §4.2.6.2.3, §5.6.2.8]
  // bool validate_qos_data_consistency(
  //     const std::map<std::string, oai::model::pcf::QosData>& qos_data_map,
  //     const std::string& association_id);

  // TODO [QOS] Resource availability and capacity management [TS 29.512 §4.2.6.8, TS 23.503 §6.1.4]
  // bool check_qos_resource_availability(
  //     const oai::model::pcf::SmPolicyDecision& requested_decision,
  //     const std::string& association_id);

  // TODO [QOS-MON] QoS monitoring coordination between services [TS 29.512 §4.2.3.25, TS 23.503 §6.1.3.21]
  // void coordinate_qos_monitoring_setup(
  //     const std::map<std::string, oai::model::pcf::QosMonitoringData>& monitoring_data,
  //     const std::string& association_id);

  // for Event Handling
  pcf_event& m_event_sub;
  bs2::connection m_sm_session_binding_connection;
  bs2::connection m_sm_update_decision_connection;
};
}  // namespace oai::pcf::app
#endif /* FILE_PCF_SM_POLICY_CONTROL_SEEN */
