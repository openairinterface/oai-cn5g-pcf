/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_POLICY_DECISION_SEEN
#define FILE_POLICY_DECISION_SEEN

#include "SmPolicyContextData.h"
#include "SmPolicyDecision.h"
#include "SmPolicyUpdateContextData.h"
#include "pcf_smpc_status_code.hpp"
#include "sm_policy_delta.hpp"

#include <cstdint>
#include <memory>

namespace oai::pcf::app::sm_policy {

/**
 * @brief Base class for policy decisions, also acts as default policy
 *
 */
class policy_decision {
 public:
  explicit policy_decision(const oai::_3gpp::model::SmPolicyDecision& decision)
      : m_decision(
            std::make_shared<oai::_3gpp::model::SmPolicyDecision>(decision)) {}

  // Copies share the immutable decision snapshot (copy-on-write); a later
  // set/apply on either copy rebinds only that copy's shared_ptr.
  policy_decision(const policy_decision& other) = default;

  /**
   * @brief Decides based on context on a policy. In case the return code is !=
   * CREATED, the decision reference may be undefined
   *
   * @param context input: The context of the individual sm policy association
   * @param decision output: The decision based on the context
   * @return oai::pcf::app::sm_policy::status_code   CREATED in case of
   * success
   */
  [[nodiscard]] virtual oai::pcf::app::sm_policy::status_code decide(
      const oai::_3gpp::model::SmPolicyContextData& context,
      oai::_3gpp::model::SmPolicyDecision& decision) const;

  /**
   * @brief Redecides based on the original context, original decision and
   * creates a new decision. The new_decision contains a complete new policy
   * decision
   *
   * @param original_context The context of the create request and/or
   * previous update requests, is changed according to updated values in
   * update_data
   * @param update_data input: The data from the update
   * @param new_decision output: the diff to the old decision (TODO currently no
   * diff, but whole object)
   * @param problem_details output: Error information
   * @return oai::pcf::app::sm_policy::status_code OK in case of successful
   * update
   */
  [[nodiscard]] virtual oai::pcf::app::sm_policy::status_code redecide(
      oai::_3gpp::model::SmPolicyContextData& original_context,
      const oai::_3gpp::model::SmPolicyUpdateContextData& update_data,
      oai::_3gpp::model::SmPolicyDecision& new_decision,
      std::string& problem_details);

  virtual ~policy_decision() = default;

  [[nodiscard]] virtual const oai::_3gpp::model::SmPolicyDecision&
  get_sm_policy_decision() const;

  virtual void set_sm_policy_decision(
      oai::_3gpp::model::SmPolicyDecision& decision);

  // Apply an incremental change set copy-on-write: copy the current immutable
  // decision, apply the delta, atomically rebind, and bump the version. This is
  // the write half of the read-modify-write that callers run under the
  // association lock, so concurrent updates cannot lose each other's changes
  // [TS 29.512 §4.2.3.2].
  virtual void apply_delta(const oai::pcf::app::sm_policy_delta& delta);

  // Cheap immutable snapshot; safe to hold after the association lock is
  // released (e.g. to notify the SMF without holding the lock across the
  // blocking network call).
  [[nodiscard]] virtual std::shared_ptr<const oai::_3gpp::model::SmPolicyDecision>
  snapshot_decision() const;

  [[nodiscard]] virtual uint64_t decision_version() const;

  [[nodiscard]] virtual std::string to_string() const;

 protected:
  oai::pcf::app::sm_policy::status_code handle_plmn_change(
      oai::_3gpp::model::SmPolicyContextData& orig_context,
      const oai::_3gpp::model::SmPolicyUpdateContextData& update,
      std::string& problem_details);

  oai::pcf::app::sm_policy::status_code handle_access_type_change(
      oai::_3gpp::model::SmPolicyContextData& orig_context,
      const oai::_3gpp::model::SmPolicyUpdateContextData& update,
      std::string& problem_details);

  oai::pcf::app::sm_policy::status_code handle_ip_address_change(
      oai::_3gpp::model::SmPolicyContextData& orig_context,
      const oai::_3gpp::model::SmPolicyUpdateContextData& update,
      std::string& problem_details);

  oai::pcf::app::sm_policy::status_code handle_rat_type_change(
      oai::_3gpp::model::SmPolicyContextData& orig_context,
      const oai::_3gpp::model::SmPolicyUpdateContextData& update,
      std::string& problem_details);

  // Authoritative decision held copy-on-write: an immutable snapshot published
  // via shared_ptr. Writers (set/apply) build a new snapshot and rebind; readers
  // take a cheap shared_ptr copy. Always non-null after construction.
  std::shared_ptr<const oai::_3gpp::model::SmPolicyDecision> m_decision;
  uint64_t m_version{0};
};
}  // namespace oai::pcf::app::sm_policy

std::ostream& operator<<(
    std::ostream& os, const oai::pcf::app::sm_policy::policy_decision& storage);

#endif
