/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include <string>
#include <memory>
#include <shared_mutex>
#include <unordered_map>
#include <optional>

#include "SmPolicyDecision.h"
#include "SmPolicyContextData.h"
#include "policy_decision.hpp"

namespace oai::pcf::app::sm_policy {

class policy_storage {
 public:
  /**
   * @brief Finds a policy based on the existing supi, dnn, slice and default
   * policies in that order.
   *
   * @param context  The policy context containing supi or dnn or snssai
   * @param chosen_decision
   * decision base class
   * @return pointer to the object implementing the chosen, null in case no
   * decision can be found
   */
  virtual std::shared_ptr<policy_decision> find_policy(
      const oai::_3gpp::model::SmPolicyContextData& context) = 0;

  /**
   * @brief Calls the callback when any of the policies have been updated
   *
   * @param callback
   */
  virtual void subscribe_to_decision_change(
      std::function<void(std::shared_ptr<policy_decision>&)> callback) = 0;

  virtual void insert_supi_decision(
      const std::string& supi,
      const oai::_3gpp::model::SmPolicyDecision& decision) = 0;

  virtual void insert_dnn_decision(
      const std::string& dnn,
      const oai::_3gpp::model::SmPolicyDecision& decision) = 0;

  virtual void insert_slice_decision(
      const oai::_3gpp::model::Snssai&,
      const oai::_3gpp::model::SmPolicyDecision& decision) = 0;

  /**
   * Indexes association_id for session binding under the UE IPv4 address,
   * SUPI and DNN of context [TS 29.513 §6.2]. Calling it again for the same id
   * re-indexes it, e.g. after a UE_IP_CH update [TS 29.513 §5.2.2.3].
   */
  virtual void insert_associations(
      const oai::_3gpp::model::SmPolicyContextData& context,
      const std::string& association_id) = 0;

  /**
   * Removes association_id from the session-binding index, whatever keys it
   * was indexed under [TS 29.513 §5.2.3.1 step 14].
   */
  virtual void remove_associations(const std::string& association_id) = 0;

  /**
   * Session binding: finds the association whose UE IPv4 address, SUPI and
   * DNN match every provided (non-empty) parameter [TS 29.513 §6.2].
   *
   * @return the association id, null if no association matches
   */
  virtual std::shared_ptr<std::string> find_association(
      const std::optional<std::string>& ipv4,
      const std::optional<std::string>& supi,
      const std::optional<std::string>& dnn) = 0;
};

}  // namespace oai::pcf::app::sm_policy