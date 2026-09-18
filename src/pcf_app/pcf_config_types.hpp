/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once
#include <cstdint>
#include <vector>

#include "config_types.hpp"

namespace oai::config::pcf {

/**
 * @brief Operator QoS-authorization limits (config view).
 *
 * Parses the `pcf.qos_authorization` YAML block. Bit rates are kept as 3GPP
 * BitRate strings here (e.g. "1 Gbps"); the app layer parses them to bit/s when
 * building oai::pcf::app::operator_qos_policy. Every field is optional; absent
 * fields keep the permissive default (no cap / allow any 5QI / fail-open)
 * [TS 29.514 §4.1.3.1, TS 29.512 §4.2.6.6].
 */
class qos_authorization_config : public config_type {
 private:
  std::vector<int32_t> m_allowed_dynamic_5qi;
  string_config_value m_max_flow_mbr_ul;
  string_config_value m_max_flow_mbr_dl;
  string_config_value m_max_session_ambr_ul;
  string_config_value m_max_session_ambr_dl;
  option_config_value m_reject_on_missing_subscription;

 public:
  qos_authorization_config();

  void from_yaml(const YAML::Node& node) override;

  [[nodiscard]] std::string to_string(const std::string& indent) const override;

  [[nodiscard]] const std::vector<int32_t>& get_allowed_dynamic_5qi() const;
  [[nodiscard]] const std::string& get_max_flow_mbr_ul() const;
  [[nodiscard]] const std::string& get_max_flow_mbr_dl() const;
  [[nodiscard]] const std::string& get_max_session_ambr_ul() const;
  [[nodiscard]] const std::string& get_max_session_ambr_dl() const;
  [[nodiscard]] bool get_reject_on_missing_subscription() const;
};

/**
 * @brief SMF notify-failure recovery limits (config view)
 *
 * Parses the `pcf.notify_failure_recovery` YAML block: TTL/cap for the two
 * bounded tracking structures (SM-side retry-drain queue, PA-side
 * pending_rollback_tracker) plus the retry-drain's bounded-retry schedule.
 * These were flagged as open, unresolved numeric choices in the design doc
 * (§8 Q2/Q3) -- exposed here as operator-tunable rather than hardcoded, since
 * neither TS 29.512 nor TS 29.514 prescribes a value for either.
 */
class notify_failure_recovery_config : public config_type {
 private:
  int_config_value m_retry_drain_ttl_seconds;
  int_config_value m_retry_drain_max_entries;
  int_config_value m_max_notify_retries;
  int_config_value m_retry_backoff_initial_ms;
  int_config_value m_rollback_tracker_ttl_seconds;
  int_config_value m_rollback_tracker_max_entries;

 public:
  notify_failure_recovery_config();

  void from_yaml(const YAML::Node& node) override;

  [[nodiscard]] std::string to_string(const std::string& indent) const override;

  [[nodiscard]] int get_retry_drain_ttl_seconds() const;
  [[nodiscard]] int get_retry_drain_max_entries() const;
  [[nodiscard]] int get_max_notify_retries() const;
  [[nodiscard]] int get_retry_backoff_initial_ms() const;
  [[nodiscard]] int get_rollback_tracker_ttl_seconds() const;
  [[nodiscard]] int get_rollback_tracker_max_entries() const;
};

class policy_config : public config_type {
 private:
  string_config_value m_pcc_rules_path;
  string_config_value m_policy_decisions_path;
  string_config_value m_traffic_rules_path;
  string_config_value m_qos_data_path;
  string_config_value m_qos_reference_path;

 public:
  explicit policy_config(
      const std::string& policy_decisions_path,
      const std::string& pcc_rules_path, const std::string& traffic_rules_path,
      const std::string& qos_data_path, const std::string& qos_reference_path);

  void from_yaml(const YAML::Node& node) override;

  [[nodiscard]] std::string to_string(const std::string& indent) const override;
  [[nodiscard]] const std::string& get_pcc_rules_path() const;
  [[nodiscard]] const std::string& get_policy_decisions_path() const;
  [[nodiscard]] const std::string& get_traffic_rules_path() const;
  [[nodiscard]] const std::string& get_qos_data_path() const;
  [[nodiscard]] const std::string& get_qos_reference_path() const;
};

class pcf_config_type : public nf {
 private:
  option_config_value m_enable_policy_provisioning_api;
  policy_config m_policy_config;
  qos_authorization_config m_qos_authorization_config;
  notify_failure_recovery_config m_notify_failure_recovery_config;

 public:
  explicit pcf_config_type(
      const std::string& name, const std::string& host,
      const sbi_interface& sbi, bool enable_policy_provisioning_api,
      const policy_config& policy);

  void from_yaml(const YAML::Node& node) override;

  [[nodiscard]] std::string to_string(const std::string& indent) const override;

  void validate() override;

  [[nodiscard]] bool enable_policy_provisioning_api() const;
  [[nodiscard]] const policy_config& get_policy_config() const;
  [[nodiscard]] const qos_authorization_config& get_qos_authorization_config()
      const;
  [[nodiscard]] const notify_failure_recovery_config&
  get_notify_failure_recovery_config() const;
};

}  // namespace oai::config::pcf