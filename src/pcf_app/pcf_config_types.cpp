/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "pcf_config_types.hpp"

#include <sstream>
#include <utility>
#include "config.hpp"

using namespace oai::config;
using namespace oai::config::pcf;

qos_authorization_config::qos_authorization_config() {
  m_config_name     = "QoS Authorization";
  m_max_flow_mbr_ul = string_config_value("Max Flow MBR Uplink", "");
  m_max_flow_mbr_dl = string_config_value("Max Flow MBR Downlink", "");
  m_max_session_ambr_ul =
      string_config_value("Max Session-AMBR Uplink", "");
  m_max_session_ambr_dl =
      string_config_value("Max Session-AMBR Downlink", "");
  m_reject_on_missing_subscription =
      option_config_value("reject_on_missing_subscription", false);
  m_set = true;
}

void qos_authorization_config::from_yaml(const YAML::Node& node) {
  if (node["allowed_dynamic_5qi"]) {
    m_allowed_dynamic_5qi.clear();
    for (const auto& entry : node["allowed_dynamic_5qi"]) {
      m_allowed_dynamic_5qi.push_back(entry.as<int32_t>());
    }
  }
  if (node["max_flow_mbr_ul"]) {
    m_max_flow_mbr_ul.from_yaml(node["max_flow_mbr_ul"]);
  }
  if (node["max_flow_mbr_dl"]) {
    m_max_flow_mbr_dl.from_yaml(node["max_flow_mbr_dl"]);
  }
  if (node["max_session_ambr_ul"]) {
    m_max_session_ambr_ul.from_yaml(node["max_session_ambr_ul"]);
  }
  if (node["max_session_ambr_dl"]) {
    m_max_session_ambr_dl.from_yaml(node["max_session_ambr_dl"]);
  }
  if (node["reject_on_missing_subscription"]) {
    m_reject_on_missing_subscription.from_yaml(
        node["reject_on_missing_subscription"]);
  }
}

std::string qos_authorization_config::to_string(
    const std::string& indent) const {
  if (!m_set) return "";
  std::string out;
  std::string title_fmt = get_title_formatter(0);
  std::string value_fmt = get_value_formatter(1);

  out.append(indent).append(fmt::format(title_fmt, m_config_name));

  std::stringstream allowed;
  for (size_t i = 0; i < m_allowed_dynamic_5qi.size(); ++i) {
    if (i) allowed << ", ";
    allowed << m_allowed_dynamic_5qi[i];
  }
  out.append(indent).append(
      fmt::format(value_fmt, "Allowed Dynamic 5QIs", allowed.str()));
  out.append(indent).append(fmt::format(
      value_fmt, m_max_flow_mbr_ul.get_config_name(),
      m_max_flow_mbr_ul.get_value()));
  out.append(indent).append(fmt::format(
      value_fmt, m_max_flow_mbr_dl.get_config_name(),
      m_max_flow_mbr_dl.get_value()));
  out.append(indent).append(fmt::format(
      value_fmt, m_max_session_ambr_ul.get_config_name(),
      m_max_session_ambr_ul.get_value()));
  out.append(indent).append(fmt::format(
      value_fmt, m_max_session_ambr_dl.get_config_name(),
      m_max_session_ambr_dl.get_value()));
  out.append(indent).append(fmt::format(
      value_fmt, m_reject_on_missing_subscription.get_config_name(),
      m_reject_on_missing_subscription.get_value() ? "true" : "false"));

  return out;
}

const std::vector<int32_t>& qos_authorization_config::get_allowed_dynamic_5qi()
    const {
  return m_allowed_dynamic_5qi;
}

const std::string& qos_authorization_config::get_max_flow_mbr_ul() const {
  return m_max_flow_mbr_ul.get_value();
}

const std::string& qos_authorization_config::get_max_flow_mbr_dl() const {
  return m_max_flow_mbr_dl.get_value();
}

const std::string& qos_authorization_config::get_max_session_ambr_ul() const {
  return m_max_session_ambr_ul.get_value();
}

const std::string& qos_authorization_config::get_max_session_ambr_dl() const {
  return m_max_session_ambr_dl.get_value();
}

bool qos_authorization_config::get_reject_on_missing_subscription() const {
  return m_reject_on_missing_subscription.get_value();
}

notify_failure_recovery_config::notify_failure_recovery_config() {
  m_config_name = "Notify-Failure Recovery";
  m_retry_drain_ttl_seconds =
      int_config_value("retry_drain_ttl_seconds", 30);
  m_retry_drain_ttl_seconds.set_validation_interval(1, 3600);
  m_retry_drain_max_entries =
      int_config_value("retry_drain_max_entries", 10000);
  m_retry_drain_max_entries.set_validation_interval(1, 1000000);
  m_max_notify_retries = int_config_value("max_notify_retries", 3);
  m_max_notify_retries.set_validation_interval(0, 20);
  m_retry_backoff_initial_ms =
      int_config_value("retry_backoff_initial_ms", 500);
  m_retry_backoff_initial_ms.set_validation_interval(1, 60000);
  m_rollback_tracker_ttl_seconds =
      int_config_value("rollback_tracker_ttl_seconds", 30);
  m_rollback_tracker_ttl_seconds.set_validation_interval(1, 3600);
  m_rollback_tracker_max_entries =
      int_config_value("rollback_tracker_max_entries", 10000);
  m_rollback_tracker_max_entries.set_validation_interval(1, 1000000);
  m_set = true;
}

void notify_failure_recovery_config::from_yaml(const YAML::Node& node) {
  if (node["retry_drain_ttl_seconds"]) {
    m_retry_drain_ttl_seconds.from_yaml(node["retry_drain_ttl_seconds"]);
  }
  if (node["retry_drain_max_entries"]) {
    m_retry_drain_max_entries.from_yaml(node["retry_drain_max_entries"]);
  }
  if (node["max_notify_retries"]) {
    m_max_notify_retries.from_yaml(node["max_notify_retries"]);
  }
  if (node["retry_backoff_initial_ms"]) {
    m_retry_backoff_initial_ms.from_yaml(node["retry_backoff_initial_ms"]);
  }
  if (node["rollback_tracker_ttl_seconds"]) {
    m_rollback_tracker_ttl_seconds.from_yaml(
        node["rollback_tracker_ttl_seconds"]);
  }
  if (node["rollback_tracker_max_entries"]) {
    m_rollback_tracker_max_entries.from_yaml(
        node["rollback_tracker_max_entries"]);
  }
}

std::string notify_failure_recovery_config::to_string(
    const std::string& indent) const {
  if (!m_set) return "";
  std::string out;
  std::string title_fmt = get_title_formatter(0);
  std::string value_fmt = get_value_formatter(1);

  out.append(indent).append(fmt::format(title_fmt, m_config_name));
  out.append(indent).append(fmt::format(
      value_fmt, m_retry_drain_ttl_seconds.get_config_name(),
      m_retry_drain_ttl_seconds.get_value()));
  out.append(indent).append(fmt::format(
      value_fmt, m_retry_drain_max_entries.get_config_name(),
      m_retry_drain_max_entries.get_value()));
  out.append(indent).append(fmt::format(
      value_fmt, m_max_notify_retries.get_config_name(),
      m_max_notify_retries.get_value()));
  out.append(indent).append(fmt::format(
      value_fmt, m_retry_backoff_initial_ms.get_config_name(),
      m_retry_backoff_initial_ms.get_value()));
  out.append(indent).append(fmt::format(
      value_fmt, m_rollback_tracker_ttl_seconds.get_config_name(),
      m_rollback_tracker_ttl_seconds.get_value()));
  out.append(indent).append(fmt::format(
      value_fmt, m_rollback_tracker_max_entries.get_config_name(),
      m_rollback_tracker_max_entries.get_value()));

  return out;
}

int notify_failure_recovery_config::get_retry_drain_ttl_seconds() const {
  return m_retry_drain_ttl_seconds.get_value();
}

int notify_failure_recovery_config::get_retry_drain_max_entries() const {
  return m_retry_drain_max_entries.get_value();
}

int notify_failure_recovery_config::get_max_notify_retries() const {
  return m_max_notify_retries.get_value();
}

int notify_failure_recovery_config::get_retry_backoff_initial_ms() const {
  return m_retry_backoff_initial_ms.get_value();
}

int notify_failure_recovery_config::get_rollback_tracker_ttl_seconds() const {
  return m_rollback_tracker_ttl_seconds.get_value();
}

int notify_failure_recovery_config::get_rollback_tracker_max_entries() const {
  return m_rollback_tracker_max_entries.get_value();
}

policy_config::policy_config(
    const std::string& policy_decisions_path, const std::string& pcc_rules_path,
    const std::string& traffic_rules_path, const std::string& qos_data_path,
    const std::string& qos_reference_path) {
  m_config_name = "Policy";
  m_traffic_rules_path =
      string_config_value("Traffic Rules", traffic_rules_path);
  m_pcc_rules_path = string_config_value("PCC Rules", pcc_rules_path);
  m_policy_decisions_path =
      string_config_value("Policy Decisions", policy_decisions_path);
  m_qos_data_path = string_config_value("QoS Data", qos_data_path);
  m_qos_reference_path =
      string_config_value("QoS References", qos_reference_path);
  m_set = true;
}

void policy_config::from_yaml(const YAML::Node& node) {
  if (node["policy_decisions_path"]) {
    m_policy_decisions_path.from_yaml(node["policy_decisions_path"]);
  }
  if (node["pcc_rules_path"]) {
    m_pcc_rules_path.from_yaml(node["pcc_rules_path"]);
  }
  if (node["traffic_rules_path"]) {
    m_traffic_rules_path.from_yaml(node["traffic_rules_path"]);
  }
  if (node["qos_data_path"]) {
    m_qos_data_path.from_yaml(node["qos_data_path"]);
  }
  if (node["qos_reference_path"]) {
    m_qos_reference_path.from_yaml(node["qos_reference_path"]);
  }
}

std::string policy_config::to_string(const std::string& indent) const {
  if (!m_set) return "";
  std::string out;
  std::string title_fmt = get_title_formatter(0);
  std::string value_fmt = get_value_formatter(1);

  out.append(indent).append(fmt::format(title_fmt, m_config_name));
  out.append(indent).append(fmt::format(
      value_fmt, m_policy_decisions_path.get_config_name(),
      m_policy_decisions_path.get_value()));
  out.append(indent).append(fmt::format(
      value_fmt, m_pcc_rules_path.get_config_name(),
      m_pcc_rules_path.get_value()));
  out.append(indent).append(fmt::format(
      value_fmt, m_traffic_rules_path.get_config_name(),
      m_traffic_rules_path.get_value()));
  out.append(indent).append(fmt::format(
      value_fmt, m_qos_data_path.get_config_name(),
      m_qos_data_path.get_value()));
  out.append(indent).append(fmt::format(
      value_fmt, m_qos_reference_path.get_config_name(),
      m_qos_reference_path.get_value()));

  return out;
}

const std::string& policy_config::get_pcc_rules_path() const {
  return m_pcc_rules_path.get_value();
}

const std::string& policy_config::get_policy_decisions_path() const {
  return m_policy_decisions_path.get_value();
}

const std::string& policy_config::get_traffic_rules_path() const {
  return m_traffic_rules_path.get_value();
}

const std::string& policy_config::get_qos_data_path() const {
  return m_qos_data_path.get_value();
}

const std::string& policy_config::get_qos_reference_path() const {
  return m_qos_reference_path.get_value();
}

pcf_config_type::pcf_config_type(
    const std::string& name, const std::string& host, const sbi_interface& sbi,
    bool enable_policy_provisioning_api, const policy_config& policy)
    : nf(name, host, sbi), m_policy_config(policy) {
  m_enable_policy_provisioning_api = option_config_value(
      "enable_policy_provisioning_api", enable_policy_provisioning_api);
  m_policy_config.set_config();
}

void pcf_config_type::from_yaml(const YAML::Node& node) {
  nf::from_yaml(node);
  if (node["enable_policy_provisioning_api"]) {
    m_enable_policy_provisioning_api.from_yaml(
        node["enable_policy_provisioning_api"]);
  }
  if (node["local_policy"]) {
    m_policy_config.from_yaml(node["local_policy"]);
  }
  if (node["qos_authorization"]) {
    m_qos_authorization_config.from_yaml(node["qos_authorization"]);
  }
  if (node["notify_failure_recovery"]) {
    m_notify_failure_recovery_config.from_yaml(
        node["notify_failure_recovery"]);
  }
}

std::string pcf_config_type::to_string(const std::string& indent) const {
  std::string out = nf::to_string("");

  unsigned int inner_width = get_inner_width(indent.length());
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, OUTER_LIST_ELEM,
      m_enable_policy_provisioning_api.get_config_name(), inner_width,
      m_enable_policy_provisioning_api.to_string(indent)));

  if (!m_enable_policy_provisioning_api.get_value()) {
    out.append(m_policy_config.to_string(indent));
  }

  out.append(m_qos_authorization_config.to_string(indent));
  out.append(m_notify_failure_recovery_config.to_string(indent));

  return out;
}

void pcf_config_type::validate() {
  nf::validate();
  m_policy_config.validate();
}

bool pcf_config_type::enable_policy_provisioning_api() const {
  return m_enable_policy_provisioning_api.get_value();
}

const policy_config& pcf_config_type::get_policy_config() const {
  return m_policy_config;
}

const qos_authorization_config&
pcf_config_type::get_qos_authorization_config() const {
  return m_qos_authorization_config;
}

const notify_failure_recovery_config&
pcf_config_type::get_notify_failure_recovery_config() const {
  return m_notify_failure_recovery_config;
}
