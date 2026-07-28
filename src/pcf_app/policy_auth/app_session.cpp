/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include <chrono>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "AppSessionContext.h"
#include "TrafficControlData.h"
#include "PccRule.h"
#include "QosData.h"
#include "QosCharacteristics.h"
#include "QosResourceType.h"
#include "Arp.h"
#include "FlowInformation.h"
#include "FlowDirectionRm.h"
#include "MediaComponent.h"
#include "MediaSubComponent.h"
#include "MediaComponentRm.h"
#include "MediaSubComponentRm.h"
#include "SmPolicyDecision.h"
#include "AfSfcRequirement.h"
#include "AppSessionContextReqData.h"
#include "AppSessionContextUpdateData.h"
#include "FlowStatus.h"
#include <nlohmann/json.hpp>
#include "policy_auth/pcf_policy_authorization_status_code.hpp"
#include "policy_auth/qos_deriver.hpp"
#include "logger.hpp"
#include "app_session.hpp"
#include "uint_generator.hpp"

#define DEFAULT_PCC_RULE_PRECEDENCE 255

namespace oai::pcf::app {
namespace policy_auth {

using namespace oai::model::pcf;
using namespace oai::pcf::app;
using namespace oai::utils;

app_session::app_session(
    std::string id, oai::model::pcf::AppSessionContextReqData context,
    std::optional<std::string> association_id)
    : m_id(std::move(id)),
      m_created_at(std::chrono::system_clock::now()),
      m_context(std::move(context)),
      m_association_id(std::move(association_id)) {}

oai::model::pcf::AppSessionContextReqData app_session::context_snapshot()
    const {
  auto context = m_context.read();
  return *context;
}

void app_session::update_context(
    const oai::model::pcf::AppSessionContextReqData& context) {
  auto handle = m_context.write();
  *handle     = context;
}

app_session_record app_session::to_record() const {
  app_session_record record;
  record.app_session_id     = m_id;
  record.association_id      = m_association_id;
  record.state              = m_state.load();
  record.owned_qos_ids      = m_qos.owned_qos_ids();
  record.owned_pcc_rule_ids = m_qos.owned_rule_ids();
  record.created_at         = m_created_at;
  record.updated_at         = std::chrono::system_clock::now();
  {
    auto context   = m_context.read();
    record.supi    = context->getSupi();
    record.dnn     = context->getDnn();
    record.ue_ipv4 = context->getUeIpv4();
  }
  // af_app_id and context_json are serialized when the DB storage backend lands
  // the in-memory backend does not use to_record().
  return record;
}

handler_result handle_service_function_chaining(
    const oai::model::pcf::AfSfcRequirement& af_sfc,
    oai::model::pcf::SmPolicyDecision& decision) {
  // Extract N6-LAN Traffic Steering Requirements
  std::shared_ptr<oai::model::pcf::TrafficControlData> traffic_control_data =
      std::make_shared<oai::model::pcf::TrafficControlData>();

  if (!af_sfc.sfcIdDlIsSet() && !af_sfc.sfcIdUlIsSet()) {
    Logger::pcf_app().error(
        "Failed either UL SFC ID or DL SFC ID should be set");
    return handler_result{
        .status          = status_code::BAD_REQUEST,
        .problem_details = "INVALID_SERVICE_INFORMATION"};
  }

  // Set Traffic Steering Policy ID for DL and/or UL based on the presence of
  // corresponding SFC IDs
  if (af_sfc.sfcIdDlIsSet()) {
    traffic_control_data->setTrafficSteeringPolIdDl(af_sfc.getSfcIdDl());
  }

  if (af_sfc.sfcIdUlIsSet()) {
    traffic_control_data->setTrafficSteeringPolIdUl(af_sfc.getSfcIdUl());
  }

  // TODO [PAS]: Transparently include SFC Metadata if available

  // Add the traffic control to PCC rules
  std::shared_ptr<oai::model::pcf::PccRule> pcc_rule =
      std::make_shared<oai::model::pcf::PccRule>();
  // Generate Id using id generator
  auto& uid_generator =
      oai::utils::uint_uid_generator<uint32_t>::get_instance();
  uint32_t uid = uid_generator.get_uid();
  Logger::pcf_app().debug(fmt::format("Generated PCC Rule ID: {}", uid));

  std::string pcc_rule_id            = std::to_string(uid);
  std::string rcId                   = "rc-" + pcc_rule_id;
  std::vector<std::string> refTcData = {rcId};

  pcc_rule->setRefTcData(refTcData);
  pcc_rule->setPccRuleId(pcc_rule_id);

  // // Create and set TCId on traffic control data and add it as RefTc to PCC
  traffic_control_data->setTcId(rcId);

  // Set traffic control to decision
  // decision.setTraffContDecs(used_traffic_control);
  auto traffic_control_map = decision.getTraffContDecs();
  traffic_control_map.insert(std::make_pair(rcId, *traffic_control_data));
  decision.setTraffContDecs(traffic_control_map);

  // Set PCC rule to decision
  auto pcc_rules_map = decision.getPccRules();
  pcc_rules_map.insert(std::make_pair(pcc_rule_id, *pcc_rule));
  decision.setPccRules(pcc_rules_map);

  return handler_result{.status = status_code::OK};
}

handler_result handle_service_function_chaining_update(
    const oai::model::pcf::AfSfcRequirement& af_sfc,
    oai::model::pcf::SmPolicyDecision& decision,
    oai::model::pcf::AppSessionContextReqData& context) {
  Logger::pcf_app().info("Handling Service Function Chaining Update");
  auto result = handle_service_function_chaining(af_sfc, decision);
  if (result.problem_details.has_value()) {
    return result;
  }

  auto af_sfc_req = context.getAfSfcReq();

  if (af_sfc.sfcIdDlIsSet()) {
    af_sfc_req.setSfcIdDl(af_sfc.getSfcIdDl());
  }

  if (af_sfc.sfcIdUlIsSet()) {
    af_sfc_req.setSfcIdUl(af_sfc.getSfcIdUl());
  }

  // TODO [PAS] Transparently include SFC Metadata if available

  context.setAfSfcReq(af_sfc_req);

  return handler_result{.status = status_code::OK};
}

handler_result validate_and_merge_decision(
    const oai::model::pcf::SmPolicyDecision& request_decision,
    oai::model::pcf::SmPolicyDecision& current_decision, bool update) {
  Logger::pcf_app().info("Validating and Merging Decision");

  // TODO [PAS] Discuss with team how to handle creation of new PCC rules for
  // the same traffic control data

  /* Note: Current implementation. The request decision contains the decision to
   * be made by the PCF. The PCC rules in the request decision will be assigned
   * a precedence value higher than the highest precedence value in the current
   * decision. During update new PCC rules will be added to the current
   * decision. With a new precedence value higher than the highest precedence
   * value in the current decision.
   */

  // Get the highest precedence value from current_decision PCC rules
  int highest_precedence = 0;
  for (const auto& [key, value] : current_decision.getPccRules()) {
    if (value.getPrecedence() > highest_precedence) {
      highest_precedence = value.getPrecedence();
    }
  }
  if (highest_precedence == 0) {
    Logger::pcf_app().debug(fmt::format(
        "Current decision has no explicit PCC rule precedence values. "
        "Starting new dynamic assignments from the default precedence floor "
        "{}.",
        DEFAULT_PCC_RULE_PRECEDENCE));
    highest_precedence = DEFAULT_PCC_RULE_PRECEDENCE;
  }

  // Check if PCC rule id in request decision exists in current decision
  if (request_decision.getPccRules().size() > 0 && !update) {
    const auto existing_pcc_rules = current_decision.getPccRules();
    for (const auto& [key, value] : request_decision.getPccRules()) {
      auto iter = existing_pcc_rules.find(key.c_str());
      if (iter != existing_pcc_rules.end() &&
          !iter->first.empty()) {
        Logger::pcf_app().debug(fmt::format(
          "Rejecting create request because PCC Rule ID '{}' already exists "
          "in the current decision. Existing PCC rules can only be changed "
          "through the update path.",
          key.c_str()));
        return handler_result{
            .status          = status_code::FORBIDDEN,
            .problem_details = "INVALID_SERVICE_INFORMATION"};
      }
    }
  }

  // Check if TcId in traffic control data in request decision exists in current
  // decision
  if (request_decision.getTraffContDecs().size() > 0 && !update) {
    const auto existing_traff_cont_decs = current_decision.getTraffContDecs();
    for (const auto& [key, value] : request_decision.getTraffContDecs()) {
      auto iter = existing_traff_cont_decs.find(key);
      if (iter != existing_traff_cont_decs.end() &&
          !iter->first.empty()) {
        Logger::pcf_app().debug(fmt::format(
          "Rejecting create request because Traffic Control ID '{}' already "
          "exists in the current decision. Existing traffic-control "
          "entries can only be changed through the update path.",
          key.c_str()));
        return handler_result{
            .status          = status_code::FORBIDDEN,
            .problem_details = "INVALID_SERVICE_INFORMATION"};
      }
    }
  }

  // Merge the request decision with current decision
  auto pccRulesMap = current_decision.getPccRules();
  for (auto& [key, value] : request_decision.getPccRules()) {
    if (value.getPrecedence() == 0) {
      Logger::pcf_app().debug(fmt::format(
          "PCC Rule '{}' arrived without an explicit precedence. Assigning "
          "the next available dynamic precedence {} so the merged decision "
          "remains unambiguous.",
          key, highest_precedence + 1));
      value.setPrecedence(++highest_precedence);
    } else if (value.getPrecedence() > highest_precedence) {
      Logger::pcf_app().debug(fmt::format(
          "PCC Rule '{}' keeps its explicit precedence {}. This becomes the "
          "new highest precedence seen during merge.",
          key, value.getPrecedence()));
      highest_precedence = value.getPrecedence();
    }
    pccRulesMap.insert(std::make_pair(key, value));
  }
  current_decision.setPccRules(pccRulesMap);

  // Merge QoS-related decision data from the request into the current decision
  // [TS 29.512 §4.2.6.2.3, §5.6.2.4]: the merged decision carries forward the
  // request's QosData, QosCharacteristics and QosMonitoringData. A colliding id
  // means the request re-authorizes that entry (a QoS upgrade/downgrade on the
  // update path), so the request value replaces the current one -- insert_or_assign
  // [TS 23.503 §4.3.3.2.2, TS 29.512 §4.2.6.6.1]. When QoS was written straight
  // into current_decision (the create path), request_decision carries no QoS and
  // these loops are no-ops.
  auto qosDecsMap = current_decision.getQosDecs();
  for (const auto& [key, value] : request_decision.getQosDecs()) {
    qosDecsMap.insert_or_assign(key, value);
  }
  current_decision.setQosDecs(qosDecsMap);  // [TS 29.512 §5.6.2.8]

  auto qosCharsMap = current_decision.getQosChars();
  for (const auto& [key, value] : request_decision.getQosChars()) {
    qosCharsMap.insert_or_assign(key, value);
  }
  current_decision.setQosChars(qosCharsMap);  // [TS 29.512 §5.6.2.16]

  auto qosMonDecsMap = current_decision.getQosMonDecs();
  for (const auto& [key, value] : request_decision.getQosMonDecs()) {
    qosMonDecsMap.insert_or_assign(key, value);
  }
  current_decision.setQosMonDecs(qosMonDecsMap);  // [TS 29.512 §5.6.2.40]

  // Conflict resolution beyond last-writer-wins -- pre-empting a lower-priority
  // service when cumulative authorized QoS is exceeded -- is deferred to Phase 2
  // [TS 23.503 §6.1.3.7].

  // Merge Traffic Control Data
  auto trafficControlMap = current_decision.getTraffContDecs();
  for (auto& [key, value] : request_decision.getTraffContDecs()) {
    trafficControlMap.insert(std::make_pair(key, value));
  }

  try {
    auto pcc_rules = current_decision.getPccRules();
    // pcc_rules.erase(key);
    for (auto& [key, value] : pcc_rules) {
      for (auto& refTcData : value.getRefTcData()) {
        // Check if refTcData is in trafficControlMap, if not remove PCC rule
        if (trafficControlMap.find(refTcData) == trafficControlMap.end()) {
          Logger::pcf_app().debug(fmt::format(
              "PCC Rule '{}' references missing Traffic Control ID '{}'. "
              "Clearing refTcData on the rule because the referenced "
              "traffic-control decision is not present after merge.",
              key.c_str(), refTcData));
          auto refTcDataVector = pcc_rules[key].getRefTcData();
          // Set empty vector
          refTcDataVector.clear();
          pcc_rules[key].setRefTcData(refTcDataVector);
          current_decision.setPccRules(pcc_rules);
        }
      }
    }
  } catch (const std::exception& e) {
    Logger::pcf_app().error(
        fmt::format("Error while processing PCC rules: {}", e.what()));
  }

  current_decision.setTraffContDecs(trafficControlMap);

  // refQosData referential integrity: after the merge, every QoS reference on a
  // PCC rule must resolve to a QosData decision in the merged policy. Drop
  // dangling references so the SMF never receives a PCC rule pointing at a
  // missing QosData [TS 29.512 §4.2.6.2.1, §5.6.2.6].
  {
    auto pcc_rules      = current_decision.getPccRules();
    const auto qos_decs = current_decision.getQosDecs();
    bool rules_changed  = false;
    for (auto& [rule_id, rule] : pcc_rules) {
      if (!rule.refQosDataIsSet()) continue;
      std::vector<std::string> resolved;
      for (const auto& ref : rule.getRefQosData()) {
        if (qos_decs.find(ref) != qos_decs.end()) {
          resolved.push_back(ref);
        } else {
          Logger::pcf_app().warn(fmt::format(
              "PCC Rule '{}' references missing QosData '{}'; dropping the "
              "dangling refQosData after merge [TS 29.512 §5.6.2.6].",
              rule_id, ref));
        }
      }
      if (resolved.size() != rule.getRefQosData().size()) {
        rule.setRefQosData(resolved);
        rules_changed = true;
      }
    }
    if (rules_changed) current_decision.setPccRules(pcc_rules);
  }

  return handler_result{.status = status_code::OK};
}

handler_result authorize_service_info(
    const oai::model::pcf::AppSessionContextReqData& reqData) {
  // TODO: Implement service authorization

  // TODO [QOS] Add QoS authorization checks [TS 29.514 §4.1.3.1, TS 23.503 §6.1.3.2.3]
  // Validate QoS requirements in MediaComponents against:
  // - User subscription QoS profile [TS 29.512 §4.2.6.6.1]
  // - Network slice QoS limits [TS 29.512 §4.2.6.7, TS 23.503 §6.1.4]
  // - Current network resource availability [TS 23.503 §6.1.3.2.3]
  // - Service level agreements [TS 23.503 §6.1.3.2.3]

  return handler_result{.status = status_code::OK};
}

// ---------------------------------------------------------------------------
// QoS parameter mapping (TS 29.513 clause 7.3.3 — AF/N5 -> QoS policy).
// Each rule is annotated with the 3GPP section it derives from.
// ---------------------------------------------------------------------------

// TS 23.501 §5.7.4 Table 5.7.4-1: the set of standardized 5QI values (GBR,
// delay-critical GBR and non-GBR). A standardized 5QI has preconfigured 5G QoS
// characteristics, so the PCF does not signal a QosCharacteristics entry for it
// (TS 29.512 §4.2.6.6.2); a value outside this set is dynamically assigned and
// requires explicitly signalled characteristics (§4.2.6.6.3).
bool is_standardized_5qi(int32_t r5qi) {
  static const std::set<int32_t> kStandardized5qi = {
      1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 65, 66, 67, 69, 70,
      71, 72, 73, 74, 75, 76, 79, 80, 82, 83, 84, 85, 86, 87};
  return kStandardized5qi.count(r5qi) > 0;
}

// TS 29.513 §7.3.3 NOTE 15/17: when desMaxLatency is present, the 5QI "may be
// done according to table 5.7.4-1 in TS 23.501". That authoritative table is not
// available in-repo, so this is an operator-tunable approximation: pick a
// standardized 5QI whose packet delay budget fits the requested latency, GBR vs
// non-GBR selected by whether a guaranteed rate was requested. Falls back to the
// best-effort default 5QI=9 (TS 29.513 §7.3.3: OTHERWISE 5QI=9).
int32_t derive_5qi(std::optional<float> des_max_latency_ms, bool has_gbr) {
  if (!des_max_latency_ms.has_value()) {
    Logger::pcf_app().debug(
        "No desired maximum latency was provided. Falling back to "
        "best-effort 5QI 9.");
    return 9;  // best-effort default
  }
  const float ms = des_max_latency_ms.value();
  if (has_gbr) {
    if (ms <= 50.0f) {
      Logger::pcf_app().debug(fmt::format(
          "GBR flow requested with desired latency {} ms. Selecting 5QI 3 "
          "because it fits the lowest-latency GBR bucket in the current "
          "heuristic.",
          ms));
      return 3;  // 5QI 3  (PDB 50ms, e.g. real-time gaming)
    }
    if (ms <= 150.0f) {
      Logger::pcf_app().debug(fmt::format(
          "GBR flow requested with desired latency {} ms. Selecting 5QI 2 "
          "because it fits the medium-latency GBR bucket in the current "
          "heuristic.",
          ms));
      return 2;  // 5QI 2  (PDB 150ms, e.g. live video)
    }
    Logger::pcf_app().debug(fmt::format(
        "GBR flow requested with desired latency {} ms, which exceeds the "
        "lower-latency GBR buckets. Selecting 5QI 4 in the current "
        "heuristic.",
        ms));
    return 4;  // 5QI 4  (PDB 300ms, non-conversational video)
  }
  if (ms <= 100.0f) {
    Logger::pcf_app().debug(fmt::format(
        "Non-GBR flow requested with desired latency {} ms. Selecting 5QI 7 "
        "because it fits the lowest-latency non-GBR bucket in the current "
        "heuristic.",
        ms));
    return 7;  // 5QI 7  (PDB 100ms, voice/interactive)
  }
  if (ms <= 300.0f) {
    Logger::pcf_app().debug(fmt::format(
        "Non-GBR flow requested with desired latency {} ms. Selecting 5QI 6 "
        "because it fits the medium-latency non-GBR bucket in the current "
        "heuristic.",
        ms));
    return 6;  // 5QI 6  (PDB 300ms, buffered streaming)
  }
  Logger::pcf_app().debug(fmt::format(
      "Non-GBR flow requested with desired latency {} ms, which exceeds the "
      "lower-latency non-GBR buckets. Falling back to best-effort 5QI 9.",
      ms));
  return 9;  // 5QI 9  (best-effort default)
}


// Generate an explicitly-signalled QosCharacteristics entry for a dynamically
// assigned (non-standardized) 5QI [TS 29.512 §4.2.6.6.3, §5.6.2.16]. Standardized
// 5QI values carry preconfigured characteristics and need no entry
// [TS 29.512 §4.2.6.6.2].
handler_result create_qos_characteristics(
    const QosData& qos_data, SmPolicyDecision& decision) {
  if (!qos_data.r5qiIsSet() || is_standardized_5qi(qos_data.getR5qi())) {
    Logger::pcf_app().trace(fmt::format(
        "Skipping explicit QosCharacteristics because 5QI {} is {}. "
        "Standardized 5QIs use preconfigured characteristics, and an unset "
        "5QI cannot be signalled.",
        qos_data.r5qiIsSet() ? std::to_string(qos_data.getR5qi()) : "<unset>",
        qos_data.r5qiIsSet() ? "standardized" : "unset"));
    return handler_result{.status = status_code::OK};
  }

  const int32_t r5qi = qos_data.getR5qi();
  Logger::pcf_app().debug(fmt::format(
      "create_qos_characteristics(): signalling characteristics for "
      "non-standardized 5QI {}",
      r5qi));

  QosCharacteristics qos_char;
  qos_char.setR5qi(r5qi);

  // Resource type inferred from the presence of a guaranteed bit rate
  // [TS 29.512 §5.6.2.16; QosResourceType per TS 29.571].
  const bool is_gbr = qos_data.gbrUlIsSet() || qos_data.gbrDlIsSet();
  oai::model::common::QosResourceType resource_type;
  resource_type.setEnumValue(
      is_gbr ? oai::model::common::QosResourceType_anyOf::
                   eQosResourceType_anyOf::NON_CRITICAL_GBR
             : oai::model::common::QosResourceType_anyOf::
                   eQosResourceType_anyOf::NON_GBR);
  qos_char.setResourceType(resource_type);

  // priorityLevel / packetDelayBudget / packetErrorRate are mandatory for a
  // signalled QosCharacteristics [TS 29.512 §5.6.2.16]. They come from the
  // operator-preconfigured set (carried on the QosData); fall back to defensive
  // defaults with a warning if the operator omitted them.
  qos_char.setPriorityLevel(
      qos_data.priorityLevelIsSet() ? qos_data.getPriorityLevel()
                                    : DEFAULT_ARP_PRIORITY_LEVEL);
  if (qos_data.packetDelayBudgetIsSet()) {
    qos_char.setPacketDelayBudget(qos_data.getPacketDelayBudget());
  } else {
    Logger::pcf_app().warn(fmt::format(
        "QoS reference for non-standardized 5QI {} has no packetDelayBudget; "
        "using default 300ms",
        r5qi));
    qos_char.setPacketDelayBudget(300);
  }
  if (qos_data.packetErrorRateIsSet()) {
    qos_char.setPacketErrorRate(qos_data.getPacketErrorRate());
  } else {
    Logger::pcf_app().warn(fmt::format(
        "QoS reference for non-standardized 5QI {} has no packetErrorRate; "
        "using default 1E-6",
        r5qi));
    qos_char.setPacketErrorRate("1E-6");
  }
  // Averaging window applies only to (delay-critical) GBR flows
  // [TS 29.512 §5.6.2.16].
  if (is_gbr && qos_data.averWindowIsSet()) {
    qos_char.setAveragingWindow(qos_data.getAverWindow());
  }

  // QosCharacteristics are keyed by the (dynamic) 5QI value [TS 29.512 §5.6.2.4].
  auto qos_chars_map = decision.getQosChars();
  qos_chars_map.insert(std::make_pair(std::to_string(r5qi), qos_char));
  decision.setQosChars(qos_chars_map);

  Logger::pcf_app().info(fmt::format(
      "Signalled QosCharacteristics for dynamic 5QI {} (resourceType={})", r5qi,
      is_gbr ? "NON_CRITICAL_GBR" : "NON_GBR"));

  return handler_result{.status = status_code::OK};
}

// TODO [QOS-MON] Setup QoS monitoring based on MediaComponent requirements
// [TS 29.512 §4.1.4.4.6, TS 29.514 §4.2.2.23]
// Tasks:
//   - Read monitoring thresholds from MediaComponent (if present) [TS 29.514 §4.2.2.23]
//   - Create QosMonitoringData entries with threshold and reporting params [TS 29.512 §5.6.2.40]
//   - Add QosMonitoringData to SmPolicyDecision.qosMonDecs [TS 29.512 §5.6.2.40]
//   - Link QosMonitoringData to the PccRule via refQosMon [TS 29.512 §5.6.2.6]
//
// [QOS-MOCK] Phase 1 — QoS monitoring setup (mock; no-op).
// Mocks the TODO [QOS-MON] task above:
//   - No monitoring thresholds are read and no QosMonitoringData is created.
//     This stub only logs to confirm the call order.
handler_result setup_qos_monitoring([[maybe_unused]] SmPolicyDecision& decision) {
  Logger::pcf_app().debug(
      "QoS monitoring setup is not implemented in Phase 1. Returning "
      "success without creating QosMonitoringData or linking refQosMon.");
  return handler_result{.status = status_code::OK};
}

namespace {

// A fully-merged decision that is internally inconsistent is a PCF-side error,
// not an AF-input error: refuse to notify the SMF and surface the diagnostic.
handler_result reject_decision(const std::string& detail) {
  Logger::pcf_app().error(fmt::format(
      "Policy decision validation failed; not notifying the SMF: {}", detail));
  return handler_result{
      .status = status_code::INTERNAL_SERVER_ERROR, .problem_details = detail};
}

}  // namespace

// See app_session.hpp for the contract. Referential-integrity violations are
// fatal (the SMF cannot process a dangling reference); PCC-rule well-formedness
// issues are logged as diagnostics only. Subscription-limit validation is not
// repeated here -- validate_qos_authorization() runs earlier in the same
// pre-notification window [TS 29.512 §4.2.6.6.1].
handler_result validate_policy_decision(const SmPolicyDecision& decision) {
  const auto qos_decs  = decision.getQosDecs();
  const auto qos_chars = decision.getQosChars();
  const auto traff     = decision.getTraffContDecs();

  for (const auto& [rule_id, rule] : decision.getPccRules()) {
    // Well-formedness diagnostics (not fatal: predefined/operator-provisioned
    // rules may legitimately omit these) [TS 29.512 §5.6.2.6, TS 23.503 §6.3.1].
    if (!rule.precedenceIsSet()) {
      Logger::pcf_app().warn(fmt::format(
          "Policy decision validation: PCC rule '{}' has no precedence.",
          rule_id));
    }
    const bool has_flows = rule.flowInfosIsSet() && !rule.getFlowInfos().empty();
    const bool has_app   = rule.appIdIsSet() && !rule.getAppId().empty();
    if (!has_flows && !has_app) {
      Logger::pcf_app().warn(fmt::format(
          "Policy decision validation: PCC rule '{}' has neither flow "
          "information nor an application id.",
          rule_id));
    }

    // Referential integrity (fatal) [TS 29.512 §4.2.6.2.1, §5.6.2.6].
    if (rule.refQosDataIsSet()) {
      for (const auto& ref : rule.getRefQosData()) {
        const auto it = qos_decs.find(ref);
        if (it == qos_decs.end()) {
          return reject_decision(fmt::format(
              "PCC rule '{}' references missing QosData '{}'", rule_id, ref));
        }
        // A non-standardized 5QI must carry a signalled QosCharacteristics
        // [TS 29.512 §4.2.6.6.3, §5.6.2.16].
        const auto& qos = it->second;
        if (qos.r5qiIsSet() && !is_standardized_5qi(qos.getR5qi()) &&
            qos_chars.find(std::to_string(qos.getR5qi())) == qos_chars.end()) {
          return reject_decision(fmt::format(
              "QosData '{}' uses non-standardized 5QI {} without a "
              "QosCharacteristics entry",
              ref, qos.getR5qi()));
        }
      }
    }
    if (rule.refTcDataIsSet()) {
      for (const auto& ref : rule.getRefTcData()) {
        if (traff.find(ref) == traff.end()) {
          return reject_decision(fmt::format(
              "PCC rule '{}' references missing TrafficControlData '{}'",
              rule_id, ref));
        }
      }
    }
  }

  Logger::pcf_app().debug(
      "Policy decision passed pre-notification validation [TS 29.512 "
      "§4.2.6.2].");
  return handler_result{.status = status_code::OK};
}

AppSessionContextReqData merge_patch_context(
    const AppSessionContextReqData& stored,
    const AppSessionContextUpdateData& patch) {
  nlohmann::json merged;
  to_json(merged, stored);
  nlohmann::json patch_json;
  to_json(patch_json, patch);

  // RFC 7396 signals removal of a map member with a JSON null value, but the
  // generated *Rm model types serialise to an object, never null -- so 3GPP
  // fStatus=REMOVED is the removal signal for both a whole media component and
  // a single sub-component inside an otherwise-retained one [TS 29.514
  // §4.2.3.2, §5.6.2.7, §5.6.2.9]. Record the removed keys before merging, then
  // drop them from the merged representation afterwards. A removed component's
  // own sub-components are moot -- the whole entry disappears regardless.
  std::set<std::string> removed_components;
  std::map<std::string, std::set<std::string>> removed_sub_components;
  if (patch.medComponentsIsSet()) {
    for (const auto& [key, media_component] : patch.getMedComponents()) {
      if (media_component.fStatusIsSet() &&
          media_component.getFStatus().getEnumValue() ==
              FlowStatus_anyOf::eFlowStatus_anyOf::REMOVED) {
        removed_components.insert(key);
        continue;
      }
      if (!media_component.medSubCompsIsSet()) continue;
      for (const auto& [sub_key, sub] : media_component.getMedSubComps()) {
        if (sub_component_removed(sub)) removed_sub_components[key].insert(sub_key);
      }
    }
  }

  // Add/replace every field the AF set; medComponents (and their medSubComps)
  // merge entry by entry, so a partial update touches only what it carries.
  merged.merge_patch(patch_json);

  // Delete the removed media components (and removed sub-components of
  // retained ones) from the merged representation.
  auto med_components = merged.find("medComponents");
  if (med_components != merged.end()) {
    for (const auto& key : removed_components) med_components->erase(key);

    for (const auto& [key, sub_keys] : removed_sub_components) {
      auto component = med_components->find(key);
      if (component == med_components->end()) continue;
      auto sub_components = component->find("medSubComps");
      if (sub_components == component->end()) continue;
      for (const auto& sub_key : sub_keys) sub_components->erase(sub_key);
      if (sub_components->empty()) component->erase("medSubComps");
    }

    if (med_components->empty()) merged.erase("medComponents");
  }

  AppSessionContextReqData result;
  from_json(merged, result);
  return result;
}

}  // namespace policy_auth

}  // namespace oai::pcf::app
