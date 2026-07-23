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
#include "logger.hpp"
#include "app_session.hpp"
#include "bitrate.hpp"
#include "uint_generator.hpp"

#define DEFAULT_PCC_RULE_PRECEDENCE 255

// Base precedence for Policy-Authorization-derived PCC rules. TS 23.503 §6.3.1
// requires PCC rule precedence to be unambiguous and leaves the numeric range to
// operator/PCF configuration; we reserve the 1000-1999 band for PA-derived rules
// (distinct from the SM Policy Control side) per the QoS implementation plan.
#define PA_QOS_PRECEDENCE_BASE 1000
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

namespace {

// Default ARP priority level for PA-derived flows. TS 29.513 Table 7.3.3-2 leaves
// ARP "as defined by application specific algorithm" (from resPrio) / "as
// configured by operator" (from qosReference); resPrio is currently unreadable
// (empty model), so a fixed operator default is used. ARP priorityLevel range is
// 1-15 (TS 29.571); 1-8 denote prioritized services (TS 29.513 Table 7.3.3-2
// NOTE 1).
constexpr int32_t DEFAULT_ARP_PRIORITY_LEVEL = 8;

// FlowDirection for an SDF filter, inferred from the IPFilterRule direction
// token. TS 29.212 clause 5.4.2 / TS 29.514 FlowDescription: "permit out ..." is
// downlink (gateway -> UE), "permit in ..." is uplink (UE -> gateway). Defaults
// to BIDIRECTIONAL when the token can't be determined.
FlowDirectionRm flow_direction_from_desc(const std::string& desc) {
  FlowDirectionRm dir;
  if (desc.find(" out ") != std::string::npos ||
      desc.rfind("permit out", 0) == 0) {
    dir.setEnumValue(FlowDirection_anyOf::eFlowDirection_anyOf::DOWNLINK);
  } else if (
      desc.find(" in ") != std::string::npos ||
      desc.rfind("permit in", 0) == 0) {
    dir.setEnumValue(FlowDirection_anyOf::eFlowDirection_anyOf::UPLINK);
  } else {
    dir.setEnumValue(FlowDirection_anyOf::eFlowDirection_anyOf::BIDIRECTIONAL);
  }
  return dir;
}

// Build one FlowInformation (SDF filter) from an IPFilterRule flow-description
// string. TS 29.512 §4.1.4.2.1 / §5.6.2.3: PCC rule SDF template carries the
// flow descriptions; TS 29.514 §5.6.2.7: MediaSubComponent.fDescs.
FlowInformation flow_info_from_desc(const std::string& desc) {
  FlowInformation flow_info;
  flow_info.setFlowDescription(desc);
  flow_info.setFlowDirection(flow_direction_from_desc(desc));
  return flow_info;
}

// True when the SDF (MediaSubComponent) is flagged REMOVED. TS 29.513
// Table 7.3.3-1: for a removed flow the authorized data rate is 0, i.e. the flow
// contributes nothing to the aggregate and installs no filter.
template <typename MediaSubComponentT>
bool sub_component_removed(const MediaSubComponentT& sub) {
  return sub.fStatusIsSet() &&
         sub.getFStatus().getEnumValue() ==
             FlowStatus_anyOf::eFlowStatus_anyOf::REMOVED;
}

// Derive the ARP. TS 29.513 Table 7.3.3-2: ARP is computed at PCC-rule level.
// resPrio -> priorityLevel is deferred (ReservPriority is an empty generated
// model, so the value is unreadable); preemptCap/preemptVuln are taken from the
// request when present (TS 29.514 §5.6.2.7), else safe defaults.
template <typename MediaComponentT>
oai::model::common::Arp derive_arp(const MediaComponentT& mc) {
  oai::model::common::Arp arp;
  // TODO [QOS] Map MediaComponent.resPrio -> arp.priorityLevel. Two blockers:
  // (1) the generated ReservPriority model is one of ~29
  // model/pcf classes OpenAPI Generator v6.0.1 left empty for this anyOf
  // shape (FlowStatus/FlowStatus_anyOf show the correct shape to backport,
  // per the submodule's own model/README.md); (2) TS 29.513 Table 7.3.2-1
  // leaves the resPrio->ARP rule itself as an "application specific
  // algorithm" -- undefined by the standard -- so a concrete mapping (e.g. a
  // fixed PRIO_1..PRIO_16 -> priorityLevel table) still has to be designed
  // once the value is readable.
  arp.setPriorityLevel(DEFAULT_ARP_PRIORITY_LEVEL);
  Logger::pcf_app().debug(fmt::format(
      "Using default ARP priority level {} because MediaComponent.resPrio is "
      "not readable from the current generated model.",
      DEFAULT_ARP_PRIORITY_LEVEL));

  if (mc.preemptCapIsSet()) {
    arp.setPreemptCap(mc.getPreemptCap());
  } else {
    oai::model::common::PreemptionCapability cap;
    cap.setEnumValue(oai::model::common::PreemptionCapability_anyOf::
                         ePreemptionCapability_anyOf::NOT_PREEMPT);
    arp.setPreemptCap(cap);
    Logger::pcf_app().debug(
        "No pre-emption capability was provided in the request. Defaulting "
        "ARP preemptCap to NOT_PREEMPT.");
  }
  if (mc.preemptVulnIsSet()) {
    arp.setPreemptVuln(mc.getPreemptVuln());
  } else {
    oai::model::common::PreemptionVulnerability vuln;
    vuln.setEnumValue(oai::model::common::PreemptionVulnerability_anyOf::
                          ePreemptionVulnerability_anyOf::NOT_PREEMPTABLE);
    arp.setPreemptVuln(vuln);
    Logger::pcf_app().debug(
        "No pre-emption vulnerability was provided in the request. "
        "Defaulting ARP preemptVuln to NOT_PREEMPTABLE.");
  }
  return arp;
}

}  // namespace

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

// Extract and process the QoS requirements of one MediaComponent, orchestrating
// QosData creation, QoS characteristics and monitoring [TS 29.513 §7.3.3].
template <typename MediaComponentT>
handler_result handle_qos_requirements(
    const MediaComponentT& media_component, const std::string& app_session_id,
    SmPolicyDecision& decision, qos_context& qos_ctx,
    const qos_reference_store& qos_ref_store) {
  Logger::pcf_app().info(fmt::format(
      "Handling QoS requirements for app-session {}", app_session_id));

  QosData derived_qos_data;
  handler_result result = create_qos_data_from_media_component(
      media_component, app_session_id, decision, qos_ctx, qos_ref_store,
      derived_qos_data);
  if (result.problem_details.has_value()) {
    Logger::pcf_app().error(fmt::format(
        "QoS requirements for app-session {} rejected: {}", app_session_id,
        result.problem_details.value()));
    return result;
  }

  create_qos_characteristics(derived_qos_data, decision);
  setup_qos_monitoring(decision);
  Logger::pcf_app().debug(fmt::format(
      "QoS requirements for app-session {} handled successfully",
      app_session_id));
  return handler_result{.status = status_code::OK};
}

// Create the QosData + PccRule (with SDF filters) for one MediaComponent
// [TS 29.512 §5.6.2.8, §4.1.4.2.1; TS 29.513 §7.3.3].
template <typename MediaComponentT>
handler_result create_qos_data_from_media_component(
    const MediaComponentT& media_component, const std::string& app_session_id,
    SmPolicyDecision& decision, qos_context& qos_ctx,
    const qos_reference_store& qos_ref_store, QosData& out_qos_data) {
  Logger::pcf_app().debug("create_qos_data_from_media_component()");

  // Deterministic PA-QOS-{app_session_id}-{medCompN} id convention
  // [TS 29.512 §4.1.4.2.1]. Keying on the AF's media-component number means a
  // PATCH re-sending the same medCompN targets the same QosData/PccRule (modify
  // in place); a medCompN not seen before for this app-session installs a new
  // flow (add). This is not spelled out in one normative sentence -- it follows
  // from combining three points in the spec, none of which is TS 29.513 §7.3.3
  // (that clause only derives QoS *values* from a MediaComponent's fields; it
  // never mentions medCompN and has no bearing on identity/lifecycle):
  //   1. "medComponents" is a *map* keyed by "medCompN" for both
  //      AppSessionContextReqData (create) and AppSessionContextUpdateData
  //      (PATCH) [TS 29.514 tables 5.6.2.3-1, 5.6.2.5-1] -- a JSON object can't
  //      repeat a key, so medCompN is only guaranteed unique *within one
  //      request* by this alone.
  //   2. TS 29.514 §4.2.3.2 mandates the PATCH body be an RFC 7396 JSON Merge
  //      Patch. RFC 7396's own merge algorithm is what turns "same key" into
  //      "modify that member" and "new key" into "add a member" -- the
  //      cross-request identity comes from combining (1)'s map key with this
  //      RFC, not from a PCF-authored rule.
  //   3. TS 29.514 §4.2.3.13 ("a media component's ... lifetime", "each media
  //      component modification") and §4.2.3.41 ("a new or previously provided
  //      MediaComponentRm element") both presuppose exactly this model, though
  //      each is scoped to its own optional feature rather than stated as a
  //      general rule.
  const int32_t med_comp_n = media_component.getMedCompN();
  const std::string qos_id =
      "PA-QOS-" + app_session_id + "-qos-" + std::to_string(med_comp_n);
  const std::string rule_id =
      "PA-QOS-" + app_session_id + "-" + std::to_string(med_comp_n);
  Logger::pcf_app().debug(fmt::format(
      "Deriving QoS: qosId='{}', pccRuleId='{}' (medCompN={})", qos_id, rule_id,
      med_comp_n));

  QosData qos_data;
  qos_data.setQosId(qos_id);

  // TS 29.513 §7.3.3 (Table 7.3.3-1/-2): if the qosReference resolves to an
  // operator-preconfigured QoS set, take 5QI/MBR/GBR/ARP "as configured by
  // operator" rather than deriving them from the request.
  bool from_reference = false;
  if (media_component.qosReferenceIsSet()) {
    std::shared_ptr<const QosData> ref =
        qos_ref_store.find(media_component.getQosReference());
    if (ref) {
      qos_data = *ref;
      qos_data.setQosId(qos_id);  // preserve our generated id
      from_reference = true;
      Logger::pcf_app().info(fmt::format(
          "Using operator-preconfigured QoS reference '{}' for qosId '{}'",
          media_component.getQosReference(), qos_id));
        Logger::pcf_app().debug(
          "Because the qosReference resolved successfully, operator-"
          "configured 5QI, MBR, GBR, and ARP values override any QoS "
          "derivation from the request.");
    } else {
      Logger::pcf_app().warn(fmt::format(
          "qosReference '{}' not found in the QoS reference store; deriving QoS "
          "from the MediaComponent instead",
          media_component.getQosReference()));
    }
  }

  // Build SDF filters from the request's flow descriptions regardless of whether
  // QoS was taken from a reference set [TS 29.512 §4.1.4.2.1, TS 29.514 §5.6.2.7].
  // Also accumulate the per-SDF Maximum Authorized Data Rate (MBR) as the sum
  // over service data flows [TS 29.513 Table 7.3.3-2].
  std::vector<FlowInformation> flow_infos;
  std::optional<std::string> mbr_ul;
  std::optional<std::string> mbr_dl;
  bool has_sub_components = media_component.medSubCompsIsSet();
  bool has_non_removed_sub_components = false;
  bool has_uplink_sdf                 = false;
  bool has_downlink_sdf               = false;
  bool saw_ul_rate_source             = false;
  bool saw_dl_rate_source             = false;

  if (has_sub_components) {
    Logger::pcf_app().trace(fmt::format(
        "MediaComponent has {} sub-component(s) (SDFs)",
        media_component.getMedSubComps().size()));
    for (const auto& [key, sub] : media_component.getMedSubComps()) {
      // Removed flows contribute 0 data rate and install no filter [Table 7.3.3-1].
      if (sub_component_removed(sub)) {
        Logger::pcf_app().trace(fmt::format(
            "Sub-component fNum={} is REMOVED; skipping (0 data rate)", key));
        continue;
      }

      has_non_removed_sub_components = true;

      bool include_ul = true;
      bool include_dl = true;
      if (sub.fDescsIsSet()) {
        include_ul = false;
        include_dl = false;
        for (const auto& desc : sub.getFDescs()) {
          Logger::pcf_app().trace(
              fmt::format("SDF filter (fNum={}): '{}'", key, desc));
          FlowInformation flow_info = flow_info_from_desc(desc);
          switch (flow_info.getFlowDirection().getEnumValue()) {
            case FlowDirection_anyOf::eFlowDirection_anyOf::UPLINK:
              include_ul = true;
              break;
            case FlowDirection_anyOf::eFlowDirection_anyOf::DOWNLINK:
              include_dl = true;
              break;
            default:
              include_ul = true;
              include_dl = true;
              break;
          }
          flow_infos.push_back(std::move(flow_info));
        }
      } else {
        Logger::pcf_app().debug(fmt::format(
            "Sub-component fNum={} has no flow descriptions. Any provided "
            "bandwidth is treated as applying to both directions because no "
            "SDF direction can be inferred.",
            key));
      }

      has_uplink_sdf   = has_uplink_sdf || include_ul;
      has_downlink_sdf = has_downlink_sdf || include_dl;

      // Per-SDF MBR: MediaSubComponent bandwidth if present, else fall back to
      // the MediaComponent-level value [TS 29.513 Table 7.3.3-1].
      if (sub.marBwUlIsSet()) {
        saw_ul_rate_source = true;
        if (include_ul) {
          mbr_ul = oai::utils::bitrate::sum(mbr_ul, sub.getMarBwUl());
        }
      } else if (media_component.marBwUlIsSet()) {
        saw_ul_rate_source = true;
        if (include_ul) {
          mbr_ul =
              oai::utils::bitrate::sum(mbr_ul, media_component.getMarBwUl());
        }
      }
      if (sub.marBwDlIsSet()) {
        saw_dl_rate_source = true;
        if (include_dl) {
          mbr_dl = oai::utils::bitrate::sum(mbr_dl, sub.getMarBwDl());
        }
      } else if (media_component.marBwDlIsSet()) {
        saw_dl_rate_source = true;
        if (include_dl) {
          mbr_dl =
              oai::utils::bitrate::sum(mbr_dl, media_component.getMarBwDl());
        }
      }
    }

    if (has_non_removed_sub_components) {
      if (saw_ul_rate_source && !has_uplink_sdf) {
        Logger::pcf_app().debug(
            "Setting uplink MBR to 0 bps because the request carried uplink "
            "bandwidth information, but none of the non-removed service data "
            "flows included an uplink flow description. The missing uplink "
            "direction is therefore treated as zero authorized rate.");
        mbr_ul = oai::utils::bitrate::from_bps(0);
      }
      if (saw_dl_rate_source && !has_downlink_sdf) {
        Logger::pcf_app().debug(
            "Setting downlink MBR to 0 bps because the request carried "
            "downlink bandwidth information, but none of the non-removed "
            "service data flows included a downlink flow description. The "
            "missing downlink direction is therefore treated as zero "
            "authorized rate.");
        mbr_dl = oai::utils::bitrate::from_bps(0);
      }
    }

    Logger::pcf_app().debug(fmt::format(
        "Aggregated per-SDF MBR from request: ul='{}', dl='{}'{}",
        mbr_ul.value_or("<none>"), mbr_dl.value_or("<none>"),
        from_reference
            ? " (ignored: MBR/GBR are taken from the qosReference set)"
            : ""));
  } else {
    // No service data flows described: use the component-level MBR directly.
    if (media_component.marBwUlIsSet()) mbr_ul = media_component.getMarBwUl();
    if (media_component.marBwDlIsSet()) mbr_dl = media_component.getMarBwDl();
    Logger::pcf_app().debug(fmt::format(
        "No sub-components; using component-level MBR: ul='{}', dl='{}'",
        mbr_ul.value_or("<none>"), mbr_dl.value_or("<none>")));
  }

  if (!from_reference) {
    // minDesBwDl/Ul ("minimum desired bandwidth") is intentionally not read
    // here: TS 29.514 Table 5.6.2.7-1 marks it Applicability "IMS_SBI"
    // (Table 5.8-1, feature 5), so an AF is only meant to send it once the
    // PCF has negotiated that feature -- and IMS_SBI also gates unrelated
    // IMS-specific behaviour (charging correlation, credit reallocation,
    // PS<->CS handover indication) this PCF does not implement. Negotiating
    // the bit solely to unlock this one field would misrepresent PCF
    // capabilities to the AF, so this stays deferred until IMS_SBI itself is
    // implemented. See kPcfSupportedFeatures in pcf_policy_authorization.cpp.

    // Guaranteed Authorized Data Rate (GBR): derived only when the AF requested
    // a minimum/guaranteed rate (mirBw). GBR is not derived for non-GBR flows
    // [TS 29.513 Table 7.3.3-1, NOTE 6].
    const bool has_gbr =
        media_component.mirBwUlIsSet() || media_component.mirBwDlIsSet();

    if (mbr_ul) qos_data.setMaxbrUl(*mbr_ul);
    if (mbr_dl) qos_data.setMaxbrDl(*mbr_dl);
    if (has_gbr) {
      if (media_component.mirBwUlIsSet())
        qos_data.setGbrUl(media_component.getMirBwUl());
      if (media_component.mirBwDlIsSet())
        qos_data.setGbrDl(media_component.getMirBwDl());
      Logger::pcf_app().debug(fmt::format(
          "GBR requested (mirBw present): gbrUl='{}', gbrDl='{}'",
          media_component.mirBwUlIsSet() ? media_component.getMirBwUl()
                                         : "<none>",
          media_component.mirBwDlIsSet() ? media_component.getMirBwDl()
                                         : "<none>"));
      } else {
        Logger::pcf_app().debug(
          "No minimum or guaranteed bitrate was requested. Leaving the "
          "authorized QoS as non-GBR and omitting GBR fields.");
    }

    // 5QI from desired latency [TS 29.513 §7.3.3 NOTE 15/17].
    //
    // desMaxLoss ("maximum desirable transport level packet loss rate") is the
    // loss twin of desMaxLatency: TS 29.513 §7.3.3 NOTE 15/17 map it to the 5QI
    // Packet Error Rate exactly as desMaxLatency maps to the Packet Delay
    // Budget. It is intentionally NOT read here. Both fields carry Applicability
    // "QoSHint"/"FLUS" [TS 29.514 §5.6.2.7, §4.2.2.33], a feature this PCF does
    // not negotiate (kPcfSupportedFeatures = 0x0), and the spec prescribes NO
    // mapping formula for either -- NOTE 15/17 only say the derivation "may
    // consider" them, citing non-normative examples. Rather than invent a
    // second non-normative heuristic for a field a compliant AF can't even send
    // until QoSHint is advertised, desMaxLoss stays deferred.
    // NOTE: desMaxLatency below is read as a pragmatic best-effort
    // despite the same gate; the QoSHint pair should be handled together (and
    // the feature formally negotiated) when QoSHint is taken on.
    std::optional<float> latency =
        media_component.desMaxLatencyIsSet()
            ? std::optional<float>(media_component.getDesMaxLatency())
            : std::nullopt;
    const int32_t r5qi = derive_5qi(latency, has_gbr);
    qos_data.setR5qi(r5qi);
    Logger::pcf_app().debug(fmt::format(
        "Derived 5QI={} (desMaxLatency={}, has_gbr={})", r5qi,
        latency.has_value() ? std::to_string(latency.value()) : "<unset>",
        has_gbr));

    // ARP at PCC-rule level [TS 29.513 Table 7.3.3-2].
    qos_data.setArp(derive_arp(media_component));

    // Maximum Packet Loss Rate is authorized only for 5QI=1 flows
    // [TS 29.512 §4.2.6.6.2].
    if (r5qi == 1) {
      if (media_component.maxPacketLossRateUlIsSet() ||
          media_component.maxPacketLossRateDlIsSet()) {
        Logger::pcf_app().debug(
            "Authorizing requested maximum packet loss values because the "
            "derived QoS is 5QI 1.");
      }
      if (media_component.maxPacketLossRateUlIsSet())
        qos_data.setMaxPacketLossRateUl(
            media_component.getMaxPacketLossRateUl());
      if (media_component.maxPacketLossRateDlIsSet())
        qos_data.setMaxPacketLossRateDl(
            media_component.getMaxPacketLossRateDl());
    } else if (
        media_component.maxPacketLossRateUlIsSet() ||
        media_component.maxPacketLossRateDlIsSet()) {
      Logger::pcf_app().debug(fmt::format(
          "Ignoring requested maximum packet loss values because the derived "
          "QoS is 5QI {}. Packet loss is only signalled for 5QI 1.",
          r5qi));
    }
  } else {
    // QoS came from the operator-preconfigured qosReference set; the request's
    // MBR/GBR/5QI/ARP are not consulted. Log the effective values that will be
    // sent to the SMF so the reference-vs-request distinction is visible.
    Logger::pcf_app().debug(fmt::format(
        "Effective QoS from qosReference: 5QI={}, maxbrUl='{}', maxbrDl='{}', "
        "gbrUl='{}', gbrDl='{}'",
        qos_data.r5qiIsSet() ? std::to_string(qos_data.getR5qi()) : "<unset>",
        qos_data.maxbrUlIsSet() ? qos_data.getMaxbrUl() : "<none>",
        qos_data.maxbrDlIsSet() ? qos_data.getMaxbrDl() : "<none>",
        qos_data.gbrUlIsSet() ? qos_data.getGbrUl() : "<none>",
        qos_data.gbrDlIsSet() ? qos_data.getGbrDl() : "<none>"));
  }

  // A PCC rule with an SDF template must carry at least one filter
  // [TS 29.512 §4.1.4.2.1]. Fall back to a permit-all bidirectional filter when
  // the request described no service data flows.
  if (flow_infos.empty()) {
    if (!has_sub_components || has_non_removed_sub_components) {
      if (!has_sub_components) {
        Logger::pcf_app().debug(
            "No media sub-components were provided, so no SDF filters could "
            "be built. Installing a permit-all fallback filter to keep the "
            "PCC rule valid.");
      } else {
        Logger::pcf_app().debug(
            "Non-removed sub-components were present, but none of them "
            "provided any flow descriptions. Installing a permit-all "
            "fallback filter to keep the PCC rule valid.");
      }
      flow_infos.push_back(
          flow_info_from_desc("permit out ip from any to assigned"));
    } else {
      Logger::pcf_app().debug(
          "All sub-components are marked REMOVED, so no SDF filters are "
          "installed and no permit-all fallback is created.");
    }
  }

  // Write the QosData [TS 29.512 §5.6.2.8]. insert_or_assign so a PATCH
  // modification (same qosId, i.e. same medCompN -- see the id-derivation
  // comment above) overwrites the existing flow in place.
  auto qos_data_map = decision.getQosDecs();
  qos_data_map.insert_or_assign(qos_id, qos_data);
  decision.setQosDecs(qos_data_map);

  // Precedence in the PA band [TS 29.512 §4.1.4.2.1, TS 23.503 §6.3.1]. On a
  // modify-in-place, reuse the existing rule's precedence so SMF rule ordering
  // is stable; on a new flow, assign a fresh unique value from the uid
  // generator.
  auto pcc_rules_map        = decision.getPccRules();
  const auto existing_rule  = pcc_rules_map.find(rule_id);
  int32_t precedence;
  if (existing_rule != pcc_rules_map.end() &&
      existing_rule->second.precedenceIsSet()) {
    precedence = existing_rule->second.getPrecedence();
  } else {
    auto& uid_generator = uint_uid_generator<uint32_t>::get_instance();
    precedence =
        PA_QOS_PRECEDENCE_BASE + static_cast<int32_t>(uid_generator.get_uid());
  }

  PccRule pcc_rule;
  pcc_rule.setPccRuleId(rule_id);
  pcc_rule.setPrecedence(precedence);
  pcc_rule.setRefQosData({qos_id});
  pcc_rule.setFlowInfos(flow_infos);

  pcc_rules_map.insert_or_assign(rule_id, pcc_rule);
  decision.setPccRules(pcc_rules_map);

  // Record the ids this app-session contributed into its ledger so PATCH/DELETE
  // can later edit exactly these entries; the payload lives in the decision
  // owned by the SM policy association.
  qos_ctx.record_qos_flow(qos_id);
  qos_ctx.record_pcc_rule(
      rule_id, static_cast<uint32_t>(precedence), {qos_id});

  Logger::pcf_app().info(fmt::format(
      "Created QosData '{}' ({}) and PccRule '{}' (precedence={}, {} SDF "
      "filter(s))",
      qos_id, from_reference ? "from qosReference" : "derived", rule_id,
      precedence, flow_infos.size()));

  out_qos_data = qos_data;
  return handler_result{.status = status_code::OK};
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

// ARP priority level range [TS 23.501 §5.7.2.2: 1 (highest) .. 15 (lowest)].
constexpr int32_t ARP_PRIORITY_MIN = 1;
constexpr int32_t ARP_PRIORITY_MAX = 15;

handler_result forbidden(const std::string& cause, const std::string& detail) {
  Logger::pcf_app().warn(fmt::format("QoS authorization rejected: {}", detail));
  return handler_result{
      .status = status_code::FORBIDDEN, .problem_details = cause};
}

// A fully-merged decision that is internally inconsistent is a PCF-side error,
// not an AF-input error: refuse to notify the SMF and surface the diagnostic.
handler_result reject_decision(const std::string& detail) {
  Logger::pcf_app().error(fmt::format(
      "Policy decision validation failed; not notifying the SMF: {}", detail));
  return handler_result{
      .status = status_code::INTERNAL_SERVER_ERROR, .problem_details = detail};
}

// The authorized Session-AMBR (bit/s, per direction) to validate the cumulative
// non-GBR rate against.
struct session_ambr_limit {
  std::optional<uint64_t> ul_bps;
  std::optional<uint64_t> dl_bps;
};

// A SmPolicyDecision may carry several SessionRules; at most one is *active* at
// a time, selected by the SMF from each rule's condition data [TS 29.512
// §4.2.6.2, §5.6.2.4]. At create time we don't know which conditional rule will
// be active, so authorize against the UNCONDITIONAL (default) rule -- the
// baseline that always applies. If only conditional rules exist (no default),
// fall back to the tightest AMBR so the authorized aggregate cannot exceed any
// applicable rule.
session_ambr_limit find_authorized_session_ambr(
    const SmPolicyDecision& decision) {
  session_ambr_limit unconditional;
  session_ambr_limit tightest;
  bool have_unconditional = false;
  int conditional_count   = 0;

  for (const auto& [sess_rule_id, rule] : decision.getSessRules()) {
    if (!rule.authSessAmbrIsSet()) continue;
    const auto ambr                  = rule.getAuthSessAmbr();
    const std::optional<uint64_t> ul = bitrate::to_bps(ambr.getUplink());
    const std::optional<uint64_t> dl = bitrate::to_bps(ambr.getDownlink());

    if (!rule.refCondDataIsSet()) {
      // The default (unconditional) rule -- the value we authorize against.
      unconditional      = {ul, dl};
      have_unconditional = true;
    } else {
      // Conservative fallback: keep the tightest AMBR seen across conditionals.
      ++conditional_count;
      if (ul && (!tightest.ul_bps || *ul < *tightest.ul_bps)) tightest.ul_bps = ul;
      if (dl && (!tightest.dl_bps || *dl < *tightest.dl_bps)) tightest.dl_bps = dl;
    }
  }

  if (have_unconditional) {
    if (conditional_count > 0) {
      Logger::pcf_app().debug(fmt::format(
          "Decision carries {} conditional session rule(s); authorizing "
          "against the unconditional Session-AMBR [TS 29.512 §4.2.6.2].",
          conditional_count));
    }
    return unconditional;
  }
  if (conditional_count > 0) {
    Logger::pcf_app().warn(
        "No unconditional session rule; authorizing against the tightest "
        "conditional Session-AMBR (conservative) [TS 29.512 §4.2.6.2].");
  }
  return tightest;  // both nullopt if no rule carried an AMBR
}

}  // namespace

// Validate the QoS this app-session authorized against operator policy and the
// subscribed envelope [TS 29.514 §4.1.3.1, TS 23.503 §6.1.3.2.3].
//
// See app_session.hpp for the contract. Per-flow checks (5QI allow-list, ARP
// range, per-flow MBR ceiling, GBR<=MBR) apply only to this session's own flows
// (owned_qos_ids) -- operator-provisioned base QoS on the decision is inherently
// authorized and must not be re-judged. The cumulative Session-AMBR check sums
// the non-GBR MBR of ALL flows in the decision, since Session-AMBR bounds the
// aggregate non-GBR rate of the PDU session [TS 23.503 §6.1.4].
handler_result validate_qos_authorization(
    const SmPolicyDecision& decision,
    const std::vector<std::string>& owned_qos_ids,
    const operator_qos_policy& op_policy) {
  const std::set<std::string> owned(owned_qos_ids.begin(), owned_qos_ids.end());

  // Authorized Session-AMBR to validate the cumulative non-GBR rate against.
  // Prefers the unconditional (default) session rule when the decision carries
  // several [TS 29.512 §4.2.6.2, §5.6.2.4].
  const session_ambr_limit ambr = find_authorized_session_ambr(decision);
  const std::optional<uint64_t> auth_ambr_ul = ambr.ul_bps;
  const std::optional<uint64_t> auth_ambr_dl = ambr.dl_bps;

  uint64_t cumulative_nongbr_ul_bps = 0;
  uint64_t cumulative_nongbr_dl_bps = 0;

  for (const auto& [qos_id, qos] : decision.getQosDecs()) {
    const bool is_gbr = qos.gbrUlIsSet() || qos.gbrDlIsSet();
    const std::optional<uint64_t> maxbr_ul =
        qos.maxbrUlIsSet() ? bitrate::to_bps(qos.getMaxbrUl()) : std::nullopt;
    const std::optional<uint64_t> maxbr_dl =
        qos.maxbrDlIsSet() ? bitrate::to_bps(qos.getMaxbrDl()) : std::nullopt;

    // Per-flow checks apply only to this session's own authorized flows.
    if (owned.count(qos_id) > 0) {
      // A. 5QI must be standardized or in the operator allow-list (empty list
      // = allow any) [TS 29.512 §4.2.6.6.2/3].
      if (qos.r5qiIsSet()) {
        const int32_t r5qi = qos.getR5qi();
        if (!is_standardized_5qi(r5qi) &&
            !op_policy.allowed_dynamic_5qi.empty() &&
            op_policy.allowed_dynamic_5qi.count(r5qi) == 0) {
          return forbidden(
              "REQUESTED_SERVICE_NOT_AUTHORIZED",
              fmt::format(
                  "flow '{}' uses dynamic 5QI {} which is not in the operator "
                  "allow-list",
                  qos_id, r5qi));
        }
      }

      // B. ARP priority level in range [TS 23.501 §5.7.2.2].
      if (qos.arpIsSet()) {
        const int32_t priority = qos.getArp().getPriorityLevel();
        if (priority < ARP_PRIORITY_MIN || priority > ARP_PRIORITY_MAX) {
          return forbidden(
              "REQUESTED_SERVICE_NOT_AUTHORIZED",
              fmt::format(
                  "flow '{}' ARP priority level {} out of range [{}..{}]",
                  qos_id, priority, ARP_PRIORITY_MIN, ARP_PRIORITY_MAX));
        }
      }

      // C. Per-flow MBR must not exceed the operator ceiling
      // [TS 29.512 §4.2.6.6.2].
      if (maxbr_ul && op_policy.max_flow_mbr_ul_bps &&
          *maxbr_ul > *op_policy.max_flow_mbr_ul_bps) {
        return forbidden(
            "REQUESTED_SERVICE_NOT_AUTHORIZED",
            fmt::format(
                "flow '{}' uplink MBR {} bps exceeds operator per-flow cap {} "
                "bps",
                qos_id, *maxbr_ul, *op_policy.max_flow_mbr_ul_bps));
      }
      if (maxbr_dl && op_policy.max_flow_mbr_dl_bps &&
          *maxbr_dl > *op_policy.max_flow_mbr_dl_bps) {
        return forbidden(
            "REQUESTED_SERVICE_NOT_AUTHORIZED",
            fmt::format(
                "flow '{}' downlink MBR {} bps exceeds operator per-flow cap "
                "{} bps",
                qos_id, *maxbr_dl, *op_policy.max_flow_mbr_dl_bps));
      }

      // E. Structural sanity: a GBR flow's GBR must not exceed its MBR.
      if (qos.gbrUlIsSet() && maxbr_ul) {
        if (const auto gbr_ul = bitrate::to_bps(qos.getGbrUl());
            gbr_ul && *gbr_ul > *maxbr_ul) {
          return forbidden(
              "INVALID_SERVICE_INFORMATION",
              fmt::format(
                  "flow '{}' uplink GBR {} bps exceeds its MBR {} bps", qos_id,
                  *gbr_ul, *maxbr_ul));
        }
      }
      if (qos.gbrDlIsSet() && maxbr_dl) {
        if (const auto gbr_dl = bitrate::to_bps(qos.getGbrDl());
            gbr_dl && *gbr_dl > *maxbr_dl) {
          return forbidden(
              "INVALID_SERVICE_INFORMATION",
              fmt::format(
                  "flow '{}' downlink GBR {} bps exceeds its MBR {} bps",
                  qos_id, *gbr_dl, *maxbr_dl));
        }
      }
    }

    // D. Accumulate non-GBR MBR across ALL flows for the Session-AMBR check.
    if (!is_gbr) {
      if (maxbr_ul) cumulative_nongbr_ul_bps += *maxbr_ul;
      if (maxbr_dl) cumulative_nongbr_dl_bps += *maxbr_dl;
    }
  }

  // D. Cumulative non-GBR MBR must not exceed the authorized Session-AMBR
  // [TS 23.503 §6.1.4, TS 29.512 §4.2.6.6.1].
  if (auth_ambr_ul || auth_ambr_dl) {
    if (auth_ambr_ul && cumulative_nongbr_ul_bps > *auth_ambr_ul) {
      return forbidden(
          "REQUESTED_SERVICE_NOT_AUTHORIZED",
          fmt::format(
              "cumulative non-GBR uplink MBR {} bps exceeds authorized "
              "Session-AMBR {} bps",
              cumulative_nongbr_ul_bps, *auth_ambr_ul));
    }
    if (auth_ambr_dl && cumulative_nongbr_dl_bps > *auth_ambr_dl) {
      return forbidden(
          "REQUESTED_SERVICE_NOT_AUTHORIZED",
          fmt::format(
              "cumulative non-GBR downlink MBR {} bps exceeds authorized "
              "Session-AMBR {} bps",
              cumulative_nongbr_dl_bps, *auth_ambr_dl));
    }
  } else if (op_policy.reject_on_missing_subscription) {
    return forbidden(
        "REQUESTED_SERVICE_NOT_AUTHORIZED",
        "no authorized Session-AMBR available and operator policy requires one "
        "(reject_on_missing_subscription)");
  } else {
    // Fail-open: no Session-AMBR constraint available [TS 29.512 §4.2.2.2].
    Logger::pcf_app().debug(
        "No authorized Session-AMBR in the decision; skipping the cumulative "
        "bandwidth check (fail-open per TS 29.512 §4.2.2.2).");
  }

  Logger::pcf_app().debug("QoS authorization checks passed.");
  return handler_result{.status = status_code::OK};
}

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

// Explicit instantiations of the QoS-derivation templates: MediaComponent for
// the create path (POST) and MediaComponentRm for the update path (PATCH). The
// definitions live in this TU; these make both specializations available to
// callers (pcf_policy_authorization.cpp, tests) at link time.
template handler_result create_qos_data_from_media_component<MediaComponent>(
    const MediaComponent&, const std::string&, SmPolicyDecision&, qos_context&,
    const qos_reference_store&, QosData&);
template handler_result create_qos_data_from_media_component<MediaComponentRm>(
    const MediaComponentRm&, const std::string&, SmPolicyDecision&,
    qos_context&, const qos_reference_store&, QosData&);
template handler_result handle_qos_requirements<MediaComponent>(
    const MediaComponent&, const std::string&, SmPolicyDecision&, qos_context&,
    const qos_reference_store&);
template handler_result handle_qos_requirements<MediaComponentRm>(
    const MediaComponentRm&, const std::string&, SmPolicyDecision&,
    qos_context&, const qos_reference_store&);

}  // namespace policy_auth

}  // namespace oai::pcf::app
