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
#include "SmPolicyDecision.h"
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

using namespace oai::_3gpp::model;
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

const oai::_3gpp::model::AppSessionContextReqData&
app_session::get_app_session_context() const {
  return m_context;
}

void app_session::set_app_session_context(
    oai::_3gpp::model::AppSessionContextReqData& context) {
  m_context = context;
void app_session::update_context(
    const oai::_3gpp::model::AppSessionContextReqData& context) {
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

// TODO: Restore handle_service_function_chaining and
// handle_service_function_chaining_update once AfSfcRequirement and
// AppSessionContextReqData::afSfcReq are regenerated in the new model.
// Ref: 3GPP TS 29.514 §4.2.2.8 N6-LAN traffic steering (SFC).

handler_result validate_and_merge_decision(
    const oai::_3gpp::model::SmPolicyDecision& request_decision,
    oai::_3gpp::model::SmPolicyDecision& current_decision, bool update) {
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
    for (const auto& [key, value] : request_decision.getPccRules()) {
      auto iter = current_decision.getPccRules().find(key.c_str());
      if (iter != current_decision.getPccRules().end() &&
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
    for (const auto& [key, value] : request_decision.getTraffContDecs()) {
      auto iter = current_decision.getTraffContDecs().find(key);
      if (iter != current_decision.getTraffContDecs().end() &&
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

  // TODO [QOS] Merge QoS-related decision data [TS 29.512 §4.2.6.2.3, §5.6.2.4]
  // Tasks:
  //   - Merge QosData entries from request_decision into current_decision [TS 29.512 §5.6.2.8]
  //   - Merge QosChars (QoS Characteristics) for non-standard 5QIs [TS 29.512 §5.6.2.16]
  //   - Merge QosMonDecs (QoS Monitoring Data) entries [TS 29.512 §5.6.2.40]
  //   - Validate QoS parameter consistency across merged rules [TS 23.503 §6.1.3.7]
  //
  // [QOS-MOCK] Mocks the TODO [QOS] task above:
  //   - QosData is written directly to current_decision by
  //     create_qos_data_from_media_component() before this call, so no merge
  //     from request_decision is needed on the QoS mock path.
  //   - QosChars and QosMonDecs merge is not performed (stubs only log).
  Logger::pcf_app().debug(
      "Skipping QoS-specific merge work in validate_and_merge_decision(). "
      "PCC rules and traffic-control data are merged, but QosData, "
      "QosCharacteristics, and QosMonitoringData are still handled by the "
      "Phase 1 mock path.");

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

  return handler_result{.status = status_code::OK};
}

handler_result authorize_service_info(
    const oai::_3gpp::model::AppSessionContextReqData& reqData) {
  // TODO: Implement service authorization

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
bool sub_component_removed(const MediaSubComponent& sub) {
  return sub.fStatusIsSet() &&
         sub.getFStatus().getEnumValue() ==
             FlowStatus_anyOf::eFlowStatus_anyOf::REMOVED;
}

// Derive the ARP. TS 29.513 Table 7.3.3-2: ARP is computed at PCC-rule level.
// resPrio -> priorityLevel is deferred (ReservPriority is an empty generated
// model, so the value is unreadable); preemptCap/preemptVuln are taken from the
// request when present (TS 29.514 §5.6.2.7), else safe defaults.
oai::model::common::Arp derive_arp(const MediaComponent& mc) {
  oai::model::common::Arp arp;
  // TODO [QOS] Map MediaComponent.resPrio -> arp.priorityLevel once the
  // ReservPriority model exposes its value [TS 29.513 Table 7.3.3-2].
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
handler_result handle_qos_requirements(
    const MediaComponent& media_component, const std::string& app_session_id,
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
handler_result create_qos_data_from_media_component(
    const MediaComponent& media_component, const std::string& app_session_id,
    SmPolicyDecision& decision, qos_context& qos_ctx,
    const qos_reference_store& qos_ref_store, QosData& out_qos_data) {
  Logger::pcf_app().debug("create_qos_data_from_media_component()");

  // PA-QOS-{app_session_id}-{seq} id convention [TS 29.512 §4.1.4.2.1]. The
  // shared uid generator guarantees uniqueness of {seq} across the process.
  auto& uid_generator = uint_uid_generator<uint32_t>::get_instance();
  const uint32_t seq   = uid_generator.get_uid();
  const std::string qos_id =
      "PA-QOS-" + app_session_id + "-qos-" + std::to_string(seq);
  const std::string rule_id =
      "PA-QOS-" + app_session_id + "-" + std::to_string(seq);
  Logger::pcf_app().debug(fmt::format(
      "Deriving QoS: qosId='{}', pccRuleId='{}' (seq={})", qos_id, rule_id,
      seq));

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

  // Write the QosData [TS 29.512 §5.6.2.8].
  auto qos_data_map = decision.getQosDecs();
  qos_data_map.insert(std::make_pair(qos_id, qos_data));
  decision.setQosDecs(qos_data_map);

  // Write the PccRule referencing the QosData, with the SDF filters and a
  // precedence in the PA band [TS 29.512 §4.1.4.2.1, TS 23.503 §6.3.1].
  const int32_t precedence = PA_QOS_PRECEDENCE_BASE + static_cast<int32_t>(seq);
  PccRule pcc_rule;
  pcc_rule.setPccRuleId(rule_id);
  pcc_rule.setPrecedence(precedence);
  pcc_rule.setRefQosData({qos_id});
  pcc_rule.setFlowInfos(flow_infos);

  auto pcc_rules_map = decision.getPccRules();
  pcc_rules_map.insert(std::make_pair(rule_id, pcc_rule));
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

// TODO [QOS] Validate QoS requirements against policies and subscription
// [TS 29.514 §4.1.3.1, TS 23.503 §6.1.3.2.3]
// Tasks:
//   - Check QoS params against user subscription QoS profile [TS 29.512 §4.2.6.6.1]
//   - Verify cumulative bandwidth against network slice limits [TS 29.512 §4.2.6.7, TS 23.503 §6.1.4]
//   - Validate resource availability for requested QoS [TS 23.503 §6.1.3.2.3]
//   - Return FORBIDDEN if any check fails [TS 29.514 §4.1.3.1]
//
// [QOS-MOCK] Phase 1 — QoS authorization (mock; always approved).
// Mocks the TODO [QOS] task above:
//   - No subscription or resource checks are performed; always returns OK.
handler_result validate_qos_authorization() {
  Logger::pcf_app().debug(
      "QoS authorization checks are still mocked. Returning success without "
      "evaluating subscription, slice, or resource constraints.");
  return handler_result{.status = status_code::OK};
}

}  // namespace policy_auth

}  // namespace oai::pcf::app
