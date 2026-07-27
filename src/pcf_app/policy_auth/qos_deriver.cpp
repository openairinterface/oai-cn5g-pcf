/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "policy_auth/qos_deriver.hpp"

#include <optional>
#include <set>
#include <string>
#include <vector>

#include "Arp.h"
#include "FlowDirectionRm.h"
#include "FlowInformation.h"
#include "MediaComponent.h"
#include "MediaComponentRm.h"
#include "MediaSubComponent.h"
#include "MediaSubComponentRm.h"
#include "PccRule.h"
#include "SmPolicyDecision.h"
#include "bitrate.hpp"
#include "logger.hpp"
#include "policy_auth/app_session.hpp"
#include "policy_auth/qos_derivation_helpers.hpp"
#include "uint_generator.hpp"

// Base precedence for Policy-Authorization-derived PCC rules. TS 23.503 §6.3.1
// requires PCC rule precedence to be unambiguous and leaves the numeric range to
// operator/PCF configuration; we reserve the 1000-1999 band for PA-derived rules
// (distinct from the SM Policy Control side) per the QoS implementation plan.
#define PA_QOS_PRECEDENCE_BASE 1000

namespace oai::pcf::app::policy_auth {

using namespace oai::model::pcf;
using namespace oai::pcf::app;
using namespace oai::utils;

namespace {

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

// ARP priority level range [TS 23.501 §5.7.2.2: 1 (highest) .. 15 (lowest)].
constexpr int32_t ARP_PRIORITY_MIN = 1;
constexpr int32_t ARP_PRIORITY_MAX = 15;

handler_result forbidden(const std::string& cause, const std::string& detail) {
  Logger::pcf_app().warn(fmt::format("QoS authorization rejected: {}", detail));
  return handler_result{
      .status = status_code::FORBIDDEN, .problem_details = cause};
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

qos_deriver::qos_deriver(
    const qos_reference_store& qos_ref_store,
    const operator_qos_policy& op_policy)
    : m_qos_ref_store(qos_ref_store), m_op_policy(op_policy) {}

// Extract and process the QoS requirements of one MediaComponent, orchestrating
// QosData creation, QoS characteristics and monitoring [TS 29.513 §7.3.3].
template <typename MediaComponentT>
handler_result qos_deriver::handle_qos_requirements(
    const MediaComponentT& media_component, const std::string& app_session_id,
    SmPolicyDecision& decision, qos_context& qos_ctx) {
  Logger::pcf_app().info(fmt::format(
      "Handling QoS requirements for app-session {}", app_session_id));

  QosData derived_qos_data;
  handler_result result = create_qos_data_from_media_component(
      media_component, app_session_id, decision, qos_ctx, derived_qos_data);
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
handler_result qos_deriver::create_qos_data_from_media_component(
    const MediaComponentT& media_component, const std::string& app_session_id,
    SmPolicyDecision& decision, qos_context& qos_ctx, QosData& out_qos_data) {
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
        m_qos_ref_store.find(media_component.getQosReference());
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

// Validate the QoS this app-session authorized against operator policy and the
// subscribed envelope [TS 29.514 §4.1.3.1, TS 23.503 §6.1.3.2.3].
//
// Checks the app-session's own QoS flows (identified by `owned_qos_ids`, keys
// into `decision.qosDecs`): allowed 5QI, ARP priority range, per-flow MBR
// ceiling, and GBR<=MBR structural sanity [TS 29.512 §4.2.6.6.2]. Additionally
// checks that the cumulative non-GBR MBR of all flows in the decision does not
// exceed the authorized Session-AMBR carried in `decision.sessRules` (populated
// by the SM side, sm_policy::authorize_session_rule) [TS 23.503 §6.1.4,
// TS 29.512 §4.2.6.6.1]. When no authorized Session-AMBR is available the check
// fails open unless op_policy.reject_on_missing_subscription is set
// [TS 29.512 §4.2.2.2]. Returns FORBIDDEN with a cause on the first violation.
handler_result qos_deriver::validate_qos_authorization(
    const SmPolicyDecision& decision,
    const std::vector<std::string>& owned_qos_ids) {
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
            !m_op_policy.allowed_dynamic_5qi.empty() &&
            m_op_policy.allowed_dynamic_5qi.count(r5qi) == 0) {
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
      if (maxbr_ul && m_op_policy.max_flow_mbr_ul_bps &&
          *maxbr_ul > *m_op_policy.max_flow_mbr_ul_bps) {
        return forbidden(
            "REQUESTED_SERVICE_NOT_AUTHORIZED",
            fmt::format(
                "flow '{}' uplink MBR {} bps exceeds operator per-flow cap {} "
                "bps",
                qos_id, *maxbr_ul, *m_op_policy.max_flow_mbr_ul_bps));
      }
      if (maxbr_dl && m_op_policy.max_flow_mbr_dl_bps &&
          *maxbr_dl > *m_op_policy.max_flow_mbr_dl_bps) {
        return forbidden(
            "REQUESTED_SERVICE_NOT_AUTHORIZED",
            fmt::format(
                "flow '{}' downlink MBR {} bps exceeds operator per-flow cap "
                "{} bps",
                qos_id, *maxbr_dl, *m_op_policy.max_flow_mbr_dl_bps));
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
  } else if (m_op_policy.reject_on_missing_subscription) {
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

// Explicit instantiations of the QoS-derivation templates: MediaComponent for
// the create path (POST) and MediaComponentRm for the update path (PATCH). The
// definitions live in this TU; these make both specializations available to
// callers (pcf_policy_authorization.cpp, tests) at link time.
template handler_result qos_deriver::create_qos_data_from_media_component<
    MediaComponent>(
    const MediaComponent&, const std::string&, SmPolicyDecision&, qos_context&,
    QosData&);
template handler_result qos_deriver::create_qos_data_from_media_component<
    MediaComponentRm>(
    const MediaComponentRm&, const std::string&, SmPolicyDecision&,
    qos_context&, QosData&);
template handler_result qos_deriver::handle_qos_requirements<MediaComponent>(
    const MediaComponent&, const std::string&, SmPolicyDecision&,
    qos_context&);
template handler_result qos_deriver::handle_qos_requirements<MediaComponentRm>(
    const MediaComponentRm&, const std::string&, SmPolicyDecision&,
    qos_context&);

}  // namespace oai::pcf::app::policy_auth
