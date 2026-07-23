/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_SMF_NOTIFY_OUTCOME_H_SEEN
#define FILE_SMF_NOTIFY_OUTCOME_H_SEEN

namespace oai::pcf::app::sm_policy {

// Mirrors TS 29.512 Table 5.7.3-2's cause taxonomy for
// Npcf_SMPolicyControl_UpdateNotify responses, at the granularity a
// rollback-vs-retry decision needs. Deliberately NOT the same enum as
// sm_policy::status_code, which serves other (association create/bind) paths
// and collapses PCC_RULE_EVENT/PCC_QOS_FLOW_EVENT together.
enum class smf_notify_outcome {
  applied,               // 200 OK / 204 No Content, no partial-failure report
  partial_failure,       // 200 OK + a PartialSuccessReport array present
  temporary_rejection,   // cause == PCC_QOS_FLOW_EVENT (or unrecognized/other)
  permanent_rejection,   // cause == PCC_RULE_EVENT
  transport_ambiguous,   // no HTTP response at all, or an unmodeled 5xx/other
};

inline const char* to_string(smf_notify_outcome outcome) {
  switch (outcome) {
    case smf_notify_outcome::applied:
      return "applied";
    case smf_notify_outcome::partial_failure:
      return "partial_failure";
    case smf_notify_outcome::temporary_rejection:
      return "temporary_rejection";
    case smf_notify_outcome::permanent_rejection:
      return "permanent_rejection";
    case smf_notify_outcome::transport_ambiguous:
      return "transport_ambiguous";
  }
  return "unknown";
}

}  // namespace oai::pcf::app::sm_policy
#endif  // FILE_SMF_NOTIFY_OUTCOME_H_SEEN
