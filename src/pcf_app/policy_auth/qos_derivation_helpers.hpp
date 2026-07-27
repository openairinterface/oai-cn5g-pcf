/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_QOS_DERIVATION_HELPERS_HPP_SEEN
#define FILE_QOS_DERIVATION_HELPERS_HPP_SEEN

#include <cstdint>

#include "FlowStatus.h"
#include "FlowStatus_anyOf.h"

namespace oai::pcf::app::policy_auth {

// Default ARP priority level for PA-derived flows. TS 29.513 Table 7.3.3-2
// leaves ARP "as defined by application specific algorithm" (from resPrio) /
// "as configured by operator" (from qosReference); resPrio is currently
// unreadable (empty model), so a fixed operator default is used. ARP
// priorityLevel range is 1-15 (TS 29.571); 1-8 denote prioritized services
// (TS 29.513 Table 7.3.3-2 NOTE 1).
constexpr int32_t DEFAULT_ARP_PRIORITY_LEVEL = 8;

// True when the SDF (MediaSubComponent) is flagged REMOVED. TS 29.513
// Table 7.3.3-1: for a removed flow the authorized data rate is 0, i.e. the
// flow contributes nothing to the aggregate and installs no filter.
template <typename MediaSubComponentT>
bool sub_component_removed(const MediaSubComponentT& sub) {
  return sub.fStatusIsSet() &&
         sub.getFStatus().getEnumValue() ==
             oai::model::pcf::FlowStatus_anyOf::eFlowStatus_anyOf::REMOVED;
}

}  // namespace oai::pcf::app::policy_auth

#endif  // FILE_QOS_DERIVATION_HELPERS_HPP_SEEN
