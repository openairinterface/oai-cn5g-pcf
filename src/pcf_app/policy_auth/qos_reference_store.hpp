/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_QOS_REFERENCE_STORE_HPP_SEEN
#define FILE_QOS_REFERENCE_STORE_HPP_SEEN

#include "QosData.h"
#include "crud_store.hpp"

namespace oai::pcf::app::policy_auth {

/**
 * @brief Store of operator-preconfigured QoS sets, keyed by the AF-supplied
 * `qosReference` string [TS 29.513 §7.3.3].
 *
 * This is exactly the generic keyed store with `find(qosReference)` returning
 * the preconfigured set, so it is just an alias: the value is the existing
 * oai::model::pcf::QosData (5QI, ARP, MBR/GBR, priorityLevel, PDB/PER, ...) held
 * read-only (const) since references are provisioned once at startup.
 */
using qos_reference_store =
    oai::utils::crud_store<const oai::model::pcf::QosData>;

}  // namespace oai::pcf::app::policy_auth

#endif  // FILE_QOS_REFERENCE_STORE_HPP_SEEN
