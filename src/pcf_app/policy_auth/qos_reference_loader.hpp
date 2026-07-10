/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_QOS_REFERENCE_LOADER_HPP_SEEN
#define FILE_QOS_REFERENCE_LOADER_HPP_SEEN

#include <cstddef>
#include <string>

#include "qos_reference_store.hpp"

namespace oai::pcf::app::policy_auth {

/**
 * @brief Provision operator-preconfigured QoS reference sets from YAML into a
 * qos_reference_store.
 *
 * Loading is a provisioning concern, not a storage one, so it is a free function
 * that populates through the generic crud_store `insert()` interface -- it works
 * with any backend (crud_store_memory now, a DB-backed crud_store later) and
 * removes the need for a bespoke qos_reference_store subclass.
 *
 * Each file in @p dir_path is a YAML map of `<qosReference>: { <QosData fields> }`,
 * parsed with the same yaml_to_json + QosData::from_json + validate() pipeline
 * used by sm_policy::policy_provisioning_file. [TS 29.513 §7.3.3]
 *
 * @return the number of QoS reference sets loaded.
 */
std::size_t load_qos_references_from_directory(
    qos_reference_store& store, const std::string& dir_path);

}  // namespace oai::pcf::app::policy_auth

#endif  // FILE_QOS_REFERENCE_LOADER_HPP_SEEN
