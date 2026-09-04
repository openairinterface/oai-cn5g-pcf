/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "qos_reference_store.hpp"

#include <memory>
#include <sstream>

#include "QosData.h"
#include "boost/filesystem.hpp"
#include "conversions.hpp"
#include "logger.hpp"

namespace oai::pcf::app::policy_auth {

using oai::_3gpp::model::QosData;

std::size_t load_qos_references_from_directory(
    qos_reference_store& store, const std::string& dir_path) {
  namespace fs = boost::filesystem;
  if (!fs::exists(dir_path)) {
    Logger::pcf_app().warn(
        "QoS reference directory %s does not exist; no qosReference sets loaded",
        dir_path.c_str());
    return 0;
  }

  std::size_t loaded = 0;
  for (fs::directory_iterator it(dir_path), end; it != end; ++it) {
    if (fs::is_directory(it->status())) continue;

    YAML::Node file_node;
    try {
      file_node = YAML::LoadFile(it->path().native());
    } catch (const YAML::BadFile& ex) {
      Logger::pcf_app().warn(
          "Could not read QoS reference file %s: %s",
          it->path().native().c_str(), ex.msg.c_str());
      continue;
    }

    // Each file is a map<qosReference, {QosData fields}> -- same YAML->model
    // pipeline as sm_policy::policy_provisioning_file.
    const auto json = oai::utils::conv::yaml_to_json(file_node);
    for (const auto& elem : json.items()) {
      QosData qos_data;
      try {
        from_json(elem.value(), qos_data);
        std::stringstream stream;
        if (!qos_data.validate(stream)) {
          Logger::pcf_app().warn(
              "Invalid QoS reference '%s': %s", elem.key().c_str(),
              stream.str().c_str());
          continue;
        }
        // The reference key is the map key; also set it as the QosId so a
        // loaded set is self-describing (the create path overrides the id).
        qos_data.setQosId(elem.key());
        store.insert(elem.key(), std::make_shared<const QosData>(qos_data));
        ++loaded;
        Logger::pcf_app().debug(
            "Loaded QoS reference '%s'", elem.key().c_str());
      } catch (const std::exception& e) {
        Logger::pcf_app().warn(
            "Error parsing QoS reference '%s': %s", elem.key().c_str(),
            e.what());
      }
    }
  }
  Logger::pcf_app().info("Loaded %zu QoS reference set(s)", loaded);
  return loaded;
}

}  // namespace oai::pcf::app::policy_auth
