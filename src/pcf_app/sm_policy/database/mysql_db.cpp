/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

#include "mysql_db.hpp"

#include <boost/algorithm/string.hpp>
#include <chrono>
#include <thread>
#include <stdexcept>

#include "logger.hpp"
#include "pcf_config.hpp"

using namespace oai::pcf::app;
using namespace oai::model::common;
using namespace oai::config::pcf;
using namespace oai::pcf::provisioning::model;
using namespace oai::model::pcf;

extern std::unique_ptr<pcf_config> pcf_cfg;

//------------------------------------------------------------------------------
mysql_db::mysql_db() : database_wrapper<mysql_db>(), m_db_connection_status() {}

//------------------------------------------------------------------------------
mysql_db::~mysql_db() {}

//------------------------------------------------------------------------------
bool mysql_db::connect(uint32_t num_retries) {
  Logger::pcf_db().debug("Connecting to MySQL DB");

  uint32_t i = 0;
  while (i < num_retries) {
    try {
      db = std::make_shared<odb::mysql::database>(
          pcf_cfg->get_database_config().get_user(),           // MySQL username
          pcf_cfg->get_database_config().get_pass(),           // MySQL password
          pcf_cfg->get_database_config().get_database_name(),  // Database name
          pcf_cfg->get_database_config()
              .get_host(),  // Host (Docker container IP or localhost if port
                            // forwarding)
          pcf_cfg->get_database_config().get_port()  // Port
      );

      // Test Connection
      odb::transaction t(db->begin());
      db->execute("SELECT 1");
      t.commit();

      Logger::pcf_db().info("Connected to MySQL DB");
      return true;
    } catch (const odb::exception& e) {
      Logger::pcf_db().error(
          "An error occurred when connecting to MySQL DB (%s), retry ...",
          e.what());
      i++;
    } catch (const odb::mysql::database_exception& e) {
      Logger::pcf_db().error(
          "An error occurred when connecting to MySQL DB (%s), retry ...",
          e.what());
      i++;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }
  if (i == num_retries) {
    return false;
    // throw std::runtime_error("Cannot connect to MySQL DB");
  }
  return true;
}

/**
 * set and get default policy rules
 */

bool mysql_db::setDefaultPolicyDecision(std::vector<std::string> rules) {
  check_db_connection();

  nlohmann::json j_rules = rules;
  SupiPolicyDecision defaultPolicyDecision;
  defaultPolicyDecision.setSupi("default");
  defaultPolicyDecision.setPccRuleIds(rules);

  try {
    odb::transaction t(db->begin());
    Logger::pcf_db().debug("Set default policy rules: %s", j_rules.dump());
    db->update(defaultPolicyDecision);
    t.commit();
  } catch (const odb::object_not_persistent& e) {
    try {
      odb::transaction t(db->begin());
      db->persist(defaultPolicyDecision);
      t.commit();
    } catch (const std::exception& e) {
      Logger::pcf_db().error("Error while setting default rules: %s", e.what());
      throw;
    }
  } catch (const std::exception& e) {
    Logger::pcf_db().error("Error while setting default rules: %s", e.what());
    throw;
  }

  return true;
}

std::vector<std::string> mysql_db::getDefaultPolicyDecision() {
  check_db_connection();

  try {
    odb::transaction t(db->begin());
    Logger::pcf_db().debug("Reading default policy rules");
    std::shared_ptr<SupiPolicyDecision> supiPolicyDecision(
        db->load<SupiPolicyDecision>("default"));
    t.commit();
    return supiPolicyDecision->getPccRuleIds();
  } catch (const odb::object_not_persistent& e) {
    Logger::pcf_db().error("Error: No default policy rules found.");
    throw NotFoundException("Default policy rules not found.");
  } catch (const std::exception& e) {
    Logger::pcf_db().error(
        "Error while retrieving default policy rules", e.what());
    throw;
  }
}

/**
 * SupiPolicyDecision CRUD functions
 */

bool mysql_db::createSupiPolicyDecision(
    const SupiPolicyDecision& supiPolicyDecision) {
  check_db_connection();

  try {
    odb::transaction t(db->begin());
    nlohmann::json j_data = supiPolicyDecision;
    Logger::pcf_db().debug("Creating supi policy decision: %s", j_data.dump());
    db->persist(supiPolicyDecision);
    t.commit();
  } catch (const odb::object_already_persistent& e) {
    Logger::pcf_db().error(
        "SupiPolicyDecision with supi %s already exists.",
        supiPolicyDecision.getSupi());
    throw AlreadyExistException(
        "SupiPolicyDecision with supi " + supiPolicyDecision.getSupi() +
        " already exists.");
  } catch (const std::exception& e) {
    Logger::pcf_db().error(
        "Error while storing SupiPolicyDecision: %s", e.what());
    throw;
  }

  return true;
}

SupiPolicyDecision mysql_db::getSupiPolicyDecision(const std::string& supi) {
  check_db_connection();

  try {
    odb::transaction t(db->begin());
    Logger::pcf_db().debug("Reading supi policy decision with supi %s", supi);
    std::shared_ptr<SupiPolicyDecision> supiPolicyDecision(
        db->load<SupiPolicyDecision>(supi));
    t.commit();
    return *supiPolicyDecision;
  } catch (const odb::object_not_persistent& e) {
    Logger::pcf_db().error(
        "Error: SupiPolicyDecision object with supi %s not found.", supi);
    throw NotFoundException("SupiPolicyDecision object not found.");
  } catch (const std::exception& e) {
    Logger::pcf_db().error(
        "Error while retrieving SupiPolicyDecision: %s", e.what());
    throw;
  }
}

bool mysql_db::updateSupiPolicyDecision(
    const SupiPolicyDecision& supiPolicyDecision) {
  check_db_connection();

  try {
    odb::transaction t(db->begin());
    nlohmann::json j_data = supiPolicyDecision;
    Logger::pcf_db().debug("Updating supi policy decision %s", j_data.dump());
    db->update(supiPolicyDecision);
    t.commit();
  } catch (const odb::object_not_persistent& e) {
    Logger::pcf_db().error(
        "SupiPolicyDecision with supi %s does not exist.",
        supiPolicyDecision.getSupi());
    throw NotFoundException(
        "SupiPolicyDecision with supi " + supiPolicyDecision.getSupi() +
        " does not exist.");
  } catch (const std::exception& e) {
    Logger::pcf_db().error(
        "Error while updating SupiPolicyDecision: %s", e.what());
    throw;
  }

  return true;
}

bool mysql_db::deleteSupiPolicyDecision(const std::string& supi) {
  check_db_connection();

  try {
    odb::transaction t(db->begin());
    Logger::pcf_db().debug("Deleting supi policy decision with supi %s", supi);
    std::shared_ptr<SupiPolicyDecision> supiPolicyDecision(
        db->load<SupiPolicyDecision>(supi));
    db->erase(*supiPolicyDecision);
    t.commit();
  } catch (const odb::object_not_persistent& e) {
    Logger::pcf_db().error(
        "SupiPolicyDecision with supi %s does not exist.", supi);
    throw NotFoundException(
        "SupiPolicyDecision with supi " + supi + " does not exist.");
  } catch (const std::exception& e) {
    Logger::pcf_db().error(
        "Error while deleting SupiPolicyDecision: %s", e.what());
    throw;
  }

  return true;
}

std::vector<SupiPolicyDecision> mysql_db::getAllSupiPolicyDecisions() {
  check_db_connection();

  std::vector<SupiPolicyDecision> results;
  try {
    odb::transaction t(db->begin());
    Logger::pcf_db().debug("Reading all supi policy decisions");
    odb::result<SupiPolicyDecision> r(db->query<SupiPolicyDecision>());

    for (odb::result<SupiPolicyDecision>::iterator i(r.begin()); i != r.end();
         ++i) {
      results.push_back(*i);
    }

    t.commit();
  } catch (const std::exception& e) {
    Logger::pcf_db().error(
        "Error while retrieving all SupiPolicyDecisions: %s", e.what());
    throw;
  }

  return results;
}

/**
 * DnnPolicyDecision CRUD functions
 */

bool mysql_db::createDnnPolicyDecision(
    const DnnPolicyDecision& dnnPolicyDecision) {
  check_db_connection();

  try {
    odb::transaction t(db->begin());
    nlohmann::json j_data = dnnPolicyDecision;
    Logger::pcf_db().info("Creating dnn policy decision: %s", j_data.dump());
    db->persist(dnnPolicyDecision);
    t.commit();
  } catch (const odb::object_already_persistent& e) {
    Logger::pcf_db().error(
        "DnnPolicyDecision with dnn %s already exists.",
        dnnPolicyDecision.getDnn());
    throw AlreadyExistException(
        "DnnPolicyDecision with dnn " + dnnPolicyDecision.getDnn() +
        " already exists.");
  } catch (const std::exception& e) {
    Logger::pcf_db().error(
        "Error while storing DnnPolicyDecision: %s", e.what());
    throw;
  }

  return true;
}

DnnPolicyDecision mysql_db::getDnnPolicyDecision(const std::string& dnn) {
  check_db_connection();

  try {
    odb::transaction t(db->begin());
    Logger::pcf_db().debug("Reading dnn policy decision with dnn %s", dnn);
    std::shared_ptr<DnnPolicyDecision> dnnPolicyDecision(
        db->load<DnnPolicyDecision>(dnn));
    t.commit();
    return *dnnPolicyDecision;
  } catch (const odb::object_not_persistent& e) {
    Logger::pcf_db().error(
        "Error: DnnPolicyDecision object with dnn %s not found.", dnn);
    throw NotFoundException("DnnPolicyDecision object not found.");
  } catch (const std::exception& e) {
    Logger::pcf_db().error(
        "Error while retrieving DnnPolicyDecision: %s", e.what());
    throw;
  }
}

bool mysql_db::updateDnnPolicyDecision(
    const DnnPolicyDecision& dnnPolicyDecision) {
  check_db_connection();

  try {
    odb::transaction t(db->begin());
    nlohmann::json j_data = dnnPolicyDecision;
    Logger::pcf_db().info("Updating dnn policy decision %s", j_data.dump());
    db->update(dnnPolicyDecision);
    t.commit();
  } catch (const odb::object_not_persistent& e) {
    Logger::pcf_db().error(
        "DnnPolicyDecision with dnn %s does not exist.",
        dnnPolicyDecision.getDnn());
    throw NotFoundException(
        "DnnPolicyDecision with dnn " + dnnPolicyDecision.getDnn() +
        " does not exist.");
  } catch (const std::exception& e) {
    Logger::pcf_db().error(
        "Error while updating DnnPolicyDecision: %s", e.what());
    throw;
  }

  return true;
}

bool mysql_db::deleteDnnPolicyDecision(const std::string& dnn) {
  check_db_connection();

  try {
    odb::transaction t(db->begin());
    Logger::pcf_db().debug("Deleting dnn policy decision with dnn %s", dnn);
    std::shared_ptr<DnnPolicyDecision> dnnPolicyDecision(
        db->load<DnnPolicyDecision>(dnn));
    db->erase(*dnnPolicyDecision);
    t.commit();
  } catch (const odb::object_not_persistent& e) {
    Logger::pcf_db().error(
        "DnnPolicyDecision with dnn %s does not exist.", dnn);
    throw NotFoundException(
        "DnnPolicyDecision with dnn " + dnn + " does not exist.");
  } catch (const std::exception& e) {
    Logger::pcf_db().error(
        "Error while deleting DnnPolicyDecision: %s", e.what());
    throw;
  }

  return true;
}

std::vector<DnnPolicyDecision> mysql_db::getAllDnnPolicyDecisions() {
  check_db_connection();

  std::vector<DnnPolicyDecision> results;
  try {
    odb::transaction t(db->begin());
    Logger::pcf_db().debug("Reading all dnn policy decisions");
    odb::result<DnnPolicyDecision> r(db->query<DnnPolicyDecision>());

    for (odb::result<DnnPolicyDecision>::iterator i(r.begin()); i != r.end();
         ++i) {
      results.push_back(*i);
    }

    t.commit();
  } catch (const std::exception& e) {
    Logger::pcf_db().error(
        "Error while retrieving all DnnPolicyDecisions: %s", e.what());
    throw;
  }

  return results;
}

/**
 * SlicePolicyDecision CRUD functions
 */

bool mysql_db::createSlicePolicyDecision(
    const SlicePolicyDecision& slicePolicyDecision) {
  check_db_connection();

  try {
    odb::transaction t(db->begin());
    nlohmann::json j_data = slicePolicyDecision;
    Logger::pcf_db().info("Creating slice policy decision: %s", j_data.dump());
    db->persist(slicePolicyDecision);
    t.commit();
  } catch (const odb::object_already_persistent& e) {
    nlohmann::json j_slice = slicePolicyDecision.getSnssai();
    Logger::pcf_db().error(
        "SlicePolicyDecision with slice %s already exists.", j_slice.dump());
    throw AlreadyExistException(
        "SlicePolicyDecision with slice " + j_slice.dump() +
        " already exists.");
  } catch (const std::exception& e) {
    Logger::pcf_db().error(
        "Error while storing SlicePolicyDecision: %s", e.what());
    throw;
  }

  return true;
}

SlicePolicyDecision mysql_db::getSlicePolicyDecision(const Snssai& slice) {
  check_db_connection();

  try {
    odb::transaction t(db->begin());
    nlohmann::json j_slice = slice;
    Logger::pcf_db().info(
        "Reading slice policy decision with slice %s", j_slice.dump());
    std::shared_ptr<SlicePolicyDecision> slicePolicyDecision(
        db->load<SlicePolicyDecision>(slice));
    t.commit();
    return *slicePolicyDecision;
  } catch (const odb::object_not_persistent& e) {
    nlohmann::json json_slice = slice;
    Logger::pcf_db().error(
        "Error: SlicePolicyDecision object with slice %s not found.",
        json_slice.dump());
    throw NotFoundException("SlicePolicyDecision object not found.");
  } catch (const std::exception& e) {
    Logger::pcf_db().error(
        "Error while retrieving SlicePolicyDecision: %s", e.what());
    throw;
  }
}

bool mysql_db::updateSlicePolicyDecision(
    const SlicePolicyDecision& slicePolicyDecision) {
  check_db_connection();

  try {
    odb::transaction t(db->begin());
    nlohmann::json j_data = slicePolicyDecision;
    Logger::pcf_db().info("Updating slice policy decision: %s", j_data.dump());
    db->update(slicePolicyDecision);
    t.commit();
  } catch (const odb::object_not_persistent& e) {
    nlohmann::json j_slice = slicePolicyDecision.getSnssai();
    Logger::pcf_db().error(
        "SlicePolicyDecision with slice %s does not exist.", j_slice.dump());
    throw NotFoundException(
        "SlicePolicyDecision with slice " + j_slice.dump() +
        " does not exist.");
  } catch (const std::exception& e) {
    Logger::pcf_db().error(
        "Error while updating SlicePolicyDecision: %s", e.what());
    throw;
  }

  return true;
}

bool mysql_db::deleteSlicePolicyDecision(const Snssai& slice) {
  check_db_connection();

  try {
    odb::transaction t(db->begin());
    std::shared_ptr<SlicePolicyDecision> slicePolicyDecision(
        db->load<SlicePolicyDecision>(slice));
    nlohmann::json j_slice = slice;
    Logger::pcf_db().info(
        "Deleting slice policy decision with slice %s", j_slice.dump());
    db->erase(*slicePolicyDecision);
    t.commit();
  } catch (const odb::object_not_persistent& e) {
    nlohmann::json j_slice = slice;
    Logger::pcf_db().error(
        "SlicePolicyDecision with slice %s does not exist.", j_slice.dump());
    throw NotFoundException(
        "SlicePolicyDecision with slice " + j_slice.dump() +
        " does not exist.");
  } catch (const std::exception& e) {
    Logger::pcf_db().error(
        "Error while deleting SlicePolicyDecision: %s", e.what());
    throw;
  }

  return true;
}

std::vector<SlicePolicyDecision> mysql_db::getAllSlicePolicyDecisions() {
  check_db_connection();

  std::vector<SlicePolicyDecision> results;
  try {
    odb::transaction t(db->begin());
    Logger::pcf_db().info("Reading all slice policy decisions");
    odb::result<SlicePolicyDecision> r(db->query<SlicePolicyDecision>());

    for (odb::result<SlicePolicyDecision>::iterator i(r.begin()); i != r.end();
         ++i) {
      results.push_back(*i);
    }

    t.commit();
  } catch (const std::exception& e) {
    Logger::pcf_db().error(
        "Error while retrieving all SlicePolicyDecisions: %s", e.what());
    throw;
  }

  return results;
}

/**
 * QosData CRUD functions
 */

bool mysql_db::createQosData(const QosData& qosData) {
  check_db_connection();

  try {
    odb::transaction t(db->begin());
    nlohmann::json j_data = qosData;
    Logger::pcf_db().info("qosData %s", j_data.dump());
    db->persist(qosData);
    t.commit();
  } catch (const odb::object_already_persistent& e) {
    Logger::pcf_db().error(
        "QosData with id %s already exists.", qosData.getQosId());
    throw AlreadyExistException(
        "QosData with id " + qosData.getQosId() + " already exists.");
  } catch (const std::exception& e) {
    Logger::pcf_db().error("Error while storing QosData: %s", e.what());
    throw;
  }

  return true;
}

QosData mysql_db::getQosData(const std::string& qosId) {
  check_db_connection();

  try {
    odb::transaction t(db->begin());
    std::shared_ptr<QosData> qosData(db->load<QosData>(qosId));
    t.commit();
    return *qosData;
  } catch (const odb::object_not_persistent& e) {
    Logger::pcf_db().error(
        "Error: QosData object with qosId %s not found.", qosId);
    throw NotFoundException("QosData object not found.");
  } catch (const std::exception& e) {
    Logger::pcf_db().error("Error while retrieving QosData: %s", e.what());
    throw;
  }
}

bool mysql_db::updateQosData(const QosData& qosData) {
  check_db_connection();

  try {
    odb::transaction t(db->begin());
    nlohmann::json j_data = qosData;
    Logger::pcf_db().debug("Updating QosData %s", j_data.dump());
    db->update(qosData);
    t.commit();
  } catch (const odb::object_not_persistent& e) {
    Logger::pcf_db().error(
        "QosData with id %s does not exist.", qosData.getQosId());
    throw NotFoundException(
        "QosData with id " + qosData.getQosId() + " does not exist.");
  } catch (const std::exception& e) {
    Logger::pcf_db().error("Error while updating QosData: %s", e.what());
    throw;
  }

  return true;
}

bool mysql_db::deleteQosData(const std::string& qosId) {
  check_db_connection();

  try {
    odb::transaction t(db->begin());
    Logger::pcf_db().debug("Deleting QosData with id %s", qosId);
    std::shared_ptr<QosData> qosData(db->load<QosData>(qosId));
    db->erase(*qosData);
    t.commit();
  } catch (const odb::object_not_persistent& e) {
    Logger::pcf_db().error("QosData with id %s does not exist.", qosId);
    throw NotFoundException("QosData with id " + qosId + " does not exist.");
  } catch (const std::exception& e) {
    Logger::pcf_db().error("Error while deleting QosData: %s", e.what());
    throw;
  }

  return true;
}

std::vector<QosData> mysql_db::getAllQosData() {
  check_db_connection();

  std::vector<QosData> results;
  try {
    odb::transaction t(db->begin());
    Logger::pcf_db().debug("Reading all QosData");
    odb::result<QosData> r(db->query<QosData>());

    for (odb::result<QosData>::iterator i(r.begin()); i != r.end(); ++i) {
      results.push_back(*i);
    }

    t.commit();
  } catch (const std::exception& e) {
    Logger::pcf_db().error("Error while retrieving all QosData: %s", e.what());
    throw;
  }

  return results;
}

/**
 * TrafficControlData CRUD functions
 */

bool mysql_db::createTrafficControlData(
    const TrafficControlData& trafficControlData) {
  check_db_connection();

  try {
    nlohmann::json json_trafficControlData      = trafficControlData;
    TrafficControlDataODB trafficControlDataODB = json_trafficControlData;

    odb::transaction t(db->begin());
    Logger::pcf_db().info(
        "trafficControlData %s", json_trafficControlData.dump());
    db->persist(trafficControlDataODB);
    t.commit();
  } catch (const odb::object_already_persistent& e) {
    Logger::pcf_db().error(
        "TrafficControlData with id %s already exists.",
        trafficControlData.getTcId());
    throw AlreadyExistException(
        "TrafficControlData with id " + trafficControlData.getTcId() +
        " already exists.");
  } catch (const std::exception& e) {
    Logger::pcf_db().error(
        "Error while storing TrafficControlData: %s", e.what());
    throw;
  }

  return true;
}

TrafficControlData mysql_db::getTrafficControlData(const std::string& tcId) {
  check_db_connection();

  try {
    odb::transaction t(db->begin());
    std::shared_ptr<TrafficControlDataODB> trafficControlDataODB(
        db->load<TrafficControlDataODB>(tcId));
    t.commit();

    nlohmann::json json_trafficControlDataODB = *trafficControlDataODB;
    TrafficControlData trafficControlData     = json_trafficControlDataODB;

    return trafficControlData;
  } catch (const odb::object_not_persistent& e) {
    Logger::pcf_db().error(
        "Error: TrafficControlData object with tcId %s not found.", tcId);
    throw NotFoundException("TrafficControlData object not found.");
  } catch (const std::exception& e) {
    Logger::pcf_db().error(
        "Error while retrieving TrafficControlData: %s", e.what());
    throw;
  }
}

bool mysql_db::updateTrafficControlData(
    const TrafficControlData& trafficControlData) {
  check_db_connection();

  try {
    nlohmann::json json_trafficControlData      = trafficControlData;
    TrafficControlDataODB trafficControlDataODB = json_trafficControlData;

    odb::transaction t(db->begin());
    Logger::pcf_db().info(
        "Updating TrafficControlData %s", json_trafficControlData.dump());
    db->update(trafficControlDataODB);
    t.commit();
  } catch (const odb::object_not_persistent& e) {
    Logger::pcf_db().error(
        "TrafficControlData with id %s does not exist.",
        trafficControlData.getTcId());
    throw NotFoundException(
        "TrafficControlData with id " + trafficControlData.getTcId() +
        " does not exist.");
  } catch (const std::exception& e) {
    Logger::pcf_db().error(
        "Error while updating TrafficControlData: %s", e.what());
    throw;
  }

  return true;
}

bool mysql_db::deleteTrafficControlData(const std::string& tcId) {
  check_db_connection();

  try {
    odb::transaction t(db->begin());
    Logger::pcf_db().debug("Deleting TrafficControlData with id %s", tcId);
    std::shared_ptr<TrafficControlDataODB> trafficControlDataODB(
        db->load<TrafficControlDataODB>(tcId));
    db->erase(*trafficControlDataODB);
    t.commit();
  } catch (const odb::object_not_persistent& e) {
    Logger::pcf_db().error(
        "TrafficControlData with id %s does not exist.", tcId);
    throw NotFoundException(
        "TrafficControlData with id " + tcId + " does not exist.");
  } catch (const std::exception& e) {
    Logger::pcf_db().error(
        "Error while deleting TrafficControlData: %s", e.what());
    throw;
  }

  return true;
}

std::vector<TrafficControlData> mysql_db::getAllTrafficControlData() {
  check_db_connection();

  std::vector<TrafficControlData> results;
  try {
    odb::transaction t(db->begin());
    Logger::pcf_db().debug("Reading all TrafficControlData");
    odb::result<TrafficControlDataODB> r(db->query<TrafficControlDataODB>());

    for (odb::result<TrafficControlDataODB>::iterator i(r.begin());
         i != r.end(); ++i) {
      nlohmann::json json_trafficControlDataODB = *i;
      TrafficControlData trafficControlData     = json_trafficControlDataODB;
      results.push_back(trafficControlData);
    }

    t.commit();
  } catch (const std::exception& e) {
    Logger::pcf_db().error(
        "Error while retrieving all TrafficControlData: %s", e.what());
    throw;
  }

  return results;
}

/**
 * PccRule CRUD functions
 */

bool mysql_db::createPccRule(const oai::model::pcf::PccRule& pccRule) {
  check_db_connection();

  try {
    nlohmann::json json_pccRule = pccRule;
    PccRuleODB pccRuleODB       = json_pccRule;

    odb::transaction t(db->begin());
    Logger::pcf_db().info("PccRule: %s", json_pccRule.dump());
    db->persist(pccRuleODB);
    t.commit();
  } catch (const odb::object_already_persistent& e) {
    Logger::pcf_db().error(
        "PccRule with id %s already exists.", pccRule.getPccRuleId());
    throw AlreadyExistException(
        "PccRule with id " + pccRule.getPccRuleId() + " already exists.");
  } catch (const std::exception& e) {
    Logger::pcf_db().error("Error while storing PccRule: %s", e.what());
    throw;
  }

  return true;
}

oai::model::pcf::PccRule mysql_db::getPccRule(const std::string& pccRuleId) {
  check_db_connection();

  try {
    odb::transaction t(db->begin());
    std::shared_ptr<PccRuleODB> pccRuleODB(db->load<PccRuleODB>(pccRuleId));
    t.commit();

    nlohmann::json json_pccRuleODB = *pccRuleODB;
    PccRule pccRule                = json_pccRuleODB;

    return pccRule;
  } catch (const odb::object_not_persistent& e) {
    Logger::pcf_db().error(
        "Error: PccRule object with pccRuleId %s not found.", pccRuleId);
    throw NotFoundException("PccRule object not found.");
  } catch (const std::exception& e) {
    Logger::pcf_db().error("Error while retrieving PccRule: %s", e.what());
    throw;
  }
}

bool mysql_db::updatePccRule(const oai::model::pcf::PccRule& pccRule) {
  check_db_connection();

  try {
    nlohmann::json json_pccRule = pccRule;
    PccRuleODB pccRuleODB       = json_pccRule;

    odb::transaction t(db->begin());
    Logger::pcf_db().info("Updating PccRule %s", json_pccRule.dump());
    db->update(pccRuleODB);
    t.commit();
  } catch (const odb::object_not_persistent& e) {
    Logger::pcf_db().error(
        "PccRule with id %s does not exist.", pccRule.getPccRuleId());
    throw NotFoundException(
        "PccRule with id " + pccRule.getPccRuleId() + " does not exist.");
  } catch (const std::exception& e) {
    Logger::pcf_db().error("Error while updating PccRule: %s", e.what());
    throw;
  }

  return true;
}

bool mysql_db::deletePccRule(const std::string& pccRuleId) {
  check_db_connection();

  try {
    odb::transaction t(db->begin());
    Logger::pcf_db().debug("Deleting PccRule with id %s", pccRuleId);
    std::shared_ptr<PccRuleODB> pccRuleODB(db->load<PccRuleODB>(pccRuleId));
    db->erase(*pccRuleODB);
    t.commit();
  } catch (const odb::object_not_persistent& e) {
    Logger::pcf_db().error("PccRule with id %s does not exist.", pccRuleId);
    throw NotFoundException(
        "PccRule with id " + pccRuleId + " does not exist.");
  } catch (const std::exception& e) {
    Logger::pcf_db().error("Error while deleting PccRule: %s", e.what());
    throw;
  }

  return true;
}

std::vector<oai::model::pcf::PccRule> mysql_db::getAllPccRules() {
  check_db_connection();

  std::vector<oai::model::pcf::PccRule> results;
  try {
    odb::transaction t(db->begin());
    Logger::pcf_db().debug("Reading all PccRules");
    odb::result<PccRuleODB> r(db->query<PccRuleODB>());

    for (odb::result<PccRuleODB>::iterator i(r.begin()); i != r.end(); ++i) {
      nlohmann::json json_pccRuleODB   = *i;
      oai::model::pcf::PccRule pccRule = json_pccRuleODB;
      results.push_back(pccRule);
    }

    t.commit();
  } catch (const std::exception& e) {
    Logger::pcf_db().error("Error while retrieving all PccRules: %s", e.what());
    throw;
  }

  return results;
}

oai::model::pcf::SmPolicyDecision mysql_db::getSmPolicyDecision(
    const std::vector<std::string>& pccRuleIds) {
  check_db_connection();
  SmPolicyDecision decision = {};
  std::map<std::string, PccRule> pccRuleMap;
  std::map<std::string, QosData> qosDataMap;
  std::map<std::string, TrafficControlData> trafficControlDataMap;
  try {
    odb::transaction t(db->begin());
    for (const std::string& pccRuleId : pccRuleIds) {
      try {
        PccRule pccRule = getPccRule(pccRuleId);

        std::vector<std::string> qosDataIds = pccRule.getRefQosData();
        for (const std::string& qosDataId : qosDataIds) {
          QosData qosData = getQosData(qosDataId);
          qosDataMap.insert(std::make_pair(qosDataId, qosData));
        }

        std::vector<std::string> trafficControlDataIds = pccRule.getRefTcData();
        for (const std::string& tcId : trafficControlDataIds) {
          TrafficControlData trafficControlData = getTrafficControlData(tcId);
          trafficControlDataMap.insert(
              std::make_pair(tcId, trafficControlData));
        }

        pccRuleMap.insert(std::make_pair(pccRuleId, pccRule));
      } catch (const NotFoundException& e) {
        Logger::pcf_db().error(
            "A requested PccRule, QosData or TrafficControlData for "
            "SmPolicyDecision does not exist.",
            e.what());
        throw;
      }
    }
    t.commit();
  } catch (const std::exception& e) {
    Logger::pcf_db().error(
        "Error while retrieving data for SmPolicyDecision", e.what());
    throw;
  }
  decision.setPccRules(pccRuleMap);
  decision.setQosDecs(qosDataMap);
  decision.setTraffContDecs(trafficControlDataMap);
  return decision;
}