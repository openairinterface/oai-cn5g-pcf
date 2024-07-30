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

#include "logger.hpp"
#include "pcf_config.hpp"

using namespace oai::pcf::app;
using namespace oai::model::common;
using namespace oai::config::pcf;

extern std::unique_ptr<pcf_config> pcf_cfg;

//------------------------------------------------------------------------------
mysql_db::mysql_db(pcf_event& ev)
    : database_wrapper<mysql_db>(), m_event_sub(ev), m_db_connection_status() {}

//------------------------------------------------------------------------------
mysql_db::~mysql_db() {
  if (db_connection_event.connected()) db_connection_event.disconnect();
  close_connection();
}

//------------------------------------------------------------------------------
bool mysql_db::initialize() {
  Logger::pcf_db().debug("Initializing MySQL DB ...");
  if (!mysql_init(&mysql_connector)) {
    Logger::pcf_db().error("Cannot initialize MySQL");
    throw std::runtime_error("Cannot initialize MySQL");
  }
  Logger::pcf_db().debug("Done!");
  return true;
}

//------------------------------------------------------------------------------
bool mysql_db::connect(uint32_t num_retries) {
  Logger::pcf_db().debug("Connecting to MySQL DB");

  uint32_t i = 0;
  while (i < num_retries) {
    // TODO: use mysql_real_connect_nonblocking (only from MySQL 8.0.16)
    if (!mysql_real_connect(
            &mysql_connector, pcf_cfg->get_database_config().get_host().c_str(),
            pcf_cfg->get_database_config().get_user().c_str(),
            pcf_cfg->get_database_config().get_pass().c_str(),
            pcf_cfg->get_database_config().get_database_name().c_str(),
            pcf_cfg->get_database_config().get_port(), 0, 0)) {
      Logger::pcf_db().error(
          "An error occurred when connecting to MySQL DB (%s), retry ...",
          mysql_error(&mysql_connector));
      i++;
    } else {
      Logger::pcf_db().info("Connected to MySQL DB");
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }
  if (i == num_retries) {
    return false;
    // throw std::runtime_error("Cannot connect to MySQL DB");
  }
  return true;
}

//------------------------------------------------------------------------------
bool mysql_db::close_connection() {
  Logger::pcf_db().debug("Close the connection with MySQL DB");
  mysql_close(&mysql_connector);
  return true;
}