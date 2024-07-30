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

#ifndef MYSQL_DB_HPP
#define MYSQL_DB_HPP

#include <mysql/mysql.h>
#include <shared_mutex>

#include "database_wrapper.hpp"
#include "pcf_event.hpp"
#include "Snssai.h"

namespace oai::pcf::app {

class mysql_db : public database_wrapper<mysql_db> {
 public:
  mysql_db(pcf_event& ev);

  virtual ~mysql_db();

  bool initialize();

  bool connect(uint32_t num_retries);

  bool close_connection();

 private:
  MYSQL mysql_connector;
  bs2::connection db_connection_event;
  pcf_event& m_event_sub;
  mutable std::shared_mutex m_db_connection_status;
};
}  // namespace oai::pcf::app

#endif  // MYSQL_DB_HPP
