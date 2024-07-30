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

#ifndef DATABASE_WRAPPER_HPP
#define DATABASE_WRAPPER_HPP

#include <nlohmann/json.hpp>
#include "database_wrapper_abstraction.hpp"

#define MAX_FIRST_CONNECTION_RETRY 100

namespace oai::pcf::app {

template<class DerivedT>
class database_wrapper : public database_wrapper_abstraction {
 public:
  database_wrapper(){};

  virtual ~database_wrapper(){};

  bool initialize() override {
    Logger::pcf_app().debug("Initialize from database_wrapper");
    auto derived = static_cast<DerivedT*>(this);
    return derived->initialize();
  }

  bool connect(uint32_t num_retries) override {
    Logger::pcf_app().debug(
        "Establish the connection to the DB (from database_wrapper)");
    auto derived = static_cast<DerivedT*>(this);
    return derived->connect(num_retries);
  }

  bool close_connection() override {
    Logger::pcf_app().debug("Initialize from database_wrapper");
    auto derived = static_cast<DerivedT*>(this);
    return derived->close_connection();
  }
};
}  // namespace oai::pcf::app
#endif  // DATABASE_WRAPPER_HPP