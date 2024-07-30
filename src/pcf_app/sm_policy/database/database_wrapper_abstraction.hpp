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

#ifndef DATABASE_WRAPPER_ABSTRACTION_HPP
#define DATABASE_WRAPPER_ABSTRACTION_HPP

#include "logger.hpp"

namespace oai::pcf::app {
class database_wrapper_abstraction {
 public:
  database_wrapper_abstraction(){};

  virtual ~database_wrapper_abstraction(){};
  // virtual std::unique_ptr<database_wrapper_abstraction> clone() const = 0;

  /*
   * Initialize the DB
   * @param void
   * @return true if successful, otherwise return false
   */
  virtual bool initialize() = 0;

  /*
   * Establish the connection between PCF and the DB
   * @param [uint32_t] num_retries: Number of retires
   * @return true if successful, otherwise return false
   */
  virtual bool connect(uint32_t num_retries) = 0;

  /*
   * Close the connection established to the DB
   * @param void
   * @return true if successful, otherwise return false
   */
  virtual bool close_connection() = 0;
};
}  // namespace oai::pcf::app

#endif  // DATABASE_WRAPPER_ABSTRACTION_HPP
