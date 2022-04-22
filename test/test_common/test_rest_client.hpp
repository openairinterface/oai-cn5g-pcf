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

/*! \file test_rest_client.hpp
 \brief
 \author  Stefan Spettel
 \company Openairinterface Software Allianse
 \date 2022
 \email: stefan.spettel@eurecom.fr
 */

#ifndef FILE_TEST_REST_CLIENT_H_SEEN
#define FILE_TEST_REST_CLIENT_H_SEEN

#include <iostream>
#include <string>

class TestRestClient {
 private:
  std::string custom_method;
  bool get_method;
  bool post_method;
  std::string body;
  std::string url;

  bool use_json;

  long doRequest(std::string& response, std::string& response_headers);

 public:
  long sendPost(
      std::string url, std::string body, std::string& response,
      std::string& headers);
  long sendGet(
      std::string url, std::string body, std::string& response,
      std::string& headers);
  long sendDelete(
      std::string url, std::string body, std::string& response,
      std::string& headers);
};

#endif