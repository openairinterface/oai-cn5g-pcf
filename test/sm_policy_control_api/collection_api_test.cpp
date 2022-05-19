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

/*! \file collection_api_test.cpp
 \brief
 \author  Stefan Spettel
 \company Openairinterface Software Allianse
 \date 2022
 \email: stefan.spettel@eurecom.fr
 */

#include "gtest/gtest.h"
#include "sm_api_test.cpp"
#include "pcf_config.hpp"
#include "test_rest_client.hpp"
#include "SmPolicyContextData.h"
#include "SmPolicyDecision.h"

using namespace oai::pcf::model;

namespace oai::pcf::test {

TEST_F(SMApiTest, CreateNewSMPolicyAssociation) {
  std::string response_body;
  std::string response_headers;

  std::string url = fmt::format("{}sm-policies", base_url);

  // TODO correct json values
  std::string body = "{}";

  std::cout << "send the following json" << body << std::endl;

  int code = rest_client->sendPost(url, body, response_body, response_headers);

  std::cout << "Received response: " << response_body << std::endl;
  std::cout << "Received headers: " << response_headers << std::endl;

  EXPECT_EQ(code, 201);
}

}  // namespace oai::pcf::test