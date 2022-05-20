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
#include "gmock/gmock.h"
#include "sm_api_test.cpp"
#include "pcf_config.hpp"
#include "test_rest_client.hpp"
#include "SmPolicyContextData.h"
#include "SmPolicyDecision.h"
#include "logger.hpp"

using namespace oai::pcf::model;

using ::testing::MatchesRegex;

namespace oai::pcf::test {

SmPolicyContextData createDefaultContextData() {
  SmPolicyContextData ctx;
  ctx.setSupi("imsi-208950000000032");
  PduSessionType session_type;
  session_type.setEnumValue(PduSessionType_anyOf::ePduSessionType_anyOf::IPV4);
  ctx.setPduSessionType(session_type);

  ctx.setPduSessionId(42);
  ctx.setDnn("default");
  ctx.setNotificationUri("asdf");
  Snssai snssai;
  snssai.setSd("123");
  snssai.setSst(222);
  ctx.setSliceInfo(snssai);
  return ctx;
}

TEST_F(SMApiTest, CreateNewSMPolicyAssociation) {
  std::string response_body;
  std::string response_headers;
  std::string url = fmt::format("{}sm-policies", base_url);

  SmPolicyContextData ctx = createDefaultContextData();

  nlohmann::json j;
  to_json(j, ctx);
  std::string body = j.dump();

  int code = rest_client->sendPost(url, body, response_body, response_headers);

  EXPECT_EQ(code, 201);

  // Check that location is here and in correct format
  EXPECT_THAT(
      response_headers,
      MatchesRegex(".*Location: "
                   "*http:\\/\\/.*:.*\\/npcf-smpolicycontrol\\/v1\\/"
                   "sm-policies\\/[0-9]*.*"));

  SmPolicyDecision decision;
  try {
    nlohmann::json j2 = nlohmann::json::parse(response_body);
    from_json(j2, decision);
    EXPECT_TRUE(decision.pccRulesIsSet());
    EXPECT_TRUE(decision.traffContDecsIsSet());
  } catch (...) {
    FAIL() << "Could not parse json";
  }
}

TEST_F(SMApiTest, CreateNewSMPolicyAssociationMissingSUPI) {
  std::string response_body;
  std::string response_headers;
  std::string url = fmt::format("{}sm-policies", base_url);

  // we need to create it form a string, as the model class uses default values

  std::string body = R"(
    {"dnn": "default",
    "notificationUri":"a",
    "pduSessionId": 0,
    "pduSessionType: "IPV4",
    "sliceInfo": {"sst":0, "sd":"asdf"}
    }
    )";
  int code = rest_client->sendPost(url, body, response_body, response_headers);

  EXPECT_EQ(code, 400);
}

}  // namespace oai::pcf::test