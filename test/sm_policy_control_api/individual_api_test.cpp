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

/*! \file individual_api_test.cpp
 \brief
 \author  Stefan Spettel
 \company Openairinterface Software Allianse
 \date 2022
 \email: stefan.spettel@eurecom.fr
 */

#include "gtest/gtest.h"
#include "sm_api_test.cpp"
#include "pcf_config.hpp"

using namespace oai::pcf::model;

using ::testing::MatchesRegex;
using ::testing::_;
using ::testing::Return;
using ::testing::Values;

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

namespace oai::pcf::test {

class IndividualSMPolicyDocumentApiTest : public ::testing::TestWithParam<::std::tuple<sm_policy::status_code, http_status_code_e>>
{
 public:
  SMApiTest sm_api_test;

 sm_policy::status_code status()
  {
    sm_policy::status_code status_code;
    http_status_code_e http_status;
    std::tie(status_code, http_status) = GetParam();
    return status_code;
  }

  http_status_code_e expected_http_status()
  {
    sm_policy::status_code status_code;
    http_status_code_e http_status;
    std::tie(status_code, http_status) = GetParam();
    return http_status;
  }
};

INSTANTIATE_TEST_SUITE_P(TestingDifferentState, IndividualSMPolicyDocumentApiTest,
    Values(
        std::make_tuple(sm_policy::status_code::OK, HTTP_STATUS_CODE_200_OK),
        std::make_tuple(sm_policy::status_code::INVALID_PARAMETERS, HTTP_STATUS_CODE_400_BAD_REQUEST),
        std::make_tuple(sm_policy::status_code::CONTEXT_DENIED, HTTP_STATUS_CODE_400_BAD_REQUEST),
        std::make_tuple(sm_policy::status_code::NOT_FOUND, HTTP_STATUS_CODE_404_NOT_FOUND),
        std::make_tuple(sm_policy::status_code::USER_UNKOWN, HTTP_STATUS_CODE_500_INTERNAL_SERVER_ERROR)));

TEST_P(IndividualSMPolicyDocumentApiTest, update_sm_policy_association) {
  std::string response_body;
  std::string response_headers;
  std::string url = fmt::format("{}/sm-policies/:smPolicyId/update", sm_api_test.base_url);

  SmPolicyContextData ctx = createDefaultContextData();

  nlohmann::json j;
  to_json(j, ctx);
  std::string body = j.dump();

  EXPECT_CALL(*sm_api_test.mock_pcf_smpc_inst, update_sm_policy_handler(_, _, _, _))
    .WillOnce(Return(status()));

  int code = sm_api_test.rest_client->sendPost(url, body, response_body, response_headers);

  EXPECT_EQ(code, expected_http_status());
}

}  // namespace oai::pcf::test