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

/*! \file pcf_sm_policy_control.cpp
 \brief
 \author  Rohan Kharade
 \company Openairinterface Software Allianse
 \date 2021
 \email: rohan.kharade@openairinterface.org
 */

#include "pcf_sm_policy_control.hpp"
#include "conversions.hpp"
#include "logger.hpp"
#include "pcf.h"
#include "pcf_config.hpp"
#include "pcf_client.hpp"
#include "Snssai.h"
//#include "individual_sm_association.hpp"
#include "slice_policy_decision.hpp"

#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <stdexcept>
#include <unordered_map>
#include <map>

using namespace oai::pcf::app;
using namespace oai::pcf::app::sm_policy;
using namespace oai::pcf::config;
using namespace oai::pcf::model;

using namespace std;

extern pcf_smpc* pcf_smpc_inst;
extern pcf_config pcf_cfg;

//------------------------------------------------------------------------------
pcf_smpc::pcf_smpc() {
  // TODO currently hardcode the policy decisions, should come from UDR or file
  SmPolicyDecision decision;
  PccRule rule;

  FlowInformation flow;
  flow.setFlowDescription("permit out ip from any to assigned");
  std::vector<FlowInformation> flow_information;
  flow_information.push_back(flow);

  rule.setPccRuleId("default");
  rule.setFlowInfos(flow_information);

  std::map<std::string, PccRule> pcc_rule_map;
  pcc_rule_map["default"] = rule;

  decision.setPccRules(pcc_rule_map);

  Snssai snssai;
  snssai.setSd("123");
  snssai.setSst(222);

  slice_policy_decision slice_desc(snssai, decision);

  m_slice_policy_decisions.insert(std::make_pair(snssai, slice_desc));
}

//------------------------------------------------------------------------------
pcf_smpc_error_code pcf_smpc::create_sm_policy_handler(
    const SmPolicyContextData& context, SmPolicyDecision& decision,
    std::string& problem_details) {
  Snssai slice = context.getSliceInfo();
  std::unordered_map<
      Snssai, slice_policy_decision, snssai_hasher>::const_iterator got =
      m_slice_policy_decisions.find(slice);

  // TODO the plan here is to have: user based decisions, then dnn based
  // decisions, then slice based decision and a default decision and reply with
  // the policy decision in that order
  if (got == m_slice_policy_decisions.end()) {
    std::string description = fmt::format(
        "SM Policy request from SUPI {}: Did not find policy based on slice: "
        "{}-{}",
        context.getSupi(), slice.getSd(), slice.getSst());

    Logger::pcf_app().info(description);
    problem_details = description;
    return pcf_smpc_error_code::ContextDenied;
  } else {
    pcf_smpc_error_code res = got->second.decide(context, decision);
    if (res != pcf_smpc_error_code::Created) {
      std::string description = fmt::format(
          "SM Policy request from SUPI {}: Could not create policy based on "
          "slice: {}-{}",
          context.getSupi(), slice.getSd(), slice.getSst());
      problem_details = description;
      return res;
    }

    Logger::pcf_app().info(fmt::format(
        "SM Policy request from SUPI {}: CREATED", context.getSupi()));

    return res;
  }
}

//------------------------------------------------------------------------------
pcf_smpc::~pcf_smpc() {
  Logger::pcf_app().debug("Delete PCF SMPC instance...");
}
