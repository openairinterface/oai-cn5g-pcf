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

#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <stdexcept>
#include <unordered_map>
#include <map>
#include <shared_mutex>
#include <memory>

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

  rule.setPccRuleId("default_slice1");
  rule.setFlowInfos(flow_information);

  std::map<std::string, PccRule> pcc_rule_map;
  pcc_rule_map["default_slice"] = rule;

  decision.setPccRules(pcc_rule_map);

  Snssai snssai;
  snssai.setSd("123");
  snssai.setSst(222);

  slice_policy_decision slice_desc(snssai, decision);

  m_slice_policy_decisions.insert(std::make_pair(snssai, slice_desc));

  supi_policy_decision supi_desc("imsi-123", decision);

  m_supi_policy_decisions.insert(std::make_pair("imsi-123", supi_desc));

  dnn_policy_decision dnn_desc("default", decision);

  m_dnn_policy_decisions.insert(std::make_pair("default", dnn_desc));

  default_decision = std::make_unique<policy_decision>(decision);
}

bool pcf_smpc::find_policy(
    const SmPolicyContextData& context, policy_decision** chosen_decision) {
  std::string msg_base =
      fmt::format("SM Policy request from SUPI {}: ", context.getSupi());

  bool found = true;

  // First, check based on SUPI, then DNN, then Slice, then global default rule.
  std::shared_lock lock_supi(m_supi_policy_decisions_mutex);
  std::unordered_map<std::string, supi_policy_decision>::iterator got_supi =
      m_supi_policy_decisions.find(context.getSupi());

  if (got_supi == m_supi_policy_decisions.end()) {
    Logger::pcf_app().debug(msg_base + "Did not find SUPI policy");
    std::shared_lock lock_dnn(m_dnn_policy_decisions_mutex);
    std::unordered_map<std::string, dnn_policy_decision>::iterator got_dnn =
        m_dnn_policy_decisions.find(context.getDnn());

    if (got_dnn == m_dnn_policy_decisions.end()) {
      Logger::pcf_app().debug(msg_base + "Did not find DNN policy");
      std::shared_lock lock_slice(m_slice_policy_decisions_mutex);
      std::unordered_map<Snssai, slice_policy_decision, snssai_hasher>::iterator
          got_slice = m_slice_policy_decisions.find(context.getSliceInfo());

      if (got_slice == m_slice_policy_decisions.end()) {
        Logger::pcf_app().debug(msg_base + "Did not find slice policy");
        if (!default_decision) {
          Logger::pcf_app().debug(msg_base + "Did not find default policy");
          found = false;
        } else {
          Logger::pcf_app().debug(msg_base + "Decide based on default policy");
          *chosen_decision = default_decision.get();
        }
      } else {
        Logger::pcf_app().debug(msg_base + "Decide based on slice");
        *chosen_decision = &got_slice->second;
      }
    } else {
      Logger::pcf_app().debug(msg_base + "Decide based on DNN");
      *chosen_decision = &got_dnn->second;
    }
  } else {
    Logger::pcf_app().debug(msg_base + "Decide based on SUPI");
    *chosen_decision = &got_supi->second;
  }
  return found;
}

//------------------------------------------------------------------------------
status_code pcf_smpc::create_sm_policy_handler(
    const SmPolicyContextData& context, SmPolicyDecision& decision,
    std::string& association_id, std::string& problem_details) {
  std::shared_lock lock_supi(m_supi_policy_decisions_mutex);
  std::shared_lock lock_dnn(m_dnn_policy_decisions_mutex);
  std::shared_lock lock_slice(m_slice_policy_decisions_mutex);

  policy_decision* chosen_decision;

  bool found = find_policy(context, &chosen_decision);
  if (!found) {
    problem_details = fmt::format(
        "SM policy request from SUPI {}: No policies found", context.getSupi());
    return status_code::CONTEXT_DENIED;
  }

  status_code res = chosen_decision->decide(context, decision);
  // we can release the locks here
  lock_slice.unlock();
  lock_dnn.unlock();
  lock_supi.unlock();

  if (res != status_code::CREATED) {
    problem_details = fmt::format(
        "SM Policy request from SUPI {}: Invalid policy decision provisioned",
        context.getSupi());
  } else {
    association_id = std::to_string(m_association_id_generator.get_uid());

    individual_sm_association assoc(context, decision, association_id);

    std::unique_lock lock_assocations(m_associations_mutex);
    m_associations.insert(std::make_pair(association_id, assoc));

    Logger::pcf_app().info(fmt::format(
        "Created Policy Decision for SUPI {} with ID {}", context.getSupi(),
        association_id));
  }
  return res;
}

//------------------------------------------------------------------------------
pcf_smpc::~pcf_smpc() {
  Logger::pcf_app().debug("Delete PCF SMPC instance...");
}
