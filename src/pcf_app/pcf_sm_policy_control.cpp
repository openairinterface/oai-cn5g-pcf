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
#include "TrafficControlData.h"
#include "sm_policy/policy_decision.hpp"

#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <stdexcept>
#include <unordered_map>
#include <map>
#include <shared_mutex>
#include <memory>
#include <string>

using namespace oai::pcf::app;
using namespace oai::pcf::app::sm_policy;
using namespace oai::pcf::config;
using namespace oai::pcf::model;

using namespace std;

extern pcf_smpc* pcf_smpc_inst;
extern pcf_config pcf_cfg;

//------------------------------------------------------------------------------
pcf_smpc::pcf_smpc(
    std::shared_ptr<oai::pcf::app::sm_policy::policy_storage> policy_storage) {
  m_policy_storage = policy_storage;

  std::function<void(const std::shared_ptr<policy_decision>& decision)> f =
      std::bind(&pcf_smpc::handle_policy_change, this, std::placeholders::_1);

  m_policy_storage->subscribe_to_decision_change(f);
}

void pcf_smpc::handle_policy_change(
    const std::shared_ptr<policy_decision>& decision) {
  Logger::pcf_app().warn("Policy changed, but not implemented!");
}

//------------------------------------------------------------------------------
status_code pcf_smpc::create_sm_policy_handler(
    const SmPolicyContextData& context, SmPolicyDecision& decision,
    std::string& association_id, std::string& problem_details) {
  std::shared_ptr<policy_decision> chosen_decision =
      m_policy_storage->find_policy(context);

  if (!chosen_decision) {
    problem_details = fmt::format(
        "SM policy request from SUPI {}: No policies found", context.getSupi());
    return status_code::CONTEXT_DENIED;
  }

  std::shared_ptr<SmPolicyDecision> decision_ptr;

  status_code res = chosen_decision->decide(context, decision_ptr);

  if (res != status_code::CREATED) {
    problem_details = fmt::format(
        "SM Policy request from SUPI {}: Invalid policy decision provisioned",
        context.getSupi());
  } else {
    association_id = std::to_string(m_association_id_generator.get_uid());

    individual_sm_association assoc(context, decision_ptr, association_id);

    std::unique_lock lock_assocations(m_associations_mutex);
    m_associations.insert(std::make_pair(association_id, assoc));

    Logger::pcf_app().info(fmt::format(
        "Created Policy Decision for SUPI {} with ID {}", context.getSupi(),
        association_id));
  }
  decision = *decision_ptr;
  return res;
}

//------------------------------------------------------------------------------
sm_policy::status_code pcf_smpc::delete_sm_policy_handler(
    std::string id, const SmPolicyDeleteData& delete_data,
    std::string& problem_details) {
  // TODO for now, just delete, ignore the delete_data
  std::unique_lock lock_associations(m_associations_mutex);
  std::unordered_map<std::string, individual_sm_association>::const_iterator
      iter = m_associations.find(id);
  if (iter == m_associations.end()) {
    problem_details =
        fmt::format("Could not delete policy association: ID {} not found", id);
    Logger::pcf_app().info(problem_details);
    return status_code::NOT_FOUND;
  }
  m_associations.erase(iter);
  Logger::pcf_app().info(
      fmt::format("Deleted policy association with ID {}", id));

  return status_code::OK;
}

//------------------------------------------------------------------------------
sm_policy::status_code pcf_smpc::get_sm_policy_handler(
    std::string id, oai::pcf::model::SmPolicyControl& control,
    std::string& problem_details) {
  std::shared_lock lock_associations(m_associations_mutex);
  std::unordered_map<std::string, individual_sm_association>::const_iterator
      iter = m_associations.find(id);
  if (iter == m_associations.end()) {
    problem_details = fmt::format(
        "Could not retrieve policy association: ID {} not found", id);
    Logger::pcf_app().info(problem_details);
    return status_code::NOT_FOUND;
  }
  control.setContext(iter->second.get_sm_policy_context_data());
  control.setPolicy(*(iter->second.get_sm_policy_decision()));

  Logger::pcf_app().info(
      fmt::format("Retrieved policy association with ID {}", id));

  return status_code::OK;
}

//------------------------------------------------------------------------------
sm_policy::status_code pcf_smpc::update_sm_policy_handler(
    std::string id, const SmPolicyUpdateContextData& update_context,
    SmPolicyDecision& decision, std::string& problem_details) {
  std::unique_lock lock_associations(m_associations_mutex);
  std::unordered_map<std::string, individual_sm_association>::iterator iter =
      m_associations.find(id);

  if (iter == m_associations.end()) {
    problem_details =
        fmt::format("Could not update policy association: ID {} not found", id);
    Logger::pcf_app().info(problem_details);
    return status_code::NOT_FOUND;
  }

  std::shared_ptr<SmPolicyDecision> new_decision_ptr;

  std::shared_ptr<SmPolicyDecision> orig_decision =
      iter->second.get_sm_policy_decision();
  SmPolicyContextData orig_context = iter->second.get_sm_policy_context_data();

  // find the original decision to redecide
  std::shared_ptr<policy_decision> chosen_decision =
      m_policy_storage->find_policy(orig_context);
  // this may happen when the policy has been updated/deleted in the meantime.
  if (!chosen_decision) {
    problem_details = fmt::format(
        "SM policy update from SUPI {}: No policies found",
        orig_context.getSupi());
    Logger::pcf_app().info(problem_details);
    return status_code::CONTEXT_DENIED;
  }

  status_code res = chosen_decision->redecide(
      orig_context, orig_decision, update_context, new_decision_ptr,
      problem_details);
  // we can release the locks here

  // update the existing context and policy and receive a policy diff
  // TODO in TS 23.512 Chapter 4.2.6 it is described that only the diff should
  // be returned. here, we return the whole policy object.
  individual_sm_association assoc(orig_context, new_decision_ptr, id);
  iter->second = assoc;
  // overwrite existing association
  m_associations.insert(std::make_pair(id, assoc));
  decision = *new_decision_ptr;
  return res;
}

//------------------------------------------------------------------------------
pcf_smpc::~pcf_smpc() {
  Logger::pcf_app().debug("Delete PCF SMPC instance...");
}
