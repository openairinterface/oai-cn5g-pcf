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
  SmPolicyDecision decision_supi;
  SmPolicyDecision decision_tmp;

  std::string supi = "imsi-208950000000032";
  std::string dnn  = "default";
  Snssai snssai;
  snssai.setSd("123");
  snssai.setSst(222);

  create_default_policy_decision(
      "supi-rule-internet", "permit out ip from any to assigned",
      "default-traffic", "internet-dn", "route-internet", 10, decision_supi);

  // to have second PCC rule within same profile
  create_default_policy_decision(
      "supi-rule-edge", "permit out ip from 8.8.8.8 to assigned",
      "edge-traffic", "edge-dn", "route-edge1", 9, decision_tmp);

  std::map<std::string, PccRule> pcc_rules_supi = decision_supi.getPccRules();
  pcc_rules_supi.insert(std::make_pair(
      "supi-rule-edge", decision_tmp.getPccRules()["supi-rule-edge"]));

  std::map<std::string, TrafficControlData> traffic_control_decs =
      decision_supi.getTraffContDecs();
  traffic_control_decs.insert(std::make_pair(
      "edge-traffic", decision_tmp.getTraffContDecs()["edge-traffic"]));

  decision_supi.setPccRules(pcc_rules_supi);
  decision_supi.setTraffContDecs(traffic_control_decs);

  SmPolicyDecision decision_dnn;

  create_default_policy_decision(
      "dnn-rule-internet", "permit out ip from any to assigned",
      "default-traffic", "internet-dn", "route-internet", 10, decision_dnn);

  SmPolicyDecision decision_slice;

  create_default_policy_decision(
      "slice-rule-internet", "permit out ip from any to assigned",
      "default-traffic", "internet-dn", "route-internet", 10, decision_slice);

  SmPolicyDecision decision_default;

  create_default_policy_decision(
      "default-rule-internet", "permit out ip from any to assigned",
      "default-traffic", "internet-dn", "route-internet", 10, decision_default);

  supi_policy_decision supi_desc(supi, decision_supi);
  m_supi_policy_decisions.insert(std::make_pair(supi, supi_desc));

  slice_policy_decision slice_desc(snssai, decision_slice);
  m_slice_policy_decisions.insert(std::make_pair(snssai, slice_desc));

  dnn_policy_decision dnn_desc(dnn, decision_dnn);
  m_dnn_policy_decisions.insert(std::make_pair(dnn, dnn_desc));

  default_decision = std::make_unique<policy_decision>(decision_default);
}

void pcf_smpc::create_default_policy_decision(
    std::string pcc_rule_name, std::string flow_description, std::string tc_id,
    std::string dnai, std::string route_policy_id, int precedence,
    SmPolicyDecision& decision) {
  PccRule rule;
  FlowInformation flow;
  flow.setFlowDescription(flow_description);
  std::vector<FlowInformation> flow_information;
  flow_information.push_back(flow);

  // 29.512 5.6.2.6 array only for forwards compatibility, n=1
  std::vector<std::string> tc_ids;
  tc_ids.push_back(tc_id);

  rule.setFlowInfos(flow_information);
  rule.setPccRuleId(pcc_rule_name);
  rule.setRefTcData(tc_ids);
  rule.setPrecedence(precedence);

  std::map<std::string, PccRule> pcc_rule_map;
  pcc_rule_map[pcc_rule_name] = rule;

  decision.setPccRules(pcc_rule_map);

  TrafficControlData traffic_control;
  traffic_control.setTcId(tc_id);

  RouteToLocation route_to_loc;
  route_to_loc.setDnai(dnai);
  route_to_loc.setRouteProfId(route_policy_id);

  std::vector<RouteToLocation> route_to_locs;
  route_to_locs.push_back(route_to_loc);
  traffic_control.setRouteToLocs(route_to_locs);

  std::map<std::string, TrafficControlData> traffic_cont_map;

  traffic_cont_map[tc_id] = traffic_control;

  decision.setTraffContDecs(traffic_cont_map);
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
  control.setPolicy(iter->second.get_sm_policy_decision());

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

  SmPolicyDecision orig_decision   = iter->second.get_sm_policy_decision();
  SmPolicyContextData orig_context = iter->second.get_sm_policy_context_data();

  // find the original decision to redecide

  std::shared_lock lock_supi(m_supi_policy_decisions_mutex);
  std::shared_lock lock_dnn(m_dnn_policy_decisions_mutex);
  std::shared_lock lock_slice(m_slice_policy_decisions_mutex);

  policy_decision* chosen_decision;

  // this may happen when the policy has been updated/deleted in the meantime.
  bool found = find_policy(orig_context, &chosen_decision);
  if (!found) {
    problem_details = fmt::format(
        "SM policy update from SUPI {}: No policies found",
        orig_context.getSupi());
    Logger::pcf_app().info(problem_details);
    return status_code::CONTEXT_DENIED;
  }

  status_code res = chosen_decision->redecide(
      orig_context, orig_decision, update_context, decision, problem_details);
  // we can release the locks here
  lock_slice.unlock();
  lock_dnn.unlock();
  lock_supi.unlock();

  // update the existing context and policy and receive a policy diff
  // TODO in TS 23.512 Chapter 4.2.6 it is described that only the diff should
  // be returned. here, we return the whole policy object.
  individual_sm_association assoc(orig_context, decision, id);
  iter->second = assoc;
  // overwrite existing association
  m_associations.insert(std::make_pair(id, assoc));

  return res;
}

//------------------------------------------------------------------------------
pcf_smpc::~pcf_smpc() {
  Logger::pcf_app().debug("Delete PCF SMPC instance...");
}
