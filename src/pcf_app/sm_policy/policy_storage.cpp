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

/*! \file policy_storage.cpp
 \brief
 \author  Stefan Spettel
 \company Openairinterface Software Allianse
 \date 2022
 \email: stefan.spettel@eurecom.fr
 */

#include "policy_storage.hpp"
#include "logger.hpp"

using namespace oai::pcf::app::sm_policy;
using namespace oai::pcf::model;

void policy_storage::create_default_policy_decision(
    std::string pcc_rule_name, std::string flow_description, std::string tc_id,
    std::string dnai, std::string route_policy_id, int precedence,
    std::shared_ptr<SmPolicyDecision>& decision) {
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

  decision->setPccRules(pcc_rule_map);

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

  decision->setTraffContDecs(traffic_cont_map);
}

policy_storage::policy_storage() {
  // TODO currently hardcode the policy decisions, should come from UDR or file
  std::shared_ptr<SmPolicyDecision> decision_supi =
      std::make_shared<SmPolicyDecision>();
  std::shared_ptr<SmPolicyDecision> decision_tmp =
      std::make_shared<SmPolicyDecision>();
  std::string supi = "imsi-208950000000031";
  std::string dnn  = "default";
  Snssai snssai;
  snssai.setSd("123");
  snssai.setSst(222);

  create_default_policy_decision(
      "supi-rule-internet", "permit out ip from any to assigned",
      "internet-traffic", "access_gnb_1", "routex", 10, decision_supi);

  // to have second PCC rule within same profile
  create_default_policy_decision(
      "supi-rule-edge", "permit out ip from 8.8.8.8 to assigned",
      "edge-traffic", "edge-dn", "route-edge1", 9, decision_tmp);

  std::map<std::string, PccRule> pcc_rules_supi = decision_supi->getPccRules();
  pcc_rules_supi.insert(std::make_pair(
      "supi-rule-edge", decision_tmp->getPccRules()["supi-rule-edge"]));

  std::map<std::string, TrafficControlData> traffic_control_decs =
      decision_supi->getTraffContDecs();

  TrafficControlData traffic = traffic_control_decs["internet-traffic"];
  std::vector<RouteToLocation> routes;

  RouteToLocation route0;
  route0.setDnai("access_gnb_1");
  RouteToLocation route1;
  route1.setDnai("ulcl1");
  RouteToLocation route2;
  route2.setDnai("iupf1");
  RouteToLocation route3;
  route3.setDnai("aupf1");
  RouteToLocation route4;
  route4.setDnai("internet");
  RouteToLocation route5;
  route5.setDnai("aupf3");

  RouteToLocation route6;
  route6.setDnai("aupf2");
  RouteToLocation route7;
  route7.setDnai("edge");

  routes.push_back(route0);
  routes.push_back(route1);
  routes.push_back(route2);
  routes.push_back(route3);
  routes.push_back(route4);

  // routes.push_back(route5);

  traffic.setRouteToLocs(routes);
  traffic_control_decs["internet-traffic"] = traffic;

  TrafficControlData traffic2 = traffic_control_decs["edge-traffic"];
  std::vector<RouteToLocation> routes2;

  routes2.push_back(route0);
  routes2.push_back(route7);
  routes2.push_back(route6);
  routes2.push_back(route1);

  traffic2.setRouteToLocs(routes2);
  traffic_control_decs["edge-traffic"] = traffic2;

  decision_supi->setTraffContDecs(traffic_control_decs);
  decision_supi->setPccRules(pcc_rules_supi);

  std::shared_ptr<SmPolicyDecision> decision_dnn =
      std::make_shared<SmPolicyDecision>();

  create_default_policy_decision(
      "dnn-rule-internet", "permit out ip from any to assigned",
      "default-traffic", "internet-dn", "route-internet", 10, decision_dnn);

  std::shared_ptr<SmPolicyDecision> decision_slice =
      std::make_shared<SmPolicyDecision>();

  create_default_policy_decision(
      "slice-rule-internet", "permit out ip from any to assigned",
      "default-traffic", "internet-dn", "route-internet", 10, decision_slice);

  std::shared_ptr<SmPolicyDecision> decision_default =
      std::make_shared<SmPolicyDecision>();

  create_default_policy_decision(
      "default-rule-internet", "permit out ip from any to assigned",
      "default-traffic", "internet-dn", "route-internet", 10, decision_default);

  insert_supi_decision(supi, decision_supi);
  insert_dnn_decision(dnn, decision_dnn);
  insert_slice_decision(snssai, decision_slice);

  default_decision = std::make_shared<policy_decision>(decision_default);
}

void policy_storage::insert_supi_decision(
    std::string supi, const std::shared_ptr<SmPolicyDecision>& decision) {
  std::unique_lock supi_decision_lock(m_supi_policy_decisions_mutex);

  std::shared_ptr<supi_policy_decision> desc =
      std::make_shared<supi_policy_decision>(supi, decision);

  m_supi_policy_decisions.insert(std::make_pair(supi, desc));
  notify_subscribers(desc);
}

void policy_storage::insert_dnn_decision(
    std::string dnn, const std::shared_ptr<SmPolicyDecision>& decision) {
  std::unique_lock dnn_decision_lock(m_dnn_policy_decisions_mutex);

  std::shared_ptr<dnn_policy_decision> desc =
      std::make_shared<dnn_policy_decision>(dnn, decision);

  m_dnn_policy_decisions.insert(std::make_pair(dnn, desc));
  notify_subscribers(desc);
}

void policy_storage::insert_slice_decision(
    Snssai slice, const std::shared_ptr<SmPolicyDecision>& decision) {
  std::unique_lock slice_decision_lock(m_slice_policy_decisions_mutex);

  std::shared_ptr<slice_policy_decision> desc =
      std::make_shared<slice_policy_decision>(slice, decision);

  m_slice_policy_decisions.insert(std::make_pair(slice, desc));
  notify_subscribers(desc);
}
/**
 * @brief Finds a policy based on the existing supi, dnn, slice and default
 * policies in that order.
 *
 * @param context  The policy context containing supi or dnn or snssai
 * @param chosen_decision
 * decision base class
 * @return pointer to the object implementing the chosen, null in case no
 * decision can be found
 */
std::shared_ptr<policy_decision> policy_storage::find_policy(
    const oai::pcf::model::SmPolicyContextData& context) {
  std::string msg_base = "SM Policy request from SUPI:";
  std::string supi     = context.getSupi();

  std::shared_ptr<policy_decision> res_ptr;

  // First, check based on SUPI, then DNN, then Slice, then global default rule.
  std::shared_lock lock_supi(m_supi_policy_decisions_mutex);
  auto got_supi = m_supi_policy_decisions.find(context.getSupi());

  if (got_supi == m_supi_policy_decisions.end()) {
    Logger::pcf_app().debug(
        "%s %s - Did not find SUPI policy", msg_base.c_str(), supi.c_str());
    std::shared_lock lock_dnn(m_dnn_policy_decisions_mutex);
    auto got_dnn = m_dnn_policy_decisions.find(context.getDnn());

    if (got_dnn == m_dnn_policy_decisions.end()) {
      Logger::pcf_app().debug(
          "%s %s - Did not find DNN policy", msg_base.c_str(), supi.c_str());
      std::shared_lock lock_slice(m_slice_policy_decisions_mutex);
      auto got_slice = m_slice_policy_decisions.find(context.getSliceInfo());

      if (got_slice == m_slice_policy_decisions.end()) {
        Logger::pcf_app().debug(
            "%s %s - Did not find slice policy", msg_base.c_str(),
            supi.c_str());

        if (!default_decision) {
          Logger::pcf_app().debug(
              "%s %s - Did not find default policy", msg_base.c_str(),
              supi.c_str());

          return res_ptr;  // null
        } else {
          Logger::pcf_app().debug(
              "%s %s - Decide based on default policy", msg_base.c_str(),
              supi.c_str());
          return default_decision;
        }
      } else {
        Logger::pcf_app().debug("%s Decide based on slice", msg_base.c_str());
        return got_slice->second;
      }
    } else {
      Logger::pcf_app().debug("%s Decide based on DNN", msg_base.c_str());
      return got_dnn->second;
    }
  } else {
    Logger::pcf_app().debug("%s Decide based on SUPI", msg_base.c_str());
    return got_supi->second;
  }
  return res_ptr;
}

void policy_storage::notify_subscribers(
    const std::shared_ptr<policy_decision>& decision) {
  // TODO
}