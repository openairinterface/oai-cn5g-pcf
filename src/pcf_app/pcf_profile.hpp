/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_PCF_PROFILE_HPP_SEEN
#define FILE_PCF_PROFILE_HPP_SEEN

#include <arpa/inet.h>
#include <netinet/in.h>
#include <map>
#include <memory>
#include <nlohmann/json.hpp>
#include <shared_mutex>
#include <utility>
#include <vector>

#include "logger.hpp"
#include "3gpp_23.003.h"
#include "3gpp_29.510.h"
#include "nf_profile.hpp"

namespace oai::pcf::app {

class pcf_profile : public oai::sba::nf_profile {
 public:
  pcf_profile() : oai::sba::nf_profile() {
    nf_type     = "NF_TYPE_UNKNOWN";
    custom_info = {};
  }

  explicit pcf_profile(const std::string& id) : oai::sba::nf_profile(id) {
    nf_type     = "NF_TYPE_UNKNOWN";
    custom_info = {};
  }

  pcf_profile& operator=(const pcf_profile& s) {
    if (this == &s) return *this;
    nf_instance_id   = s.nf_instance_id;
    heartBeat_timer  = s.heartBeat_timer;
    snssais          = s.snssais;
    ipv6_addresses   = s.ipv6_addresses;
    ipv4_addresses   = s.ipv4_addresses;
    fqdn             = s.fqdn;
    priority         = s.priority;
    capacity         = s.capacity;
    nf_type          = s.nf_type;
    nf_instance_name = s.nf_instance_name;
    nf_status        = s.nf_status;
    plmn_list        = s.plmn_list;
    json_data        = s.json_data;
    is_updated       = s.is_updated;
    custom_info      = s.custom_info;
    pcf_info         = s.pcf_info;
    nf_services      = s.nf_services;
    return *this;
  }
  // pcf_profile(pcf_profile &b) = delete;

  ~pcf_profile() override {
    Logger::pcf_app().debug("Delete PCF Profile instance...");
  }

  /*
   * Set pcf info
   * @param [pcf_info_t &] s: pcf info
   * @return void
   */
  void set_pcf_info(const oai::common::sbi::pcf_info_t& s);

  /*
   * Add an snssai_pcf_info_item to the pcf info
   * @param [const snssai_pcf_info_item_t &] s: snssai_pcf_info_item
   * @return void
   */
  // void add_pcf_info_item(const snssai_pcf_info_item_t& s);

  /*
   * Get NF instance pcf info
   * @param [pcf_info_t &] s: store instance's pcf info
   * @return void:
   */
  void get_pcf_info(oai::common::sbi::pcf_info_t& s) const;

  /*
   * Print related-information for NF profile
   * @param void
   * @return void:
   */
  void display() override;

  /*
   * Represent NF profile as json object
   * @param [nlohmann::json &] data: Json data
   * @return void
   */
  void to_json(nlohmann::json& data) const override;

  /*
   * Covert from a json represetation to PCF profile
   * @param [nlohmann::json &] data: Json data
   * @return void
   */
  void from_json(const nlohmann::json& data);

  /*
   * Handle heartbeart timeout event
   * @param [uint64_t] ms: current time
   * @return void
   */
  void handle_heartbeart_timeout(uint64_t ms);

 protected:
  oai::common::sbi::pcf_info_t pcf_info;
};

}  // namespace oai::pcf::app

#endif
