/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "pcf_profile.hpp"

#include <arpa/inet.h>

#include "logger.hpp"
#include "string.hpp"

using namespace oai::pcf::app;
using namespace oai::common::sbi;

void pcf_profile::set_pcf_info(const pcf_info_t& info) {
  pcf_info = info;
}

void pcf_profile::get_pcf_info(pcf_info_t& info) const {
  info = pcf_info;
}

void pcf_profile::display() {
  oai::sba::nf_profile::display();

  Logger::pcf_app().debug("\tPCF Info");
  Logger::pcf_app().debug("\t\t GroupId: %s", pcf_info.groupid.c_str());
  for (const auto& supi : pcf_info.supi_ranges) {
    Logger::pcf_app().debug(
        "\t\t SupiRanges: Start - %s, End - %s, Pattern - %s",
        supi.supi_range.start.c_str(), supi.supi_range.end.c_str(),
        supi.supi_range.pattern.c_str());
  }
  for (const auto& gpsi : pcf_info.gpsi_ranges) {
    Logger::pcf_app().debug(
        "\t\t GpsiRanges: Start - %s, End - %s, Pattern - %s",
        gpsi.identity_range.start.c_str(), gpsi.identity_range.end.c_str(),
        gpsi.identity_range.pattern.c_str());
  }
  for (const auto& dnn : pcf_info.dnn_list) {
    Logger::pcf_app().debug("\t\t DNN: %s", dnn.c_str());
  }
}

void pcf_profile::to_json(nlohmann::json& data) const {
  oai::sba::nf_profile::to_json(data);

  // Preserve the PCF registration payload produced before using the common
  // NF profile implementation.
  data.erase("customInfo");
  data.erase("json_data");
  if (snssais.empty()) data["sNssais"] = nlohmann::json::array();

  data["nfServices"] = nlohmann::json::array();
  for (const auto& service : nf_services) {
    nlohmann::json item       = {};
    item["serviceInstanceId"] = service.service_instance_id;
    item["serviceName"]       = service.service_name;
    item["versions"]          = nlohmann::json::array();
    for (const auto& version : service.versions) {
      nlohmann::json value     = {};
      value["apiVersionInUri"] = version.api_version_in_uri;
      value["apiFullVersion"]  = version.api_full_version;
      item["versions"].push_back(value);
    }
    item["scheme"]          = service.scheme;
    item["nfServiceStatus"] = service.nf_service_status;
    item["ipEndPoints"]     = nlohmann::json::array();
    for (const auto& endpoint : service.ip_endpoints) {
      nlohmann::json value = {};
      value["ipv4Address"] = inet_ntoa(endpoint.ipv4_address);
      value["transport"]   = endpoint.transport;
      value["port"]        = endpoint.port;
      item["ipEndPoints"].push_back(value);
    }
    data["nfServices"].push_back(item);
  }

  data["custom_info"] = custom_info;

  auto& info         = data["pcfInfo"];
  info["groupId"]    = pcf_info.groupid;
  info["dnnList"]    = nlohmann::json::array();
  info["supiRanges"] = nlohmann::json::array();
  info["gpsiRanges"] = nlohmann::json::array();

  for (const auto& supi : pcf_info.supi_ranges) {
    info["supiRanges"].push_back(
        {{"start", supi.supi_range.start},
         {"end", supi.supi_range.end},
         {"pattern", supi.supi_range.pattern}});
  }
  for (const auto& gpsi : pcf_info.gpsi_ranges) {
    info["gpsiRanges"].push_back(
        {{"start", gpsi.identity_range.start},
         {"end", gpsi.identity_range.end},
         {"pattern", gpsi.identity_range.pattern}});
  }
  for (const auto& dnn : pcf_info.dnn_list) {
    info["dnnList"].push_back(dnn);
  }

  Logger::pcf_app().debug("PCF profile to json:\n %s", data.dump().c_str());
}

void pcf_profile::from_json(const nlohmann::json& data) {
  snssais.clear();
  ipv4_addresses.clear();
  pcf_info = {};

  if (data.contains("nfInstanceId"))
    nf_instance_id = data.at("nfInstanceId").get<std::string>();
  if (data.contains("nfInstanceName"))
    nf_instance_name = data.at("nfInstanceName").get<std::string>();
  if (data.contains("nfType")) nf_type = data.at("nfType").get<std::string>();
  if (data.contains("nfStatus"))
    nf_status = data.at("nfStatus").get<std::string>();
  if (data.contains("heartBeatTimer"))
    heartBeat_timer = data.at("heartBeatTimer").get<int32_t>();
  if (data.contains("fqdn")) fqdn = data.at("fqdn").get<std::string>();
  if (data.contains("priority")) priority = data.at("priority").get<uint16_t>();
  if (data.contains("capacity")) capacity = data.at("capacity").get<uint16_t>();

  if (data.contains("sNssais")) {
    for (const auto& item : data.at("sNssais")) {
      snssais.emplace_back(
          item.at("sst").get<int>(), item.at("sd").get<std::string>());
    }
  }

  if (data.contains("ipv4Addresses")) {
    for (const auto& item : data.at("ipv4Addresses")) {
      struct in_addr address = {};
      auto value             = item.get<std::string>();
      if (inet_pton(AF_INET, oai::utils::trim(value).c_str(), &address) == 1) {
        ipv4_addresses.push_back(address);
      } else {
        Logger::pcf_app().warn(
            "Address conversion: Bad value %s",
            oai::utils::trim(value).c_str());
      }
    }
  }

  if (data.contains("pcfInfo")) {
    const auto& info = data.at("pcfInfo");
    if (info.contains("groupId"))
      pcf_info.groupid = info.at("groupId").get<std::string>();
    if (info.contains("dnnList")) {
      for (const auto& dnn : info.at("dnnList"))
        pcf_info.dnn_list.push_back(dnn.get<std::string>());
    }
    if (info.contains("supiRanges")) {
      for (const auto& range : info.at("supiRanges")) {
        supi_range_info_item_t item = {};
        item.supi_range.start       = range.at("start");
        item.supi_range.end         = range.at("end");
        item.supi_range.pattern     = range.at("pattern");
        pcf_info.supi_ranges.push_back(item);
      }
    }
    if (info.contains("gpsiRanges")) {
      for (const auto& range : info.at("gpsiRanges")) {
        identity_range_info_item_t item = {};
        item.identity_range.start       = range.at("start");
        item.identity_range.end         = range.at("end");
        item.identity_range.pattern     = range.at("pattern");
        pcf_info.gpsi_ranges.push_back(item);
      }
    }
  }

  display();
}

void pcf_profile::handle_heartbeart_timeout(uint64_t ms) {
  Logger::pcf_app().info(
      "Handle heartbeart timeout profile %s, time %d", nf_instance_id.c_str(),
      ms);
  set_nf_status("SUSPENDED");
}
