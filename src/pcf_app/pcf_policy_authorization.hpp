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

/*! \file pcf_policy_authorization.hpp
 \brief
 \author  Tariro Mukute
 \company University of Cape Town
 \date 2024
 \email: mkttar001@myuct.ac.za
 */

#ifndef FILE_PCF_POLICY_AUTHORIZATION_SEEN
#define FILE_PCF_POLICY_AUTHORIZATION_SEEN

#include <string>
#include <unordered_map>
#include <shared_mutex>
#include <memory>
#include <optional>

#include "SmPolicyContextData.h"
#include "SmPolicyDecision.h"
#include "TrafficControlData.h"
#include "AppSessionContext.h"
#include "AppSessionContextUpdateDataPatch.h"
#include "AppSessionContextReqData.h"
#include "policy_auth/pcf_policy_authorization_status_code.hpp"
#include "policy_auth/app_session.hpp"
#include "uint_generator.hpp"
#include "pcf_event.hpp"

namespace oai::pcf::app {

/**
 * @brief Service class to handle Session Management Policies
 *
 */
class pcf_policy_authorization {
 public:
  explicit pcf_policy_authorization(pcf_event& ev);
  pcf_policy_authorization(pcf_policy_authorization const&) = delete;
  void operator=(pcf_policy_authorization const&) = delete;

  virtual ~pcf_policy_authorization();

  /**
   * @brief Handler for receiving service policy requests, as defined in
   * 3GPP TS 29.514 Chapter 4.2.2
   * It creates an application session context in the PCF. The result
   * returns an update context created.
   *
   * @param context input: context from the request
   * provisioning
   * @return policy_auth::status_code
   */
  policy_auth::status_code post_app_sessions_handler(
      const oai::model::pcf::AppSessionContext& context,
      std::string& problem_details);

  /**
   * @brief Handler for receiving service policy requests to update application
   * session context, as defined in 3GPP TS 29.514 Chapter 4.2.3
   *
   * @param app_session_id input: context from the request
   * @param app_session_context_update_data_patch input: context from the
   * request
   * @param context output: the applications session context that has been
   * updated provisioning
   * @return policy_auth::status_code
   */
  policy_auth::status_code mod_app_session_handler(
      const std::string& app_session_id,
      const oai::model::pcf::AppSessionContextUpdateDataPatch&
          app_session_context_update_data_patch,
      const oai::model::pcf::AppSessionContext& context,
      std::string& problem_details);

  private:
    // for Event Handling
    pcf_event& m_event_sub;
};

class session_binding_key {
public:
    session_binding_key() = default;

    session_binding_key(
        const std::optional<std::string>& ueIpv4,
        const std::optional<oai::model::common::Ipv6Addr>& ueIpv6,
        const std::optional<std::string>& ueMac,
        const std::optional<std::string>& dnn,
        const std::optional<oai::model::common::Snssai>& sliceInfo,
        const std::optional<std::string>& supi,
        const std::optional<std::string>& gpsi,
        const std::optional<std::string>& ipDomain
    ) : m_UeIpv4(ueIpv4),
        m_UeIpv6(ueIpv6),
        m_UeMac(ueMac),
        m_Dnn(dnn),
        m_SliceInfo(sliceInfo),
        m_Supi(supi),
        m_Gpsi(gpsi),
        m_IpDomain(ipDomain) {}

    // Accessors
    const std::optional<std::string>& GetUeIpv4() const { return m_UeIpv4; }
    const std::optional<oai::model::common::Ipv6Addr>& GetUeIpv6() const { return m_UeIpv6; }
    const std::optional<std::string>& GetUeMac() const { return m_UeMac; }
    const std::optional<std::string>& GetDnn() const { return m_Dnn; }
    const std::optional<oai::model::common::Snssai>& GetSliceInfo() const { return m_SliceInfo; }
    const std::optional<std::string>& GetSupi() const { return m_Supi; }
    const std::optional<std::string>& GetGpsi() const { return m_Gpsi; }
    const std::optional<std::string>& GetIpDomain() const { return m_IpDomain; }

private:
    std::optional<std::string> m_UeIpv4;
    std::optional<oai::model::common::Ipv6Addr> m_UeIpv6;
    std::optional<std::string> m_UeMac;
    std::optional<std::string> m_Dnn;
    std::optional<oai::model::common::Snssai> m_SliceInfo;
    std::optional<std::string> m_Supi;
    std::optional<std::string> m_Gpsi;
    std::optional<std::string> m_IpDomain;
};

/**
 * @brief Extract session key from an AppSessionContextReqData object
 *
 * This function extracts the session_binding_key from a given AppSessionContextReqData object.
 * It assumes that the input data contains all required fields to form a valid session_binding_key.
 *
 * @param context The input AppSessionContextReqData object
 *
 * @return A reference to the extracted session_binding_key
 */
session_binding_key extract_session_key(const oai::model::pcf::AppSessionContextReqData& context);

}  // namespace oai::pcf::app
#endif /* FILE_PCF_POLICY_AUTHORIZATION_SEEN */
