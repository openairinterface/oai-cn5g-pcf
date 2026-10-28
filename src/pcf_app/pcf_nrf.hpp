/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include <memory>
#include <string>

#include "3gpp_29.500.h"
#include "pcf_profile.hpp"
#include "pcf_event.hpp"
#include "sbi_helper.hpp"
#include "../common-src/sba/nf_service.hpp"

namespace oai::pcf::app {

/*
 * PCF side of the NRF procedures (Nnrf_NFManagement). Registration,
 * heartbeat, re-registration on heartbeat failure, registration retry and
 * deregistration are provided by oai::sba::nf_service; this class only builds
 * the PCF NF profile and supplies the PCF configuration.
 */
class pcf_nrf : public oai::sba::nf_service {
 public:
  explicit pcf_nrf(const std::shared_ptr<pcf_event>& ev);
  pcf_nrf(pcf_nrf const&)        = delete;
  void operator=(pcf_nrf const&) = delete;

  ~pcf_nrf() override;

  using oai::sba::nf_service::register_to_nrf;

  /**
   * Trigger NF instance registration to NRF with the PCF profile and the NRF
   * address from the configuration
   * @return true if the PCF is registered, false otherwise (a retry is then
   * scheduled by nf_service)
   */
  bool register_to_nrf();

 protected:
  bool nrf_registration_enabled() const override;

 private:
  pcf_profile m_nf_instance_profile;  // PCF profile
  oai::common::sbi::nf_addr_t m_nrf_addr;

  /**
   * Generate PCF profile and stores it in m_nf_instance_profile
   */
  void generate_pcf_profile();
};
}  // namespace oai::pcf::app
