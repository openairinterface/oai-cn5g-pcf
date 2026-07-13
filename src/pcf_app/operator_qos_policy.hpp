/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_OPERATOR_QOS_POLICY_HPP_SEEN
#define FILE_OPERATOR_QOS_POLICY_HPP_SEEN

#include <cstdint>
#include <optional>
#include <set>

namespace oai::pcf::app {

/**
 * @brief Operator-configurable QoS authorization limits.
 *
 * Shared by the SM Policy Control side (authorizing the subscribed Session-AMBR
 * / default QoS into a SessionRule -- TS 29.512 §4.2.6.6.1) and the Policy
 * Authorization side (validating AF-requested QoS -- TS 29.514 §4.1.3.1). Bit
 * rates are stored pre-parsed to bit/s so the hot path never re-parses 3GPP
 * BitRate strings.
 *
 * Defaults are deliberately permissive (empty allow-list = allow any 5QI;
 * nullopt caps = no clamp; fail-open on missing subscription) so a
 * default-constructed instance authorizes the subscribed values unchanged. The
 * operator tightens these via config.
 */
struct operator_qos_policy {
  // Dynamic (non-standardized) 5QIs the PCF may authorize. Empty => allow any.
  // Consumed by the Policy Authorization validator; not used SM-side (subscribed
  // default 5QIs are inherently authorized).
  std::set<int32_t> allowed_dynamic_5qi;

  // Per-service-data-flow MBR ceiling (Policy Authorization side). nullopt => no
  // cap. [TS 29.512 §4.2.6.6.2]
  std::optional<uint64_t> max_flow_mbr_ul_bps;
  std::optional<uint64_t> max_flow_mbr_dl_bps;

  // Authorized Session-AMBR ceiling (SM Policy Control side). nullopt => no
  // clamp. [TS 29.512 §4.2.6.6.1]
  std::optional<uint64_t> max_session_ambr_ul_bps;
  std::optional<uint64_t> max_session_ambr_dl_bps;

  // When true, the Policy Authorization validator rejects QoS if no subscribed
  // Session-AMBR is available to check against (fail-closed). Default false =
  // fail-open, per TS 29.512 §4.2.2.2 ("no Session-AMBR constraints apply unless
  // operator policies define any").
  bool reject_on_missing_subscription{false};
};

}  // namespace oai::pcf::app

#endif  // FILE_OPERATOR_QOS_POLICY_HPP_SEEN
