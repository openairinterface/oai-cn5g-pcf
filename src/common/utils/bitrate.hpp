/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_BITRATE_HPP_SEEN
#define FILE_BITRATE_HPP_SEEN

#include <cstdint>
#include <optional>
#include <regex>
#include <string>

namespace oai::utils::bitrate {

/**
 * @brief Helpers for arithmetic on 3GPP "BitRate" strings (e.g. "10 Mbps").
 *
 * The 3GPP BitRate type (TS 29.571 clause 5.2.2; the pattern is reproduced in
 * this repo as BANDWIDTH_VALIDATION_REGEX in model/common_model/Helpers.h) is a
 * decimal string "<number> <unit>" with unit in {bps, Kbps, Mbps, Gbps, Tbps}
 * and an optional space. Units are decimal (1 Kbps = 1000 bps), per 3GPP.
 *
 * These helpers exist because TS 29.513 clause 7.3.3 (Table 7.3.3-2) requires
 * summing per-service-data-flow data rates ("Maximum/Guaranteed Authorized Data
 * Rate ... is the sum of all ... for all the service data flows"), which is not
 * possible on the opaque string form.
 */

// Decimal multipliers to bits-per-second (3GPP bit rates are decimal, not 2^n).
inline constexpr uint64_t kBps  = 1ULL;
inline constexpr uint64_t kKbps = 1000ULL;
inline constexpr uint64_t kMbps = 1000ULL * 1000ULL;
inline constexpr uint64_t kGbps = 1000ULL * 1000ULL * 1000ULL;
inline constexpr uint64_t kTbps = 1000ULL * 1000ULL * 1000ULL * 1000ULL;

/**
 * @brief Parse a 3GPP BitRate string to bits-per-second.
 * @return the value in bps, or std::nullopt if the string is not a valid
 *         BitRate (empty, malformed, or unknown unit).
 *
 * Accepts an optional single space and a decimal fraction, e.g. "10 Mbps",
 * "10Mbps", "10.5 Mbps" (= 10 500 000 bps). Matches BANDWIDTH_VALIDATION_REGEX.
 */
inline std::optional<uint64_t> to_bps(const std::string& bitrate) {
  // (^\d+(\.\d+)?) ?(bps|Kbps|Mbps|Gbps|Tbps)$  -- same shape as the model's
  // BANDWIDTH_VALIDATION_REGEX in model/common_model/Helpers.h.
  static const std::regex kRe(
      R"(^(\d+)(?:\.(\d+))? ?(bps|Kbps|Mbps|Gbps|Tbps)$)");
  std::smatch m;
  if (!std::regex_match(bitrate, m, kRe)) {
    return std::nullopt;
  }

  const std::string& unit = m[3].str();
  uint64_t multiplier;
  if (unit == "bps") {
    multiplier = kBps;
  } else if (unit == "Kbps") {
    multiplier = kKbps;
  } else if (unit == "Mbps") {
    multiplier = kMbps;
  } else if (unit == "Gbps") {
    multiplier = kGbps;
  } else {  // "Tbps"
    multiplier = kTbps;
  }

  uint64_t bps = 0;
  // Integer part.
  try {
    bps = std::stoull(m[1].str()) * multiplier;
  } catch (const std::exception&) {
    return std::nullopt;  // overflow / out of range
  }

  // Optional fractional part: interpret ".<digits>" as digits/10^n of a unit.
  if (m[2].matched) {
    const std::string frac = m[2].str();
    // fractional bps = frac_value * multiplier / 10^frac.length()
    uint64_t denom = 1;
    for (size_t i = 0; i < frac.size(); ++i) denom *= 10ULL;
    // Split to keep precision within uint64: (frac * multiplier) may be large.
    // multiplier is at most 1e12 and frac < denom, so frac*multiplier fits.
    const uint64_t frac_value = std::stoull(frac);
    bps += (frac_value * multiplier) / denom;
  }

  return bps;
}

/**
 * @brief Format a bits-per-second value back into a 3GPP BitRate string.
 *
 * Picks the largest unit that keeps the value an exact integer (so "10500 Kbps"
 * rather than "10.5 Mbps"), guaranteeing the output has no fractional part and
 * always satisfies BANDWIDTH_VALIDATION_REGEX. 0 -> "0 bps".
 */
inline std::string from_bps(uint64_t bps) {
  if (bps == 0) return "0 bps";
  if (bps % kTbps == 0) return std::to_string(bps / kTbps) + " Tbps";
  if (bps % kGbps == 0) return std::to_string(bps / kGbps) + " Gbps";
  if (bps % kMbps == 0) return std::to_string(bps / kMbps) + " Mbps";
  if (bps % kKbps == 0) return std::to_string(bps / kKbps) + " Kbps";
  return std::to_string(bps) + " bps";
}

/**
 * @brief Sum two optional BitRate strings, returning a BitRate string.
 *
 * Used to combine per-SDF authorized data rates into the per-PCC-rule total
 * (TS 29.513 Table 7.3.3-2). Unparseable operands are treated as absent. If
 * both are absent, returns std::nullopt (nothing to set).
 */
inline std::optional<std::string> sum(
    const std::optional<std::string>& a, const std::optional<std::string>& b) {
  std::optional<uint64_t> av = a ? to_bps(*a) : std::nullopt;
  std::optional<uint64_t> bv = b ? to_bps(*b) : std::nullopt;
  if (!av && !bv) return std::nullopt;
  return from_bps(av.value_or(0) + bv.value_or(0));
}

}  // namespace oai::utils::bitrate

#endif  // FILE_BITRATE_HPP_SEEN
