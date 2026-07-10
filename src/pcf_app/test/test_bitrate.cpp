/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// Tests for the 3GPP BitRate arithmetic helper (src/common/utils/bitrate.hpp)
// used to sum per-service-data-flow data rates per TS 29.513 Table 7.3.3-2.
// Dependency-free (no models/gtest-only), so it runs on any host.

#include <gtest/gtest.h>

#include <optional>
#include <string>

#include "bitrate.hpp"

using namespace oai::utils::bitrate;

TEST(Bitrate, ParsesEachUnitAsDecimal) {
  EXPECT_EQ(to_bps("1500 bps").value(), 1500ULL);
  EXPECT_EQ(to_bps("500 Kbps").value(), 500000ULL);
  EXPECT_EQ(to_bps("10 Mbps").value(), 10000000ULL);
  EXPECT_EQ(to_bps("1 Gbps").value(), 1000000000ULL);
  EXPECT_EQ(to_bps("1 Tbps").value(), 1000000000000ULL);
}

TEST(Bitrate, AcceptsOptionalSpace) {
  EXPECT_EQ(to_bps("10Mbps").value(), 10000000ULL);
  EXPECT_EQ(to_bps("10 Mbps").value(), 10000000ULL);
}

TEST(Bitrate, ParsesFractionalValues) {
  EXPECT_EQ(to_bps("10.5 Mbps").value(), 10500000ULL);
  EXPECT_EQ(to_bps("0.5 Gbps").value(), 500000000ULL);
}

TEST(Bitrate, RejectsMalformedOrUnsupportedUnits) {
  EXPECT_FALSE(to_bps("").has_value());
  EXPECT_FALSE(to_bps("garbage").has_value());
  EXPECT_FALSE(to_bps("Mbps").has_value());
  EXPECT_FALSE(to_bps("10 Pbps").has_value());  // Pbps not in the accepted set
  EXPECT_FALSE(to_bps("10 mbps").has_value());  // wrong case
}

TEST(Bitrate, FormatsUsingLargestExactUnit) {
  EXPECT_EQ(from_bps(10000000ULL), "10 Mbps");
  EXPECT_EQ(from_bps(10500000ULL), "10500 Kbps");  // not Mbps-exact -> Kbps
  EXPECT_EQ(from_bps(1500ULL), "1500 bps");         // not Kbps-exact -> bps
  EXPECT_EQ(from_bps(0ULL), "0 bps");
  EXPECT_EQ(from_bps(1000000000000ULL), "1 Tbps");
}

TEST(Bitrate, RoundTripsExactValues) {
  EXPECT_EQ(from_bps(to_bps("500 Kbps").value()), "500 Kbps");
  EXPECT_EQ(from_bps(to_bps("2 Gbps").value()), "2 Gbps");
}

TEST(Bitrate, FormattedOutputIsAlwaysReparseable) {
  for (uint64_t v : {0ULL, 1500ULL, 10500000ULL, 10000000ULL, 1000000000000ULL}) {
    auto s = from_bps(v);
    ASSERT_TRUE(to_bps(s).has_value()) << "not reparseable: " << s;
    EXPECT_EQ(to_bps(s).value(), v) << s;
  }
}

TEST(BitrateSum, SumsTwoPresentRates) {
  EXPECT_EQ(sum(std::string("10 Mbps"), std::string("500 Kbps")).value(),
            "10500 Kbps");
  EXPECT_EQ(sum(std::string("1 Mbps"), std::string("1 Mbps")).value(), "2 Mbps");
}

TEST(BitrateSum, TreatsAbsentOrUnparseableOperandsAsZero) {
  EXPECT_EQ(sum(std::string("10 Mbps"), std::nullopt).value(), "10 Mbps");
  EXPECT_EQ(sum(std::nullopt, std::string("2 Mbps")).value(), "2 Mbps");
  EXPECT_EQ(sum(std::string("garbage"), std::string("2 Mbps")).value(), "2 Mbps");
}

TEST(BitrateSum, ReturnsNulloptWhenBothAbsent) {
  EXPECT_FALSE(sum(std::nullopt, std::nullopt).has_value());
  EXPECT_FALSE(sum(std::string("garbage"), std::nullopt).has_value());
}
