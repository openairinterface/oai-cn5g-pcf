/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// Tests for the IP/SUPI/DNN association index in policy_storage_yaml. The index
// must be reclaimed when an SM policy is deleted (remove_associations), must
// not drop entries owned by a newer association that reused the same key, and
// must resolve a reused key to the newest association.

#include <gtest/gtest.h>

#include <optional>
#include <string>

#include "SmPolicyContextData.h"
#include "sm_policy/policy_storage_yaml.hpp"

using oai::_3gpp::model::SmPolicyContextData;
using oai::pcf::app::sm_policy::policy_storage_yaml;

namespace {

SmPolicyContextData make_context(
    const std::string& ip, const std::string& supi, const std::string& dnn) {
  SmPolicyContextData context;
  context.setIpv4Address(ip);
  context.setSupi(supi);
  context.setDnn(dnn);
  return context;
}

std::optional<std::string> find_by_ip(
    policy_storage_yaml& storage, const std::string& ip) {
  auto found = storage.find_association(ip, std::nullopt, std::nullopt);
  return found ? std::optional<std::string>(*found) : std::nullopt;
}

std::optional<std::string> find_by_supi(
    policy_storage_yaml& storage, const std::string& supi) {
  // IP key deliberately absent so the lookup falls through to SUPI.
  auto found = storage.find_association("0.0.0.0", supi, std::nullopt);
  return found ? std::optional<std::string>(*found) : std::nullopt;
}

}  // namespace

TEST(PolicyStorageAssociations, RemoveErasesIpAndSupiEntries) {
  policy_storage_yaml storage;
  const auto ctx = make_context("12.1.1.2", "imsi-1", "oai");

  storage.insert_associations(ctx, "1");
  ASSERT_EQ(find_by_ip(storage, "12.1.1.2"), "1");
  ASSERT_EQ(find_by_supi(storage, "imsi-1"), "1");

  storage.remove_associations(ctx, "1");

  EXPECT_FALSE(find_by_ip(storage, "12.1.1.2").has_value());
  EXPECT_FALSE(find_by_supi(storage, "imsi-1").has_value());
}

TEST(PolicyStorageAssociations, CreateDeleteCyclesDoNotAccumulate) {
  policy_storage_yaml storage;
  for (int i = 1; i <= 5; ++i) {
    const auto ctx       = make_context("12.1.1.2", "imsi-1", "oai");
    const std::string id = std::to_string(i);
    storage.insert_associations(ctx, id);
    storage.remove_associations(ctx, id);
  }
  EXPECT_FALSE(find_by_ip(storage, "12.1.1.2").has_value());
  EXPECT_FALSE(find_by_supi(storage, "imsi-1").has_value());
}

TEST(PolicyStorageAssociations, ReusedKeyResolvesToNewestAssociation) {
  policy_storage_yaml storage;
  const auto ctx = make_context("12.1.1.2", "imsi-1", "oai");

  storage.insert_associations(ctx, "1");
  storage.insert_associations(ctx, "2");

  EXPECT_EQ(find_by_ip(storage, "12.1.1.2"), "2");
  EXPECT_EQ(find_by_supi(storage, "imsi-1"), "2");
}

TEST(PolicyStorageAssociations, RemovingOldAssociationKeepsNewerOwnersEntry) {
  policy_storage_yaml storage;
  const auto ctx = make_context("12.1.1.2", "imsi-1", "oai");

  storage.insert_associations(ctx, "1");
  storage.insert_associations(ctx, "2");  // same UE re-establishes

  storage.remove_associations(ctx, "1");  // late delete of the old one

  EXPECT_EQ(find_by_ip(storage, "12.1.1.2"), "2");
  EXPECT_EQ(find_by_supi(storage, "imsi-1"), "2");

  storage.remove_associations(ctx, "2");
  EXPECT_FALSE(find_by_ip(storage, "12.1.1.2").has_value());
}

TEST(PolicyStorageAssociations, RemoveIsIdempotentAndIgnoresUnknownIds) {
  policy_storage_yaml storage;
  const auto ctx = make_context("12.1.1.2", "imsi-1", "oai");

  EXPECT_NO_THROW(storage.remove_associations(ctx, "does-not-exist"));

  storage.insert_associations(ctx, "1");
  storage.remove_associations(ctx, "1");
  EXPECT_NO_THROW(storage.remove_associations(ctx, "1"));
}

TEST(PolicyStorageAssociations, DistinctUesAreIndependent) {
  policy_storage_yaml storage;
  const auto a = make_context("12.1.1.2", "imsi-1", "oai");
  const auto b = make_context("12.1.1.3", "imsi-2", "oai");

  storage.insert_associations(a, "1");
  storage.insert_associations(b, "2");
  storage.remove_associations(a, "1");

  EXPECT_FALSE(find_by_ip(storage, "12.1.1.2").has_value());
  EXPECT_EQ(find_by_ip(storage, "12.1.1.3"), "2");
  EXPECT_EQ(find_by_supi(storage, "imsi-2"), "2");
}
