/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// Tests for the IP/SUPI/DNN association index in policy_storage_yaml, which
// pcf_smpc uses for session binding: associating AF session information with
// one and only one PDU session [TS 23.503 §6.1.3.2.2, TS 29.513 §6.2].
//
// What the standards mandate, and what these tests check:
//  - Binding compares the UE IPv4/IPv6 address, the UE identity (SUPI) and the
//    DNN the AF provides with those of the PDU session, and "all parameters
//    shall match, if provided" [TS 29.513 §6.2 a)-c), TS 29.514 §4.2.2.2
//    NOTE 7].
//  - The same private IPv4 address may be allocated to PDU sessions on
//    different DNNs, so the DNN is part of the binding [TS 23.503 §6.1.1.2.1].
//  - When a PDU session ends, the PCF removes the binding information of that
//    PDU session, and only that one [TS 29.512 §4.2.5.2, TS 29.513 §5.2.3.1
//    steps 9 and 14 with NOTE 2].
//
// For an IP type PDU session the AF sends "ueIpv4" or "ueIpv6"
// [TS 29.514 §4.2.2.2]. The index only understands IPv4, and Policy
// Authorization passes AppSessionContextReqData::getUeIpv4(), a std::string,
// so an AF request that carried only "ueIpv6" reaches find_association() as
// ipv4 "". Tests model that request as "" with the SUPI and DNN the AF sent.
//
// References are to Release 18: TS 23.503 V18.6.0, TS 29.512 V18.13.0,
// TS 29.513 V18.7.0, TS 29.514 V18.7.0.

#include <gtest/gtest.h>

#include <atomic>
#include <optional>
#include <string>
#include <thread>
#include <vector>

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

// An IPv6-only (or non-IP) PDU session: IPv4 is never set, so
// getIpv4Address() returns "".
SmPolicyContextData make_context_without_ipv4(
    const std::string& supi, const std::string& dnn) {
  SmPolicyContextData context;
  context.setSupi(supi);
  context.setDnn(dnn);
  return context;
}

std::optional<std::string> find(
    policy_storage_yaml& storage, const std::optional<std::string>& ip,
    const std::optional<std::string>& supi,
    const std::optional<std::string>& dnn) {
  auto found = storage.find_association(ip, supi, dnn);
  return found ? std::optional<std::string>(*found) : std::nullopt;
}

std::optional<std::string> find_by_ip(
    policy_storage_yaml& storage, const std::string& ip) {
  auto found = storage.find_association(ip, std::nullopt, std::nullopt);
  return found ? std::optional<std::string>(*found) : std::nullopt;
}

// An AF request that identified the UE by SUPI and sent no "ueIpv4" (e.g. it
// sent "ueIpv6"), which Policy Authorization passes as ipv4 "".
std::optional<std::string> find_by_supi(
    policy_storage_yaml& storage, const std::string& supi) {
  auto found = storage.find_association("", supi, std::nullopt);
  return found ? std::optional<std::string>(*found) : std::nullopt;
}

}  // namespace

// --- Removal on SM Policy Association termination ---------------------------

// On Npcf_SMPolicyControl_Delete the PCF removes the PDU session's policy and
// binding information [TS 29.512 §4.2.5.2, TS 29.513 §5.2.3.1 steps 9 and 14],
// so the deleted session can no longer be bound.
TEST(PolicyStorageAssociations, RemoveErasesIpAndSupiEntries) {
  policy_storage_yaml storage;
  const auto ctx = make_context("12.1.1.2", "imsi-1", "oai");

  storage.insert_associations(ctx, "1");
  ASSERT_EQ(find_by_ip(storage, "12.1.1.2"), "1");
  ASSERT_EQ(find_by_supi(storage, "imsi-1"), "1");

  storage.remove_associations("1");

  EXPECT_FALSE(find_by_ip(storage, "12.1.1.2").has_value());
  EXPECT_FALSE(find_by_supi(storage, "imsi-1").has_value());
}

// Same requirement as above over repeated establish/terminate cycles: nothing
// from a terminated PDU session stays bindable [TS 29.513 §5.2.3.1 step 14].
TEST(PolicyStorageAssociations, CreateDeleteCyclesDoNotAccumulate) {
  policy_storage_yaml storage;
  for (int i = 1; i <= 5; ++i) {
    const auto ctx       = make_context("12.1.1.2", "imsi-1", "oai");
    const std::string id = std::to_string(i);
    storage.insert_associations(ctx, id);
    storage.remove_associations(id);
  }
  EXPECT_FALSE(find_by_ip(storage, "12.1.1.2").has_value());
  EXPECT_FALSE(find_by_supi(storage, "imsi-1").has_value());
}

// Implementation behaviour, not mandated: two live associations with the same
// IPv4, SUPI and DNN (a PDU session re-established before the old one's delete
// arrives) are ambiguous, since binding must pick one and only one PDU session
// [TS 29.513 §6.2]. The index resolves that to the newest association.
TEST(PolicyStorageAssociations, ReusedKeyResolvesToNewestAssociation) {
  policy_storage_yaml storage;
  const auto ctx = make_context("12.1.1.2", "imsi-1", "oai");

  storage.insert_associations(ctx, "1");
  storage.insert_associations(ctx, "2");

  EXPECT_EQ(find_by_ip(storage, "12.1.1.2"), "2");
  EXPECT_EQ(find_by_supi(storage, "imsi-1"), "2");
}

// Terminating a PDU session removes the binding information of that PDU
// session only [TS 29.513 §5.2.3.1 step 14, NOTE 2], so a late delete of the
// old association must leave the newer one bindable.
TEST(PolicyStorageAssociations, RemovingOldAssociationKeepsNewerOwnersEntry) {
  policy_storage_yaml storage;
  const auto ctx = make_context("12.1.1.2", "imsi-1", "oai");

  storage.insert_associations(ctx, "1");
  storage.insert_associations(ctx, "2");  // same UE re-establishes

  storage.remove_associations("1");  // late delete of the old one

  EXPECT_EQ(find_by_ip(storage, "12.1.1.2"), "2");
  EXPECT_EQ(find_by_supi(storage, "imsi-1"), "2");

  storage.remove_associations("2");
  EXPECT_FALSE(find_by_ip(storage, "12.1.1.2").has_value());
}

// Indexing an id again moves it to its new keys, as after a UE_IP_CH update:
// the PCF updates the binding information, so only the new address binds
// [TS 29.513 §5.2.2.3 steps 16 to 21].
TEST(PolicyStorageAssociations, ReindexingMovesAssociationToItsNewKeys) {
  policy_storage_yaml storage;
  storage.insert_associations(make_context("10.0.0.5", "imsi-1", "oai"), "1");
  storage.insert_associations(make_context("10.0.0.9", "imsi-1", "oai"), "1");

  EXPECT_FALSE(find_by_ip(storage, "10.0.0.5").has_value());
  EXPECT_EQ(find_by_ip(storage, "10.0.0.9"), "1");

  storage.remove_associations("1");
  EXPECT_FALSE(find_by_ip(storage, "10.0.0.9").has_value());
  EXPECT_FALSE(find_by_supi(storage, "imsi-1").has_value());
}

// Robustness, not mandated: removing an unknown or already-removed id is a
// no-op.
TEST(PolicyStorageAssociations, RemoveIsIdempotentAndIgnoresUnknownIds) {
  policy_storage_yaml storage;
  const auto ctx = make_context("12.1.1.2", "imsi-1", "oai");

  EXPECT_NO_THROW(storage.remove_associations("does-not-exist"));

  storage.insert_associations(ctx, "1");
  storage.remove_associations("1");
  EXPECT_NO_THROW(storage.remove_associations("1"));
}

// Terminating one UE's PDU session must not touch another UE's binding
// information [TS 29.513 §5.2.3.1 step 14, NOTE 2].
TEST(PolicyStorageAssociations, DistinctUesAreIndependent) {
  policy_storage_yaml storage;
  const auto a = make_context("12.1.1.2", "imsi-1", "oai");
  const auto b = make_context("12.1.1.3", "imsi-2", "oai");

  storage.insert_associations(a, "1");
  storage.insert_associations(b, "2");
  storage.remove_associations("1");

  EXPECT_FALSE(find_by_ip(storage, "12.1.1.2").has_value());
  EXPECT_EQ(find_by_ip(storage, "12.1.1.3"), "2");
  EXPECT_EQ(find_by_supi(storage, "imsi-2"), "2");
}

// --- Session binding: all provided parameters must match --------------------

// With no IPv4 provided, binding uses the parameters the AF did provide. Here
// the SUPI alone identifies the UE's only PDU session [TS 29.513 §6.2 b)].
TEST(PolicyStorageAssociations, SupiAloneBindsTheUesOnlySession) {
  policy_storage_yaml storage;
  storage.insert_associations(make_context("12.1.1.2", "imsi-1", "oai"), "1");

  EXPECT_EQ(find(storage, std::nullopt, "imsi-1", std::nullopt), "1");
  EXPECT_EQ(find(storage, "", "imsi-1", std::nullopt), "1");
  // A DNN alone does not identify a UE.
  EXPECT_FALSE(find(storage, std::nullopt, std::nullopt, "oai").has_value());
}

// A provided "ueIpv4" that matches no PDU session is a binding failure. The
// PCF must not fall back to another of the UE's sessions on the SUPI alone,
// because the IPv4 address would then not match [TS 29.513 §6.2 a),
// TS 29.514 §4.2.2.2 NOTE 7].
TEST(PolicyStorageAssociations, ProvidedIpv4MustMatch) {
  policy_storage_yaml storage;
  storage.insert_associations(make_context("12.1.1.2", "imsi-1", "oai"), "1");

  EXPECT_FALSE(find(storage, "9.9.9.9", "imsi-1", std::nullopt).has_value());
}

// The IPv4 address matches, but the AF names a different UE. Every provided
// parameter has to match, so there is no binding [TS 29.513 §6.2 b),
// TS 29.514 §4.2.2.2 NOTE 7].
TEST(PolicyStorageAssociations, ProvidedSupiMustMatch) {
  policy_storage_yaml storage;
  storage.insert_associations(
      make_context("10.0.0.5", "imsi-A", "internet"), "1");

  EXPECT_FALSE(find(storage, "10.0.0.5", "imsi-B", "internet").has_value());
}

// The IPv4 address and SUPI match, but the AF names a different DNN, so there
// is no binding [TS 29.513 §6.2 c), TS 29.514 §4.2.2.2 NOTE 7].
TEST(PolicyStorageAssociations, ProvidedDnnMustMatch) {
  policy_storage_yaml storage;
  storage.insert_associations(
      make_context("10.0.0.5", "imsi-A", "internet"), "1");

  EXPECT_FALSE(find(storage, "10.0.0.5", "imsi-A", "ims").has_value());
}

// IPv6-only PDU sessions have no IPv4 address. Indexing "" as if it were one
// makes every such session share one IP entry, so an AF request for UE-A
// (ueIpv6 + SUPI + DNN) binds to whichever UE was indexed last. Binding has to
// match the SUPI the AF provided [TS 29.513 §6.2 b)], and associate the AF
// session with one and only one PDU session [TS 23.503 §6.1.3.2.2].
TEST(PolicyStorageAssociations, EmptyIpv4IsNotSharedAcrossUes) {
  policy_storage_yaml storage;
  storage.insert_associations(make_context_without_ipv4("imsi-A", "ims"), "1");
  storage.insert_associations(make_context_without_ipv4("imsi-B", "ims"), "2");

  EXPECT_EQ(find(storage, "", "imsi-A", "ims"), "1");
  EXPECT_EQ(find(storage, "", "imsi-B", "ims"), "2");
  // A UE with no association must not resolve to someone else's session.
  EXPECT_FALSE(find(storage, "", "imsi-C", "ims").has_value());
}

// A UE with IPv6-only PDU sessions on two DNNs. Terminating one removes that
// session's binding information only [TS 29.513 §5.2.3.1 step 14, NOTE 2], so
// an AF request for the other one (ueIpv6 + SUPI + DNN) must still bind to it
// [TS 29.513 §6.2].
TEST(
    PolicyStorageAssociations, TerminatingOneSessionKeepsUesOtherSessionBound) {
  policy_storage_yaml storage;
  const auto internet = make_context_without_ipv4("imsi-1", "internet");
  const auto ims      = make_context_without_ipv4("imsi-1", "ims");
  storage.insert_associations(internet, "1");
  storage.insert_associations(ims, "2");

  storage.remove_associations("2");

  EXPECT_EQ(find(storage, "", "imsi-1", "internet"), "1");
}

// A UE with IPv6-only PDU sessions on two DNNs. The DNN the AF provides has to
// match [TS 29.513 §6.2 c)], so each request binds to the session on its own
// DNN rather than to the most recently created one.
TEST(PolicyStorageAssociations, ProvidedDnnSelectsAmongUesSessions) {
  policy_storage_yaml storage;
  storage.insert_associations(
      make_context_without_ipv4("imsi-1", "internet"), "1");
  storage.insert_associations(make_context_without_ipv4("imsi-1", "ims"), "2");

  EXPECT_EQ(find(storage, "", "imsi-1", "internet"), "1");
  EXPECT_EQ(find(storage, "", "imsi-1", "ims"), "2");
}

// The same private IPv4 address may be allocated to PDU sessions on different
// DNNs [TS 23.503 §6.1.1.2.1], so the IP alone is not enough. The DNN and SUPI
// the AF provides have to match as well [TS 29.513 §6.2,
// TS 29.514 §4.2.2.2 NOTE 7].
TEST(PolicyStorageAssociations, SameIpv4OnDifferentDnnsResolvesByDnn) {
  policy_storage_yaml storage;
  storage.insert_associations(
      make_context("10.0.0.5", "imsi-A", "internet"), "1");
  storage.insert_associations(make_context("10.0.0.5", "imsi-B", "ims"), "2");

  EXPECT_EQ(find(storage, "10.0.0.5", "imsi-A", "internet"), "1");
  EXPECT_EQ(find(storage, "10.0.0.5", "imsi-B", "ims"), "2");
}

// --- Thread safety -----------------------------------------------------------

// Not a 3GPP requirement. find_association() must hold each map's own lock.
// SMF creates and deletes
// write the SUPI map (insert_or_assign can rehash, remove erases nodes) while
// AF session-binding lookups read it. With the SUPI map read under the IP
// map's mutex, this is a data race: it can crash or misread here, and
// ThreadSanitizer reports it deterministically.
TEST(PolicyStorageAssociations, ConcurrentLookupsAndUpdatesAreSafe) {
  policy_storage_yaml storage;
  constexpr int kSupis      = 256;
  constexpr int kIterations = 20;
  std::atomic<bool> stop{false};

  std::vector<std::thread> readers;
  for (int r = 0; r < 4; ++r) {
    readers.emplace_back([&storage, &stop, r] {
      int i = r;
      while (!stop.load(std::memory_order_relaxed)) {
        // Unknown IP so every lookup falls through to the SUPI map.
        storage.find_association(
            "", "imsi-" + std::to_string(i++ % kSupis), std::nullopt);
      }
    });
  }

  for (int round = 0; round < kIterations; ++round) {
    for (int i = 0; i < kSupis; ++i) {
      const auto id = std::to_string(round * kSupis + i);
      storage.insert_associations(
          make_context_without_ipv4("imsi-" + std::to_string(i), "oai"), id);
    }
    for (int i = 0; i < kSupis; ++i) {
      const auto id = std::to_string(round * kSupis + i);
      storage.remove_associations(id);
    }
  }

  stop = true;
  for (auto& t : readers) t.join();
  EXPECT_FALSE(find_by_supi(storage, "imsi-0").has_value());
}
