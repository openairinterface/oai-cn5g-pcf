/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include <gtest/gtest.h>

#include <memory>
#include <optional>
#include <string>

#include "AppSessionContextReqData.h"
#include "app_session.hpp"
#include "app_session_storage_memory.hpp"

using namespace oai::pcf::app::policy_auth;

namespace {
std::shared_ptr<app_session> make_session(
    const std::string& id, std::optional<std::string> association_id) {
  oai::model::pcf::AppSessionContextReqData ctx;
  return std::make_shared<app_session>(id, ctx, std::move(association_id));
}
}  // namespace

TEST(AppSessionStorageMemory, GenerateIdReturnsUniqueIds) {
  app_session_storage_memory storage;
  auto id1 = storage.generate_id();
  auto id2 = storage.generate_id();
  EXPECT_FALSE(id1.empty());
  EXPECT_NE(id1, id2);
}

TEST(AppSessionStorageMemory, InsertAndFindRoundTrips) {
  app_session_storage_memory storage;
  auto session = make_session("sess-1", "assoc-1");

  storage.insert(session);
  auto found = storage.find("sess-1");

  ASSERT_NE(found, nullptr);
  EXPECT_EQ(found->id(), "sess-1");
}

TEST(AppSessionStorageMemory, FindUnknownIdReturnsNull) {
  app_session_storage_memory storage;
  EXPECT_EQ(storage.find("does-not-exist"), nullptr);
}

TEST(AppSessionStorageMemory, FindByAssociationReturnsAllBoundSessions) {
  app_session_storage_memory storage;
  storage.insert(make_session("sess-1", "assoc-shared"));
  storage.insert(make_session("sess-2", "assoc-shared"));
  storage.insert(make_session("sess-3", "assoc-other"));

  auto bound = storage.find_by_association("assoc-shared");

  EXPECT_EQ(bound.size(), 2u);
  bool has_sess1 = false, has_sess2 = false;
  for (const auto& s : bound) {
    if (s->id() == "sess-1") has_sess1 = true;
    if (s->id() == "sess-2") has_sess2 = true;
  }
  EXPECT_TRUE(has_sess1);
  EXPECT_TRUE(has_sess2);
}

TEST(AppSessionStorageMemory, FindByAssociationUnknownReturnsEmpty) {
  app_session_storage_memory storage;
  storage.insert(make_session("sess-1", "assoc-1"));

  EXPECT_TRUE(storage.find_by_association("no-such-assoc").empty());
}

TEST(AppSessionStorageMemory, RemoveErasesSessionButOnlyItsOwnAssociationEntry) {
  app_session_storage_memory storage;
  storage.insert(make_session("sess-1", "assoc-shared"));
  storage.insert(make_session("sess-2", "assoc-shared"));

  storage.remove("sess-1");

  EXPECT_EQ(storage.find("sess-1"), nullptr);
  auto remaining = storage.find_by_association("assoc-shared");
  ASSERT_EQ(remaining.size(), 1u);
  EXPECT_EQ(remaining.front()->id(), "sess-2");
}

TEST(AppSessionStorageMemory, RemoveUnknownIdIsSafeNoOp) {
  app_session_storage_memory storage;
  EXPECT_NO_THROW(storage.remove("does-not-exist"));
}

TEST(AppSessionStorageMemory, InsertSessionWithoutAssociationIsFindableById) {
  app_session_storage_memory storage;
  storage.insert(make_session("sess-1", std::nullopt));

  EXPECT_NE(storage.find("sess-1"), nullptr);
}
