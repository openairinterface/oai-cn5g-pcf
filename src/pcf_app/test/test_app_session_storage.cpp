/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// Tests for app_session_storage: the single concrete store that composes a
// generic crud_store backend and adds UUID id generation plus the 1:N
// association index. Backed here by an in-memory crud_store.

#include <gtest/gtest.h>

#include <memory>
#include <optional>
#include <string>

#include "AppSessionContextReqData.h"
#include "app_session.hpp"
#include "app_session_storage.hpp"
#include "crud_store.hpp"

using namespace oai::pcf::app::policy_auth;

namespace {

app_session_storage make_storage() {
  return app_session_storage(
      std::make_shared<oai::utils::crud_store_memory<app_session>>());
}

std::shared_ptr<app_session> make_session(
    const std::string& id, std::optional<std::string> association_id) {
  oai::model::pcf::AppSessionContextReqData ctx;
  return std::make_shared<app_session>(id, ctx, std::move(association_id));
}

}  // namespace

TEST(AppSessionStorage, GenerateIdReturnsUniqueIds) {
  auto storage = make_storage();
  auto id1 = storage.generate_id();
  auto id2 = storage.generate_id();
  EXPECT_FALSE(id1.empty());
  EXPECT_NE(id1, id2);
}

TEST(AppSessionStorage, InsertAndFindRoundTrips) {
  auto storage = make_storage();
  storage.insert(make_session("sess-1", "assoc-1"));

  auto found = storage.find("sess-1");
  ASSERT_NE(found, nullptr);
  EXPECT_EQ(found->id(), "sess-1");
}

TEST(AppSessionStorage, FindUnknownIdReturnsNull) {
  auto storage = make_storage();
  EXPECT_EQ(storage.find("does-not-exist"), nullptr);
}

TEST(AppSessionStorage, InsertNullIsIgnored) {
  auto storage = make_storage();
  EXPECT_NO_THROW(storage.insert(nullptr));
  EXPECT_TRUE(storage.find_all().empty());
}

TEST(AppSessionStorage, FindByAssociationReturnsAllBoundSessions) {
  auto storage = make_storage();
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

TEST(AppSessionStorage, FindByAssociationUnknownReturnsEmpty) {
  auto storage = make_storage();
  storage.insert(make_session("sess-1", "assoc-1"));
  EXPECT_TRUE(storage.find_by_association("no-such-assoc").empty());
}

TEST(AppSessionStorage, RemoveErasesSessionButOnlyItsOwnAssociationEntry) {
  auto storage = make_storage();
  storage.insert(make_session("sess-1", "assoc-shared"));
  storage.insert(make_session("sess-2", "assoc-shared"));

  storage.remove("sess-1");

  EXPECT_EQ(storage.find("sess-1"), nullptr);
  auto remaining = storage.find_by_association("assoc-shared");
  ASSERT_EQ(remaining.size(), 1u);
  EXPECT_EQ(remaining.front()->id(), "sess-2");
}

TEST(AppSessionStorage, RemoveUnknownIdIsSafeNoOp) {
  auto storage = make_storage();
  EXPECT_NO_THROW(storage.remove("does-not-exist"));
}

TEST(AppSessionStorage, InsertSessionWithoutAssociationIsFindableById) {
  auto storage = make_storage();
  storage.insert(make_session("sess-1", std::nullopt));
  EXPECT_NE(storage.find("sess-1"), nullptr);
}
