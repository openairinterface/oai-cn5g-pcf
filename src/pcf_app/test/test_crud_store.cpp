/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// Tests for the generic string-keyed repository (src/common/utils/crud_store.hpp)
// reused by every Policy Authorization store: the insert/find/find_all/remove
// core and the on_inserted/on_removed secondary-index hooks. Dependency-free.

#include <gtest/gtest.h>

#include <memory>
#include <set>
#include <string>
#include <unordered_map>

#include "crud_store.hpp"

using oai::utils::crud_store_memory;

namespace {

struct item {
  std::string group;
};

// A concrete store exercising the secondary-index hooks, modelling the shape of
// a store that maintains a secondary association index.
class item_store : public crud_store_memory<item> {
 public:
  std::vector<std::shared_ptr<item>> find_by_group(
      const std::string& group) const {
    std::vector<std::shared_ptr<item>> out;
    std::shared_lock lock(m_mutex);
    auto it = m_by_group.find(group);
    if (it == m_by_group.end()) return out;
    for (const auto& id : it->second) {
      auto entry = m_entries.find(id);
      if (entry != m_entries.end()) out.push_back(entry->second);
    }
    return out;
  }

 protected:
  void on_inserted(
      const std::string& id, const std::shared_ptr<item>& value) override {
    if (value) m_by_group[value->group].insert(id);
  }
  void on_removed(
      const std::string& id, const std::shared_ptr<item>& value) override {
    if (!value) return;
    auto it = m_by_group.find(value->group);
    if (it == m_by_group.end()) return;
    it->second.erase(id);
    if (it->second.empty()) m_by_group.erase(it);
  }

 private:
  std::unordered_map<std::string, std::set<std::string>> m_by_group;
};

}  // namespace

TEST(CrudStoreMemory, InsertAndFindRoundTrips) {
  crud_store_memory<item> s;
  s.insert("a", std::make_shared<item>(item{"g1"}));
  ASSERT_NE(s.find("a"), nullptr);
  EXPECT_EQ(s.find("a")->group, "g1");
}

TEST(CrudStoreMemory, FindUnknownReturnsNull) {
  crud_store_memory<item> s;
  EXPECT_EQ(s.find("nope"), nullptr);
}

TEST(CrudStoreMemory, InsertNullIsIgnored) {
  crud_store_memory<item> s;
  s.insert("a", nullptr);
  EXPECT_EQ(s.size(), 0u);
}

TEST(CrudStoreMemory, ReinsertOverwrites) {
  crud_store_memory<item> s;
  s.insert("a", std::make_shared<item>(item{"g1"}));
  s.insert("a", std::make_shared<item>(item{"g2"}));
  EXPECT_EQ(s.size(), 1u);
  EXPECT_EQ(s.find("a")->group, "g2");
}

TEST(CrudStoreMemory, FindAllReturnsEveryEntry) {
  crud_store_memory<item> s;
  s.insert("a", std::make_shared<item>(item{"g1"}));
  s.insert("b", std::make_shared<item>(item{"g2"}));
  EXPECT_EQ(s.find_all().size(), 2u);
}

TEST(CrudStoreMemory, RemoveErasesAndIsSafeOnUnknown) {
  crud_store_memory<item> s;
  s.insert("a", std::make_shared<item>(item{"g1"}));
  s.remove("a");
  EXPECT_EQ(s.find("a"), nullptr);
  EXPECT_EQ(s.size(), 0u);
  EXPECT_NO_THROW(s.remove("does-not-exist"));
}

TEST(CrudStoreMemory, ConstValueInstantiationWorks) {
  // Models qos_reference_store = crud_store<const QosData>.
  crud_store_memory<const int> s;
  s.insert("k", std::make_shared<const int>(42));
  ASSERT_NE(s.find("k"), nullptr);
  EXPECT_EQ(*s.find("k"), 42);
}

TEST(CrudStoreHooks, SecondaryIndexIsMaintainedOnInsert) {
  item_store s;
  s.insert("a", std::make_shared<item>(item{"g1"}));
  s.insert("b", std::make_shared<item>(item{"g1"}));
  s.insert("c", std::make_shared<item>(item{"g2"}));

  EXPECT_EQ(s.find_by_group("g1").size(), 2u);
  EXPECT_EQ(s.find_by_group("g2").size(), 1u);
  EXPECT_TRUE(s.find_by_group("none").empty());
}

TEST(CrudStoreHooks, SecondaryIndexIsMaintainedOnRemove) {
  item_store s;
  s.insert("a", std::make_shared<item>(item{"g1"}));
  s.insert("b", std::make_shared<item>(item{"g1"}));

  s.remove("a");

  auto g1 = s.find_by_group("g1");
  ASSERT_EQ(g1.size(), 1u);
}
