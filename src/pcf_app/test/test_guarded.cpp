/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include <gtest/gtest.h>

#include <string>
#include <thread>
#include <vector>

#include "guarded.hpp"

using oai::utils::guarded;

TEST(Guarded, DefaultConstructionValueInitializes) {
  guarded<int> g;
  EXPECT_EQ(*g.read(), 0);
}

TEST(Guarded, ExplicitValueConstruction) {
  guarded<std::string> g(std::string("hello"));
  EXPECT_EQ(*g.read(), "hello");
}

TEST(Guarded, WriteHandleMutatesUnderlyingValue) {
  guarded<int> g(0);
  {
    auto h = g.write();
    *h     = 42;
  }
  EXPECT_EQ(*g.read(), 42);
}

TEST(Guarded, ArrowOperatorAccessesMembers) {
  struct point {
    int x;
    int y;
  };
  guarded<point> g(point{1, 2});
  {
    auto h = g.write();
    h->x   = 10;
    h->y   = 20;
  }
  auto r = g.read();
  EXPECT_EQ(r->x, 10);
  EXPECT_EQ(r->y, 20);
}

TEST(Guarded, ConcurrentWritesAreSerialized) {
  guarded<int> counter(0);
  constexpr int kThreads          = 8;
  constexpr int kIncrementsPerThread = 1000;

  std::vector<std::thread> threads;
  threads.reserve(kThreads);
  for (int t = 0; t < kThreads; ++t) {
    threads.emplace_back([&counter]() {
      for (int i = 0; i < kIncrementsPerThread; ++i) {
        auto h = counter.write();
        *h     = *h + 1;
      }
    });
  }
  for (auto& t : threads) t.join();

  EXPECT_EQ(*counter.read(), kThreads * kIncrementsPerThread);
}

TEST(Guarded, ReadAfterWriteOnSeparateHandlesSeesLatestValue) {
  guarded<int> g(1);
  { auto h = g.write(); *h = 2; }
  EXPECT_EQ(*g.read(), 2);
  { auto h = g.write(); *h = 3; }
  EXPECT_EQ(*g.read(), 3);
}
