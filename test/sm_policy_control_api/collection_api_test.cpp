#include "gtest/gtest.h"
#include "pistache/endpoint.h"
#include "pcf-api-server.h"
#include "pcf_app.hpp"

class CollectionTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // TODO
  }

  void TearDown() override {
    // TODO
  }
};

TEST_F(CollectionTest, CreateNewSMPolicyAssociation) {
  // TODO real test with REST client
  const std::string a = "ASDF";
  const std::string b = "ASDF";

  EXPECT_EQ(a, b);
}

TEST_F(CollectionTest, RemoveExistingSMPolicyAssociation) {
  // TODO real test with REST client
  const std::string a = "ASDF";
  const std::string b = "fSDF";

  EXPECT_NE(a, b);
}
