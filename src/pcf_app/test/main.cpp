/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include <gtest/gtest.h>

#include "logger.hpp"

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);

  // The code under test (app_session.cpp) logs via Logger::pcf_app(); the
  // logger registry must be initialized before the first call.
  Logger::init("pcf_unit_tests", /*log_stdout=*/false, /*log_rot_file=*/false);

  return RUN_ALL_TESTS();
}
