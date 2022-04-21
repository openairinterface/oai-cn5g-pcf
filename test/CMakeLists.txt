################################################################################
# Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The OpenAirInterface Software Alliance licenses this file to You under
# the OAI Public License, Version 1.1  (the "License"); you may not use this file
# except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.openairinterface.org/?page_id=698
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#-------------------------------------------------------------------------------
# For more information about the OpenAirInterface (OAI) Software Alliance:
#      contact@openairinterface.org
################################################################################
# Author: Stefan SPETTEL
###############################################################################

set(SRC_TOP_DIR /openair-pcf/src)
set(TEST_TOP_DIR ${SRC_TOP_DIR}/../test)

set(TESTDIR1 ${TEST_TOP_DIR}/sm_policy_control_api)
set(TEST11 ${TESTDIR1}/collection_api_test)
set(TEST12 ${TESTDIR1}/individual_api_test)

file(GLOB PCF_TEST_SRC_FILES
    ${TESTDIR1}/collection_api_test.cpp
    ${TESTDIR1}/individual_api_test.cpp
)
 

include_directories(${SRC_TOP_DIR})
include_directories(${TEST_TOP_DIR})
include_directories(${TEST_TOP_DIR}/test_common)

add_executable(run_unit_tests ${TEST_TOP_DIR}/run_unit_tests.cpp  ${PCF_TEST_SRC_FILES})
target_link_libraries (run_unit_tests ${ASAN}  -Wl,--start-group CN_UTILS PCF PCF_API 3GPP_COMMON_TYPES ${CRYPTO_LIBRARIES} -lnghttp2_asio -lboost_system -lboost_thread -lssl -lcrypto  dl -Wl,--end-group
pthread m rt config++ event boost_system pistache curl gtest)

ADD_SUBDIRECTORY(sm_policy_control_api)

add_test(test run_unit_tests ${TEST_TOP_DIR}/conf/pcf_test1.conf)