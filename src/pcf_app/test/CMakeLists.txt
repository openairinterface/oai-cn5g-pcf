################################################################################
# SPDX-License-Identifier: LicenseRef-CSSL-1.0
################################################################################
#
# PCF unit tests (GoogleTest + CTest). Configured only when BUILD_TESTING=ON
# (see ../CMakeLists.txt); mirrors src/oai-cn5g-common-src/test/CMakeLists.txt.
#
# Coverage note: test_guarded.cpp has no dependency beyond guarded.hpp and
# gtest, so it builds and runs on any host with gtest installed. The other
# suites pull in the 3GPP wire models (SmPolicyDecision, AppSessionContextReqData,
# ...) via pcf_model.cmake/common_model.cmake, which transitively need
# oai-cn5g-common-src/utils/utils.cmake (config.cpp -> Snssai -> conversions.cpp
# -> output_wrapper.cpp/fqdn.cpp/mime_parser.cpp). Those three files are missing
# `#include <cstdint>` upstream and fail on some newer host toolchains -- the
# same pre-existing issue that blocks a native build of the full "pcf"
# executable. Build via the Docker `checks` stage (pinned toolchain) if the
# native build hits it here.

include(GoogleTest)

set(NF_TARGET pcf_unit_tests)

add_executable(${NF_TARGET}
  main.cpp
  test_guarded.cpp
  test_qos_context.cpp
  test_app_session_storage_memory.cpp
  test_app_session.cpp
  test_qos_processing.cpp
)

## Common modules (re-included with NF_TARGET=pcf_unit_tests so their
## target_sources(${NF_TARGET} ...) calls attach to THIS target instead of
## the "pcf" executable). USED_PCF_MODEL_SRC_FILES / USED_COMMON_MODEL_SRC_FILES /
## USED_SMF_MODEL_SRC_FILES and PACKAGE_VERSION / PACKAGE_BUGREPORT are already
## populated/defined by the time this subdirectory is processed
## (../../oai_pcf/CMakeLists.txt runs first).
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/common/common.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger/logger.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/config/config.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils/utils.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/pcf/pcf_model.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/common_model/common_model.cmake)
# PCF's SmPolicyContextData/SmPolicyUpdateContextData reference SMF model types
# (DnnSelectionMode, VplmnQos) directly; the real "pcf" executable gets these
# transitively via used_common_files.cmake's own include(smf_model.cmake).
# Re-included explicitly here for the same reason as the includes above.
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/smf/smf_model.cmake)

target_link_libraries(${NF_TARGET}
  PCF
  gtest gtest_main
  boost_system boost_thread
  ssl crypto
  fmt spdlog
  yaml-cpp
  pthread m rt dl
)

gtest_discover_tests(${NF_TARGET} PROPERTIES LABELS "unit")
