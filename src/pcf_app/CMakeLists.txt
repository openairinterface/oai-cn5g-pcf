################################################################################
# SPDX-License-Identifier: LicenseRef-CSSL-1.0
################################################################################
include_directories(${SRC_TOP_DIR}/common)
include_directories(${SRC_TOP_DIR}/common/msg)
include_directories(${SRC_TOP_DIR}/common/utils)
include_directories(${SRC_TOP_DIR}/itti)
include_directories(${SRC_TOP_DIR}/pcf)
include_directories(${SRC_TOP_DIR}/api-server/api)
include_directories(${SRC_TOP_DIR}/api-server/impl)
include_directories(${SRC_TOP_DIR}/api-server/)
include_directories(${SRC_TOP_DIR}/pcf_app/sm_policy/)
include_directories(${SRC_TOP_DIR}/pcf_app/policy_auth/)
include_directories(${SRC_TOP_DIR}/api-server/provisioning_api/api)
include_directories(${SRC_TOP_DIR}/api-server/provisioning_api/impl)
include_directories(${SRC_TOP_DIR}/api-server/provisioning_api/handler)
include_directories(${SRC_TOP_DIR}/api-server/provisioning_api/model)

## Common modules
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/http/http.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/common/common.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils/utils.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger/logger.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/config/config.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/pcf_model.cmake)
include(${SRC_TOP_DIR}/common/utils/utils.cmake)

add_library (PCF STATIC
  pcf_config_types.cpp
  pcf_config.cpp
  operator_qos_policy_builder.cpp
  notify_failure_recovery_policy_builder.cpp
  pcf_app.cpp
  pcf_nrf.cpp
  pcf_profile.cpp
  pcf_event.cpp
  sm_policy_delta.cpp
  pcf_sm_policy_control.cpp
  task_manager.cpp
  sm_policy/individual_sm_association.cpp
  sm_policy/retry_drain_queue.cpp
  sm_policy/smf_notify_response_classifier.cpp
  sm_policy/policy_decision.cpp
  sm_policy/qos_session_authorization.cpp
  sm_policy/slice_policy_decision.cpp
  sm_policy/supi_policy_decision.cpp
  sm_policy/dnn_policy_decision.cpp
  sm_policy/policy_storage_yaml.cpp
  sm_policy/policy_storage_db.cpp
  sm_policy/policy_provisioning_file.cpp
  policy_auth/app_session.cpp
  policy_auth/qos_context.cpp
  policy_auth/pending_rollback_tracker.cpp
  policy_auth/rollback_delta.cpp
  policy_auth/rollback_orchestration.cpp
  policy_auth/apply_decision_with_retry.cpp
  policy_auth/af_notify.cpp
  policy_auth/app_session_storage.cpp
  policy_auth/qos_reference_loader.cpp
  pcf_policy_authorization.cpp
  sm_policy/database/mysql_db.cpp
  )

################################################################################
# Unit tests (GoogleTest + CTest). Opt-in: off by default, enabled with
# -DBUILD_TESTING=ON. Not part of the default build; the runtime "pcf"
# executable does not depend on this target. Test registration is enabled at
# the PCF build root so root-level ctest sees these tests.
################################################################################
if(BUILD_TESTING)
  ADD_SUBDIRECTORY(${CMAKE_CURRENT_SOURCE_DIR}/test ${CMAKE_CURRENT_BINARY_DIR}/test)
endif()
