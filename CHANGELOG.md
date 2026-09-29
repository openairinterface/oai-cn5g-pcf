<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# RELEASE NOTES:

## Unreleased

* Features
  - N5 Policy Authorization service (`Npcf_PolicyAuthorization`, 3GPP TS 29.514):
  full application session lifecycle over `POST`, `GET`, `PATCH` and `DELETE`
  of `/app-sessions`, including RFC 7396 JSON Merge Patch semantics on
  modification
  - QoS derivation from AF service information per 3GPP TS 29.513 clause 7.3.3:
  `QosData`, `QosCharacteristics` and PCC rules with service data flow filters,
  derived from MediaComponent bandwidth, latency and priority attributes or
  taken from an operator-preconfigured `qosReference` set
  - QoS authorization against operator policy and the subscribed Session-AMBR,
  configurable through the new `pcf.qos_authorization` block
  - N7 SM Policy Association UpdateNotify (`Npcf_SMPolicyControl_UpdateNotify`,
  3GPP TS 29.512 clause 4.2.3.2): AF-derived QoS is now provisioned to the SMF
  - SMF notify-failure recovery: response classification per 3GPP TS 29.512
  table 5.7.3-2, bounded retry with exponential backoff, and compensating
  rollback on a confirmed permanent rejection; bounds configurable through the
  new `pcf.notify_failure_recovery` block
  - Operator-preconfigured QoS reference sets loaded from
  `pcf.local_policy.qos_reference_path`
* Tests
  - GoogleTest/CTest unit-test infrastructure for the PCF application layer,
  with 247 cases across 20 suites; build with `build_pcf --tests` or the
  `checks` stage of `docker/Dockerfile.pcf.ubuntu`
  - `ci-scripts/tests/pa_app_session_tests.py`: end-to-end N5 application
  session lifecycle test against a live PCF

## v2.2.1 -- April 2026

* Build and CI fixes for RHEL 9 based environments
  - Switch container registry usage to `registry.redhat.io`
  - Replace RHEL `yq` image pull with direct GitHub download flow
  - Pass the EPEL URL as a parameter in Jenkins RHEL jobs
* Licensing and documentation
  - Re-license the project from OAI Public License v1.1 to CSSL v1.0
  - Re-license documentation under CC-BY-4.0 and orchestration/CI assets under MIT
  - Add `NOTICE`, `LICENSES/`, and related contribution/documentation updates

## v2.2.0 -- December 2025

* Features
  - PCF Provisioning API: Introduced support for provisioning Policy Decisions,
  PCC Rules, QoS Data, and Traffic Control Data.
* Fixes
  - HTTP/2 PUT request for each endpoint
  - LTTNG build issue
* Future Fixes
  - Add support for Ubuntu 24.04
  - Add support for RHEL 10, update container images to UBI 10
  - Fix build issue in non-containerized environment

## v2.1.0 -- August 2024

* Features
  - Add possibility to read QoS values from file
* Fixes
  - Fix HTTP/2 server shutdown
  - Use new FlowDirection fix
* Tech Debt
  - Stopping support for RHEL8/Rocky8 in favor of RHEL9/Rocky9
  - HTTP client cpr library refactoring effort
  - Resynch PCF with common source git-submodule and use utils from there

## v2.0.0 -- December 2023

* Features
  - Support YAML configuration file
    * Yaml validation default value
  - Add support for traffic steering rules
  - Add support for redirection rules
* Fixes
  - Handling boolean values in yaml parsing for policies
* Tech debt
  - Updated common models to 3GPP TS 29.571 Release 16.13.0 and moved them to the shared common submodule
  - Updated PCF models to Release 16.17.0 and moved them to the shared common submodule
  - Switching to clang-format-12
  - Published image on Docker-Hub is using now Ubuntu-22 as base image
    * Ubuntu-18 is no longer supported

## v1.5.1 -- May 2023

* Add HTTP/2 support
* Code Refactoring for:
  * Logging mechanism (runtime log level selection)
  * Installation / build scripts
  * Continuous Integration scripts
* Published image on Docker-Hub is using now Ubuntu-20 as base image
  * We will soon obsolete the build system for Ubuntu18.04

## v1.5.0 -- January 2023

* Initial release
* NRF registration
* Add Npcf_SMPolicyControl API Create, Update, Delete and Get procedures
* Add file based policy provisioning
* Add policy decision feature based on SUPI, DNN, Slice and default policy
* Fixed docker exit by catching SIGTERM
* release mode does not use libasan anymore --> allocation of 20T virtual memory is no longer done

