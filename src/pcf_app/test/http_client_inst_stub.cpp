/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// pcf_sm_policy_control.cpp and pcf_nrf.cpp both `extern` this global and
// reference it in code paths that are always linked in (e.g. pcf_smpc's
// constructor default-binds http_send_fn to it), even though every test here
// injects its own fake http_send_fn/http_client and never actually
// dereferences it. The real definition lives in oai_pcf/main.cpp, which
// isn't part of this executable (this target has its own gtest main.cpp
// instead) -- this stub supplies just the storage so the link succeeds.
#include "http_client.hpp"

#include <memory>

std::shared_ptr<oai::http::http_client> http_client_inst = nullptr;
