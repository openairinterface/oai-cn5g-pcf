/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "application_sessions_collection_api_handler.h"
#include "ProblemDetails.h"
#include "logger.hpp"
#include "api_defs.h"

namespace oai::pcf::api {

using namespace oai::_3gpp::model;
using namespace oai::_3gpp::model;
using namespace oai::common::sbi;
using namespace oai::pcf::app::policy_auth;

api_response application_sessions_collection_api_handler::post_app_sessions(
    const AppSessionContext& app_session_context) {
  api_response response;

  ProblemDetails problem_details;
  std::string problem_description;
  std::string content_type = "application/problem+json";
  std::string location;
  std::string app_session_id;
  nlohmann::json json_data;
  uint16_t http_code;

  status_code res = m_pa_service->post_app_sessions_handler(
      app_session_context, app_session_id, problem_description);

  problem_details.setDetail(problem_description);

  switch (res) {
    case status_code::CREATED:
      content_type = "application/json";
      location  = m_address + app_sessions::get_route() + "/" + app_session_id;
      http_code = http_status_code::CREATED;
      break;
    // The handler returns a machine-readable 3GPP cause (e.g.
    // REQUESTED_SERVICE_NOT_AUTHORIZED, INVALID_SERVICE_INFORMATION) in
    // problem_description; surface it as the ProblemDetails cause with the
    // matching HTTP status [TS 29.514 §4.2.2.2, TS 29.571 §5.2.7].
    case status_code::FORBIDDEN:
      problem_details.setCause(problem_description);
      http_code = http_status_code::FORBIDDEN;
      break;
    case status_code::BAD_REQUEST:
      problem_details.setCause(problem_description);
      http_code = http_status_code::BAD_REQUEST;
      break;
    case status_code::NOT_FOUND:
      problem_details.setCause(problem_description);
      http_code = http_status_code::NOT_FOUND;
      break;
    default:
      problem_details.setCause("INTERNAL_ERROR");
      http_code = http_status_code::INTERNAL_SERVER_ERROR;
  }

  if (http_code == http_status_code::CREATED) {
    // 3GPP TS 29.514 §4.2.2.2: 201 Created with the AppSessionContext
    // representation in the body and a Location header pointing at the newly
    // created Individual Application Session Context resource. The response
    // carries ascRespData with the negotiated supported features (§4.2.2.2,
    // §5.8).
    AppSessionContext created = app_session_context;
    created.setAscRespData(
        oai::pcf::app::pcf_policy_authorization::build_response_data(
            created.getAscReqData()));
    to_json(json_data, created);
    response.headers.add<Pistache::Http::Header::Location>(location);
    Logger::pcf_app().debug(fmt::format("Created app session; Location: {}", location));
  } else {
    to_json(json_data, problem_details);
  }

  response.headers.add<Pistache::Http::Header::ContentType>(
      Pistache::Http::Mime::MediaType(content_type));
  response.body        = json_data.dump();
  response.status_code = http_code;
  return response;
}

}  // namespace oai::pcf::api