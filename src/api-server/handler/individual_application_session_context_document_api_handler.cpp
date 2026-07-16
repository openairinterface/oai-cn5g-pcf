/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "individual_application_session_context_document_api_handler.h"
#include "ProblemDetails.h"
#include "AppSessionContext.h"

namespace oai::pcf::api {

using namespace oai::_3gpp::model;
using namespace oai::_3gpp::model;
using namespace oai::common::sbi;
using namespace oai::pcf::app::policy_auth;

api_response
individual_application_session_context_document_api_handler::delete_app_session(
    const std::string& app_session_id,
    const EventsSubscReqData& events_subsc_req_data) {
  api_response response;
  ProblemDetails problem_details;
  std::string problem_description;
  nlohmann::json json_data;
  uint16_t http_code;

  // TODO [QOS-SUB] events_subsc_req_data (subscription to the termination
  // EventsNotification) is not handled yet; AF termination notifications land
  // in Phase 3 [TS 29.514 §4.2.4].
  status_code res = m_pa_service->delete_app_session_handler(
      app_session_id, problem_description);

  switch (res) {
    case status_code::OK:
      // 3GPP TS 29.514 §4.2.4: successful termination returns 204 No Content.
      response.status_code = http_status_code::NO_CONTENT;
      return response;
    case status_code::NOT_FOUND:
      problem_details.setCause("CONTEXT_NOT_FOUND");
      http_code = http_status_code::NOT_FOUND;
      break;
    default:
      problem_details.setCause("INTERNAL_ERROR");
      http_code = http_status_code::INTERNAL_SERVER_ERROR;
  }

  problem_details.setDetail(problem_description);
  to_json(json_data, problem_details);
  response.headers.add<Pistache::Http::Header::ContentType>(
      Pistache::Http::Mime::MediaType(std::string("application/problem+json")));
  response.body        = json_data.dump();
  response.status_code = http_code;
  return response;
}

api_response
individual_application_session_context_document_api_handler::get_app_session(
    const std::string& app_session_id) {
  api_response response;
  ProblemDetails problem_details;
  std::string problem_description;
  std::string content_type = "application/problem+json";
  nlohmann::json json_data;
  uint16_t http_code;

  AppSessionContext app_session_context;
  status_code res = m_pa_service->get_app_session_handler(
      app_session_id, app_session_context, problem_description);

  switch (res) {
    case status_code::OK:
      // 3GPP TS 29.514 §4.2.5.1: return the AppSessionContext representation.
      content_type = "application/json";
      http_code    = http_status_code::OK;
      break;
    case status_code::NOT_FOUND:
      problem_details.setCause("CONTEXT_NOT_FOUND");
      http_code = http_status_code::NOT_FOUND;
      break;
    default:
      problem_details.setCause("INTERNAL_ERROR");
      http_code = http_status_code::INTERNAL_SERVER_ERROR;
  }

  if (res == status_code::OK) {
    to_json(json_data, app_session_context);
  } else {
    problem_details.setDetail(problem_description);
    to_json(json_data, problem_details);
  }

  response.headers.add<Pistache::Http::Header::ContentType>(
      Pistache::Http::Mime::MediaType(content_type));
  response.body        = json_data.dump();
  response.status_code = http_code;
  return response;
}

api_response
individual_application_session_context_document_api_handler::mod_app_session(
    const std::string& app_session_id,
    const AppSessionContextUpdateDataPatch&
        app_session_context_update_data_patch) {
  api_response response;
  ProblemDetails problem_details;
  std::string problem_description;
  std::string content_type = "application/problem+json";
  nlohmann::json json_data;
  uint16_t http_code;

  AppSessionContext app_session_context;
  status_code res = m_pa_service->mod_app_session_handler(
      app_session_id, app_session_context_update_data_patch,
      app_session_context, problem_description);

  problem_details.setDetail(problem_description);

  switch (res) {
    case status_code::OK:
      content_type = "application/json";
      http_code    = http_status_code::OK;
      break;
    // The handler returns a machine-readable 3GPP cause in problem_description;
    // surface it with the matching HTTP status [TS 29.514 §4.2.3.2,
    // TS 29.571 §5.2.7].
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

  if (res == status_code::OK) {
    to_json(json_data, app_session_context);
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