/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_APP_SESSION_SEEN
#define FILE_APP_SESSION_SEEN

#include "AppSessionContext.h"
#include "AppSessionContextReqData.h"

namespace oai::pcf::app::policy_auth {

class app_session {
 public:
  explicit app_session(
      const oai::_3gpp::model::AppSessionContextReqData& context,
      const oai::_3gpp::model::SmPolicyDecision& decision,
      const std::string& id)
      : m_decision(decision) {
    m_context = context;
    // TODO [PAS] add association id to be used during update
    m_id = id;
  }

  virtual ~app_session() = default;

  [[nodiscard]] virtual const oai::_3gpp::model::AppSessionContextReqData&
  get_app_session_context() const;

  [[nodiscard]] virtual void set_app_session_context(
      oai::_3gpp::model::AppSessionContextReqData& context);

  [[nodiscard]] virtual std::string get_id() const;

 private:
  // TODO: create a struct only for attributes that need to be stored?
  oai::_3gpp::model::AppSessionContextReqData m_context;
  // TODO: create a struct only for attributes that need to be stored?
  oai::_3gpp::model::SmPolicyDecision m_decision;
  // attributes that need to be stored
  // reference session
  // reference pcc rules
  std::string m_id;
};

/**
 * Handlers for processing different App Session operation procedures
 *
 * 3GPP TS 29.514 4.2.x
 */

// TODO: Restore handle_service_function_chaining and
// handle_service_function_chaining_update once AfSfcRequirement and
// AppSessionContextReqData::afSfcReq are regenerated in the new model.
// Ref: 3GPP TS 29.514 §4.2.2.8 N6-LAN traffic steering (SFC).

//   oai::pcf::app::policy_auth::status_code handle_traffic_routing(
//       oai::_3gpp::model::SmPolicyContextData& orig_context,
//       const oai::_3gpp::model::SmPolicyUpdateContextData& update,
//       std::string& problem_details);

oai::pcf::app::policy_auth::handler_result authorize_service_info(
    const oai::_3gpp::model::AppSessionContextReqData& reqData);

oai::pcf::app::policy_auth::handler_result validate_and_merge_decision(
    const oai::_3gpp::model::SmPolicyDecision& request_decision,
    oai::_3gpp::model::SmPolicyDecision& current_decision, bool update = false);

}  // namespace oai::pcf::app::policy_auth

#endif  // FILE_APP_SESSION_SEEN
