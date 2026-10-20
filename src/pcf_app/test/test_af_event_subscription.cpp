/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// EventsSubscReqData.events[].event is the Npcf_PolicyAuthorization AfEvent
// (TS 29.514 §5.6.3.3). It used to be parsed with the TS 29.517 AfEvent of the
// same name, so every evSubsc a NEF sends (SUCCESSFUL_/FAILED_RESOURCES_
// ALLOCATION) was rejected and app-session creation failed.

#include <gtest/gtest.h>

#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>

#include "EventsSubscReqData.h"

using oai::_3gpp::model::EventsSubscReqData;

TEST(AfEventSubscription, ParsesTheEvSubscANefSends) {
  const auto j = nlohmann::json::parse(R"({
    "notifUri": "http://oai-nef:8080/nef-notify/v1/notify/1",
    "events": [{"event": "FAILED_RESOURCES_ALLOCATION"},
               {"event": "QOS_NOTIF"},
               {"event": "SUCCESSFUL_RESOURCES_ALLOCATION"}]})");
  EventsSubscReqData ev;
  ASSERT_NO_THROW(j.get_to(ev));
  ASSERT_EQ(ev.getEvents().size(), 3u);
  nlohmann::json back;
  to_json(back, ev);
  EXPECT_EQ(back["events"], j["events"]);
}

TEST(AfEventSubscription, RoundTripsEveryTs29514Value) {
  for (const char* v :
       {"ACCESS_TYPE_CHANGE",
        "ANI_REPORT",
        "APP_DETECTION",
        "CHARGING_CORRELATION",
        "EPS_FALLBACK",
        "FAILED_QOS_UPDATE",
        "FAILED_RESOURCES_ALLOCATION",
        "OUT_OF_CREDIT",
        "PDU_SESSION_STATUS",
        "PLMN_CHG",
        "QOS_MONITORING",
        "QOS_NOTIF",
        "RAN_NAS_CAUSE",
        "REALLOCATION_OF_CREDIT",
        "SAT_CATEGORY_CHG",
        "SUCCESSFUL_QOS_UPDATE",
        "SUCCESSFUL_RESOURCES_ALLOCATION",
        "TSN_BRIDGE_INFO",
        "UP_PATH_CHG_FAILURE",
        "USAGE_REPORT"}) {
    const auto j = nlohmann::json{{"events", {{{"event", v}}}}};
    EventsSubscReqData ev;
    ASSERT_NO_THROW(j.get_to(ev)) << v;
    nlohmann::json back;
    to_json(back, ev);
    EXPECT_EQ(back["events"][0]["event"], v);
  }
}

TEST(AfEventSubscription, RejectsANaEventExposureValue) {
  // UE_MOBILITY belongs to the TS 29.517 AfEvent, not to this one.
  const auto j = nlohmann::json{{"events", {{{"event", "UE_MOBILITY"}}}}};
  EventsSubscReqData ev;
  EXPECT_THROW(j.get_to(ev), std::invalid_argument);
}
