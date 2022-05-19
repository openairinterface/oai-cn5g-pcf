/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

/*! \file test_rest_client.cpp
 \brief
 \author  Stefan Spettel
 \company Openairinterface Software Allianse
 \date 2022
 \email: stefan.spettel@eurecom.fr
 */

#include "test_rest_client.hpp"
#include "logger.hpp"

#include <memory>
#include <curl/curl.h>

using namespace oai::pcf::test;

static std::size_t callback(
    const char* in, std::size_t size, std::size_t num, std::string* out) {
  const std::size_t totalBytes(size * num);
  out->append(in, totalBytes);
  return totalBytes;
}

long TestRestClient::doRequest(
    std::string& response, std::string& response_headers) {
  CURL* curl = curl_easy_init();
  if (curl) {
    if (get_method) {
      curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    } else if (post_method) {
      curl_easy_setopt(curl, CURLOPT_HTTPPOST, 1);
    } else {
      curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, custom_method);
    }

    char* body_char            = &body[0];
    struct curl_slist* headers = NULL;
    if (use_json) {
      std::string content_type = "Content-Type: application/json";
      headers = curl_slist_append(headers, content_type.c_str());
      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

      curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.length());
      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body_char);
    }
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);

    // response information.
    std::unique_ptr<std::string> http_data(new std::string());
    std::unique_ptr<std::string> http_header_data(new std::string());
    long http_code = 0;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, http_data.get());
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, http_header_data.get());

    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
      std::cout << fmt::format("Received curl error: {}\n");
      curl_slist_free_all(headers);
      curl_easy_cleanup(curl);
      return -1;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    response         = *http_data;
    response_headers = *http_header_data;

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return http_code;
  }
}

long TestRestClient::sendPost(
    std::string url, std::string body, std::string& response,
    std::string& headers) {
  post_method = true;
  use_json    = true;
  this->url   = url;
  this->body  = body;
  return doRequest(response, headers);
}
long TestRestClient::sendGet(
    std::string url, std::string body, std::string& response,
    std::string& headers) {
  get_method = true;
  this->url  = url;
  this->body = body;
  return doRequest(response, headers);
}

long TestRestClient::sendDelete(
    std::string url, std::string body, std::string& response,
    std::string& headers) {
  this->custom_method = "DELETE";
  this->url           = url;
  this->body          = body;
  return doRequest(response, headers);
}
