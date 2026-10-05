/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "association_index.hpp"

using namespace oai::pcf::app::sm_policy;

namespace {

// Absent and empty AF/SMF attributes both mean "not provided".
std::string provided(const std::optional<std::string>& value) {
  return value.value_or("");
}

void erase_from(
    std::unordered_map<std::string, std::unordered_set<std::string>>& by_key,
    const std::string& key, const std::string& association_id) {
  if (key.empty()) return;
  auto it = by_key.find(key);
  if (it == by_key.end()) return;
  it->second.erase(association_id);
  if (it->second.empty()) by_key.erase(it);
}

}  // namespace

association_index::binding_keys association_index::keys_of(
    const oai::_3gpp::model::SmPolicyContextData& context) {
  // unsetIpv4Address() only clears the "is set" flag, so check it rather than
  // trusting getIpv4Address().
  return {
      context.ipv4AddressIsSet() ? context.getIpv4Address() : "",
      context.getSupi(), context.getDnn()};
}

void association_index::upsert(
    const std::string& association_id, const binding_keys& keys) {
  auto s = m_state.write();
  erase_record(*s, association_id);

  s->records[association_id] = {keys, s->next_sequence++};
  if (!keys.ipv4.empty()) s->by_ipv4[keys.ipv4].insert(association_id);
  if (!keys.supi.empty()) s->by_supi[keys.supi].insert(association_id);
}

void association_index::remove(const std::string& association_id) {
  auto s = m_state.write();
  erase_record(*s, association_id);
}

void association_index::erase_record(
    state& s, const std::string& association_id) {
  auto it = s.records.find(association_id);
  if (it == s.records.end()) return;
  erase_from(s.by_ipv4, it->second.keys.ipv4, association_id);
  erase_from(s.by_supi, it->second.keys.supi, association_id);
  s.records.erase(it);
}

std::optional<std::string> association_index::find(
    const std::optional<std::string>& ipv4,
    const std::optional<std::string>& supi,
    const std::optional<std::string>& dnn) const {
  const std::string want_ipv4 = provided(ipv4);
  const std::string want_supi = provided(supi);
  const std::string want_dnn  = provided(dnn);

  auto s = m_state.read();

  const std::unordered_map<std::string, id_set>* by_key = nullptr;
  const std::string* key                                = nullptr;
  if (!want_ipv4.empty()) {
    by_key = &s->by_ipv4;
    key    = &want_ipv4;
  } else if (!want_supi.empty()) {
    by_key = &s->by_supi;
    key    = &want_supi;
  } else {
    return std::nullopt;
  }

  auto candidates = by_key->find(*key);
  if (candidates == by_key->end()) return std::nullopt;

  const auto matches = [&](const binding_keys& k) {
    return (want_ipv4.empty() || k.ipv4 == want_ipv4) &&
           (want_supi.empty() || k.supi == want_supi) &&
           (want_dnn.empty() || k.dnn == want_dnn);
  };

  std::optional<std::string> best;
  std::uint64_t best_sequence = 0;
  for (const auto& id : candidates->second) {
    const record& r = s->records.at(id);
    if (!matches(r.keys)) continue;
    if (!best || r.sequence > best_sequence) {
      best          = id;
      best_sequence = r.sequence;
    }
  }
  return best;
}
