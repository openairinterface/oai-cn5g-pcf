/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "SmPolicyContextData.h"
#include "guarded.hpp"

namespace oai::pcf::app::sm_policy {

/**
 * @brief Session-binding index of the live SM policy associations.
 *
 * Session binding associates AF session information with one and only one PDU
 * session, comparing the UE address, the UE identity (SUPI) and the DNN the AF
 * provides with those of the PDU session; all parameters shall match, if
 * provided [TS 23.503 §6.1.3.2.2, TS 29.513 §6.2, TS 29.514 §4.2.2.2 NOTE 7].
 *
 * The index keeps, per association id, the keys it was indexed under. That
 * lets find() check every provided parameter, lets one key (a SUPI with
 * several PDU sessions, a private IPv4 address reused on another DNN
 * [TS 23.503 §6.1.1.2.1]) map to several associations, and lets remove() drop
 * exactly what the association contributed, whatever its context looks like
 * by then [TS 29.513 §5.2.3.1 step 14].
 *
 * An empty string means "not provided", both in the indexed keys (an
 * IPv6-only PDU session has no IPv4 address) and in lookups (Policy
 * Authorization passes absent AF attributes as "").
 *
 * IPv6 prefixes, S-NSSAI and IP domain are not indexed yet
 * [TS 29.513 §6.2 a), d), e)].
 *
 * All state sits behind one lock, so lookups never race with updates.
 */
class association_index {
 public:
  struct binding_keys {
    std::string ipv4;
    std::string supi;
    std::string dnn;
  };

  /** The keys an association's SM policy context provides for binding. */
  [[nodiscard]] static binding_keys keys_of(
      const oai::_3gpp::model::SmPolicyContextData& context);

  /**
   * Indexes association_id under keys. An id that is already indexed is
   * re-indexed: the keys it had before no longer find it.
   */
  void upsert(const std::string& association_id, const binding_keys& keys);

  /** Removes association_id and all its keys. Unknown ids are ignored. */
  void remove(const std::string& association_id);

  /**
   * Finds the association whose keys match every provided (non-empty)
   * parameter. The IPv4 address or, failing that, the SUPI selects the
   * candidates; a DNN alone does not identify a PDU session. When several
   * associations match, the most recently indexed one is returned.
   */
  [[nodiscard]] std::optional<std::string> find(
      const std::optional<std::string>& ipv4,
      const std::optional<std::string>& supi,
      const std::optional<std::string>& dnn) const;

 private:
  using id_set = std::unordered_set<std::string>;

  struct record {
    binding_keys keys;
    std::uint64_t sequence;
  };

  struct state {
    std::unordered_map<std::string, record> records;
    std::unordered_map<std::string, id_set> by_ipv4;
    std::unordered_map<std::string, id_set> by_supi;
    std::uint64_t next_sequence = 0;
  };

  static void erase_record(state& s, const std::string& association_id);

  oai::utils::guarded<state> m_state;
};

}  // namespace oai::pcf::app::sm_policy
