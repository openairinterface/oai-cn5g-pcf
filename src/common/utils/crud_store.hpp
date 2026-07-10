/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_CRUD_STORE_HPP_SEEN
#define FILE_CRUD_STORE_HPP_SEEN

#include <cstddef>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace oai::utils {

/**
 * @brief Generic string-keyed repository interface for shared_ptr<Value>.
 *
 * The common insert/find/find_all/remove contract shared by the Policy
 * Authorization stores (app-sessions, QoS references, and
 * AF-subscription / monitoring stores). Store-specific concerns that don't fit
 * a plain keyed CRUD -- id generation, secondary indexes -- are added by the
 * concrete store interface/implementation, not here.
 */
template <typename Value>
class crud_store {
 public:
  virtual ~crud_store() = default;

  virtual void insert(
      const std::string& id, std::shared_ptr<Value> value) = 0;

  /** @return the value, or nullptr if not found. */
  [[nodiscard]] virtual std::shared_ptr<Value> find(
      const std::string& id) const = 0;

  [[nodiscard]] virtual std::vector<std::shared_ptr<Value>> find_all() const = 0;

  virtual void remove(const std::string& id) = 0;
};

/**
 * @brief In-memory implementation of crud_store, written once and reused for
 * every store.
 *
 * Thread-safe via a single shared_mutex (concurrent reads, exclusive writes).
 * Concrete stores that need a secondary index override on_inserted/on_removed;
 * those hooks run with the write lock already held, so an implementation must
 * touch its index directly and MUST NOT re-lock (that would deadlock). A
 * subclass reads its index under a shared lock and may read m_entries directly
 * (both are protected).
 *
 * crud_store is a virtual base so a concrete store can inherit both this
 * implementation and an extended store interface without duplicating the
 * crud_store subobject.
 */
template <typename Value>
class crud_store_memory : public virtual crud_store<Value> {
 public:
  void insert(const std::string& id, std::shared_ptr<Value> value) override {
    if (!value) return;
    std::unique_lock lock(m_mutex);
    m_entries[id] = value;
    on_inserted(id, value);
  }

  [[nodiscard]] std::shared_ptr<Value> find(
      const std::string& id) const override {
    std::shared_lock lock(m_mutex);
    auto it = m_entries.find(id);
    return it == m_entries.end() ? nullptr : it->second;
  }

  [[nodiscard]] std::vector<std::shared_ptr<Value>> find_all() const override {
    std::shared_lock lock(m_mutex);
    std::vector<std::shared_ptr<Value>> out;
    out.reserve(m_entries.size());
    for (const auto& entry : m_entries) out.push_back(entry.second);
    return out;
  }

  void remove(const std::string& id) override {
    std::unique_lock lock(m_mutex);
    auto it = m_entries.find(id);
    if (it == m_entries.end()) return;
    std::shared_ptr<Value> value = it->second;
    m_entries.erase(it);
    on_removed(id, value);
  }

  [[nodiscard]] std::size_t size() const {
    std::shared_lock lock(m_mutex);
    return m_entries.size();
  }

 protected:
  /**
   * @brief Hooks for maintaining a secondary index. Called with m_mutex held
   * exclusively; implementations must not re-lock it.
   */
  virtual void on_inserted(
      const std::string& /*id*/, const std::shared_ptr<Value>& /*value*/) {}
  virtual void on_removed(
      const std::string& /*id*/, const std::shared_ptr<Value>& /*value*/) {}

  mutable std::shared_mutex m_mutex;
  std::unordered_map<std::string, std::shared_ptr<Value>> m_entries;
};

}  // namespace oai::utils

#endif  // FILE_CRUD_STORE_HPP_SEEN
