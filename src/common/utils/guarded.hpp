/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_GUARDED_HPP_SEEN
#define FILE_GUARDED_HPP_SEEN

#include <mutex>
#include <shared_mutex>
#include <utility>

namespace oai::utils {

/**
 * @brief A value bundled with the mutex that guards it.
 *
 * Access to the wrapped value is only possible through an RAII handle that holds
 * the appropriate lock, so "the data is only touched under its lock" becomes a
 * compile-time property rather than a convention. This is the fine-grained
 * locking primitive used by the app-session aspects.
 *
 * Equivalent in spirit to boost::synchronized_value and the C++ concurrency-TS
 * synchronized_value (N4033); kept in-house to avoid depending on Boost.Thread.
 * See C++ Core Guidelines (RAII locks).
 *
 * @tparam T     the guarded value type (must be default-constructible for the
 *               default constructor)
 * @tparam Mutex a SharedMutex type (defaults to std::shared_mutex so reads can
 *               proceed concurrently)
 */
template <typename T, typename Mutex = std::shared_mutex>
class guarded {
 public:
  guarded() : m_value() {}
  explicit guarded(T value) : m_value(std::move(value)) {}

  guarded(const guarded&)            = delete;
  guarded& operator=(const guarded&) = delete;

  /** Exclusive (read/write) access; holds a unique lock for its lifetime. */
  class write_handle {
   public:
    write_handle(Mutex& mutex, T& value) : m_lock(mutex), m_ptr(&value) {}
    T* operator->() const noexcept { return m_ptr; }
    T& operator*() const noexcept { return *m_ptr; }

   private:
    std::unique_lock<Mutex> m_lock;
    T* m_ptr;
  };

  /** Shared (read-only) access; holds a shared lock for its lifetime. */
  class read_handle {
   public:
    read_handle(Mutex& mutex, const T& value) : m_lock(mutex), m_ptr(&value) {}
    const T* operator->() const noexcept { return m_ptr; }
    const T& operator*() const noexcept { return *m_ptr; }

   private:
    std::shared_lock<Mutex> m_lock;
    const T* m_ptr;
  };

  [[nodiscard]] write_handle write() { return write_handle(m_mutex, m_value); }
  [[nodiscard]] read_handle read() const {
    return read_handle(m_mutex, m_value);
  }

 private:
  mutable Mutex m_mutex;
  T m_value;
};

}  // namespace oai::utils

#endif  // FILE_GUARDED_HPP_SEEN
