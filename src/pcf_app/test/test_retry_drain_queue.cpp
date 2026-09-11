/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

// Tests for retry_drain_queue: the SM-side bounded retry-drain queue for
// temporary/ambiguous SMF notify outcomes.
// due_entries()/report_attempt() take an explicit `now`, so backoff/TTL
// boundaries are tested deterministically by varying that argument instead
// of sleeping.

#include <gtest/gtest.h>

#include <chrono>
#include <string>

#include "sm_policy/retry_drain_queue.hpp"

using oai::pcf::app::sm_policy::drain_result;
using oai::pcf::app::sm_policy::retry_drain_queue;

namespace {
using namespace std::chrono_literals;
}  // namespace

TEST(RetryDrainQueue, FreshlyEnqueuedEntryIsNotImmediatelyDue) {
  retry_drain_queue queue(30s, 100, 3, 500ms);
  const auto t0 = std::chrono::steady_clock::now();
  queue.enqueue("assoc-1", 1);

  // next_eligible_at = enqueue time + backoff_initial -- not due at t0.
  EXPECT_TRUE(queue.due_entries(t0).empty());
  EXPECT_EQ(queue.due_entries(t0 + 600ms).size(), 1u);
}

TEST(RetryDrainQueue, DueEntryContainsTheEnqueuedKey) {
  retry_drain_queue queue(30s, 100, 3, 500ms);
  const auto t0 = std::chrono::steady_clock::now();
  queue.enqueue("assoc-1", 42);

  const auto due = queue.due_entries(t0 + 600ms);
  ASSERT_EQ(due.size(), 1u);
  EXPECT_EQ(due[0].first, "assoc-1");
  EXPECT_EQ(due[0].second, 42u);
}

TEST(RetryDrainQueue, ReportAttemptOnUnknownKeyReturnsNotFound) {
  retry_drain_queue queue(30s, 100, 3, 500ms);
  const auto now = std::chrono::steady_clock::now();

  EXPECT_EQ(
      queue.report_attempt("assoc-1", 1, /*success=*/true, now),
      drain_result::not_found);
}

TEST(RetryDrainQueue, ReportAttemptSuccessRemovesTheEntry) {
  retry_drain_queue queue(30s, 100, 3, 500ms);
  const auto now = std::chrono::steady_clock::now();
  queue.enqueue("assoc-1", 1);

  EXPECT_EQ(
      queue.report_attempt("assoc-1", 1, /*success=*/true, now),
      drain_result::succeeded);
  // Removed: a second report for the same key is no longer tracked.
  EXPECT_EQ(
      queue.report_attempt("assoc-1", 1, /*success=*/true, now),
      drain_result::not_found);
}

TEST(RetryDrainQueue, ReportAttemptFailureReschedulesWithBackoff) {
  retry_drain_queue queue(30s, 100, /*max_retries=*/3, 100ms);
  const auto t0 = std::chrono::steady_clock::now();
  queue.enqueue("assoc-1", 1);

  EXPECT_EQ(
      queue.report_attempt("assoc-1", 1, /*success=*/false, t0),
      drain_result::rescheduled);

  // Not due again immediately after the failed attempt...
  EXPECT_TRUE(queue.due_entries(t0).empty());
  // ...but is due again once its (backed-off) next-eligible time passes.
  EXPECT_EQ(queue.due_entries(t0 + 1s).size(), 1u);
}

TEST(RetryDrainQueue, ReportAttemptExhaustsAfterMaxRetries) {
  retry_drain_queue queue(30s, 100, /*max_retries=*/2, 10ms);
  const auto now = std::chrono::steady_clock::now();
  queue.enqueue("assoc-1", 1);

  EXPECT_EQ(
      queue.report_attempt("assoc-1", 1, /*success=*/false, now),
      drain_result::rescheduled);  // attempt 1/2
  EXPECT_EQ(
      queue.report_attempt("assoc-1", 1, /*success=*/false, now),
      drain_result::exhausted);  // attempt 2/2 -- log-only escalation

  // Exhaustion removes the entry -- nothing left to report against.
  EXPECT_EQ(
      queue.report_attempt("assoc-1", 1, /*success=*/false, now),
      drain_result::not_found);
}

TEST(RetryDrainQueue, EnqueueAtCapacityDropsTheNewEntry) {
  retry_drain_queue queue(30s, /*max_entries=*/1, 3, 500ms);
  const auto now = std::chrono::steady_clock::now();
  queue.enqueue("assoc-1", 1);
  queue.enqueue("assoc-2", 1);  // over cap -- dropped

  EXPECT_EQ(queue.due_entries(now + 600ms).size(), 1u);
  EXPECT_EQ(
      queue.report_attempt("assoc-2", 1, /*success=*/true, now),
      drain_result::not_found);
}

// enqueue() is idempotent for an already-queued key: it must NOT reset
// backoff/attempt progress. Verified indirectly -- if it wrongly reset the
// attempt count, the second failure below would reschedule instead of
// exhausting.
TEST(RetryDrainQueue, ReEnqueueingAnAlreadyQueuedKeyDoesNotResetProgress) {
  retry_drain_queue queue(30s, 100, /*max_retries=*/2, 10ms);
  const auto now = std::chrono::steady_clock::now();
  queue.enqueue("assoc-1", 1);

  EXPECT_EQ(
      queue.report_attempt("assoc-1", 1, /*success=*/false, now),
      drain_result::rescheduled);  // attempt 1/2

  queue.enqueue("assoc-1", 1);  // no-op: already queued

  EXPECT_EQ(
      queue.report_attempt("assoc-1", 1, /*success=*/false, now),
      drain_result::exhausted);  // attempt 2/2, not reset back to 1/2
}

TEST(RetryDrainQueue, SweepExpiredRemovesEntriesOlderThanTtl) {
  retry_drain_queue queue(/*ttl=*/10s, 100, 3, 500ms);
  const auto approx_enqueue_time = std::chrono::steady_clock::now();
  queue.enqueue("assoc-1", 1);

  queue.sweep_expired(approx_enqueue_time + 20s);

  EXPECT_EQ(
      queue.report_attempt("assoc-1", 1, /*success=*/true, approx_enqueue_time),
      drain_result::not_found);
}

TEST(RetryDrainQueue, SweepExpiredLeavesFreshEntriesAlone) {
  retry_drain_queue queue(/*ttl=*/10s, 100, 3, 500ms);
  const auto approx_enqueue_time = std::chrono::steady_clock::now();
  queue.enqueue("assoc-1", 1);

  queue.sweep_expired(approx_enqueue_time + 1s);

  EXPECT_EQ(queue.due_entries(approx_enqueue_time + 600ms).size(), 1u);
}
