/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/def.h"

#include "event/job_queue.h"

#include <atomic>
#include <thread>
#include <vector>

TEST(job_queue, concurrent_producers_publish_every_job_once)
{
    static constexpr int producer_count = 4;
    static constexpr int jobs_per_producer = 4096;
    static constexpr int expected_jobs = producer_count * jobs_per_producer;

    job_queue<int> queue;
    std::atomic<int> producers_done {0};
    std::atomic<int> producer_failures {0};
    std::vector<std::thread> producers;
    producers.reserve(producer_count);

    for (int producer = 0; producer < producer_count; ++producer) {
        producers.emplace_back([producer, &queue, &producers_done, &producer_failures] {
            for (int job = 0; job < jobs_per_producer; ++job) {
                if (queue.insert_job(producer * jobs_per_producer + job) !=
                    job_queue_submit_result::ACCEPTED) {
                    producer_failures.fetch_add(1, std::memory_order_relaxed);
                    break;
                }
            }
            producers_done.fetch_add(1, std::memory_order_release);
        });
    }

    std::vector<bool> observed(expected_jobs, false);
    int observed_count = 0;
    while (producers_done.load(std::memory_order_acquire) != producer_count ||
           queue.has_pending()) {
        auto &jobs = queue.get_all();
        for (int job : jobs) {
            ASSERT_GE(job, 0);
            ASSERT_LT(job, expected_jobs);
            ASSERT_FALSE(observed[job]);
            observed[job] = true;
            ++observed_count;
        }
        jobs.clear();
        std::this_thread::yield();
    }

    for (std::thread &producer : producers) {
        producer.join();
    }

    EXPECT_EQ(0, producer_failures.load(std::memory_order_relaxed));
    EXPECT_EQ(expected_jobs, observed_count);
    EXPECT_FALSE(queue.has_pending());
}

TEST(job_queue, unpublished_reservation_does_not_stall_later_shutdown_job)
{
    job_queue<int> queue;
    auto unpublished_tx = queue.reserve();

    ASSERT_TRUE(static_cast<bool>(unpublished_tx));
    ASSERT_EQ(job_queue_submit_result::ACCEPTED, queue.insert_job(2));
    EXPECT_TRUE(queue.has_pending());
    EXPECT_TRUE(queue.has_runnable());

    auto &shutdown_jobs = queue.get_all();
    ASSERT_EQ(1U, shutdown_jobs.size());
    EXPECT_EQ(2, shutdown_jobs[0]);
    shutdown_jobs.clear();
    EXPECT_TRUE(queue.has_pending());
    EXPECT_FALSE(queue.has_runnable());

    ASSERT_EQ(job_queue_submit_result::ACCEPTED, unpublished_tx.commit(1));
    auto &jobs = queue.get_all();
    ASSERT_EQ(1U, jobs.size());
    EXPECT_EQ(1, jobs[0]);
    jobs.clear();
    EXPECT_FALSE(queue.has_pending());
}

TEST(job_queue, reservation_does_not_stall_jobs_published_before_it)
{
    job_queue<int> queue;

    ASSERT_EQ(job_queue_submit_result::ACCEPTED, queue.insert_job(1));
    auto reserved = queue.reserve();
    ASSERT_TRUE(static_cast<bool>(reserved));
    EXPECT_TRUE(queue.has_runnable());

    auto &first_batch = queue.get_all();
    ASSERT_EQ(1U, first_batch.size());
    EXPECT_EQ(1, first_batch[0]);
    first_batch.clear();
    EXPECT_TRUE(queue.has_pending());

    ASSERT_EQ(job_queue_submit_result::ACCEPTED, reserved.commit(2));
    auto &second_batch = queue.get_all();
    ASSERT_EQ(1U, second_batch.size());
    EXPECT_EQ(2, second_batch[0]);
    second_batch.clear();
    EXPECT_FALSE(queue.has_pending());
}

TEST(job_queue, reservation_without_terminal_slot_is_not_runnable)
{
    job_queue<int> queue;
    auto reserved = queue.reserve();

    ASSERT_TRUE(static_cast<bool>(reserved));
    EXPECT_TRUE(queue.has_pending());
    EXPECT_FALSE(queue.has_runnable());

    reserved.reset();
    EXPECT_FALSE(queue.has_pending());
    EXPECT_FALSE(queue.has_runnable());
}

TEST(job_queue, close_rejects_new_work_but_preserves_existing_reservation)
{
    job_queue<int> queue;
    auto accepted_before_close = queue.reserve();
    ASSERT_TRUE(static_cast<bool>(accepted_before_close));

    queue.close_admission();
    auto rejected_after_close = queue.reserve();
    EXPECT_FALSE(static_cast<bool>(rejected_after_close));
    EXPECT_EQ(job_queue_submit_result::CLOSED, rejected_after_close.result());
    EXPECT_EQ(job_queue_submit_result::CLOSED, queue.insert_job(2));

    EXPECT_EQ(job_queue_submit_result::ACCEPTED, accepted_before_close.commit(1));
    auto &jobs = queue.get_all();
    ASSERT_EQ(1U, jobs.size());
    EXPECT_EQ(1, jobs[0]);
    jobs.clear();
    EXPECT_FALSE(queue.has_pending());
}

TEST(job_queue, pinned_post_orders_after_previously_committed_jobs)
{
    job_queue<int> queue;
    job_queue<int>::node close_node;

    ASSERT_EQ(job_queue_submit_result::ACCEPTED, queue.insert_job(1));
    queue.post_pinned(close_node, 100);
    ASSERT_EQ(job_queue_submit_result::ACCEPTED, queue.insert_job(2));
    EXPECT_TRUE(queue.has_runnable());

    // One FIFO: a snapshot can never contain the pinned close entry without the job that was
    // committed before it.
    auto &jobs = queue.get_all();
    ASSERT_EQ(3U, jobs.size());
    EXPECT_EQ(1, jobs[0]);
    EXPECT_EQ(100, jobs[1]);
    EXPECT_EQ(2, jobs[2]);
    jobs.clear();
    EXPECT_FALSE(queue.has_pending());
}

TEST(job_queue, pinned_post_is_deliverable_after_close_admission)
{
    job_queue<int> queue;
    job_queue<int>::node close_node;

    queue.close_admission();
    ASSERT_EQ(job_queue_submit_result::CLOSED, queue.insert_job(1));

    // Shutdown posts a force-close after admission is closed; the pinned lane must stay open.
    queue.post_pinned(close_node, 100);
    EXPECT_TRUE(queue.has_runnable());

    auto &jobs = queue.get_all();
    ASSERT_EQ(1U, jobs.size());
    EXPECT_EQ(100, jobs[0]);
    jobs.clear();
    EXPECT_FALSE(queue.has_pending());
}

TEST(job_queue, pinned_post_is_runnable_despite_foreign_unpublished_reservation)
{
    job_queue<int> queue;
    job_queue<int>::node close_node;
    auto stalled_foreign_tx = queue.reserve();

    ASSERT_TRUE(static_cast<bool>(stalled_foreign_tx));
    queue.post_pinned(close_node, 100);
    EXPECT_TRUE(queue.has_runnable());

    auto &close_jobs = queue.get_all();
    ASSERT_EQ(1U, close_jobs.size());
    EXPECT_EQ(100, close_jobs[0]);
    close_jobs.clear();
    EXPECT_TRUE(queue.has_pending());

    ASSERT_EQ(job_queue_submit_result::ACCEPTED, stalled_foreign_tx.commit(1));
    auto &late_jobs = queue.get_all();
    ASSERT_EQ(1U, late_jobs.size());
    EXPECT_EQ(1, late_jobs[0]);
    late_jobs.clear();
    EXPECT_FALSE(queue.has_pending());
}

TEST(job_queue, pinned_node_is_reusable_after_its_occurrence_is_consumed)
{
    job_queue<int> queue;
    job_queue<int>::node close_node;

    queue.post_pinned(close_node, 100);
    auto &first_jobs = queue.get_all();
    ASSERT_EQ(1U, first_jobs.size());
    EXPECT_EQ(100, first_jobs[0]);
    first_jobs.clear();

    // The consumer must not have recycled the caller-owned node into its pool: a pool job after
    // the re-post must neither overwrite nor reorder the re-posted entry.
    queue.post_pinned(close_node, 101);
    ASSERT_EQ(job_queue_submit_result::ACCEPTED, queue.insert_job(2));

    auto &second_jobs = queue.get_all();
    ASSERT_EQ(2U, second_jobs.size());
    EXPECT_EQ(101, second_jobs[0]);
    EXPECT_EQ(2, second_jobs[1]);
    second_jobs.clear();
    EXPECT_FALSE(queue.has_pending());
}
