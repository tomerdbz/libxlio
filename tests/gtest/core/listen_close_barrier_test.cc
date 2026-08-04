/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/def.h"

#include "sock/worker_listener_close_barrier.h"

#include <chrono>
#include <future>

TEST(listen_close_barrier, one_initiator_owns_close_and_all_waiters_observe_completion)
{
    worker_listener_close_barrier barrier;
    ASSERT_TRUE(barrier.begin(2U));
    EXPECT_FALSE(barrier.begin(2U));

    std::future<void> first_waiter = std::async(std::launch::async, [&barrier] { barrier.wait(); });
    std::future<void> second_waiter =
        std::async(std::launch::async, [&barrier] { barrier.wait(); });

    EXPECT_EQ(std::future_status::timeout, first_waiter.wait_for(std::chrono::milliseconds(0)));
    EXPECT_EQ(std::future_status::timeout, second_waiter.wait_for(std::chrono::milliseconds(0)));
    barrier.notify_closed();
    EXPECT_EQ(std::future_status::timeout, first_waiter.wait_for(std::chrono::milliseconds(0)));
    EXPECT_EQ(std::future_status::timeout, second_waiter.wait_for(std::chrono::milliseconds(0)));
    barrier.notify_closed();
    EXPECT_EQ(std::future_status::ready, first_waiter.wait_for(std::chrono::seconds(1)));
    EXPECT_EQ(std::future_status::ready, second_waiter.wait_for(std::chrono::seconds(1)));
}

TEST(listen_close_barrier, empty_close_transaction_is_complete_immediately)
{
    worker_listener_close_barrier barrier;

    EXPECT_TRUE(barrier.begin(0U));
    EXPECT_FALSE(barrier.begin(0U));

    std::future<void> waiter = std::async(std::launch::async, [&barrier] { barrier.wait(); });
    EXPECT_EQ(std::future_status::ready, waiter.wait_for(std::chrono::seconds(1)));
}
