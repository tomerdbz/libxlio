/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/def.h"

#include "sock/worker_rx_close_barrier.h"

TEST(worker_rx_close_barrier, open_call_leaves_without_close_handoff)
{
    worker_rx_close_barrier barrier;

    ASSERT_TRUE(barrier.try_enter(true));
    EXPECT_EQ(1U, barrier.active_calls());
    EXPECT_FALSE(barrier.close_waiting());
    EXPECT_FALSE(barrier.leave());
    EXPECT_EQ(0U, barrier.active_calls());
}

TEST(worker_rx_close_barrier, retiring_socket_rejects_new_rx_admission)
{
    worker_rx_close_barrier barrier;

    EXPECT_FALSE(barrier.try_enter(false));
    EXPECT_EQ(0U, barrier.active_calls());
    EXPECT_FALSE(barrier.defer_close_if_active());
}

TEST(worker_rx_close_barrier, deferred_close_resumes_after_last_active_call)
{
    worker_rx_close_barrier barrier;

    ASSERT_TRUE(barrier.try_enter(true));
    ASSERT_TRUE(barrier.try_enter(true));
    ASSERT_TRUE(barrier.defer_close_if_active());
    EXPECT_TRUE(barrier.close_waiting());
    EXPECT_FALSE(barrier.try_enter(true));

    EXPECT_FALSE(barrier.leave());
    EXPECT_TRUE(barrier.close_waiting());
    EXPECT_TRUE(barrier.leave());
    EXPECT_FALSE(barrier.close_waiting());
    EXPECT_EQ(0U, barrier.active_calls());
}

TEST(worker_rx_close_barrier, repeated_close_coalesces_into_one_resume)
{
    worker_rx_close_barrier barrier;

    ASSERT_TRUE(barrier.try_enter(true));
    ASSERT_TRUE(barrier.defer_close_if_active());
    ASSERT_TRUE(barrier.defer_close_if_active());

    EXPECT_TRUE(barrier.leave());
    EXPECT_FALSE(barrier.close_waiting());
}
