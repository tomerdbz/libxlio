/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/def.h"

#include <cerrno>
#include <thread>

#include "sock/worker_shutdown_result.h"

TEST(worker_shutdown_result, publishes_success_from_worker_to_caller)
{
    worker_shutdown_result result;
    std::thread worker([&result] { result.complete(0, 0); });
    int error = -1;

    EXPECT_EQ(0, result.wait(error));
    EXPECT_EQ(0, error);
    worker.join();
}

TEST(worker_shutdown_result, publishes_failure_errno_from_worker_to_caller)
{
    worker_shutdown_result result;
    std::thread worker([&result] { result.complete(-1, ENOTCONN); });
    int error = 0;

    EXPECT_EQ(-1, result.wait(error));
    EXPECT_EQ(ENOTCONN, error);
    worker.join();
}
