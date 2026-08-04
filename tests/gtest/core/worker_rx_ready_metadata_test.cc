/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/def.h"

#include "sock/worker_rx_ready_metadata.h"

TEST(worker_rx_ready_metadata, detach_clears_all_shared_metadata)
{
    size_t shared_byte_count = 513U;
    size_t shared_offset = 17U;
    int shared_descriptor_count = 3;

    worker_rx_ready_metadata detached = worker_rx_ready_metadata::detach_from(
        shared_byte_count, shared_offset, shared_descriptor_count);

    EXPECT_EQ(513U, detached.byte_count);
    EXPECT_EQ(17U, detached.offset);
    EXPECT_EQ(3, detached.descriptor_count);
    EXPECT_EQ(0U, shared_byte_count);
    EXPECT_EQ(0U, shared_offset);
    EXPECT_EQ(0, shared_descriptor_count);
}

TEST(worker_rx_ready_metadata, leftover_metadata_precedes_concurrent_arrivals)
{
    worker_rx_ready_metadata detached {256U, 9U, 2};
    size_t shared_byte_count = 64U;
    size_t shared_offset = 0U;
    int shared_descriptor_count = 1;

    detached.publish_before_existing(shared_byte_count, shared_offset, shared_descriptor_count,
                                     true);

    EXPECT_EQ(320U, shared_byte_count);
    EXPECT_EQ(9U, shared_offset);
    EXPECT_EQ(3, shared_descriptor_count);
}

TEST(worker_rx_ready_metadata, empty_detached_list_preserves_concurrent_metadata)
{
    worker_rx_ready_metadata detached;
    size_t shared_byte_count = 41U;
    size_t shared_offset = 5U;
    int shared_descriptor_count = 1;

    detached.publish_before_existing(shared_byte_count, shared_offset, shared_descriptor_count,
                                     false);

    EXPECT_EQ(41U, shared_byte_count);
    EXPECT_EQ(5U, shared_offset);
    EXPECT_EQ(1, shared_descriptor_count);
}
