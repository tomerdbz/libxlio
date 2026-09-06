/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef WORKER_RX_READY_METADATA_H
#define WORKER_RX_READY_METADATA_H

#include <assert.h>
#include <cstddef>
#include <utility>

/**
 * Metadata owned by a worker receive while its descriptor list is detached.
 *
 * detach_from() and publish_before_existing() are called with the socket TCP
 * lock held. The list splice is performed by the caller in the same lock scope
 * because the intrusive list type is private to sockinfo.
 */
struct worker_rx_ready_metadata {
    static worker_rx_ready_metadata detach_from(size_t &shared_byte_count, size_t &shared_offset,
                                                int &shared_descriptor_count) noexcept
    {
        return worker_rx_ready_metadata {std::exchange(shared_byte_count, 0U),
                                         std::exchange(shared_offset, 0U),
                                         std::exchange(shared_descriptor_count, 0)};
    }

    void publish_before_existing(size_t &shared_byte_count, size_t &shared_offset,
                                 int &shared_descriptor_count,
                                 bool has_detached_descriptors) const noexcept
    {
        if (!has_detached_descriptors) {
            assert(byte_count == 0U);
            assert(offset == 0U);
            assert(descriptor_count == 0);
            return;
        }

        assert(descriptor_count > 0);
        shared_byte_count += byte_count;
        shared_offset = offset;
        shared_descriptor_count += descriptor_count;
    }

    size_t byte_count = 0U;
    size_t offset = 0U;
    int descriptor_count = 0;
};

#endif /* WORKER_RX_READY_METADATA_H */
