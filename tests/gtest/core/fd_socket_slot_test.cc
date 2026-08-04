/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/def.h"

#include "sock/fd_socket_slot.h"

#include <atomic>
#include <thread>

TEST(fd_socket_slot, pointer_and_worker_admission_kind_are_one_atomic_snapshot)
{
    alignas(64) unsigned char worker_tcp_storage[64] = {};
    alignas(64) unsigned char legacy_storage[64] = {};
    auto *worker_tcp = reinterpret_cast<sockinfo *>(worker_tcp_storage);
    auto *legacy = reinterpret_cast<sockinfo *>(legacy_storage);
    fd_socket_slot slot;
    std::atomic<bool> writer_done {false};
    std::atomic<unsigned> mismatches {0U};

    std::thread writer([&] {
        for (unsigned iteration = 0; iteration < 100000U; ++iteration) {
            slot.publish(worker_tcp, true);
            slot.publish(legacy, false);
        }
        writer_done.store(true, std::memory_order_release);
    });

    while (!writer_done.load(std::memory_order_acquire)) {
        fd_socket_slot::snapshot current = slot.load();
        if ((current.socket == worker_tcp && !current.needs_worker_ref) ||
            (current.socket == legacy && current.needs_worker_ref)) {
            mismatches.fetch_add(1U, std::memory_order_relaxed);
        }
    }

    writer.join();
    EXPECT_EQ(0U, mismatches.load(std::memory_order_relaxed));
}

TEST(fd_socket_slot, clear_removes_pointer_and_worker_admission_kind_together)
{
    alignas(64) unsigned char worker_tcp_storage[64] = {};
    auto *worker_tcp = reinterpret_cast<sockinfo *>(worker_tcp_storage);
    fd_socket_slot slot;

    slot.publish(worker_tcp, true);
    fd_socket_slot::snapshot published = slot.load();
    ASSERT_EQ(worker_tcp, published.socket);
    ASSERT_TRUE(published.needs_worker_ref);

    slot.clear();
    fd_socket_slot::snapshot cleared = slot.load();
    EXPECT_EQ(nullptr, cleared.socket);
    EXPECT_FALSE(cleared.needs_worker_ref);
}
