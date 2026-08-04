/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/def.h"

#include "iomux/epoll_offloaded_registry.h"

TEST(epoll_offloaded_registry, distinct_closes_keep_the_unrelated_registration)
{
    alignas(64) unsigned char socket_a_storage[64] = {};
    alignas(64) unsigned char socket_b_storage[64] = {};
    alignas(64) unsigned char socket_c_storage[64] = {};
    auto *socket_a = reinterpret_cast<sockinfo *>(socket_a_storage);
    auto *socket_b = reinterpret_cast<sockinfo *>(socket_b_storage);
    auto *socket_c = reinterpret_cast<sockinfo *>(socket_c_storage);
    epoll_offloaded_registry registry;

    registry.reset(3U);
    ASSERT_TRUE(registry.append(11, socket_b));
    ASSERT_TRUE(registry.append(12, socket_c));
    ASSERT_TRUE(registry.append(13, socket_a));

    epoll_offloaded_registry::erase_result remove_b = registry.erase(1);
    ASSERT_EQ(socket_a, remove_b.moved_socket);
    ASSERT_EQ(13, remove_b.moved_fd);
    ASSERT_EQ(1, remove_b.moved_index);
    ASSERT_TRUE(remove_b.moved_worker_owned);
    ASSERT_EQ(2, registry.count());
    EXPECT_EQ(13, registry.fds()[0]);
    EXPECT_EQ(socket_a, registry.socket_at(0));
    EXPECT_EQ(12, registry.fds()[1]);
    EXPECT_EQ(socket_c, registry.socket_at(1));

    epoll_offloaded_registry::erase_result remove_a = registry.erase(remove_b.moved_index);
    ASSERT_EQ(socket_c, remove_a.moved_socket);
    ASSERT_EQ(12, remove_a.moved_fd);
    ASSERT_EQ(1, remove_a.moved_index);
    ASSERT_TRUE(remove_a.moved_worker_owned);
    ASSERT_EQ(1, registry.count());
    EXPECT_EQ(12, registry.fds()[0]);
    EXPECT_EQ(socket_c, registry.socket_at(0));
}

TEST(epoll_offloaded_registry, removing_last_entry_has_no_displaced_socket)
{
    alignas(64) unsigned char socket_storage[64] = {};
    auto *socket = reinterpret_cast<sockinfo *>(socket_storage);
    epoll_offloaded_registry registry;

    registry.reset(1U);
    ASSERT_TRUE(registry.append(17, socket));

    epoll_offloaded_registry::erase_result removed = registry.erase(1);
    EXPECT_EQ(nullptr, removed.moved_socket);
    EXPECT_EQ(-1, removed.moved_fd);
    EXPECT_EQ(0, removed.moved_index);
    EXPECT_FALSE(removed.moved_worker_owned);
    EXPECT_EQ(0, registry.count());
}

TEST(epoll_offloaded_registry, worker_socket_cache_is_sparse)
{
    alignas(64) unsigned char socket_storage[64] = {};
    auto *socket = reinterpret_cast<sockinfo *>(socket_storage);
    epoll_offloaded_registry registry;

    registry.reset(1U << 20U);
    ASSERT_EQ(0U, registry.worker_cache_size());
    ASSERT_TRUE(registry.append(17));
    ASSERT_TRUE(registry.append(18));
    EXPECT_EQ(nullptr, registry.socket_at(0));

    epoll_offloaded_registry::erase_result non_worker_move = registry.erase(1);
    EXPECT_EQ(nullptr, non_worker_move.moved_socket);
    EXPECT_EQ(18, non_worker_move.moved_fd);
    EXPECT_EQ(1, non_worker_move.moved_index);

    ASSERT_TRUE(registry.append(19, socket));
    EXPECT_EQ(1U, registry.worker_cache_size());
    EXPECT_EQ(socket, registry.socket_at(1));

    registry.erase(2);
    EXPECT_EQ(0U, registry.worker_cache_size());
}
