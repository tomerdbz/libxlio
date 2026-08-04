/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/def.h"

#include "sock/sockinfo_tcp.h"
#include "sock/worker_socket_lifetime.h"

TEST(worker_retirement_registry, tracks_multiple_links_until_each_is_physically_destroyed)
{
    worker_retirement_registry registry;
    worker_retirement_link first;
    worker_retirement_link second;

    EXPECT_TRUE(registry.empty());

    registry.track(first);
    registry.track(second);
    EXPECT_FALSE(registry.empty());
    EXPECT_TRUE(registry.contains(first));
    EXPECT_TRUE(registry.contains(second));

    registry.untrack(first);
    EXPECT_FALSE(registry.empty());
    EXPECT_FALSE(registry.contains(first));
    EXPECT_TRUE(registry.contains(second));

    registry.untrack(second);
    EXPECT_TRUE(registry.empty());
    EXPECT_FALSE(registry.contains(second));
}

TEST(worker_retirement_owner_ref, releases_shutdown_owner_once_when_a_call_ref_remains)
{
    worker_socket_lifetime lifetime;

    ASSERT_TRUE(lifetime.try_acquire());
    ASSERT_TRUE(lifetime.begin_retirement_with_owner_ref());
    worker_retirement_owner_ref owner_ref(&lifetime);

    EXPECT_FALSE(owner_ref.complete());
    EXPECT_EQ(1U, lifetime.ref_count());
    EXPECT_EQ(worker_socket_lifecycle::RETIRING, lifetime.state());

    EXPECT_FALSE(owner_ref.complete());
    EXPECT_EQ(1U, lifetime.ref_count());

    EXPECT_EQ(worker_lifetime_release::RECHECK_RETIREMENT, lifetime.release());
    EXPECT_TRUE(lifetime.try_claim_destruction_without_ref());
}

TEST(worker_retirement_owner_ref, consumes_shutdown_owner_when_it_is_the_only_reference)
{
    worker_socket_lifetime lifetime;

    ASSERT_TRUE(lifetime.begin_retirement_with_owner_ref());
    worker_retirement_owner_ref owner_ref(&lifetime);

    EXPECT_TRUE(owner_ref.complete());
    EXPECT_EQ(0U, lifetime.ref_count());
    EXPECT_EQ(worker_socket_lifecycle::DESTROY_CLAIMED, lifetime.state());
    EXPECT_FALSE(owner_ref.complete());
}

TEST(worker_socket_lifetime, retirement_stops_admission_and_pins_until_release)
{
    worker_socket_lifetime lifetime;

    ASSERT_TRUE(lifetime.try_acquire());
    ASSERT_TRUE(lifetime.begin_retirement_with_owner_ref());

    EXPECT_EQ(worker_socket_lifecycle::RETIRING, lifetime.state());
    EXPECT_EQ(2U, lifetime.ref_count());
    EXPECT_FALSE(lifetime.try_acquire());
    EXPECT_FALSE(lifetime.consume_owner_ref_and_claim_destruction());

    EXPECT_EQ(worker_lifetime_release::NONE, lifetime.release());
    EXPECT_EQ(1U, lifetime.ref_count());
    EXPECT_TRUE(lifetime.consume_owner_ref_and_claim_destruction());
    EXPECT_FALSE(lifetime.try_claim_destruction_without_ref());

    EXPECT_EQ(0U, lifetime.ref_count());
    EXPECT_EQ(worker_socket_lifecycle::DESTROY_CLAIMED, lifetime.state());
}

TEST(worker_socket_lifetime, last_non_owner_release_requests_one_retirement_recheck)
{
    worker_socket_lifetime lifetime;

    ASSERT_TRUE(lifetime.try_acquire());
    ASSERT_TRUE(lifetime.begin_retirement_with_owner_ref());

    EXPECT_EQ(worker_lifetime_release::NONE, lifetime.release());
    EXPECT_EQ(worker_lifetime_release::RECHECK_RETIREMENT, lifetime.release());
    EXPECT_EQ(0U, lifetime.ref_count());
}

TEST(worker_socket_lifetime, reopen_is_rejected_until_old_references_drain)
{
    worker_socket_lifetime lifetime;

    ASSERT_TRUE(lifetime.try_acquire());
    ASSERT_TRUE(lifetime.begin_retirement_with_owner_ref());
    EXPECT_EQ(worker_lifetime_release::NONE, lifetime.release());

    EXPECT_FALSE(lifetime.reopen_from_retirement());
    EXPECT_EQ(worker_socket_lifecycle::RETIRING, lifetime.state());

    EXPECT_EQ(worker_lifetime_release::RECHECK_RETIREMENT, lifetime.release());
    EXPECT_TRUE(lifetime.reopen_from_retirement());
    EXPECT_EQ(worker_socket_lifecycle::OPEN, lifetime.state());
    EXPECT_EQ(0U, lifetime.ref_count());
    EXPECT_TRUE(lifetime.try_acquire());
    EXPECT_EQ(worker_lifetime_release::NONE, lifetime.release());
}

TEST(worker_socket_lifetime, destruction_and_reopen_have_one_winner)
{
    worker_socket_lifetime lifetime;

    ASSERT_TRUE(lifetime.begin_retirement_with_owner_ref());
    EXPECT_EQ(worker_lifetime_release::RECHECK_RETIREMENT, lifetime.release());

    ASSERT_TRUE(lifetime.try_claim_destruction_without_ref());
    EXPECT_FALSE(lifetime.reopen_from_retirement());
    EXPECT_FALSE(lifetime.begin_retirement_with_owner_ref());
    EXPECT_FALSE(lifetime.try_acquire());
}

TEST(worker_socket_lifetime, reopen_winner_blocks_destruction_claim)
{
    worker_socket_lifetime lifetime;

    ASSERT_TRUE(lifetime.begin_retirement_with_owner_ref());
    EXPECT_EQ(worker_lifetime_release::RECHECK_RETIREMENT, lifetime.release());

    ASSERT_TRUE(lifetime.reopen_from_retirement());
    EXPECT_FALSE(lifetime.try_claim_destruction_without_ref());
    EXPECT_FALSE(lifetime.consume_owner_ref_and_claim_destruction());
    EXPECT_EQ(worker_socket_lifecycle::OPEN, lifetime.state());
}

TEST(worker_socket_lifetime, reopen_is_unreachable_from_other_lifetime_values)
{
    {
        // OPEN with no references.
        worker_socket_lifetime lifetime;
        EXPECT_FALSE(lifetime.reopen_from_retirement());
        EXPECT_EQ(worker_socket_lifecycle::OPEN, lifetime.state());
    }
    {
        // OPEN with a reference.
        worker_socket_lifetime lifetime;
        ASSERT_TRUE(lifetime.try_acquire());
        EXPECT_FALSE(lifetime.reopen_from_retirement());
        EXPECT_EQ(1U, lifetime.ref_count());
    }
    {
        // RETIRING with a reference still held.
        worker_socket_lifetime lifetime;
        ASSERT_TRUE(lifetime.begin_retirement_with_owner_ref());
        EXPECT_FALSE(lifetime.reopen_from_retirement());
        EXPECT_EQ(worker_socket_lifecycle::RETIRING, lifetime.state());
        EXPECT_EQ(1U, lifetime.ref_count());
    }
    {
        // DESTROY_CLAIMED.
        worker_socket_lifetime lifetime;
        ASSERT_TRUE(lifetime.begin_retirement_with_owner_ref());
        ASSERT_TRUE(lifetime.consume_owner_ref_and_claim_destruction());
        EXPECT_FALSE(lifetime.reopen_from_retirement());
        EXPECT_EQ(worker_socket_lifecycle::DESTROY_CLAIMED, lifetime.state());
    }
}

TEST(worker_socket_lifetime, successful_reopen_rearms_one_future_retirement)
{
    worker_socket_lifetime lifetime;

    ASSERT_TRUE(lifetime.begin_retirement_with_owner_ref());
    EXPECT_EQ(worker_lifetime_release::RECHECK_RETIREMENT, lifetime.release());
    ASSERT_TRUE(lifetime.reopen_from_retirement());

    ASSERT_TRUE(lifetime.begin_retirement_with_owner_ref());
    EXPECT_FALSE(lifetime.begin_retirement_with_owner_ref());
    EXPECT_EQ(worker_lifetime_release::RECHECK_RETIREMENT, lifetime.release());
    EXPECT_TRUE(lifetime.try_claim_destruction_without_ref());
}

TEST(worker_socket_lifetime, existing_owner_can_pin_retiring_socket_for_control_handoff)
{
    worker_socket_lifetime lifetime;

    ASSERT_TRUE(lifetime.begin_retirement_with_owner_ref());
    EXPECT_TRUE(lifetime.try_acquire_existing());
    EXPECT_EQ(2U, lifetime.ref_count());

    EXPECT_EQ(worker_lifetime_release::NONE, lifetime.release());
    EXPECT_EQ(worker_lifetime_release::RECHECK_RETIREMENT, lifetime.release());
    EXPECT_EQ(0U, lifetime.ref_count());
}

TEST(worker_socket_lifetime, destroyed_socket_rejects_every_reference_kind)
{
    worker_socket_lifetime lifetime;

    ASSERT_TRUE(lifetime.begin_retirement_with_owner_ref());
    ASSERT_TRUE(lifetime.consume_owner_ref_and_claim_destruction());

    EXPECT_FALSE(lifetime.try_acquire());
    EXPECT_FALSE(lifetime.try_acquire_existing());
    EXPECT_EQ(0U, lifetime.ref_count());
}
