/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/def.h"

#include "sock/sockinfo_tcp.h"

#include <chrono>
#include <future>

/*
 * Pins the ownership invariants of the listen context's child batch
 * (sockinfo_tcp_listen_context::child_batch): all-or-nothing reservation - every unpublished
 * child is destroyed exactly once on failure - and no half-published listener - publication
 * transfers the whole set in one step. sockinfo_tcp cannot be constructed outside the full
 * runtime, so the batch is instantiated with a destruction-observable test child through the
 * child-type seam the listen context provides for exactly this purpose.
 */

namespace {

struct tracked_child {
    explicit tracked_child(unsigned *destructions)
        : m_destructions(destructions)
    {
    }

    ~tracked_child() { ++*m_destructions; }

    unsigned *m_destructions;
};

struct tracked_child_adopter {
    std::unique_ptr<tracked_child> *m_children;
    size_t m_capacity;
    size_t m_count;

    void operator()(std::unique_ptr<tracked_child> child) noexcept
    {
        assert(m_count < m_capacity);
        m_children[m_count++] = std::move(child);
    }
};

using tracked_child_batch = sockinfo_tcp_listen_context::child_batch<tracked_child>;

} // namespace

TEST(listen_child_batch, failure_destroys_every_unpublished_child_once)
{
    unsigned destructions = 0U;

    {
        tracked_child_batch children;
        std::unique_ptr<tracked_child> first(new tracked_child(&destructions));
        std::unique_ptr<tracked_child> second(new tracked_child(&destructions));
        ASSERT_TRUE(children.add(std::move(first)));
        ASSERT_TRUE(children.add(std::move(second)));
        EXPECT_EQ(nullptr, first.get());
        EXPECT_EQ(nullptr, second.get());
        ASSERT_EQ(2U, children.size());

        children.destroy_unpublished();
        EXPECT_EQ(2U, destructions);
        EXPECT_EQ(0U, children.size());
    }

    EXPECT_EQ(2U, destructions);
}

TEST(listen_child_batch, publication_transfers_ownership_to_explicit_adopter)
{
    unsigned destructions = 0U;
    std::unique_ptr<tracked_child> first_owner(new tracked_child(&destructions));
    std::unique_ptr<tracked_child> second_owner(new tracked_child(&destructions));
    tracked_child *first = first_owner.get();
    tracked_child *second = second_owner.get();
    std::unique_ptr<tracked_child> adopted[2];
    tracked_child_adopter adopter = {adopted, 2U, 0U};

    {
        tracked_child_batch children;
        ASSERT_TRUE(children.add(std::move(first_owner)));
        ASSERT_TRUE(children.add(std::move(second_owner)));
        EXPECT_EQ(first, children.get(0U));
        EXPECT_EQ(second, children.get(1U));
        children.publish(adopter);
        EXPECT_EQ(2U, adopter.m_count);
        EXPECT_EQ(first, adopted[0].get());
        EXPECT_EQ(second, adopted[1].get());
        EXPECT_EQ(first, children.get(0U));
        EXPECT_EQ(second, children.get(1U));
        children.stop_published_readers();
        children.acknowledge_published_retirement();
    }

    EXPECT_EQ(0U, destructions);
    adopted[0].reset();
    adopted[1].reset();
    EXPECT_EQ(2U, destructions);
}

TEST(listen_child_batch, published_children_require_external_retirement_acknowledgement)
{
    unsigned destructions = 0U;
    std::unique_ptr<tracked_child> first_owner(new tracked_child(&destructions));
    std::unique_ptr<tracked_child> second_owner(new tracked_child(&destructions));
    tracked_child *first = first_owner.get();
    tracked_child *second = second_owner.get();
    std::unique_ptr<tracked_child> adopted[2];
    tracked_child_adopter adopter = {adopted, 2U, 0U};

    tracked_child_batch children;
    ASSERT_TRUE(children.add(std::move(first_owner)));
    ASSERT_TRUE(children.add(std::move(second_owner)));
    children.publish(adopter);
    ASSERT_TRUE(children.has_published_children());
    ASSERT_EQ(2U, adopter.m_count);
    EXPECT_EQ(first, adopted[0].get());
    EXPECT_EQ(second, adopted[1].get());

    adopted[0].reset();
    adopted[1].reset();
    children.stop_published_readers();
    children.acknowledge_published_retirement();

    EXPECT_FALSE(children.has_published_children());
    EXPECT_EQ(0U, children.size());
    EXPECT_EQ(2U, destructions);
}

TEST(listen_child_batch, close_gate_waits_for_active_reader_and_rejects_late_readers)
{
    unsigned destructions = 0U;
    std::unique_ptr<tracked_child> owner(new tracked_child(&destructions));
    tracked_child *child = owner.get();
    std::unique_ptr<tracked_child> adopted[1];
    tracked_child_adopter adopter = {adopted, 1U, 0U};
    tracked_child_batch children;

    ASSERT_TRUE(children.add(std::move(owner)));
    children.publish(adopter);

    std::promise<void> close_started;
    std::future<void> close_started_future = close_started.get_future();
    std::future<void> close_complete;
    {
        auto view = children.acquire_published_read_view();
        ASSERT_EQ(1U, view.size());
        EXPECT_EQ(child, view.get(0U));

        close_complete = std::async(std::launch::async, [&children, &close_started] {
            close_started.set_value();
            children.stop_published_readers();
        });
        ASSERT_EQ(std::future_status::ready,
                  close_started_future.wait_for(std::chrono::seconds(1)));
        EXPECT_EQ(std::future_status::timeout,
                  close_complete.wait_for(std::chrono::milliseconds(50)));
    }

    ASSERT_EQ(std::future_status::ready, close_complete.wait_for(std::chrono::seconds(1)));
    {
        auto late_view = children.acquire_published_read_view();
        EXPECT_EQ(0U, late_view.size());
    }

    children.acknowledge_published_retirement();
    adopted[0].reset();
    EXPECT_EQ(1U, destructions);
}
