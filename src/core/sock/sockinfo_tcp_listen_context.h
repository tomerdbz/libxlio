/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef SOCKINFO_TCP_LISTEN_CONTEXT_H
#define SOCKINFO_TCP_LISTEN_CONTEXT_H

#include <vector>
#include <atomic>
#include <cassert>
#include <cstddef>
#include <memory>
#include <mutex>
#include <utility>
#include <condition_variable>

#include "worker_listener_close_barrier.h"

class sockinfo_tcp;

class sockinfo_tcp_listen_context {
public:
    /*
     * Listener-child batch: owns the RSS listener children until every worker job has been
     * reserved and the whole set is published in one step. Publication is the only operation
     * that relinquishes destruction ownership, so a reservation failure destroys every
     * unpublished child exactly once and no listener is ever half published.
     *
     * This is the listen context's own machinery, not a reusable component. The child type is a
     * template parameter only as a unit-test seam: sockinfo_tcp cannot be constructed outside
     * the full runtime, so the ownership invariants are pinned with a destruction-observable
     * test child instead (tests/gtest/core/listen_child_batch_test.cc).
     */
    template <typename Child> class child_batch {
        struct child_slot {
            // The raw identity outlives publication so close-side readers keep child access
            // after ownership has been handed off.
            Child *child;
            std::unique_ptr<Child> owner;
        };

    public:
        /*
         * The view intentionally holds m_children_mutex for its whole lifetime: an active reader
         * gates the close owner (stop_published_readers() blocks on the same mutex), so this is a
         * mutex hold, not a snapshot. The close-gate test pins that semantics.
         */
        class published_read_view {
        public:
            published_read_view(published_read_view &&) noexcept = default;
            published_read_view &operator=(published_read_view &&) noexcept = default;

            published_read_view(const published_read_view &) = delete;
            published_read_view &operator=(const published_read_view &) = delete;

            size_t size() const noexcept
            {
                return m_visible && m_owner ? m_owner->m_children.size() : 0U;
            }

            Child *get(size_t index) const
            {
                assert(m_visible);
                return m_owner->m_children.at(index).child;
            }

        private:
            friend class child_batch;

            explicit published_read_view(child_batch &owner)
                : m_owner(&owner)
                , m_lock(owner.m_children_mutex)
                , m_visible(owner.m_has_published_children && !owner.m_published_readers_stopped)
            {
            }

            child_batch *m_owner;
            std::unique_lock<std::mutex> m_lock;
            bool m_visible;
        };

        ~child_batch()
        {
            std::lock_guard<std::mutex> lock(m_children_mutex);
            assert(!m_has_published_children);
            if (m_owns_unpublished) {
                m_children.clear();
                m_owns_unpublished = false;
            }
        }

        child_batch() = default;
        child_batch(const child_batch &) = delete;
        child_batch &operator=(const child_batch &) = delete;

        bool add(std::unique_ptr<Child> &&child) noexcept
        {
            std::lock_guard<std::mutex> lock(m_children_mutex);
            assert(m_owns_unpublished);
            assert(child);
            try {
                Child *raw = child.get();
                m_children.push_back(child_slot {raw, std::move(child)});
                return true;
            } catch (...) {
                return false;
            }
        }

        Child *get(size_t index) const
        {
            std::lock_guard<std::mutex> lock(m_children_mutex);
            return m_children.at(index).child;
        }

        size_t size() const
        {
            std::lock_guard<std::mutex> lock(m_children_mutex);
            return m_children.size();
        }

        bool empty() const
        {
            std::lock_guard<std::mutex> lock(m_children_mutex);
            return m_children.empty();
        }

        bool reserve(size_t capacity) noexcept
        {
            std::lock_guard<std::mutex> lock(m_children_mutex);
            try {
                m_children.reserve(capacity);
                return true;
            } catch (...) {
                return false;
            }
        }

        /*
         * Transfer every owning handle to a non-throwing external adopter.
         *
         * The adopter establishes the post-publication destruction authority. The batch retains
         * only the raw identities needed to coordinate later retirement acknowledgement.
         */
        template <typename Adopter> void publish(Adopter &&adopter) noexcept
        {
            static_assert(noexcept(adopter(std::declval<std::unique_ptr<Child>>())),
                          "listener-child ownership adoption must not throw");
            std::lock_guard<std::mutex> lock(m_children_mutex);
            assert(m_owns_unpublished);
            assert(!m_published_readers_stopped);
            for (child_slot &slot : m_children) {
                assert(slot.owner.get() == slot.child);
                adopter(std::move(slot.owner));
                assert(!slot.owner);
            }
            m_owns_unpublished = false;
            m_has_published_children = true;
        }

        void destroy_unpublished() noexcept
        {
            std::lock_guard<std::mutex> lock(m_children_mutex);
            if (!m_owns_unpublished) {
                return;
            }

            m_children.clear();
            m_owns_unpublished = false;
            m_has_published_children = false;
        }

        bool has_published_children() const noexcept
        {
            std::lock_guard<std::mutex> lock(m_children_mutex);
            return m_has_published_children;
        }

        published_read_view acquire_published_read_view() { return published_read_view(*this); }

        /*
         * Establish the close-side observation barrier.
         *
         * Taking this mutex waits for every active view to finish. Once the flag is published, no
         * later reader can obtain child identities, so the close owner may retire and clear them.
         */
        void stop_published_readers() noexcept
        {
            std::lock_guard<std::mutex> lock(m_children_mutex);
            assert(m_has_published_children);
            m_published_readers_stopped = true;
        }

        void acknowledge_published_retirement() noexcept
        {
            std::lock_guard<std::mutex> lock(m_children_mutex);
            assert(m_has_published_children);
            assert(m_published_readers_stopped);
            m_children.clear();
            m_has_published_children = false;
        }

    private:
        mutable std::mutex m_children_mutex;
        std::vector<child_slot> m_children;
        bool m_owns_unpublished = true;
        bool m_has_published_children = false;
        bool m_published_readers_stopped = false;
    };

    using listen_rss_children_read_view = child_batch<sockinfo_tcp>::published_read_view;

    sockinfo_tcp_listen_context();
    ~sockinfo_tcp_listen_context();

    size_t get_listen_rss_children_size() const { return m_listen_rss_children.size(); }
    sockinfo_tcp *get_listen_rss_child(size_t index) { return m_listen_rss_children.get(index); }
    bool add_listen_rss_child(std::unique_ptr<sockinfo_tcp> &&rss_child)
    {
        return m_listen_rss_children.add(std::move(rss_child));
    }
    bool listen_rss_children_empty() const { return m_listen_rss_children.empty(); }
    void publish_listen_rss_children();
    void destroy_unstarted_listen_rss_children() { m_listen_rss_children.destroy_unpublished(); }
    bool has_published_listen_rss_children() const
    {
        return m_listen_rss_children.has_published_children();
    }
    listen_rss_children_read_view acquire_published_listen_rss_children()
    {
        return m_listen_rss_children.acquire_published_read_view();
    }
    void acknowledge_published_listen_rss_children_retired()
    {
        m_listen_rss_children.acknowledge_published_retirement();
        m_ready_connection_count.store(0U, std::memory_order_release);
    }

    int get_steering_index() const { return m_socketinfo_tcp_listen_steering_index; }
    void set_steering_index(int index) { m_socketinfo_tcp_listen_steering_index = index; }

    bool is_rss_child_listen_socket() const { return m_parent_listen_socket != nullptr; }

    sockinfo_tcp *get_parent_listen_socket() const { return m_parent_listen_socket; }
    void set_parent_listen_socket(sockinfo_tcp *parent) { m_parent_listen_socket = parent; }

    size_t get_round_robin_index() const { return m_round_robin_index; }
    size_t increment_round_robin_index() { return m_round_robin_index++; }

    void increment_finish_counter();
    void increment_close_counter();
    void increment_error_counter();
    void increment_ready_connection_count()
    {
        m_ready_connection_count.fetch_add(1U, std::memory_order_release);
    }
    void decrement_ready_connection_count(size_t count);
    bool has_ready_connections() const
    {
        return m_ready_connection_count.load(std::memory_order_acquire) != 0U;
    }
    uint16_t get_finish_counter() const { return m_sockinfo_tcp_listen_finish_counter.load(); }
    uint16_t get_error_counter() const { return m_sockinfo_tcp_listen_error_counter.load(); }

    void reset_counters();
    bool begin_close_wait();
    bool wait_for_rss_children_ready();
    void wait_for_rss_children_closed();

private:
    sockinfo_tcp *m_parent_listen_socket = nullptr;
    size_t m_round_robin_index = 0;
    child_batch<sockinfo_tcp> m_listen_rss_children;
    std::atomic_uint16_t m_sockinfo_tcp_listen_finish_counter {0};
    std::atomic_uint16_t m_sockinfo_tcp_listen_error_counter {0};
    std::atomic_size_t m_ready_connection_count {0U};
    worker_listener_close_barrier m_close_barrier;
    int m_socketinfo_tcp_listen_steering_index = -1;
    std::mutex m_ready_mutex;
    std::condition_variable m_ready_condition;
};

#endif /* SOCKINFO_TCP_LISTEN_CONTEXT_H */
