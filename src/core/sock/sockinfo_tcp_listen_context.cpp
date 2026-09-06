/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "sockinfo_tcp_listen_context.h"
#include "sockinfo_tcp.h"
#include "util/sys_vars.h"

namespace {

struct worker_listen_child_adopter {
    void operator()(std::unique_ptr<sockinfo_tcp> child) const noexcept
    {
        assert(child);
        assert(child->is_worker_posix_managed());
        assert(child->get_worker_retire_owner());
        assert(child->get_entity_context() == child->get_worker_retire_owner());

        /*
         * distribute_listen_socket() committed an allocation-free owner job before this handoff.
         * The queued job reference or worker socket list now protects physical lifetime, and the
         * worker retirement owner is the sole post-publication destruction authority.
         */
        /* coverity[leaked_storage] */
        (void)child.release();
    }
};

} // namespace

sockinfo_tcp_listen_context::sockinfo_tcp_listen_context()
{
    (void)m_listen_rss_children.reserve(safe_mce_sys().worker_threads);
}

sockinfo_tcp_listen_context::~sockinfo_tcp_listen_context() = default;

void sockinfo_tcp_listen_context::publish_listen_rss_children()
{
    m_listen_rss_children.publish(worker_listen_child_adopter {});
}

void sockinfo_tcp_listen_context::increment_finish_counter()
{
    {
        // C++ standard requires: shared variables used in condition_variable predicates must be
        // modified while holding the same mutex used by wait(), even if atomic
        std::lock_guard<std::mutex> lock(m_ready_mutex);
        m_sockinfo_tcp_listen_finish_counter.fetch_add(1);
    }
    // Wake up parent to check if all children are ready
    m_ready_condition.notify_one();
}

void sockinfo_tcp_listen_context::increment_close_counter()
{
    m_close_barrier.notify_closed();
}

void sockinfo_tcp_listen_context::increment_error_counter()
{
    {
        // C++ standard requires: shared variables used in condition_variable predicates must be
        // modified while holding the same mutex used by wait(), even if atomic
        std::lock_guard<std::mutex> lock(m_ready_mutex);
        m_sockinfo_tcp_listen_error_counter.fetch_add(1);
    }
    // Wake up parent immediately on any error
    m_ready_condition.notify_one();
}

void sockinfo_tcp_listen_context::decrement_ready_connection_count(size_t count)
{
    size_t current = m_ready_connection_count.load(std::memory_order_acquire);
    while (true) {
        assert(current >= count);
        if (current < count) {
            return;
        }
        if (m_ready_connection_count.compare_exchange_weak(
                current, current - count, std::memory_order_acq_rel, std::memory_order_acquire)) {
            return;
        }
    }
}

void sockinfo_tcp_listen_context::reset_counters()
{
    std::lock_guard<std::mutex> lock(m_ready_mutex);
    m_sockinfo_tcp_listen_finish_counter.store(0);
    m_sockinfo_tcp_listen_error_counter.store(0);
}

bool sockinfo_tcp_listen_context::begin_close_wait()
{
    const size_t child_count = get_listen_rss_children_size();
    const bool close_owner = m_close_barrier.begin(child_count);
    if (close_owner) {
        m_listen_rss_children.stop_published_readers();
    }
    return close_owner;
}

bool sockinfo_tcp_listen_context::wait_for_rss_children_ready()
{
    // std::condition_variable works only with std::unique_lock<std::mutex>
    std::unique_lock<std::mutex> lock(m_ready_mutex);
    // Wait until either:
    // 1. ALL children are ready (finish_counter == rss_children_size), OR
    // 2. At least 1 error occurred (error_counter > 0)
    // Each child wakes up parent, parent checks condition, goes back to wait if not met
    m_ready_condition.wait(lock, [this] {
        return get_finish_counter() == get_listen_rss_children_size() || get_error_counter() > 0;
    });
    return true; // Condition was met
}

void sockinfo_tcp_listen_context::wait_for_rss_children_closed()
{
    m_close_barrier.wait();
}
