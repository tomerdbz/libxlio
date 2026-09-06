/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-3-Clause
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef JOB_QUEUE_H
#define JOB_QUEUE_H

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <new>
#include <type_traits>
#include <utility>
#include <vector>

#include "utils/lock_wrapper.h"

enum class job_queue_submit_result {
    ACCEPTED,
    CLOSED,
    NO_MEMORY,
};

/**
 * Multi-producer, single-consumer queue with allocation-safe reservations.
 *
 * reserve() removes one stable node from a high-watermark pool before the producer mutates any
 * application-visible state.
 * commit() copies into that node and appends it to the ready queue without allocating.
 * The append is the ordering point, so an unpublished producer cannot block jobs committed by
 * another socket.
 *
 * Accepted reservations remain visible to shutdown until they commit or cancel, but they are not
 * runnable work and do not keep an interrupt-mode worker spinning.
 *
 * post_pinned() appends a caller-owned node to the same ready list, so a message whose delivery
 * must not fail (worker socket close) rides the one FIFO without allocating and independently of
 * admission close.
 * The consumer never recycles pinned nodes into the pool; the caller may re-post a pinned node
 * once its previous occurrence has been consumed from a get_all() snapshot.
 */
template <typename T> class job_queue {
public:
    typedef std::vector<T> queue_type;

    static_assert(std::is_nothrow_copy_constructible<T>::value,
                  "job_queue commit and consumer copies must be nothrow");
    static_assert(std::is_nothrow_destructible<T>::value,
                  "job_queue jobs must be nothrow destructible");

    struct node {
        typename std::aligned_storage<sizeof(T), alignof(T)>::type storage;
        node *next = nullptr;
        bool pinned = false;

        T *job() { return reinterpret_cast<T *>(&storage); }
    };

    class reservation {
    public:
        reservation() = default;
        reservation(reservation &&other) noexcept
            : m_owner(other.m_owner)
            , m_slot(other.m_slot)
            , m_result(other.m_result)
        {
            other.m_owner = nullptr;
            other.m_slot = nullptr;
        }

        reservation &operator=(reservation &&other) noexcept
        {
            if (this != &other) {
                reset();
                m_owner = other.m_owner;
                m_slot = other.m_slot;
                m_result = other.m_result;
                other.m_owner = nullptr;
                other.m_slot = nullptr;
            }
            return *this;
        }

        ~reservation() { reset(); }

        reservation(const reservation &) = delete;
        reservation &operator=(const reservation &) = delete;

        explicit operator bool() const { return m_owner != nullptr; }
        job_queue_submit_result result() const { return m_result; }

        job_queue_submit_result commit(const T &job)
        {
            if (!m_owner) {
                return m_result;
            }

            job_queue *owner = m_owner;
            node *reserved_slot = m_slot;
            m_owner = nullptr;
            m_slot = nullptr;
            m_result = owner->commit_reserved(reserved_slot, job);
            return m_result;
        }

        void reset()
        {
            if (m_owner) {
                job_queue *owner = m_owner;
                node *reserved_slot = m_slot;
                m_owner = nullptr;
                m_slot = nullptr;
                owner->cancel_reserved(reserved_slot);
            }
        }

    private:
        friend class job_queue<T>;

        reservation(job_queue *owner, node *reserved_slot, job_queue_submit_result result)
            : m_owner(owner)
            , m_slot(reserved_slot)
            , m_result(result)
        {
        }

        job_queue *m_owner = nullptr;
        node *m_slot = nullptr;
        job_queue_submit_result m_result = job_queue_submit_result::CLOSED;
    };

    job_queue()
    {
        static constexpr size_t initial_slots = 32U;
        m_queue_fetch.reserve(initial_slots);
        m_storage.reserve(initial_slots);
        for (size_t i = 0; i < initial_slots; ++i) {
            if (!allocate_slot_locked()) {
                break;
            }
        }
    }

    ~job_queue()
    {
        assert(m_reservations.load(std::memory_order_relaxed) == 0U);
        while (m_ready_head) {
            node *current = m_ready_head;
            m_ready_head = current->next;
            current->job()->~T();
        }
    }

    reservation reserve()
    {
        std::lock_guard<decltype(m_queue_lock)> lock(m_queue_lock);
        if (!m_accepting) {
            return reservation(nullptr, nullptr, job_queue_submit_result::CLOSED);
        }
        if (!m_free_head && !allocate_slot_locked()) {
            return reservation(nullptr, nullptr, job_queue_submit_result::NO_MEMORY);
        }

        node *reserved_slot = m_free_head;
        m_free_head = reserved_slot->next;
        reserved_slot->next = nullptr;
        m_reservations.fetch_add(1U, std::memory_order_release);
        return reservation(this, reserved_slot, job_queue_submit_result::ACCEPTED);
    }

    job_queue_submit_result insert_job(const T &job)
    {
        reservation reserved_slot = reserve();
        return reserved_slot ? reserved_slot.commit(job) : reserved_slot.result();
    }

    void close_admission()
    {
        std::lock_guard<decltype(m_queue_lock)> lock(m_queue_lock);
        m_accepting = false;
    }

    // Called only by the single consumer.
    queue_type &get_all()
    {
        if (!m_queue_fetch.empty() || m_ready_slots.load(std::memory_order_acquire) == 0U) {
            return m_queue_fetch;
        }

        node *ready_head = nullptr;
        {
            std::lock_guard<decltype(m_queue_lock)> lock(m_queue_lock);
            const size_t ready_count = m_ready_slots.load(std::memory_order_relaxed);
            if (ready_count == 0U) {
                return m_queue_fetch;
            }
            try {
                m_queue_fetch.reserve(ready_count);
            } catch (...) {
                // Publication remains intact and a later worker iteration retries.
                return m_queue_fetch;
            }

            ready_head = m_ready_head;
            m_ready_head = nullptr;
            m_ready_tail = nullptr;
            m_ready_slots.store(0U, std::memory_order_release);
        }

        node *returned_head = nullptr;
        node *returned_tail = nullptr;
        while (ready_head) {
            node *current = ready_head;
            ready_head = ready_head->next;
            m_queue_fetch.push_back(*current->job());
            current->job()->~T();
            current->next = nullptr;
            if (current->pinned) {
                // Caller-owned storage; the owner may re-post it once this occurrence is consumed.
                continue;
            }
            current->next = returned_head;
            returned_head = current;
            if (!returned_tail) {
                returned_tail = current;
            }
        }

        {
            std::lock_guard<decltype(m_queue_lock)> lock(m_queue_lock);
            if (returned_tail) {
                returned_tail->next = m_free_head;
                m_free_head = returned_head;
            }
        }
        return m_queue_fetch;
    }

    bool has_pending() const
    {
        return m_ready_slots.load(std::memory_order_acquire) > 0U ||
            m_reservations.load(std::memory_order_acquire) > 0U;
    }

    bool has_runnable() const { return m_ready_slots.load(std::memory_order_acquire) > 0U; }

    /**
     * Append a caller-owned node to the ready list.
     *
     * Never allocates and never fails; admission close does not apply, so a shutdown-initiated
     * close remains deliverable after close_admission().
     * The caller must guarantee the node's previous occurrence, if any, has already been consumed
     * from a get_all() snapshot (at most one live occurrence per node).
     */
    void post_pinned(node &pinned_node, const T &job)
    {
        new (&pinned_node.storage) T(job);
        pinned_node.next = nullptr;
        pinned_node.pinned = true;

        std::lock_guard<decltype(m_queue_lock)> lock(m_queue_lock);
        if (m_ready_tail) {
            m_ready_tail->next = &pinned_node;
        } else {
            m_ready_head = &pinned_node;
        }
        m_ready_tail = &pinned_node;
        m_ready_slots.fetch_add(1U, std::memory_order_release);
    }

private:
    bool allocate_slot_locked()
    {
        node *new_slot = new (std::nothrow) node;
        if (!new_slot) {
            return false;
        }
        try {
            m_storage.emplace_back(new_slot);
        } catch (...) {
            delete new_slot;
            return false;
        }
        new_slot->next = m_free_head;
        m_free_head = new_slot;
        return true;
    }

    job_queue_submit_result commit_reserved(node *reserved_slot, const T &job)
    {
        // T's nothrow copy construction is enforced above, so no failure can appear after
        // application-visible mutation.
        new (&reserved_slot->storage) T(job);
        reserved_slot->next = nullptr;

        std::lock_guard<decltype(m_queue_lock)> lock(m_queue_lock);
        if (m_ready_tail) {
            m_ready_tail->next = reserved_slot;
        } else {
            m_ready_head = reserved_slot;
        }
        m_ready_tail = reserved_slot;
        m_ready_slots.fetch_add(1U, std::memory_order_release);
        m_reservations.fetch_sub(1U, std::memory_order_release);
        return job_queue_submit_result::ACCEPTED;
    }

    void cancel_reserved(node *reserved_slot)
    {
        std::lock_guard<decltype(m_queue_lock)> lock(m_queue_lock);
        reserved_slot->next = m_free_head;
        m_free_head = reserved_slot;
        m_reservations.fetch_sub(1U, std::memory_order_release);
    }

    std::vector<std::unique_ptr<node>> m_storage;
    node *m_free_head = nullptr;
    node *m_ready_head = nullptr;
    node *m_ready_tail = nullptr;
    queue_type m_queue_fetch;
    lock_spin m_queue_lock;
    std::atomic<size_t> m_ready_slots {0U};
    std::atomic<size_t> m_reservations {0U};
    bool m_accepting = true;
};

#endif // JOB_QUEUE_H
