/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef WORKER_LISTENER_CLOSE_BARRIER_H
#define WORKER_LISTENER_CLOSE_BARRIER_H

#include <cassert>
#include <condition_variable>
#include <cstddef>
#include <mutex>

class worker_listener_close_barrier {
public:
    /*
     * Claim the one close transaction for this published listener-child batch.
     * The winner posts child-close work. Later callers only join the same completion barrier.
     */
    bool begin(size_t expected)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_started) {
            return false;
        }
        m_started = true;
        m_expected = expected;
        m_completed = 0U;
        m_complete = (expected == 0U);
        return true;
    }

    void notify_closed()
    {
        bool complete = false;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            assert(m_started);
            assert(!m_complete);
            assert(m_completed < m_expected);
            if (!m_started || m_complete || m_completed >= m_expected) {
                return;
            }
            ++m_completed;
            if (m_completed == m_expected) {
                m_complete = true;
                complete = true;
            }
        }
        if (complete) {
            m_condition.notify_all();
        }
    }

    void wait()
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        assert(m_started);
        m_condition.wait(lock, [this] { return m_complete; });
    }

private:
    std::mutex m_mutex;
    std::condition_variable m_condition;
    bool m_started = false;
    bool m_complete = false;
    size_t m_expected = 0U;
    size_t m_completed = 0U;
};

#endif // WORKER_LISTENER_CLOSE_BARRIER_H
