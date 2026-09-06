/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef WORKER_RX_CLOSE_BARRIER_H
#define WORKER_RX_CLOSE_BARRIER_H

#include <assert.h>
#include <cstdint>
#include <limits>

/**
 * Serializes worker-socket RX calls with the destructive portion of close.
 *
 * Every operation is called with the containing socket's TCP lock held.
 * The application lock normally limits active RX calls to one, but the count makes the ownership
 * contract explicit and keeps the barrier correct if that serialization changes later.
 */
class worker_rx_close_barrier {
public:
    bool try_enter(bool admission_open)
    {
        if (!admission_open || m_close_waiting) {
            return false;
        }

        assert(m_active_calls != std::numeric_limits<uint32_t>::max());
        if (m_active_calls == std::numeric_limits<uint32_t>::max()) {
            return false;
        }
        ++m_active_calls;
        return true;
    }

    /**
     * Park close when an admitted RX call still owns detached receive state.
     *
     * A true result transfers no reference.
     * The caller must retain the existing close-control owner reference until leave() requests
     * that the parked control be resumed.
     */
    bool defer_close_if_active()
    {
        if (m_active_calls == 0U) {
            return false;
        }

        m_close_waiting = true;
        return true;
    }

    /**
     * Finish one admitted RX call.
     *
     * True is returned exactly once, after the last call leaves, when the caller must make the
     * parked close control runnable again.
     */
    bool leave()
    {
        assert(m_active_calls > 0U);
        if (m_active_calls == 0U) {
            return false;
        }

        --m_active_calls;
        if (m_active_calls == 0U && m_close_waiting) {
            m_close_waiting = false;
            return true;
        }
        return false;
    }

    uint32_t active_calls() const { return m_active_calls; }
    bool close_waiting() const { return m_close_waiting; }

private:
    uint32_t m_active_calls = 0U;
    bool m_close_waiting = false;
};

#endif /* WORKER_RX_CLOSE_BARRIER_H */
