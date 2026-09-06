/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef FD_SOCKET_SLOT_H
#define FD_SOCKET_SLOT_H

#include <atomic>
#include <cassert>
#include <cstdint>

class sockinfo;

/*
 * The fd map must classify worker-managed POSIX TCP without dereferencing an unowned socket.
 * Store the pointer and its admission kind in one atomic word so a reader cannot pair a reused
 * pointer with stale type metadata.
 */
class fd_socket_slot {
public:
    struct snapshot {
        sockinfo *socket;
        bool needs_worker_ref;
    };

    fd_socket_slot() = default;

    fd_socket_slot(const fd_socket_slot &) = delete;
    fd_socket_slot &operator=(const fd_socket_slot &) = delete;

    void publish(sockinfo *socket, bool needs_worker_ref)
    {
        uintptr_t value = reinterpret_cast<uintptr_t>(socket);
        assert((value & WORKER_REF_TAG) == 0U);
        if (needs_worker_ref) {
            value |= WORKER_REF_TAG;
        }
        m_value.store(value, std::memory_order_release);
    }

    void clear() { m_value.store(0U, std::memory_order_release); }

    snapshot load() const
    {
        const uintptr_t value = m_value.load(std::memory_order_acquire);
        return snapshot {reinterpret_cast<sockinfo *>(value & ~WORKER_REF_TAG),
                         (value & WORKER_REF_TAG) != 0U};
    }

private:
    static constexpr uintptr_t WORKER_REF_TAG = 1U;
    std::atomic<uintptr_t> m_value {0U};
};

#endif
