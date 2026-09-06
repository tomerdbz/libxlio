/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef _EPOLL_OFFLOADED_REGISTRY_H
#define _EPOLL_OFFLOADED_REGISTRY_H

#include <cassert>
#include <cstddef>
#include <unordered_map>
#include <vector>

class sockinfo;

/*
 * The fd array is exposed to the existing epoll wait code.
 * The sparse socket map contains only worker POSIX TCP entries and is used only while the epfd lock
 * is held to update the entry moved by O(1) compaction after worker close has already cleared that
 * socket's global fd-map slot.
 * It does not own socket lifetime and must not be used by generic registration or destruction.
 */
class epoll_offloaded_registry {
public:
    struct erase_result {
        sockinfo *moved_socket = nullptr;
        int moved_fd = -1;
        int moved_index = 0;
        bool moved_worker_owned = false;
    };

    void reset(size_t capacity)
    {
        m_fds.assign(capacity, -1);
        m_worker_sockets.clear();
        m_count = 0;
    }

    bool append(int fd, sockinfo *worker_socket = nullptr) noexcept
    {
        if (m_count < 0 || static_cast<size_t>(m_count) >= m_fds.size()) {
            return false;
        }

        if (worker_socket) {
            try {
                if (!m_worker_sockets.emplace(fd, worker_socket).second) {
                    return false;
                }
            } catch (...) {
                return false;
            }
        }

        m_fds[static_cast<size_t>(m_count)] = fd;
        ++m_count;
        return true;
    }

    erase_result erase(int one_based_index)
    {
        assert(one_based_index > 0 && one_based_index <= m_count);

        const size_t removed = static_cast<size_t>(one_based_index - 1);
        const size_t last = static_cast<size_t>(m_count - 1);
        const int removed_fd = m_fds[removed];
        erase_result result;

        if (removed != last) {
            m_fds[removed] = m_fds[last];
            auto moved = m_worker_sockets.find(m_fds[removed]);
            if (moved != m_worker_sockets.end()) {
                result.moved_socket = moved->second;
            }
            result.moved_fd = m_fds[removed];
            result.moved_index = one_based_index;
            result.moved_worker_owned = result.moved_socket != nullptr;
        }

        m_fds[last] = -1;
        m_worker_sockets.erase(removed_fd);
        --m_count;
        return result;
    }

    int *fds() { return m_fds.data(); }
    const int *fds() const { return m_fds.data(); }
    int *count_ptr() { return &m_count; }
    int count() const { return m_count; }

    sockinfo *socket_at(size_t index) const
    {
        assert(index < static_cast<size_t>(m_count));
        auto found = m_worker_sockets.find(m_fds[index]);
        return found == m_worker_sockets.end() ? nullptr : found->second;
    }

    size_t worker_cache_size() const { return m_worker_sockets.size(); }

private:
    std::vector<int> m_fds;
    std::unordered_map<int, sockinfo *> m_worker_sockets;
    int m_count = 0;
};

#endif /* _EPOLL_OFFLOADED_REGISTRY_H */
