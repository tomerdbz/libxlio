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

#ifndef ENTITY_CONTEXT_H
#define ENTITY_CONTEXT_H

#include <atomic>

#include "event/poll_group.h"
#include "event/job_queue.h"
#include "event/worker_job.h"
#include "sock/sockinfo_tcp.h"
#include "util/xlio_stats.h"
#include "event/event_handler_manager_local.h"

class sockinfo;
class mem_buf_desc_t;
class worker_shutdown_result;

class entity_context : public poll_group {
public:
    enum class job_submit_result {
        ACCEPTED,
        ADMISSION_CLOSED,
        SOCKET_RETIRED,
        NO_MEMORY,
    };

    enum socket_control : uint32_t {
        SOCKET_CONTROL_CLOSE = 1U << 0,
        SOCKET_CONTROL_RETIRE_RECHECK = 1U << 1,
        SOCKET_CONTROL_CANCEL_CONNECT = 1U << 2,
        SOCKET_CONTROL_FORCE_CLOSE = 1U << 3,
    };

    enum wakeup_reason {
        WAKEUP_NONE = 0,
        WAKEUP_CQ_EVENT,
        WAKEUP_JOB_POSTED,
        WAKEUP_TIMEOUT,
    };

    // The job vocabulary lives in worker_job.h (worker_socket_state embeds the per-socket control
    // node); these aliases keep the established entity_context:: spelling at every call site.
    using job_type = worker_job_type;
    using job_flag = worker_job_flag;
    using job_desc = worker_job_desc;
    static constexpr job_type JOB_TYPE_SOCK_ADD_AND_CONNECT = ::JOB_TYPE_SOCK_ADD_AND_CONNECT;
    static constexpr job_type JOB_TYPE_SOCK_TX = ::JOB_TYPE_SOCK_TX;
    static constexpr job_type JOB_TYPE_SOCK_RX_DATA_RECVD = ::JOB_TYPE_SOCK_RX_DATA_RECVD;
    static constexpr job_type JOB_TYPE_SOCK_ADD_AND_LISTEN = ::JOB_TYPE_SOCK_ADD_AND_LISTEN;
    static constexpr job_type JOB_TYPE_SOCK_CLOSE = ::JOB_TYPE_SOCK_CLOSE;
    static constexpr job_type JOB_TYPE_SOCK_SHUTDOWN = ::JOB_TYPE_SOCK_SHUTDOWN;
    static constexpr job_type JOB_TYPE_SOCK_CONTROL = ::JOB_TYPE_SOCK_CONTROL;
    static constexpr job_flag JOB_FLAG_TX_LAST_CHUNK = ::JOB_FLAG_TX_LAST_CHUNK;
    static constexpr job_flag JOB_FLAG_FORCE_CLOSE = ::JOB_FLAG_FORCE_CLOSE;
    static constexpr job_flag JOB_FLAG_SOCK_BLOCKING = ::JOB_FLAG_SOCK_BLOCKING;

    class job_reservation {
    public:
        job_reservation() = default;
        job_reservation(job_reservation &&other) noexcept;
        job_reservation &operator=(job_reservation &&other) noexcept;
        ~job_reservation();

        job_reservation(const job_reservation &) = delete;
        job_reservation &operator=(const job_reservation &) = delete;

        explicit operator bool() const { return m_context != nullptr; }
        job_submit_result result() const { return m_result; }
        job_submit_result commit(const job_desc &job);
        void reset();

    private:
        friend class entity_context;
        job_reservation(entity_context *context, sockinfo_tcp *ref_sock,
                        job_queue<job_desc>::reservation &&queue_reservation,
                        job_submit_result result);

        entity_context *m_context = nullptr;
        sockinfo_tcp *m_ref_sock = nullptr;
        job_queue<job_desc>::reservation m_queue_reservation;
        job_submit_result m_result = job_submit_result::ADMISSION_CLOSED;
    };

    entity_context(size_t index);
    virtual ~entity_context();

    size_t get_index() const { return m_index; }
    void process();
    job_reservation reserve_job(sockinfo *sock);
    job_submit_result add_job(const job_desc &job);
    void close_job_admission();
    bool has_pending_work();
    bool has_unsettled_work();
    void drain_worker_sockets_for_shutdown();
    bool has_owned_sockets() const;

    // The caller holds the socket's TCP lock.
    // A transferred reference is consumed whether this creates or coalesces a queue entry.
    bool post_socket_control_locked(sockinfo_tcp *sock, uint32_t controls,
                                    bool transfer_worker_ref = false);
    // The caller holds the socket's TCP lock and owns the reference retained when close parked.
    void resume_parked_socket_control_locked(sockinfo_tcp *sock);

    void notify_ring_added(ring *rng) override;

    wakeup_reason wait_for_interrupt(int timeout_ms);
    void wakeup();

    bool is_sleeping() const { return m_sleeping.load(std::memory_order_acquire); }

    // Called only by the XLIO thread executing this context.
    void add_incoming_socket(sockinfo *sock);
    void reuse_worker_sockfd(int fd, sockinfo_tcp *sock);

    // Records which entity context the calling thread executes. Set once by the worker thread
    // at startup so same-worker confinement contracts can be asserted; a thread that executes
    // no context reads nullptr.
    static void set_executing_thread_context(entity_context *context);
    static entity_context *executing_thread_context();

    /*
     * The single destruction executor for every worker-managed POSIX TCP socket: whoever wins
     * the destruction claim calls this and nothing else. It unpublishes the fd slot
     * unconditionally before the object is freed - close-time paths already cleared the slot to
     * make the number reusable, and this backstop makes the unpublish-before-free rule that the
     * fd-based call admission relies on hold by construction on every destruction path. Pass the
     * retirement owner when the socket has one so its context-side bookkeeping is dropped; pass
     * nullptr for a socket that was never handed to a worker. Call with no socket or
     * fd-collection lock held.
     */
    static void complete_worker_socket_destroy(entity_context *owner, sockinfo_tcp *sock);

private:
    void connect_socket_job(const job_desc &job);
    void tx_data_job(const job_desc &job);
    void rx_data_recvd_job(const job_desc &job);
    void listen_socket_job(const job_desc &job);
    void close_socket_job(const job_desc &job);
    void shutdown_socket_job(const job_desc &job);
    void control_socket_job(const job_desc &job);
    void process_jobs();
    void repost_socket_control_node_locked(sockinfo_tcp *sock);
    void track_root_listener_retirement(sockinfo_tcp *sock);
    void add_worker_socket(sockinfo_tcp *sock);
    void close_worker_socket_helper(sockinfo_tcp *sock, bool force);

    static void entity_context_comp_cb(xlio_socket_t sock, uintptr_t userdata_sq,
                                       uintptr_t userdata_op);

    void arm_cq_notifications();
    void drain_wakeup_fd();

    job_queue<job_desc> m_job_queue;
    // Counts control-owner references across QUEUED, PROCESSING, and PARKED states.
    // A PARKED control is off the ready list, so this count is what keeps shutdown draining
    // until the parked close is resumed and consumed.
    std::atomic<size_t> m_socket_control_items {0U};
    worker_retirement_registry m_root_listener_retirements;
    size_t m_index;
    size_t m_last_job_size = 0U;
    event_handler_manager_local::time_point m_prev_proc_time;
    bool m_last_poll_hit = false;
    entity_context_stats_t m_stats;

    std::atomic<bool> m_sleeping {false};
    int m_wakeup_fd = -1;
    int m_epoll_fd = -1;
};

#endif
