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

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <climits>
#include <cstdlib>

#include "entity_context.h"
#include "vlogger/vlogger.h"
#include "dev/ring.h"
#include "sock/fd_collection.h"
#include "sock/sockinfo_tcp.h"
#include "sock/worker_shutdown_result.h"
#include "sock/sock-redirect.h"

using namespace std::chrono;

#define MODULE_NAME "entity_context"

#define ctx_logpanic __log_panic
#define ctx_logerr   __log_err
#define ctx_logwarn  __log_warn
#define ctx_loginfo  __log_info_info
#define ctx_logdbg   __log_info_dbg

namespace {

#ifdef _DEBUG

// Debug-only test seam: pauses the worker's close consumption points ('D'/'R'/'C' event points);
// driven by tests/extra_api/blocking_socket_workers_e2e recv-close-fence-order / recv-close-copy.
constexpr const char *WORKER_CONTROL_TEST_TARGET_FD = "XLIO_TEST_WORKER_CONTROL_TARGET_FD";
constexpr const char *WORKER_CONTROL_TEST_EVENT_FD = "XLIO_TEST_WORKER_CONTROL_EVENT_FD";
constexpr const char *WORKER_CONTROL_TEST_RELEASE_FD = "XLIO_TEST_WORKER_CONTROL_RELEASE_FD";

int worker_control_test_fd(const char *name)
{
    const int saved_errno = errno;
    const char *value = std::getenv(name);
    char *end = nullptr;
    long parsed = -1;

    if (value) {
        errno = 0;
        parsed = std::strtol(value, &end, 10);
        if (errno != 0 || end == value || *end != '\0' || parsed < 0 || parsed > INT_MAX) {
            parsed = -1;
        }
    }
    errno = saved_errno;
    return static_cast<int>(parsed);
}

bool worker_control_test_matches(const sockinfo_tcp *sock)
{
    return sock && worker_control_test_fd(WORKER_CONTROL_TEST_TARGET_FD) == sock->get_fd();
}

bool worker_control_test_write_event(const sockinfo_tcp *sock, char event)
{
    if (!worker_control_test_matches(sock)) {
        return false;
    }

    const int event_fd = worker_control_test_fd(WORKER_CONTROL_TEST_EVENT_FD);
    if (event_fd < 0) {
        return false;
    }

    const int saved_errno = errno;
    ssize_t result;
    do {
        result = write(event_fd, &event, sizeof(event));
    } while (result < 0 && errno == EINTR);
    errno = saved_errno;
    return result == static_cast<ssize_t>(sizeof(event));
}

void worker_control_test_after_dequeue(const sockinfo_tcp *sock)
{
    const int release_fd = worker_control_test_fd(WORKER_CONTROL_TEST_RELEASE_FD);
    if (release_fd < 0 || !worker_control_test_write_event(sock, 'D')) {
        return;
    }

    const int saved_errno = errno;
    char release = 0;
    ssize_t result;
    do {
        result = read(release_fd, &release, sizeof(release));
    } while (result < 0 && errno == EINTR);
    errno = saved_errno;
}

#else

bool worker_control_test_write_event(const sockinfo_tcp *, char)
{
    return false;
}

void worker_control_test_after_dequeue(const sockinfo_tcp *)
{
}

#endif

// The entity context the calling thread executes, set once by the worker thread at startup.
// Backs the same-worker confinement asserts; a non-worker thread reads nullptr.
thread_local entity_context *s_executing_thread_context = nullptr;

} // namespace

void entity_context::set_executing_thread_context(entity_context *context)
{
    s_executing_thread_context = context;
}

entity_context *entity_context::executing_thread_context()
{
    return s_executing_thread_context;
}

entity_context::job_reservation::job_reservation(
    entity_context *context, sockinfo_tcp *ref_sock,
    job_queue<job_desc>::reservation &&queue_reservation, job_submit_result result)
    : m_context(context)
    , m_ref_sock(ref_sock)
    , m_queue_reservation(std::move(queue_reservation))
    , m_result(result)
{
}

entity_context::job_reservation::job_reservation(job_reservation &&other) noexcept
    : m_context(other.m_context)
    , m_ref_sock(other.m_ref_sock)
    , m_queue_reservation(std::move(other.m_queue_reservation))
    , m_result(other.m_result)
{
    other.m_context = nullptr;
    other.m_ref_sock = nullptr;
}

entity_context::job_reservation &entity_context::job_reservation::operator=(
    job_reservation &&other) noexcept
{
    if (this != &other) {
        reset();
        m_context = other.m_context;
        m_ref_sock = other.m_ref_sock;
        m_queue_reservation = std::move(other.m_queue_reservation);
        m_result = other.m_result;
        other.m_context = nullptr;
        other.m_ref_sock = nullptr;
    }
    return *this;
}

entity_context::job_reservation::~job_reservation()
{
    reset();
}

entity_context::job_submit_result entity_context::job_reservation::commit(const job_desc &job)
{
    if (!m_context) {
        return m_result;
    }

    entity_context *context = m_context;
    m_context = nullptr;
    const job_queue_submit_result queue_result = m_queue_reservation.commit(job);
    if (queue_result == job_queue_submit_result::ACCEPTED) {
        m_ref_sock = nullptr;
        m_result = job_submit_result::ACCEPTED;
        std::atomic_thread_fence(std::memory_order_seq_cst);
        if (context->m_sleeping.load(std::memory_order_acquire)) {
            context->wakeup();
        }
        return m_result;
    }

    if (m_ref_sock) {
        m_ref_sock->release_worker_ref();
        m_ref_sock = nullptr;
    }
    m_result = job_submit_result::NO_MEMORY;
    return m_result;
}

void entity_context::job_reservation::reset()
{
    m_queue_reservation.reset();
    if (m_ref_sock) {
        m_ref_sock->release_worker_ref();
        m_ref_sock = nullptr;
    }
    m_context = nullptr;
}

entity_context::entity_context(size_t index)
    : poll_group(xlio_poll_group_attr {XLIO_GROUP_FLAG_SAFE | XLIO_GROUP_FLAG_DIRTY, nullptr,
                                       entity_context_comp_cb, nullptr, nullptr})
    , m_index(index)
    , m_prev_proc_time(steady_clock::now())
{
    memset(&m_stats, 0, sizeof(m_stats));
    xlio_stats_instance_create_ent_ctx_block(&m_stats);

    get_event_handler()->do_tasks(); // Update last_taken_time

    m_wakeup_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (m_wakeup_fd < 0) {
        ctx_logerr("Failed to create wakeup eventfd (errno=%d %m)", errno);
    }

    m_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (m_epoll_fd < 0) {
        ctx_logerr("Failed to create interrupt epoll fd (errno=%d %m)", errno);
    }

    if (m_epoll_fd >= 0 && m_wakeup_fd >= 0) {
        struct epoll_event ev = {};
        ev.events = EPOLLIN;
        ev.data.fd = m_wakeup_fd;
        if (epoll_ctl(m_epoll_fd, EPOLL_CTL_ADD, m_wakeup_fd, &ev) < 0) {
            ctx_logerr("Failed to add wakeup fd to epoll (errno=%d %m)", errno);
        }
    }

    ctx_logdbg("Entity Context created (%p)", this);
}

entity_context::~entity_context()
{
    assert(!m_job_queue.has_pending());
    assert(m_socket_control_items.load(std::memory_order_acquire) == 0U);
    assert(!has_owned_sockets());

    auto &jobs = m_job_queue.get_all();
    // Contract-violation backstop: the asserts above require destruction with no pending work,
    // so in a correct run this drain sees an empty snapshot. When a release build (asserts
    // compiled out) gets here with entries anyway, only the per-job worker references of data
    // jobs are dropped; a pending control entry keeps its owner reference, so its socket is
    // deliberately LEAKED. With the ordering contract already violated, leaking is the safe
    // failure mode - running or freeing the socket from a dying context could double-destroy
    // state another thread still owns.
    for (const job_desc &job : jobs) {
        if (job.job_id != JOB_TYPE_SOCK_CONTROL && job.sock &&
            job.sock->get_protocol() == PROTO_TCP) {
            sockinfo_tcp *tcp_sock = static_cast<sockinfo_tcp *>(job.sock);
            if (tcp_sock->is_worker_posix_managed()) {
                tcp_sock->release_worker_ref();
            }
        }
    }
    jobs.clear();

    xlio_stats_instance_remove_ent_ctx_block(&m_stats);

    if (m_epoll_fd >= 0) {
        close(m_epoll_fd);
    }
    if (m_wakeup_fd >= 0) {
        close(m_wakeup_fd);
    }

    ctx_logdbg("Entity Context destroyed (%p)", this);
}

void entity_context::process()
{
    auto ts = steady_clock::now();
    (!m_last_poll_hit ? m_stats.idle_time : m_stats.hit_poll_time) +=
        duration_cast<nanoseconds>(get_event_handler()->last_taken_time() - m_prev_proc_time)
            .count();
    (!m_last_job_size ? m_stats.idle_time : m_stats.job_proc_time) +=
        duration_cast<nanoseconds>(ts - get_event_handler()->last_taken_time()).count();
    m_prev_proc_time = ts;

    m_last_poll_hit = poll();

    process_jobs();

    flush();
}

void entity_context::process_jobs()
{
    auto &jobs = m_job_queue.get_all();
    for (auto &job : jobs) {
        switch (job.job_id) {
        case JOB_TYPE_SOCK_ADD_AND_CONNECT:
            connect_socket_job(job);
            break;
        case JOB_TYPE_SOCK_ADD_AND_LISTEN:
            listen_socket_job(job);
            break;
        case JOB_TYPE_SOCK_TX:
            tx_data_job(job);
            break;
        case JOB_TYPE_SOCK_RX_DATA_RECVD:
            rx_data_recvd_job(job);
            break;
        case JOB_TYPE_SOCK_CLOSE:
            close_socket_job(job);
            break;
        case JOB_TYPE_SOCK_SHUTDOWN:
            shutdown_socket_job(job);
            break;
        case JOB_TYPE_SOCK_CONTROL:
            // The control tail consumes its own owner reference and may destroy the socket, so
            // the blanket per-job reference release below must not run for this entry.
            control_socket_job(job);
            continue;
        default:
            // Unknown job type
            break;
        }
        if (job.sock && job.sock->get_protocol() == PROTO_TCP) {
            sockinfo_tcp *tcp_sock = static_cast<sockinfo_tcp *>(job.sock);
            if (tcp_sock->is_worker_posix_managed()) {
                tcp_sock->release_worker_ref();
            }
        }
    }

    m_stats.job_queue_size_acc += static_cast<uint32_t>(jobs.size());
    m_stats.job_queue_hits += (jobs.size() ? 1 : 0);
    m_stats.job_queue_size_max =
        std::max(m_stats.job_queue_size_max, static_cast<uint32_t>(jobs.size()));
    m_last_job_size = jobs.size();
    jobs.clear();
}

entity_context::job_reservation entity_context::reserve_job(sockinfo *sock)
{
    sockinfo_tcp *tcp_sock = nullptr;
    if (sock && sock->get_protocol() == PROTO_TCP) {
        tcp_sock = static_cast<sockinfo_tcp *>(sock);
        if (tcp_sock->is_worker_posix_managed() && !tcp_sock->try_acquire_worker_job_ref()) {
            return job_reservation(nullptr, nullptr, {}, job_submit_result::SOCKET_RETIRED);
        }
    }

    job_queue<job_desc>::reservation queue_reservation = m_job_queue.reserve();
    if (!queue_reservation) {
        if (tcp_sock && tcp_sock->is_worker_posix_managed()) {
            tcp_sock->release_worker_ref();
        }
        const job_submit_result result =
            queue_reservation.result() == job_queue_submit_result::CLOSED
            ? job_submit_result::ADMISSION_CLOSED
            : job_submit_result::NO_MEMORY;
        return job_reservation(nullptr, nullptr, {}, result);
    }

    return job_reservation(this, tcp_sock, std::move(queue_reservation),
                           job_submit_result::ACCEPTED);
}

entity_context::job_submit_result entity_context::add_job(const job_desc &job)
{
    job_reservation reservation = reserve_job(job.sock);
    return reservation ? reservation.commit(job) : reservation.result();
}

void entity_context::close_job_admission()
{
    m_job_queue.close_admission();
    wakeup();
}

bool entity_context::has_pending_work()
{
    return m_job_queue.has_runnable();
}

bool entity_context::has_unsettled_work()
{
    return m_job_queue.has_pending() ||
        m_socket_control_items.load(std::memory_order_acquire) != 0U;
}

bool entity_context::post_socket_control_locked(sockinfo_tcp *sock, uint32_t controls,
                                                bool transfer_worker_ref)
{
    assert(sock);
    assert(controls != 0U);
    assert(sock->is_worker_posix_managed());

    if (sock->worker_state().m_control_parked) {
        assert(!sock->worker_state().m_control_queued);
        assert(sock->worker_state().m_control_pending & SOCKET_CONTROL_CLOSE);
        assert(m_socket_control_items.load(std::memory_order_acquire) > 0U);
        if (transfer_worker_ref) {
            const worker_lifetime_release action = sock->worker_state().m_lifetime.release();
            assert(action == worker_lifetime_release::NONE);
            (void)action;
        }
    } else if (!sock->worker_state().m_control_queued) {
        if (!transfer_worker_ref && !sock->try_acquire_worker_job_ref()) {
            return false;
        }

        /*
         * The control rides the one job FIFO on the socket's preallocated node. The append is
         * the ordering point, so a destructive close processes after every job this socket
         * published before the close was posted, and an unpublished reservation of another
         * socket cannot delay it.
         */
        sock->worker_state().m_control_queued = true;
        m_socket_control_items.fetch_add(1U, std::memory_order_release);
        repost_socket_control_node_locked(sock);
    } else if (transfer_worker_ref) {
        const worker_lifetime_release action = sock->worker_state().m_lifetime.release();
        assert(action == worker_lifetime_release::NONE);
        (void)action;
    }

    sock->worker_state().m_control_pending |= controls;
    wakeup();
    return true;
}

void entity_context::repost_socket_control_node_locked(sockinfo_tcp *sock)
{
    assert(sock->worker_state().m_control_queued);
    assert(!sock->worker_state().m_control_parked);

    m_job_queue.post_pinned(sock->worker_state().m_control_node,
                            job_desc {JOB_TYPE_SOCK_CONTROL, 0, sock, nullptr, 0U, 0U});
}

void entity_context::resume_parked_socket_control_locked(sockinfo_tcp *sock)
{
    assert(sock);
    assert(sock->is_worker_posix_managed());
    assert(sock->worker_state().m_retire_owner == this);
    assert(sock->worker_state().m_control_parked);
    assert(!sock->worker_state().m_control_queued);
    assert(sock->worker_state().m_control_pending != 0U);
    assert(sock->worker_state().m_control_pending & SOCKET_CONTROL_CLOSE);
    assert(m_socket_control_items.load(std::memory_order_acquire) > 0U);

    sock->worker_state().m_control_parked = false;
    sock->worker_state().m_control_queued = true;
    repost_socket_control_node_locked(sock);

    wakeup();
}

void entity_context::control_socket_job(const job_desc &job)
{
    assert(job.sock);
    sockinfo_tcp *sock = static_cast<sockinfo_tcp *>(job.sock);

    // Debug builds expose a deterministic scheduling point for the worker RX/close ordering
    // regression. Release builds compile this hook to an empty inlineable function.
    worker_control_test_after_dequeue(sock);

    bool destroy = false;
    sock->lock_tcp_con();
    assert(sock->worker_state().m_control_queued);
    const bool republish = sock->worker_state().m_control_republish;
    sock->worker_state().m_control_republish = false;
    const uint32_t controls = sock->worker_state().m_control_pending;
    sock->worker_state().m_control_pending = 0U;
    sock->worker_state().m_control_queued = false;

    if (controls & SOCKET_CONTROL_CANCEL_CONNECT) {
        sock->cancel_connect_entity_context();
    }

    if ((controls & SOCKET_CONTROL_CLOSE) &&
        sock->worker_state().m_rx_close_barrier.defer_close_if_active()) {
        /*
         * rx_fetch_ready_buffers() temporarily owns receive descriptors and the shared
         * descriptor offset outside the TCP lock while copying to application memory.
         * Keep this control's existing owner reference, but park it off the ready list so
         * a page-fault-stalled copy cannot make the worker spin.
         * The RX guard re-appends this control after the last admitted call leaves.
         */
        const uint32_t deferred_controls = controls & ~SOCKET_CONTROL_CANCEL_CONNECT;
        assert(deferred_controls != 0U);
        assert(!sock->worker_state().m_control_parked);
        sock->worker_state().m_control_pending |= deferred_controls;
        sock->worker_state().m_control_parked = true;
        assert(sock->worker_state().m_control_pending & SOCKET_CONTROL_CLOSE);
        assert(m_socket_control_items.load(std::memory_order_acquire) > 0U);
        sock->unlock_tcp_con();
        return;
    }

    if ((controls & SOCKET_CONTROL_CLOSE) && republish) {
        /*
         * A retirement-observing RX departure committed a receive-completion job while this
         * control was already in the queue pipeline, so FIFO position alone cannot order the
         * close after it. Re-append the control behind that job and keep the owner reference.
         * Retirement admits no new RX calls, so this repeats at most once per call that was
         * admitted before retirement.
         */
        const uint32_t deferred_controls = controls & ~SOCKET_CONTROL_CANCEL_CONNECT;
        assert(deferred_controls != 0U);
        sock->worker_state().m_control_pending |= deferred_controls;
        sock->worker_state().m_control_queued = true;
        repost_socket_control_node_locked(sock);
        sock->unlock_tcp_con();
        return;
    }

    bool root_listener_retirement = false;
    if (controls & SOCKET_CONTROL_CLOSE) {
        const bool force = (controls & SOCKET_CONTROL_FORCE_CLOSE) != 0U;
        if (sock->get_entity_context() == this) {
            close_socket_job(job_desc {JOB_TYPE_SOCK_CLOSE, force ? JOB_FLAG_FORCE_CLOSE : 0, sock,
                                       nullptr, 0U, 0U});
        } else {
            assert(sock->get_listen_context());
            assert(!sock->is_sockinfo_tcp_listen_rss_child());
            sock->prepare_to_close(force);
            root_listener_retirement = true;
        }
        sock->worker_state().m_close_processed = true;
    }

    if (sock->worker_state().m_close_processed && sock->is_closable() &&
        sock->worker_ref_count() == 1U) {
        destroy = sock->worker_state().m_lifetime.consume_owner_ref_and_claim_destruction();
    }

    if (!destroy) {
        if (root_listener_retirement) {
            track_root_listener_retirement(sock);
        }
        const worker_lifetime_release action = sock->worker_state().m_lifetime.release();
        if (action == worker_lifetime_release::RECHECK_RETIREMENT &&
            sock->worker_state().m_close_processed && sock->is_closable()) {
            destroy = sock->worker_state().m_lifetime.try_claim_destruction_without_ref();
        }
    }
    const size_t control_items_before =
        m_socket_control_items.fetch_sub(1U, std::memory_order_acq_rel);
    assert(control_items_before > 0U);
    (void)control_items_before;
    sock->unlock_tcp_con();

    if (destroy) {
        complete_worker_socket_destroy(this, sock);
    }
}

void entity_context::track_root_listener_retirement(sockinfo_tcp *sock)
{
    if (!m_root_listener_retirements.contains(sock->worker_state().m_retirement_link)) {
        m_root_listener_retirements.track(sock->worker_state().m_retirement_link);
    }
}

void entity_context::complete_worker_socket_destroy(entity_context *owner, sockinfo_tcp *sock)
{
    /*
     * Unconditional unpublish-before-free backstop. Most destructions arrive with the slot
     * already cleared (close claimed the fd number for reuse); a stale publication would let a
     * new fd-based call admit against freed memory, so clearing here - before the free, on the
     * one path every destruction takes - upholds that rule by construction rather than per
     * caller. clear_socket_if() only clears a slot still holding this socket and ignores
     * invalid fds (unpublished RSS children carry a fake fd).
     */
    if (g_p_fd_collection) {
        g_p_fd_collection->clear_socket_if(sock->get_fd(), sock);
    }
    if (owner) {
        if (owner->m_root_listener_retirements.contains(sock->worker_state().m_retirement_link)) {
            owner->m_root_listener_retirements.untrack(sock->worker_state().m_retirement_link);
        }
        owner->m_pending_to_remove_lst.remove(sock);
    }
    sock->clean_socket_obj();
}

void entity_context::add_worker_socket(sockinfo_tcp *sock)
{
    add_socket_helper(sock);
    g_p_fd_collection->publish_worker_socket_if_open(sock->get_fd(), sock);
}

void entity_context::reuse_worker_sockfd(int fd, sockinfo_tcp *sock)
{
    // TIME_WAIT reuse publish is confined to the owning worker: the rss-child listener's close
    // control and this reuse RX path execute on the same entity-context thread, which is what
    // keeps the unlocked publish window safe against a concurrent listener close.
    assert(this == executing_thread_context());
    m_pending_to_remove_lst.remove(sock);
    const bool published = g_p_fd_collection->publish_worker_socket_if_open(fd, sock);
    if (unlikely(!published)) {
        ctx_logerr("Failed to republish reused worker socket (sock: %p, fd: %d)", sock, fd);
    }
    assert(published);
    m_sockets_list.push_back(sock);
}

void entity_context::close_worker_socket_helper(sockinfo_tcp *sock, bool force)
{
    remove_socket(sock);
    sock->prepare_to_close(force);
    m_pending_to_remove_lst.push_back(sock);
}

void entity_context::connect_socket_job(const job_desc &job)
{
    sockinfo *sock = job.sock;
    if (sock->get_protocol() == PROTO_TCP) {
        sockinfo_tcp *tcp_sock = static_cast<sockinfo_tcp *>(sock);
        sock->set_entity_context(this);
        add_worker_socket(tcp_sock);
        tcp_sock->connect_entity_context();
        if (sock->isPassthrough()) {
            // Blocking connect is parked on this socket and already woken by setPassthrough()+
            // do_wakeup(). Do not handle_close() here (would destroy sock under the app thread).
            // The woken connect() returns -1 and the redirect OS-connects. Non-blocking (already
            // returned EINPROGRESS) is OS-connected here. Use the post-time snapshot, not live
            // is_blocking().
            if (job.flags & JOB_FLAG_SOCK_BLOCKING) {
                return;
            }
            int fd = sock->get_fd();
            /* copy before handle_close may destroy sock */
            sock_addr peer = sock->get_peername();
            handle_close(fd, false, true);
            SYSCALL(connect, fd, peer.get_p_sa(), peer.get_socklen());
            return;
        }
        ++m_stats.socket_num_added;
        ctx_logdbg("New TCP socket added (sock: %p)", sock);
    } else {
        ctx_logdbg("Unsupported socket protocol %hd for Threads mode", sock->get_protocol());
    }
}

void entity_context::tx_data_job(const job_desc &job)
{
    if (unlikely(!job.buf || !job.sock)) {
        ctx_logwarn("Invalid TX job");
        return;
    }
    job.sock->tx_thread_commit(job.buf, job.offset, job.tot_size, job.flags);
}

void entity_context::add_incoming_socket(sockinfo *sock)
{
    if (sock->get_protocol() == PROTO_TCP) {
        ++m_stats.socket_num_added;
        add_worker_socket(reinterpret_cast<sockinfo_tcp *>(sock));
    }
}

void entity_context::rx_data_recvd_job(const job_desc &job)
{
    if (job.sock && job.sock->get_protocol() == PROTO_TCP) {
        (void)worker_control_test_write_event(static_cast<sockinfo_tcp *>(job.sock), 'R');
    }

    if (job.buf) {
        /* coverity[check_return] */
        job.buf->p_desc_owner->reclaim_recv_buffers(job.buf);
    }

    if (job.sock) {
        job.sock->rx_data_recvd(job.tot_size);
    }
}

void entity_context::listen_socket_job(const job_desc &job)
{
    sockinfo *sock = job.sock;
    if (sock->get_protocol() == PROTO_TCP) {
        sock->set_entity_context(this);
        add_socket_helper(reinterpret_cast<sockinfo_tcp *>(sock));
        reinterpret_cast<sockinfo_tcp *>(sock)->listen_entity_context();
        ++m_stats.listen_rsschild_num;
        ctx_logdbg("New TCP Listen rss_child socket added (sock: %p)", sock);
    } else {
        ctx_logdbg("Unsupported socket protocol %hd for Threads mode", sock->get_protocol());
    }
}

void entity_context::close_socket_job(const job_desc &job)
{
    sockinfo *si = job.sock;
    assert(si);

    ctx_logdbg("Processing close job for socket (sock: %p, fd: %d)", si, si->get_fd());

    if (si->get_protocol() == PROTO_TCP) {
        sockinfo_tcp *tcp_si = reinterpret_cast<sockinfo_tcp *>(si);

        (void)worker_control_test_write_event(tcp_si, 'C');

        if (tcp_si->get_listen_context()) {
            assert(tcp_si->get_listen_context()->is_rss_child_listen_socket());
            // If this is a listen RSS child, notify parent.
            // Note: We must notify parent BEFORE calling close_socket_helper():
            // - If we close the socket first, we lose the reference to the parent
            // - It's safe to close socket after parent notification because:
            //   1. Entity context runs on a single thread
            //   2. No other thread can poll for new incoming connections while we're here
            //   3. Therefore, we won't call parent epoll notify after this point
            // - This avoids backing up parent reference and keeps code clean
            sockinfo_tcp *parent = tcp_si->get_listen_context()->get_parent_listen_socket();
            parent->get_listen_context()->increment_close_counter();
            --m_stats.listen_rsschild_num;
        } else if (!tcp_si->isPassthrough()) {
            ++m_stats.socket_num_removed;
        }
        // Use poll_group::close_socket_helper which handles :
        // - remove_socket(si)
        // - prepare_to_close() and clean_socket_obj() or add to pending close list
        close_worker_socket_helper(tcp_si, (job.flags & JOB_FLAG_FORCE_CLOSE) != 0);
    }
}

void entity_context::shutdown_socket_job(const job_desc &job)
{
    assert(job.sock);
    assert(job.shutdown_result);

    int rc = -1;
    int error = EINVAL;
    if (job.sock->get_protocol() == PROTO_TCP) {
        rc = static_cast<sockinfo_tcp *>(job.sock)->shutdown_entity_context(job.shutdown_how);
        error = rc < 0 ? errno : 0;
    }
    job.shutdown_result->complete(rc, error);
}

void entity_context::drain_worker_sockets_for_shutdown()
{
    while (!m_sockets_list.empty()) {
        sockinfo_tcp *sock = static_cast<sockinfo_tcp *>(m_sockets_list.front());
        bool destroy = false;

        sock->lock_tcp_con();
        if (!sock->is_worker_posix_managed()) {
            sock->unlock_tcp_con();
            close_socket_helper(sock, true);
            continue;
        }

        bool claimed_retirement = false;
        if (sock->worker_lifecycle() == worker_socket_lifecycle::OPEN) {
            claimed_retirement = sock->begin_worker_retirement();
            const bool claimed = claimed_retirement;
            assert(claimed);
            (void)claimed;
        }
        worker_retirement_owner_ref retirement_owner_ref(
            claimed_retirement ? &sock->worker_state().m_lifetime : nullptr);
        assert(sock->worker_state().m_rx_close_barrier.active_calls() == 0U);
        assert(!sock->worker_state().m_rx_close_barrier.close_waiting());
        assert(!sock->worker_state().m_control_parked);
        remove_socket(sock);
        sock->prepare_to_close(true);
        sock->worker_state().m_close_processed = true;
        if (retirement_owner_ref) {
            destroy = retirement_owner_ref.complete(sock->is_closable());
        } else if (sock->worker_ref_count() == 0U) {
            destroy = sock->worker_state().m_lifetime.try_claim_destruction_without_ref();
        }
        if (!destroy) {
            m_pending_to_remove_lst.push_back(sock);
        }
        sock->unlock_tcp_con();

        if (destroy) {
            complete_worker_socket_destroy(this, sock);
        }
    }

    auto iter = m_pending_to_remove_lst.begin();
    while (iter != m_pending_to_remove_lst.end()) {
        sockinfo_tcp *sock = *iter;
        ++iter;
        if (!sock->is_worker_posix_managed()) {
            continue;
        }

        bool destroy = false;
        sock->lock_tcp_con();
        assert(sock->worker_state().m_rx_close_barrier.active_calls() == 0U);
        assert(!sock->worker_state().m_rx_close_barrier.close_waiting());
        assert(!sock->worker_state().m_control_parked);
        sock->prepare_to_close(true);
        sock->worker_state().m_close_processed = true;
        if (sock->worker_ref_count() == 0U) {
            destroy = sock->worker_state().m_lifetime.try_claim_destruction_without_ref();
        }
        sock->unlock_tcp_con();
        if (destroy) {
            complete_worker_socket_destroy(this, sock);
        }
    }
}

bool entity_context::has_owned_sockets() const
{
    return !m_sockets_list.empty() || !m_pending_to_remove_lst.empty() ||
        !m_root_listener_retirements.empty();
}

void entity_context::arm_cq_notifications()
{
    for (ring *rng : get_rings()) {
        bool success = rng->request_notification(CQT_RX);
        if (unlikely(!success)) {
            ctx_logerr("Failed to arm CQ notification for ring %p", rng);
        }
    }
}

void entity_context::drain_wakeup_fd()
{
    uint64_t val;
    int ret = read(m_wakeup_fd, &val, sizeof(val));
    if (unlikely(ret < 0 && errno != EAGAIN)) {
        ctx_logerr("Failed to read from wakeup fd (errno=%d %m)", errno);
    }
}

entity_context::wakeup_reason entity_context::wait_for_interrupt(int timeout_ms)
{
    wakeup_reason reason = WAKEUP_NONE;

    if (m_epoll_fd < 0 || m_wakeup_fd < 0) {
        return WAKEUP_NONE;
    }

    arm_cq_notifications();

    // Race avoidance: re-poll CQ after arming.
    if (poll()) {
        return WAKEUP_CQ_EVENT;
    }

    m_sleeping.store(true, std::memory_order_release);

    // Final re-check after setting sleeping flag. An app thread that inserted
    // a job between our has_pending() check and the store above will either:
    // (a) have its job visible if we re-check now, or
    // (b) see m_sleeping==true and write to wakeup_fd.
    if (has_pending_work()) {
        m_sleeping.store(false, std::memory_order_release);
        return WAKEUP_JOB_POSTED;
    }

    static constexpr int MAX_EVENTS = 8;
    struct epoll_event events[MAX_EVENTS];
    int nfds;

    do {
        nfds = SYSCALL(epoll_wait, m_epoll_fd, events, MAX_EVENTS, timeout_ms);
    } while (nfds == -1 && errno == EINTR && !g_b_exit);

    // TODO: handle EINTR and g_b_exit.

    if (unlikely(nfds == -1)) {
        ctx_logerr("Failed to wait for epoll events (errno=%d %m)", errno);
        return WAKEUP_NONE;
    }

    m_sleeping.store(false, std::memory_order_release);

    if (nfds == 0) {
        return WAKEUP_TIMEOUT;
    }

    for (int i = 0; i < nfds; ++i) {
        if (events[i].data.fd == m_wakeup_fd) {
            drain_wakeup_fd();
            if (reason == WAKEUP_NONE) {
                reason = WAKEUP_JOB_POSTED;
            }
        } else {
            cq_channel_info *p_cq_ch_info = g_p_fd_collection
                ? g_p_fd_collection->get_cq_channel_fd(events[i].data.fd)
                : nullptr;
            if (p_cq_ch_info) {
                ring *p_ring = p_cq_ch_info->get_ring();
                p_ring->ack_cq_events();
            }
            // CQ event has higher priority than job posted.
            reason = WAKEUP_CQ_EVENT;
        }
    }

    return reason;
}

void entity_context::wakeup()
{
    if (m_wakeup_fd >= 0) {
        const uint64_t val = 1;
        if (write(m_wakeup_fd, &val, sizeof(val)) < 0 && errno != EAGAIN) {
            ctx_logerr("Failed to write to wakeup fd (errno=%d %m)", errno);
        }
    }
}

/*static*/
void entity_context::entity_context_comp_cb(xlio_socket_t sock, uintptr_t userdata_sq,
                                            uintptr_t userdata_op)
{
    mem_buf_desc_t *buf = reinterpret_cast<mem_buf_desc_t *>(userdata_op);

    NOT_IN_USE(sock);
    NOT_IN_USE(userdata_sq);

    if (buf->lwip_pbuf.ref > 1) {
        // Optimization to reduce the number of ring locks.
        --buf->lwip_pbuf.ref;
    } else {
        buf->p_desc_owner->mem_buf_tx_release(buf, true);
    }
}

void entity_context::notify_ring_added(ring *rng)
{
    size_t num_fds = 0;
    int *fds = rng->get_rx_channel_fds(num_fds);
    for (size_t i = 0; i < num_fds; ++i) {
        struct epoll_event ev = {};
        ev.events = EPOLLIN;
        ev.data.fd = fds[i];
        if (epoll_ctl(m_epoll_fd, EPOLL_CTL_ADD, fds[i], &ev) < 0 && errno != EEXIST) {
            ctx_logerr("Failed to add CQ channel fd %d to epoll (errno=%d %m)", fds[i], errno);
        }
    }
}
