/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <sys/resource.h>

#include "utils/bullseye.h"
#include "util/libxlio.h"
#include "fd_collection.h"
#include "sock-redirect.h"
#include "sockinfo.h"
#include "sockinfo_udp.h"
#include "sockinfo_tcp.h"
#include "event/entity_context.h"
#include "event/event_handler_manager.h"
#include "iomux/epfd_info.h"

#undef MODULE_NAME
#define MODULE_NAME "fdc:"
#undef MODULE_HDR
#define MODULE_HDR MODULE_NAME "%d:%s() "

#define fdcoll_logpanic   __log_panic
#define fdcoll_logerr     __log_err
#define fdcoll_logwarn    __log_warn
#define fdcoll_loginfo    __log_info
#define fdcoll_logdetails __log_details
#define fdcoll_logdbg     __log_dbg
#define fdcoll_logfunc    __log_func

fd_collection *g_p_fd_collection = nullptr;

fd_collection::socket_call_ref::socket_call_ref(socket_call_ref &&other) noexcept
    : m_sock(other.m_sock)
    , m_owns_worker_ref(other.m_owns_worker_ref)
    , m_status(other.m_status)
{
    other.m_sock = nullptr;
    other.m_owns_worker_ref = false;
    other.m_status = socket_call_status::NOT_XLIO;
}

fd_collection::socket_call_ref &fd_collection::socket_call_ref::operator=(
    socket_call_ref &&other) noexcept
{
    if (this != &other) {
        reset();
        m_sock = other.m_sock;
        m_owns_worker_ref = other.m_owns_worker_ref;
        m_status = other.m_status;
        other.m_sock = nullptr;
        other.m_owns_worker_ref = false;
        other.m_status = socket_call_status::NOT_XLIO;
    }
    return *this;
}

void fd_collection::socket_call_ref::release_worker_socket_ref(sockinfo *sock)
{
    static_cast<sockinfo_tcp *>(sock)->release_worker_ref();
}

void fd_collection::set_socket(int fd, sockinfo *si)
{
    const bool needs_worker_ref = safe_mce_sys().worker_threads > 0 && si &&
        si->get_protocol() == PROTO_TCP && !si->is_xlio_socket();
    assert(!needs_worker_ref || static_cast<sockinfo_tcp *>(si)->is_worker_posix_managed());
    m_p_sockfd_map[fd].publish(si, needs_worker_ref);
}

fd_collection::socket_call_ref fd_collection::acquire_socket_call(int fd)
{
    // Preserve the legacy R2C lookup exactly. Only worker-mode TCP needs a synchronized fd-map
    // lookup paired with a strong object reference.
    if (safe_mce_sys().worker_threads == 0) {
        return socket_call_ref(get_sockfd(fd), false);
    }

    if (!is_valid_fd(fd)) {
        return {};
    }

    // Pointer and admission kind are one atomic snapshot. Do not dereference a worker TCP pointer
    // until the fd lock has revalidated the slot and the lifetime reference has been acquired.
    fd_socket_slot::snapshot current = m_p_sockfd_map[fd].load();
    if (!current.needs_worker_ref) {
        return socket_call_ref(current.socket, false);
    }

    lock();
    current = m_p_sockfd_map[fd].load();
    sockinfo *sock = current.socket;
    bool owns_worker_ref = false;
    socket_call_status status = sock ? socket_call_status::ACQUIRED : socket_call_status::NOT_XLIO;

    if (sock && current.needs_worker_ref) {
        sockinfo_tcp *tcp_sock = static_cast<sockinfo_tcp *>(sock);
        assert(tcp_sock->get_protocol() == PROTO_TCP);
        assert(!tcp_sock->is_xlio_socket());
        assert(tcp_sock->is_worker_posix_managed());
        owns_worker_ref = tcp_sock->try_acquire_worker_call_ref();
        if (!owns_worker_ref) {
            sock = nullptr;
            status = socket_call_status::RETIRING;
        }
    }

    unlock();
    return socket_call_ref(sock, owns_worker_ref, status);
}

bool fd_collection::publish_worker_socket_if_open(int fd, sockinfo_tcp *si)
{
    lock();
    const bool publish = is_valid_fd(fd) && si->worker_lifecycle() == worker_socket_lifecycle::OPEN;
    if (publish) {
        m_p_sockfd_map[fd].publish(si, true);
    }
    unlock();
    return publish;
}

bool fd_collection::clear_socket_if(int fd, const sockinfo *expected)
{
    lock();
    bool cleared = false;
    if (is_valid_fd(fd)) {
        if (m_p_sockfd_map[fd].load().socket == expected) {
            m_p_sockfd_map[fd].clear();
            cleared = true;
        }
    }
    unlock();
    return cleared;
}

fd_collection::worker_close_claim fd_collection::claim_worker_tcp_close(int fd)
{
    worker_close_claim claim;

    if (!is_valid_fd(fd) || !m_p_sockfd_map[fd].load().needs_worker_ref) {
        return claim;
    }

    lock();
    if (!is_valid_fd(fd)) {
        unlock();
        return claim;
    }

    fd_socket_slot::snapshot current = m_p_sockfd_map[fd].load();
    if (!current.socket || !current.needs_worker_ref) {
        unlock();
        return claim;
    }

    sockinfo_tcp *tcp_sock = static_cast<sockinfo_tcp *>(current.socket);
    assert(tcp_sock->get_protocol() == PROTO_TCP);
    assert(!tcp_sock->is_xlio_socket());
    assert(tcp_sock->is_worker_posix_managed());
    claim.sock = tcp_sock;
    if (tcp_sock->begin_worker_retirement()) {
        m_p_sockfd_map[fd].clear();
        claim.result = worker_close_result::CLAIMED;
    }

    unlock();
    return claim;
}

void fd_collection::submit_worker_tcp_close(sockinfo_tcp *sock, bool force)
{
    // Retirement is already visible to the wait predicate.
    // Wake before close control can park behind an admitted receive call.
    sock->wakeup_worker_blocking_waiters();

    sock->lock_tcp_con();
    sock->worker_state().m_force_close = sock->worker_state().m_force_close || force;
    const bool root_listener = sock->get_listen_context() &&
        !sock->is_sockinfo_tcp_listen_rss_child() &&
        sock->get_listen_context()->has_published_listen_rss_children();
    const bool force_close = sock->worker_state().m_force_close;
    sock->unlock_tcp_con();

    if (root_listener) {
        // accept_lwip_cb() reaches the root listener while the worker owns an RSS-child lock.
        // Never wait for or lock an RSS child while holding the root lock, or close can deadlock
        // against that child-to-root callback path.
        handle_listen_socket_close_worker_threads_mode(sock, force_close);
    }

    sock->lock_tcp_con();

    bool destroy = false;
    entity_context *owner = sock->get_worker_retire_owner();
    if (owner) {
        uint32_t controls = entity_context::SOCKET_CONTROL_CLOSE;
        if (sock->worker_state().m_force_close) {
            controls |= entity_context::SOCKET_CONTROL_FORCE_CLOSE;
        }
        // An in-flight blocking connect needs no cancel request here: retirement is already
        // visible and woken above, so the parked caller posts SOCKET_CONTROL_CANCEL_CONNECT
        // itself, and the close control's prepare_to_close() tears down an unattended attempt.
        const bool posted = owner->post_socket_control_locked(sock, controls, true);
        assert(posted);
        (void)posted;
        sock->unlock_tcp_con();
        return;
    }

    sock->prepare_to_close(sock->worker_state().m_force_close);
    sock->worker_state().m_close_processed = true;
    if (sock->is_closable() && sock->worker_ref_count() == 1U) {
        destroy = sock->worker_state().m_lifetime.consume_owner_ref_and_claim_destruction();
    }
    if (!destroy) {
        const worker_lifetime_release action = sock->worker_state().m_lifetime.release();
        if (action == worker_lifetime_release::RECHECK_RETIREMENT && sock->is_closable()) {
            destroy = sock->worker_state().m_lifetime.try_claim_destruction_without_ref();
        }
    }
    sock->unlock_tcp_con();

    if (destroy) {
        // The destruction claim was taken on the no-retire-owner branch above.
        entity_context::complete_worker_socket_destroy(nullptr, sock);
    }
}

void fd_collection::retire_worker_sockets_for_shutdown()
{
    for (int fd = 0; fd < m_n_fd_map_size; ++fd) {
        worker_close_claim claim = claim_worker_tcp_close(fd);
        if (claim.result != worker_close_result::CLAIMED) {
            continue;
        }

        remove_from_all_epfds(fd, false, claim.sock);
        submit_worker_tcp_close(claim.sock, true);
    }
}

fd_collection::fd_collection()
    : lock_mutex_recursive("fd_collection")
    , m_b_sysvar_offloaded_sockets(safe_mce_sys().offloaded_sockets)
#if defined(DEFINED_NGINX)
    // Avoid using socket pool for the master process (which doesn't have parent fd_collection)
    , m_use_socket_pool(safe_mce_sys().nginx_udp_socket_pool_size && g_p_app->get_worker_id() >= 0)
    , m_socket_pool_size(safe_mce_sys().nginx_udp_socket_pool_size)
    , m_socket_pool_counter(0)
#endif
{
    fdcoll_logfunc("");

    m_n_fd_map_size = 1024;
    struct rlimit rlim;
    if ((getrlimit(RLIMIT_NOFILE, &rlim) == 0) && ((int)rlim.rlim_max > m_n_fd_map_size)) {
        m_n_fd_map_size = rlim.rlim_max;
    }
    fdcoll_logdbg("using open files max limit of %d file descriptors", m_n_fd_map_size);

    m_p_sockfd_map = new fd_socket_slot[m_n_fd_map_size];

    m_p_epfd_map = new epfd_info *[m_n_fd_map_size];
    memset(m_p_epfd_map, 0, m_n_fd_map_size * sizeof(epfd_info *));

    m_p_cq_channel_map = new cq_channel_info *[m_n_fd_map_size];
    memset(m_p_cq_channel_map, 0, m_n_fd_map_size * sizeof(cq_channel_info *));
}

fd_collection::~fd_collection()
{
    fdcoll_logfunc("");

    clear();
    m_n_fd_map_size = -1;

    delete[] m_p_sockfd_map;
    m_p_sockfd_map = nullptr;

    delete[] m_p_epfd_map;
    m_p_epfd_map = nullptr;

    delete[] m_p_cq_channel_map;
    m_p_cq_channel_map = nullptr;

    m_epfd_lst.clear_without_cleanup();
    m_pending_to_remove_lst.clear_without_cleanup();
}

// Triggers connection close of all handled fds.
// This is important for TCP connection which needs some time to terminate the connection,
// before the connection can be finally and properly closed.
void fd_collection::prepare_to_close()
{
    lock();
    for (int fd = 0; fd < m_n_fd_map_size; ++fd) {
        if (get_sockfd(fd)) {
            if (!g_is_forked_child) {
                sockinfo *p_sfd_api = get_sockfd(fd);
                if (p_sfd_api) {
                    p_sfd_api->prepare_to_close(true);
                }
            }
        }
    }
    unlock();
}

// Called in destructor after Internal-Thread destroyed
void fd_collection::clear()
{
    int fd;

    fdcoll_logfunc("");

    if (!m_p_sockfd_map) {
        return;
    }

    lock();

    /* internal thread should be already dead and
     * these sockets can not be deleted through the it.
     */
    while (!m_pending_to_remove_lst.empty()) {
        sockinfo *p_sfd_api = m_pending_to_remove_lst.get_and_pop_back();
        p_sfd_api->clean_socket_obj();
    }

    g_global_stat_static.n_pending_sockets = 0;

    /* Clean up all left overs sockinfo
     */
    for (fd = 0; fd < m_n_fd_map_size; ++fd) {
        if (get_sockfd(fd)) {
            if (!g_is_forked_child) {
                sockinfo *p_sfd_api = get_sockfd(fd);
                if (p_sfd_api) {
                    p_sfd_api->statistics_print();
                    p_sfd_api->clean_socket_obj();
                }
            }

            m_p_sockfd_map[fd].clear();
            fdcoll_logdbg("destroyed fd=%d", fd);
        }

        if (m_p_epfd_map[fd]) {
            epfd_info *p_epfd = get_epfd(fd);
            if (p_epfd) {
                delete p_epfd;
            }
            m_p_epfd_map[fd] = nullptr;
            fdcoll_logdbg("destroyed epfd=%d", fd);
        }

        if (m_p_cq_channel_map[fd]) {
            cq_channel_info *p_cq_ch_info = get_cq_channel_fd(fd);
            if (p_cq_ch_info) {
                delete p_cq_ch_info;
            }
            m_p_cq_channel_map[fd] = nullptr;
            fdcoll_logdbg("destroyed cq_channel_fd=%d", fd);
        }
    }

    unlock();
    fdcoll_logfunc("done");
}

int fd_collection::addsocket(int fd, int domain, int type, bool check_offload /*= false*/)
{
    transport_t transport;
    const int SOCK_TYPE_MASK = 0xf;
    int sock_type = type & SOCK_TYPE_MASK;
    int sock_flags = type & ~SOCK_TYPE_MASK;
    sockinfo *p_sfd_api_obj;

    fdcoll_logfunc("fd=%d domain=%d type=%d", fd, domain, type);

    if (check_offload && !create_offloaded_sockets()) {
        fdcoll_logdbg(
            "socket [fd=%d, domain=%d, type=%d] is not offloaded by thread rules or by %s", fd,
            domain, type, SYS_VAR_OFFLOADED_SOCKETS);
        return -1;
    }

    if (domain != AF_INET && domain != AF_INET6) {
        return -1;
    }
    if (fd != SOCKET_FAKE_FD && !is_valid_fd(fd)) {
        return -1;
    }

    try {
        switch (sock_type) {
        case SOCK_DGRAM: {
            transport = __xlio_match_by_program(PROTO_UDP, safe_mce_sys().app_id);
            if (transport == TRANS_OS) {
                fdcoll_logdbg("All UDP rules are consistent and instructing to use OS.");
                return -1;
            }
            fdcoll_logdbg("UDP rules are either not consistent or instructing to use XLIO.");
            p_sfd_api_obj = new sockinfo_udp(fd, domain);
            break;
        }
        case SOCK_STREAM: {
            transport = __xlio_match_by_program(PROTO_TCP, safe_mce_sys().app_id);
            if (transport == TRANS_OS) {
                fdcoll_logdbg("All TCP rules are consistent and instructing to use OS.");
                return -1;
            }
            fdcoll_logdbg("TCP rules are either not consistent or instructing to use XLIO.");
            p_sfd_api_obj = new sockinfo_tcp(fd, domain);
            if (safe_mce_sys().worker_threads > 0 &&
                !static_cast<sockinfo_tcp *>(p_sfd_api_obj)->enable_worker_posix_lifetime()) {
                delete p_sfd_api_obj;
                errno = ENOMEM;
                return -1;
            }
            fd = p_sfd_api_obj->get_fd();
            break;
        }
        default:
            fdcoll_logdbg("unsupported socket type=%d", sock_type);
            return -1;
        }
    } catch (xlio_exception &e) {
        fdcoll_logdbg("recovering from %s", e.what());
        return -1;
    }
    lock();

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!p_sfd_api_obj) {
        fdcoll_logpanic("[fd=%d] Failed creating new sockinfo (%m)", fd);
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    if (sock_flags) {
        if (sock_flags & SOCK_NONBLOCK) {
            p_sfd_api_obj->fcntl(F_SETFL, O_NONBLOCK);
        }
        if (sock_flags & SOCK_CLOEXEC) {
            p_sfd_api_obj->fcntl(F_SETFD, FD_CLOEXEC);
        }
    }

    assert(!get_sockfd(fd));
    assert(!get_epfd(fd));
    set_socket(fd, p_sfd_api_obj);

    unlock();

    return fd;
}

bool fd_collection::create_offloaded_sockets()
{
    bool ret = m_b_sysvar_offloaded_sockets;

    lock();
    if (m_offload_thread_rule.find(pthread_self()) == m_offload_thread_rule.end()) {
        unlock();
        return ret;
    }
    unlock();

    return !ret;
}

/*
 * Create sockets on the given thread as offloaded/not-offloaded.
 * pass true for offloaded, false for not-offloaded.
 */
void fd_collection::offloading_rule_change_thread(bool offloaded, pthread_t tid)
{
    fdcoll_logdbg("tid=%lu, offloaded=%d", tid, offloaded);

    lock();
    if (offloaded == m_b_sysvar_offloaded_sockets) {
        m_offload_thread_rule.erase(tid);
    } else {
        m_offload_thread_rule[tid] = 1;
    }
    unlock();
}

void fd_collection::statistics_print_helper(int fd, vlog_levels_t log_level)
{
    sockinfo *socket_fd;
    epfd_info *epoll_fd;

    if ((socket_fd = get_sockfd(fd))) {
        vlog_printf(log_level, "==================== SOCKET FD ===================\n");
        socket_fd->statistics_print(log_level);
        goto found_fd;
    }
    if ((epoll_fd = get_epfd(fd))) {
        vlog_printf(log_level, "==================== EPOLL FD ====================\n");
        epoll_fd->statistics_print(log_level);
        goto found_fd;
    }

    return;

found_fd:

    vlog_printf(log_level, "==================================================\n");
}

void fd_collection::statistics_print(int fd, vlog_levels_t log_level)
{
    vlog_printf(log_level, "==================================================\n");
    if (fd) {
        vlog_printf(log_level, "============ DUMPING FD %d STATISTICS ============\n", fd);
        g_p_fd_collection->statistics_print_helper(fd, log_level);
    } else {
        vlog_printf(log_level, "======= DUMPING STATISTICS FOR ALL OPEN FDS ======\n");
        int fd_map_size = g_p_fd_collection->get_fd_map_size();
        for (int i = 0; i < fd_map_size; i++) {
            g_p_fd_collection->statistics_print_helper(i, log_level);
        }
    }
    vlog_printf(log_level, "==================================================\n");
}

int fd_collection::addepfd(int epfd, int size)
{
    fdcoll_logfunc("epfd=%d", epfd);

    if (!is_valid_fd(epfd)) {
        return -1;
    }

    lock();

    // Sanity check to remove any old sockinfo object using the same fd!!
    epfd_info *p_fd_info = get_epfd(epfd);
    if (p_fd_info) {
        fdcoll_logwarn("[fd=%d] Deleting old duplicate sockinfo object (%p)", epfd, p_fd_info);
        unlock();
        handle_close(epfd, true);
        lock();
    }

    unlock();
    p_fd_info = new epfd_info(epfd, size);
    lock();

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!p_fd_info) {
        fdcoll_logpanic("[fd=%d] Failed creating new sockinfo (%m)", epfd);
    }
    BULLSEYE_EXCLUDE_BLOCK_END
    m_p_epfd_map[epfd] = p_fd_info;
    m_epfd_lst.push_back(p_fd_info);

    unlock();

    return 0;
}

int fd_collection::add_cq_channel_fd(int cq_ch_fd, ring *p_ring)
{
    fdcoll_logfunc("cq_ch_fd=%d", cq_ch_fd);

    if (!is_valid_fd(cq_ch_fd)) {
        return -1;
    }

    lock();

    epfd_info *p_fd_info = get_epfd(cq_ch_fd);
    BULLSEYE_EXCLUDE_BLOCK_START
    if (p_fd_info) {
        fdcoll_logwarn("[fd=%d] Deleting old duplicate sockinfo object (%p)", cq_ch_fd, p_fd_info);
        unlock();
        handle_close(cq_ch_fd, true);
        lock();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    // Sanity check to remove any old objects using the same fd!!
    sockinfo *p_cq_ch_fd_api_obj = get_sockfd(cq_ch_fd);
    BULLSEYE_EXCLUDE_BLOCK_START
    if (p_cq_ch_fd_api_obj) {
        fdcoll_logwarn("[fd=%d] Deleting old duplicate object (%p)", cq_ch_fd, p_cq_ch_fd_api_obj);
        unlock();
        handle_close(cq_ch_fd, true);
        lock();
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    // Check if cq_channel_info was already created
    cq_channel_info *p_cq_ch_info = get_cq_channel_fd(cq_ch_fd);
    BULLSEYE_EXCLUDE_BLOCK_START
    if (p_cq_ch_info) {
        fdcoll_logwarn("cq channel fd already exists in fd_collection");
        m_p_cq_channel_map[cq_ch_fd] = nullptr;
        delete p_cq_ch_info;
        // coverity[assigned_pointer] /* Turn off coverity check, intended assign*/
        p_cq_ch_info = nullptr;
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    unlock();
    p_cq_ch_info = new cq_channel_info(p_ring);
    lock();

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!p_cq_ch_info) {
        fdcoll_logpanic("[fd=%d] Failed creating new cq_channel_info (%m)", cq_ch_fd);
    }
    BULLSEYE_EXCLUDE_BLOCK_END
    m_p_cq_channel_map[cq_ch_fd] = p_cq_ch_info;

    unlock();

    return 0;
}

int fd_collection::del_sockfd(int fd, bool is_for_udp_pool /*=false*/)
{
    int ret_val = -1;
    sockinfo *p_sfd_api;

    p_sfd_api = get_sockfd(fd);

    if (p_sfd_api) {
        if (safe_mce_sys().worker_threads && handle_worker_threads_mode_close(fd, p_sfd_api)) {
            return 0;
        }

        // TCP socket need some timer to before it can be deleted,
        // in order to gracefuly terminate TCP connection
        // so we have to stages:
        // 1. Prepare to close: kikstarts TCP connection termination
        // 2. Socket deletion when TCP connection == CLOSED
        if (p_sfd_api->prepare_to_close()) {
            // the socket is already closable
            // This may register the socket to be erased by internal thread,
            // However, a timer may tick on this socket before it is deleted.
            ret_val = del_socket(fd);
        } else {
            lock();
            // The socket is not ready for close.
            // Delete it from fd_col and add it to pending_to_remove list.
            // This socket will be handled and destroyed now by fd_col.
            // This will be done from fd_col timer handler.
            // Used for UDP socket pool as well
            // so closed UDP sockets will be deleted at the end of the world
            if (m_p_sockfd_map[fd].load().socket == p_sfd_api) {
                if (!is_for_udp_pool) {
                    ++g_global_stat_static.n_pending_sockets;
                }
                m_p_sockfd_map[fd].clear();
                m_pending_to_remove_lst.push_front(p_sfd_api);
            }

            unlock();
            ret_val = 0;
        }
    }

    return ret_val;
}

bool fd_collection::handle_worker_threads_mode_close(int fd, sockinfo *p_sfd_api)
{
    if (p_sfd_api->get_protocol() == PROTO_TCP) {
        sockinfo_tcp *tcp_si = static_cast<sockinfo_tcp *>(p_sfd_api);
        //  read the owner UNDER the socket lock so this routing decision is atomic
        // w.r.t. connect_threads_mode()/distribute_socket(), which publish the owner and post the
        // ADD_AND_CONNECT job while connect() holds m_tcp_con_lock for its whole body (until it
        // parks). A lock-free read here can observe the stale null from before connect published
        // the owner and then wrongly take the legacy synchronous free while the worker still has
        // the raw socket pointer queued in an ADD_AND_CONNECT job - UAF in connect_socket_job().
        tcp_si->lock_tcp_con();
        entity_context *ec = tcp_si->get_entity_context();
        tcp_si->unlock_tcp_con();
        if (ec) {
            // Incoming/outgoing sockets - delegate to entity context and return
            // Clear the socket from the fd_collection before delegating
            clear_socket(fd);
            handle_socket_close_job_worker_threads_mode(tcp_si);
            return true; // Should return from del_sockfd
        } else if (tcp_si->get_listen_context() &&
                   tcp_si->get_listen_context()->has_published_listen_rss_children()) {
            // RSS listen socket - send close jobs to children. Guarded on published children for
            // symmetry with submit_worker_tcp_close(): a second begin_close_wait() on an already
            // acknowledged batch would trip its published-children assertion.
            handle_listen_socket_close_worker_threads_mode(tcp_si, false);
            // Main listen socket - Fall through to legacy close flow below
        }
        // Other TCP sockets (e.g., created via socket() but not bound/connected/listening) - Fall
        // through to legacy close flow below
    }
    // Non-TCP sockets - Fall through to legacy close flow below
    return false; // Should continue with legacy flow
}

void fd_collection::handle_listen_socket_close_worker_threads_mode(sockinfo_tcp *listen_si,
                                                                   bool force)
{
    sockinfo_tcp_listen_context *const listen_context = listen_si->get_listen_context();
    assert(listen_context);
    const bool close_owner = listen_context->begin_close_wait();

    if (close_owner) {
        // Only the transaction owner posts close. Concurrent callers join the same wait and must
        // not reset counters or route duplicate child controls.
        const size_t num_children = listen_context->get_listen_rss_children_size();
        for (size_t i = 0; i < num_children; ++i) {
            sockinfo_tcp *child = listen_context->get_listen_rss_child(i);
            assert(child);
            handle_socket_close_job_worker_threads_mode(child, force);
        }
    }

    listen_context->wait_for_rss_children_closed();
    if (close_owner) {
        listen_context->acknowledge_published_listen_rss_children_retired();
    }
}

void fd_collection::handle_socket_close_job_worker_threads_mode(sockinfo_tcp *si, bool force)
{
    assert(si->get_worker_retire_owner());
    si->lock_tcp_con();
    si->worker_state().m_force_close = si->worker_state().m_force_close || force;
    const bool claimed = si->begin_worker_retirement();
    if (claimed) {
        uint32_t controls = entity_context::SOCKET_CONTROL_CLOSE;
        if (si->worker_state().m_force_close) {
            controls |= entity_context::SOCKET_CONTROL_FORCE_CLOSE;
        }
        const bool posted =
            si->get_worker_retire_owner()->post_socket_control_locked(si, controls, true);
        assert(posted);
        (void)posted;
    }
    si->unlock_tcp_con();
}

int fd_collection::del_epfd(int fd, bool b_cleanup /*=false*/)
{
    return del(fd, b_cleanup, m_p_epfd_map);
}

void fd_collection::remove_epfd_from_list(epfd_info *epfd)
{
    lock();
    m_epfd_lst.erase(epfd);
    unlock();
}

int fd_collection::del_cq_channel_fd(int fd, bool b_cleanup /*=false*/)
{
    return del(fd, b_cleanup, m_p_cq_channel_map);
}

template <typename cls> int fd_collection::del(int fd, bool b_cleanup, cls **map_type)
{
    fdcoll_logfunc("fd=%d%s", fd,
                   b_cleanup ? ", cleanup case: trying to remove old socket handler" : "");

    if (!is_valid_fd(fd)) {
        return -1;
    }

    lock();
    cls *p_obj = map_type[fd];
    if (p_obj) {
        map_type[fd] = NULL;
        unlock();
        p_obj->clean_obj();
        return 0;
    }
    if (!b_cleanup) {
        fdcoll_logdbg("[fd=%d] Could not find related object", fd);
    }
    unlock();
    return -1;
}

int fd_collection::del_socket(int fd)
{
    fdcoll_logfunc("fd=%d", fd);

    if (!is_valid_fd(fd)) {
        return -1;
    }

    lock();
    sockinfo *p_obj = m_p_sockfd_map[fd].load().socket;
    if (p_obj) {
        m_p_sockfd_map[fd].clear();
        unlock();
        p_obj->clean_socket_obj();
        return 0;
    }

    fdcoll_logdbg("[fd=%d] Could not find related object", fd);
    unlock();
    return -1;
}

void fd_collection::remove_from_all_epfds(int fd, bool passthrough, sockinfo *expected_socket)
{
    lock();
    for (epfd_info *ep = m_epfd_lst.front(); ep; ep = m_epfd_lst.next(ep)) {
        ep->fd_closed(fd, passthrough, expected_socket);
    }
    unlock();

    return;
}

#if defined(DEFINED_NGINX)
void fd_collection::push_socket_pool(sockinfo *sockfd)
{
    lock();
    sockfd->prepare_to_close_socket_pool(true);
    m_socket_pool.push(sockfd);
    unlock();
}

bool fd_collection::pop_socket_pool(int &fd, bool &add_to_udp_pool, int type)
{
    bool ret = false;
    add_to_udp_pool = false;
    fd = -1;

    // socket pool is used only for udp sockets
    // here we verify it, while in all other places we use general case for socket fd
    if ((type != SOCK_DGRAM) || (safe_mce_sys().nginx_udp_socket_pool_size == 0)) {
        return ret;
    }

    lock();
    if (!m_socket_pool.empty()) {
        // use fd from pool - will skip creation of new fd by os
        sockinfo *sockfd = m_socket_pool.top();
        fd = sockfd->get_fd();
        if (!m_p_sockfd_map[fd].load().socket) {
            set_socket(fd, sockfd);
            m_pending_to_remove_lst.erase(sockfd);
        }
        sockfd->prepare_to_close_socket_pool(false);
        m_socket_pool.pop();
        ret = true;
    } else {
        // pool is empty - will create of new fd by os, and will mark it as fd for the pool
        add_to_udp_pool = true;
    }
    unlock();

    return ret;
}

void fd_collection::handle_socket_pool(int fd)
{
    if (!m_use_socket_pool) {
        return;
    }

    if (m_socket_pool_counter >= m_socket_pool_size) {
        fdcoll_logdbg("Worker %d reached max UDP socket pool size (%d).", g_p_app->get_worker_id(),
                      m_socket_pool_size);
        m_use_socket_pool = false;
        return;
    }

    sockinfo *sockfd = get_sockfd(fd);
    if (sockfd) {
        ++m_socket_pool_counter;
        sockfd->set_params_for_socket_pool();
    }
}
#endif
