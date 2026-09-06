/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef FD_COLLECTION_H
#define FD_COLLECTION_H

#include <stack>
#include <unordered_map>

#include "vlogger/vlogger.h"
#include "event/event_handler_manager.h"
#include "event/timer_handler.h"
#include "sock/cleanable_obj.h"
#include "sock/fd_socket_slot.h"
#include "sock/sockinfo.h"
#include "iomux/epfd_info.h"
#include "utils/lock_wrapper.h"

typedef xlio_list_t<sockinfo, sockinfo::pending_to_remove_node_offset> sockinfo_list_t;
typedef xlio_list_t<epfd_info, epfd_info::epfd_info_node_offset> epfd_info_list_t;

typedef std::unordered_map<pthread_t, int> offload_thread_rule_t;

#if (MAX_DEFINED_LOG_LEVEL < DEFINED_VLOG_FINER)
#define fdcoll_logfuncall(log_fmt, log_args...) ((void)0)
#else
#define fdcoll_logfuncall(log_fmt, log_args...)                                                    \
    do {                                                                                           \
        if (g_vlogger_level >= VLOG_FUNC_ALL)                                                      \
            vlog_printf(VLOG_FUNC_ALL, "fdc:%d:%s() " log_fmt "\n", __LINE__, __FUNCTION__,        \
                        ##log_args);                                                               \
    } while (0)
#endif /* MAX_DEFINED_LOG_LEVEL */

extern global_stats_t g_global_stat_static;

class cq_channel_info : public cleanable_obj {
public:
    cq_channel_info(ring *p_ring)
        : m_p_ring(p_ring) {};
    ~cq_channel_info() override = default;
    ring *get_ring() const noexcept { return m_p_ring; };

protected:
    ring *m_p_ring;
};

class fd_collection : private lock_mutex_recursive {
public:
    enum class worker_close_result {
        NOT_WORKER,
        CLAIMED,
    };

    enum class socket_call_status {
        NOT_XLIO,
        ACQUIRED,
        RETIRING,
    };

    struct worker_close_claim {
        worker_close_result result = worker_close_result::NOT_WORKER;
        sockinfo_tcp *sock = nullptr;
    };

    class socket_call_ref {
    public:
        socket_call_ref() = default;
        socket_call_ref(sockinfo *sock, bool owns_worker_ref,
                        socket_call_status status = socket_call_status::NOT_XLIO)
            : m_sock(sock)
            , m_owns_worker_ref(owns_worker_ref)
            , m_status(sock ? socket_call_status::ACQUIRED : status)
        {
        }
        socket_call_ref(socket_call_ref &&other) noexcept;
        socket_call_ref &operator=(socket_call_ref &&other) noexcept;
        ~socket_call_ref() { reset(); }

        socket_call_ref(const socket_call_ref &) = delete;
        socket_call_ref &operator=(const socket_call_ref &) = delete;

        sockinfo *get() const { return m_sock; }
        sockinfo *operator->() const { return m_sock; }
        explicit operator bool() const { return m_sock != nullptr; }
        bool owns_worker_ref() const { return m_owns_worker_ref; }
        socket_call_status status() const { return m_status; }
        sockinfo *detach(bool &owns_worker_ref)
        {
            sockinfo *sock = m_sock;
            owns_worker_ref = m_owns_worker_ref;
            m_sock = nullptr;
            m_owns_worker_ref = false;
            m_status = socket_call_status::NOT_XLIO;
            return sock;
        }

    private:
        static void release_worker_socket_ref(sockinfo *sock);
        void reset()
        {
            if (m_sock && m_owns_worker_ref) {
                release_worker_socket_ref(m_sock);
            }
            m_sock = nullptr;
            m_owns_worker_ref = false;
            m_status = socket_call_status::NOT_XLIO;
        }

        sockinfo *m_sock = nullptr;
        bool m_owns_worker_ref = false;
        socket_call_status m_status = socket_call_status::NOT_XLIO;
    };

    fd_collection();
    ~fd_collection() override;

    /**
     * Create and add a sockinfo. Use get_sock() to get it.
     * @param domain e.g AF_INET.
     * @param type e.g SOCK_DGRAM.
     * @return socket fd or -1 on failure.
     */
    int addsocket(int fd, int domain, int type, bool check_offload = false);

    /**
     * Create epfd_info. Use get_epfd() to get it.
     * @param epfd epoll fd.
     * @param size epoll fd size (as passed to epoll_create).
     * @return 0 on success, -1 on failure.
     */
    int addepfd(int epfd, int size);

    /**
     * Create cq_channel_info. Use get_cq_channel_info() to get it.
     * @param cq_ch_fd: cq channel fd.
     * @param p_ring: pointer to ring which is the relevant rx_cq owner.
     * @return 0 on success, -1 on failure.
     */
    int add_cq_channel_fd(int cq_ch_fd, ring *p_ring);

    /**
     * Remove sockinfo.
     */
    int del_sockfd(int fd, bool is_for_udp_pool = false);
    worker_close_claim claim_worker_tcp_close(int fd);
    void submit_worker_tcp_close(sockinfo_tcp *sock, bool force = false);
    void retire_worker_sockets_for_shutdown();

    /**
     * Handle worker threads mode close flow.
     * @return true if should return from del_sockfd, false if should continue with legacy flow
     */
    bool handle_worker_threads_mode_close(int fd, sockinfo *p_sfd_api);

    /**
     * Handle listen socket close in worker threads mode - send jobs to children and wait.
     */
    void handle_listen_socket_close_worker_threads_mode(sockinfo_tcp *listen_si, bool force);

    /**
     * Handle socket close job in worker threads mode - remove from fd_col and send job to entity
     * context.
     */
    void handle_socket_close_job_worker_threads_mode(sockinfo_tcp *si, bool force = false);

    /**
     * Remove epfd_info.
     */
    int del_epfd(int fd, bool b_cleanup = false);
    void remove_epfd_from_list(epfd_info *epfd);

    /**
     * Remove cq_channel_info.
     */
    int del_cq_channel_fd(int fd, bool b_cleanup = false);

    void set_socket(int fd, sockinfo *si);
    bool publish_worker_socket_if_open(int fd, sockinfo_tcp *si);
    void clear_socket(int fd) { m_p_sockfd_map[fd].clear(); }
    bool clear_socket_if(int fd, const sockinfo *expected);

    /**
     * Call set_immediate_os_sample of the input fd.
     */
    inline bool set_immediate_os_sample(int fd);

    inline void reuse_sockfd(int fd, sockinfo *p_sfd_api_obj);
    inline void destroy_sockfd(sockinfo *p_sfd_api_obj);
    /**
     * Get sockinfo by fd.
     */
    inline sockinfo *get_sockfd(int fd);
    socket_call_ref acquire_socket_call(int fd);

    /**
     * Get epfd_info by fd.
     */
    inline epfd_info *get_epfd(int fd);

    /**
     * Get cq_channel_info by fd.
     */
    inline cq_channel_info *get_cq_channel_fd(int fd);

    /**
     * Get the fd_map size.
     */
    inline int get_fd_map_size();

    /**
     * Remove fd from the collection of all epfd's
     */
    void remove_from_all_epfds(int fd, bool passthrough, sockinfo *expected_socket = nullptr);

    /**
     * Remove everything from the collection.
     */
    void clear();
    void prepare_to_close();

    void offloading_rule_change_thread(bool offloaded, pthread_t tid);

    /**
     * Dump fd statistics using XLIO logger.
     */
    void statistics_print(int fd, vlog_levels_t log_level);

#if defined(DEFINED_NGINX)
    bool pop_socket_pool(int &fd, bool &add_to_udp_pool, int type);
    void push_socket_pool(sockinfo *sockfd);
    void handle_socket_pool(int fd);
#endif
private:
    template <typename cls> int del(int fd, bool b_cleanup, cls **map_type);
    template <typename cls> inline cls *get(int fd, cls **map_type);
    int del_socket(int fd);
    inline bool is_valid_fd(int fd);

    inline bool create_offloaded_sockets();

    // Fd collection timer implementation
    // This gives context to handle pending to remove fds.
    // In case of TCP we recheck if TCP socket is closable and delete
    // it if it does otherwise we run handle_timer of the socket to
    // progress the TCP connection.
    void handle_timer_expired(void *user_data);

    void statistics_print_helper(int fd, vlog_levels_t log_level);

private:
    int m_n_fd_map_size;
    fd_socket_slot *m_p_sockfd_map;
    epfd_info **m_p_epfd_map;
    cq_channel_info **m_p_cq_channel_map;

    epfd_info_list_t m_epfd_lst;
    // Contains fds which are in closing process
    sockinfo_list_t m_pending_to_remove_lst;

    const bool m_b_sysvar_offloaded_sockets;

    // if (m_b_sysvar_offloaded_sockets is true) contain all threads that need not be offloaded.
    // else contain all threads that need to be offloaded.
    offload_thread_rule_t m_offload_thread_rule;

#if defined(DEFINED_NGINX)
    bool m_use_socket_pool;
    std::stack<sockinfo *> m_socket_pool;
    int m_socket_pool_size;
    int m_socket_pool_counter;
#endif
};

inline bool fd_collection::is_valid_fd(int fd)
{
    if (fd < 0 || fd >= m_n_fd_map_size) {
        return false;
    }
    return true;
}

template <typename cls> inline cls *fd_collection::get(int fd, cls **map_type)
{
    if (!is_valid_fd(fd)) {
        return NULL;
    }

    cls *obj = map_type[fd];
    return obj;
}

inline void fd_collection::reuse_sockfd(int fd, sockinfo *p_sfd_api_obj)
{
    lock();
    m_pending_to_remove_lst.erase(p_sfd_api_obj);
    set_socket(fd, p_sfd_api_obj);
    --g_global_stat_static.n_pending_sockets;
    unlock();
}

inline void fd_collection::destroy_sockfd(sockinfo *p_sfd_api_obj)
{
    lock();
    --g_global_stat_static.n_pending_sockets;
    m_pending_to_remove_lst.erase(p_sfd_api_obj);
    p_sfd_api_obj->clean_socket_obj();
    unlock();
}

inline sockinfo *fd_collection::get_sockfd(int fd)
{
    if (!is_valid_fd(fd)) {
        return nullptr;
    }
    return m_p_sockfd_map[fd].load().socket;
}

inline epfd_info *fd_collection::get_epfd(int fd)
{
    return get(fd, m_p_epfd_map);
}

inline cq_channel_info *fd_collection::get_cq_channel_fd(int fd)
{
    return get(fd, m_p_cq_channel_map);
}

inline int fd_collection::get_fd_map_size()
{
    return m_n_fd_map_size;
}

extern fd_collection *g_p_fd_collection;

inline sockinfo *fd_collection_get_sockfd(int fd)
{
    if (g_p_fd_collection) {
        return g_p_fd_collection->get_sockfd(fd);
    }
    return nullptr;
}

inline fd_collection::socket_call_ref fd_collection_acquire_socket_call(int fd)
{
    if (g_p_fd_collection) {
        if (safe_mce_sys().worker_threads == 0) {
            return fd_collection::socket_call_ref(g_p_fd_collection->get_sockfd(fd), false);
        }
        return g_p_fd_collection->acquire_socket_call(fd);
    }
    return {};
}

inline epfd_info *fd_collection_get_epfd(int fd)
{
    if (g_p_fd_collection) {
        return g_p_fd_collection->get_epfd(fd);
    }
    return nullptr;
}

#endif
