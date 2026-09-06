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

#include "entity_context_manager.h"
#include <algorithm>

#include "util/sys_vars.h"
#include "sock/sockinfo_tcp.h"

// Static
entity_context_manager *entity_context_manager::s_p_entity_context_manager = nullptr;

// Static
entity_context_manager *entity_context_manager::instance()
{
    return s_p_entity_context_manager;
}

// Static
void entity_context_manager::create()
{
    if (!s_p_entity_context_manager) {
        s_p_entity_context_manager = new entity_context_manager();
    }
}

// Static
void entity_context_manager::destroy()
{
    if (s_p_entity_context_manager) {
        delete s_p_entity_context_manager;
        s_p_entity_context_manager = nullptr;
    }
}

// Static
void entity_context_manager::fork_nullify()
{
    // Just nullify the pointer so it can be recreated on next create.
    // Since fork works with copy-on-write, the old pointer is just abondend and thus never copied.
    s_p_entity_context_manager = nullptr;
}

entity_context_manager::entity_context_manager()
{
    m_entity_contexts.reserve(safe_mce_sys().worker_threads);

    for (size_t i = 0; i < safe_mce_sys().worker_threads; i++) {
        m_entity_contexts.push_back(new entity_context(i));
    }
}

entity_context_manager::~entity_context_manager()
{
    std::for_each(m_entity_contexts.begin(), m_entity_contexts.end(),
                  [](entity_context *ctx) { delete ctx; });
}

entity_context::job_submit_result entity_context_manager::socket_job_reservation::commit(
    sockinfo *si, entity_context::job_type jobtype)
{
    if (!m_context || !m_reservation) {
        return m_reservation.result();
    }

    if (si->get_protocol() == PROTO_TCP) {
        sockinfo_tcp *tcp_sock = static_cast<sockinfo_tcp *>(si);
        tcp_sock->set_worker_retire_owner(m_context);
    }
    si->publish_entity_context_owner(m_context);

    // Snapshot is_blocking() under connect()'s socket lock. connect_socket_job must not reread
    // a live fcntl(O_NONBLOCK) flip.
    const entity_context::job_submit_result result = m_reservation.commit(entity_context::job_desc {
        jobtype, si->is_blocking() ? entity_context::JOB_FLAG_SOCK_BLOCKING : 0, si, nullptr, 0U,
        0U});
    if (result != entity_context::job_submit_result::ACCEPTED) {
        si->publish_entity_context_owner(nullptr);
        if (si->get_protocol() == PROTO_TCP) {
            static_cast<sockinfo_tcp *>(si)->set_worker_retire_owner(nullptr);
        }
    }
    return result;
}

entity_context_manager::socket_job_reservation entity_context_manager::reserve_socket_job(
    sockinfo *si)
{
    const uint16_t next_idx =
        m_next_distribute.fetch_add(1U, std::memory_order_relaxed) % safe_mce_sys().worker_threads;
    entity_context *context = m_entity_contexts[next_idx];
    if (si->get_protocol() == PROTO_TCP) {
        sockinfo_tcp *tcp_sock = static_cast<sockinfo_tcp *>(si);
        assert(tcp_sock->is_worker_posix_managed());
        if (!tcp_sock->is_worker_posix_managed()) {
            return {};
        }
    }
    return socket_job_reservation(context, context->reserve_job(si));
}

bool entity_context_manager::distribute_listen_socket(sockinfo_tcp *si)
{
    const size_t child_count = std::min(static_cast<size_t>(safe_mce_sys().worker_threads),
                                        si->get_listen_context()->get_listen_rss_children_size());
    std::vector<entity_context::job_reservation> reservations;
    try {
        reservations.reserve(child_count);
        for (size_t i = 0; i < child_count; ++i) {
            sockinfo_tcp *child = si->get_listen_context()->get_listen_rss_child(i);
            if (!child->enable_worker_posix_lifetime()) {
                return false;
            }
            entity_context::job_reservation reservation = m_entity_contexts[i]->reserve_job(child);
            if (!reservation) {
                return false;
            }
            reservations.push_back(std::move(reservation));
        }
    } catch (...) {
        return false;
    }

    assert(si->is_worker_posix_managed());
    if (!si->is_worker_posix_managed()) {
        return false;
    }
    si->set_worker_retire_owner(m_entity_contexts.front());
    for (size_t i = 0; i < child_count; ++i) {
        sockinfo_tcp *listen_rss_child = si->get_listen_context()->get_listen_rss_child(i);
        listen_rss_child->set_worker_retire_owner(m_entity_contexts[i]);
        listen_rss_child->get_listen_context()->set_steering_index(i);
        listen_rss_child->publish_entity_context_owner(m_entity_contexts[i]);
        const entity_context::job_submit_result result = reservations[i].commit(
            entity_context::job_desc {entity_context::JOB_TYPE_SOCK_ADD_AND_LISTEN, 0,
                                      listen_rss_child, nullptr, 0U, 0U});
        // A valid reservation owns its queue node, and commit is allocation-free and nothrow.
        // Returning after an earlier child was published would make rollback ownership ambiguous.
        assert(result == entity_context::job_submit_result::ACCEPTED);
        (void)result;
    }
    return true;
}

int entity_context_manager::calculate_entity_context_pow2()
{
    int worker_threads = safe_mce_sys().worker_threads;

    if (worker_threads == 0 || worker_threads == 1) {
        return worker_threads;
    }

    // Find next power of 2 that is >= worker_threads
    // Assume the number doesn't exceed 32bit.
    int pow2 = 1;
    while (pow2 < worker_threads) {
        pow2 <<= 1;
    }

    return pow2;
}
