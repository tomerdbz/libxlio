/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef WORKER_SOCKET_STATE_H
#define WORKER_SOCKET_STATE_H

#include "worker_rx_close_barrier.h"
#include "worker_socket_lifetime.h"

#include "event/job_queue.h"
#include "event/worker_job.h"

#include <assert.h>
#include <cstdint>

class entity_context;
class sockinfo_tcp;
class worker_retirement_registry;

struct worker_retirement_link {
private:
    friend class worker_retirement_registry;

    worker_retirement_registry *m_registry = nullptr;
    worker_retirement_link *m_prev = nullptr;
    worker_retirement_link *m_next = nullptr;
};

/**
 * Allocation-free owner-context registry for retiring sockets that are not members of the
 * context's poll-group socket lists.
 */
class worker_retirement_registry {
public:
    bool empty() const { return m_head == nullptr; }

    bool contains(const worker_retirement_link &link) const { return link.m_registry == this; }

    void track(worker_retirement_link &link)
    {
        assert(!link.m_registry);
        if (link.m_registry) {
            return;
        }

        link.m_registry = this;
        link.m_prev = nullptr;
        link.m_next = m_head;
        if (m_head) {
            m_head->m_prev = &link;
        }
        m_head = &link;
    }

    void untrack(worker_retirement_link &link)
    {
        assert(link.m_registry == this);
        if (link.m_registry != this) {
            return;
        }

        if (link.m_prev) {
            link.m_prev->m_next = link.m_next;
        } else {
            m_head = link.m_next;
        }
        if (link.m_next) {
            link.m_next->m_prev = link.m_prev;
        }
        link.m_registry = nullptr;
        link.m_prev = nullptr;
        link.m_next = nullptr;
    }

private:
    worker_retirement_link *m_head = nullptr;
};

/**
 * Exact-once token for the owner reference created by begin_worker_retirement().
 */
class worker_retirement_owner_ref {
public:
    explicit worker_retirement_owner_ref(worker_socket_lifetime *lifetime = nullptr)
        : m_lifetime(lifetime)
    {
    }

    ~worker_retirement_owner_ref() { assert(!m_lifetime); }

    worker_retirement_owner_ref(const worker_retirement_owner_ref &) = delete;
    worker_retirement_owner_ref &operator=(const worker_retirement_owner_ref &) = delete;

    explicit operator bool() const { return m_lifetime != nullptr; }

    bool complete(bool destruction_allowed = true)
    {
        if (!m_lifetime) {
            return false;
        }

        worker_socket_lifetime *lifetime = m_lifetime;
        m_lifetime = nullptr;
        if (destruction_allowed && lifetime->ref_count() == 1U) {
            const bool claimed = lifetime->consume_owner_ref_and_claim_destruction();
            // This token holds the owner reference, so an observed count of one means it is the
            // last reference and the caller has quiesced owner-side handoffs; the destruction
            // claim cannot be contested here. Enforce that traced invariant in debug builds.
            assert(claimed);
            return claimed;
        }

        (void)lifetime->release();
        return false;
    }

private:
    worker_socket_lifetime *m_lifetime;
};

/**
 * Cold state owned only by worker-managed POSIX TCP sockets.
 *
 * The sidecar is created before a worker-ref fd slot is published and remains immutable in address
 * until the containing socket is destroyed.
 * This keeps default R2C and XLIO Socket API objects free of worker-only representation cost while
 * preserving direct, allocation-free access in every lifetime and retirement transition.
 */
struct worker_socket_state {
    worker_socket_lifetime m_lifetime;
    entity_context *m_retire_owner = nullptr;
    sockinfo_tcp *m_timewait_listener = nullptr;
    worker_retirement_link m_retirement_link;
    worker_rx_close_barrier m_rx_close_barrier;
    // Preallocated queue node for close/retire-recheck/cancel-connect controls. Control
    // delivery therefore cannot fail and rides the owner context's one job FIFO, which orders
    // the destructive close after every job the socket published before the close was posted.
    // All m_control_* state is mutated under the socket's TCP lock; the node itself is linked
    // into the queue under the queue lock and holds at most one live occurrence.
    job_queue<worker_job_desc>::node m_control_node;
    uint32_t m_control_pending = 0U;
    bool m_control_queued = false;
    bool m_control_parked = false;
    // A retirement-observing RX departure published a receive-completion job while the control
    // node was already in the queue pipeline; the worker must re-append the control behind that
    // job before processing a destructive close.
    bool m_control_republish = false;
    bool m_close_processed = false;
    bool m_force_close = false;
};

#endif /* WORKER_SOCKET_STATE_H */
