/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef WORKER_SOCKET_LIFETIME_H
#define WORKER_SOCKET_LIFETIME_H

#include <assert.h>
#include <atomic>
#include <cstdint>
#include <limits>

enum class worker_socket_lifecycle : uint32_t {
    OPEN = 0,
    RETIRING,
    DESTROY_CLAIMED,
};

enum class worker_lifetime_release : uint8_t {
    NONE = 0,
    RECHECK_RETIREMENT,
};

/**
 * Worker-only TCP lifetime state.
 *
 * The lifecycle and reference count share one atomic word so call admission cannot race a close
 * transition between checking OPEN and taking its reference. The fd-collection lock remains the
 * authority for which object occupies a numeric fd; this class protects the selected object's
 * physical lifetime and retirement transition.
 *
 * A caller that receives RECHECK_RETIREMENT must arrange an allocation-free notification before
 * allowing another thread to destroy the containing socket. sockinfo_tcp serializes that handoff
 * with m_tcp_con_lock.
 */
class worker_socket_lifetime {
public:
    worker_socket_lifetime() = default;

    worker_socket_lifetime(const worker_socket_lifetime &) = delete;
    worker_socket_lifetime &operator=(const worker_socket_lifetime &) = delete;

    bool try_acquire()
    {
        uint64_t current = m_value.load(std::memory_order_acquire);
        while (decode_state(current) == worker_socket_lifecycle::OPEN) {
            const uint32_t refs = decode_refs(current);
            if (unlikely_ref_overflow(refs)) {
                return false;
            }

            const uint64_t desired = encode(worker_socket_lifecycle::OPEN, refs + 1U);
            if (m_value.compare_exchange_weak(current, desired, std::memory_order_acq_rel,
                                              std::memory_order_acquire)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Pin an already selected socket while it is either open or retiring.
     *
     * This is for owner-side control handoffs only. New fd-based calls must use try_acquire(),
     * which rejects retirement.
     */
    bool try_acquire_existing()
    {
        uint64_t current = m_value.load(std::memory_order_acquire);
        while (true) {
            const worker_socket_lifecycle lifecycle = decode_state(current);
            if (lifecycle != worker_socket_lifecycle::OPEN &&
                lifecycle != worker_socket_lifecycle::RETIRING) {
                return false;
            }
            const uint32_t refs = decode_refs(current);
            if (unlikely_ref_overflow(refs)) {
                return false;
            }

            const uint64_t desired = encode(lifecycle, refs + 1U);
            if (m_value.compare_exchange_weak(current, desired, std::memory_order_acq_rel,
                                              std::memory_order_acquire)) {
                return true;
            }
        }
    }

    bool begin_retirement_with_owner_ref()
    {
        uint64_t current = m_value.load(std::memory_order_acquire);
        while (decode_state(current) == worker_socket_lifecycle::OPEN) {
            const uint32_t refs = decode_refs(current);
            if (unlikely_ref_overflow(refs)) {
                return false;
            }

            const uint64_t desired = encode(worker_socket_lifecycle::RETIRING, refs + 1U);
            if (m_value.compare_exchange_weak(current, desired, std::memory_order_acq_rel,
                                              std::memory_order_acquire)) {
                return true;
            }
        }

        return false;
    }

    worker_lifetime_release release()
    {
        uint64_t current = m_value.load(std::memory_order_acquire);
        while (true) {
            const uint32_t refs = decode_refs(current);
            assert(refs > 0U);
            if (refs == 0U) {
                return worker_lifetime_release::NONE;
            }

            const worker_socket_lifecycle lifecycle = decode_state(current);
            assert(lifecycle == worker_socket_lifecycle::OPEN ||
                   lifecycle == worker_socket_lifecycle::RETIRING);
            if (lifecycle != worker_socket_lifecycle::OPEN &&
                lifecycle != worker_socket_lifecycle::RETIRING) {
                return worker_lifetime_release::NONE;
            }
            const uint32_t remaining = refs - 1U;
            const uint64_t desired = encode(lifecycle, remaining);
            if (m_value.compare_exchange_weak(current, desired, std::memory_order_acq_rel,
                                              std::memory_order_acquire)) {
                return lifecycle == worker_socket_lifecycle::RETIRING && remaining == 0U
                    ? worker_lifetime_release::RECHECK_RETIREMENT
                    : worker_lifetime_release::NONE;
            }
        }
    }

    bool try_claim_destruction_without_ref()
    {
        uint64_t expected = encode(worker_socket_lifecycle::RETIRING, 0U);
        return m_value.compare_exchange_strong(
            expected, encode(worker_socket_lifecycle::DESTROY_CLAIMED, 0U),
            std::memory_order_acq_rel, std::memory_order_acquire);
    }

    bool consume_owner_ref_and_claim_destruction()
    {
        uint64_t expected = encode(worker_socket_lifecycle::RETIRING, 1U);
        return m_value.compare_exchange_strong(
            expected, encode(worker_socket_lifecycle::DESTROY_CLAIMED, 0U),
            std::memory_order_acq_rel, std::memory_order_acquire);
    }

    /**
     * Reopen a fully drained retired socket for a new incarnation (TIME_WAIT reuse).
     *
     * Competes only with the destruction claim: both consume exactly (RETIRING, 0), so there is
     * one winner. The caller must not depend on any state weaker than (RETIRING, 0); the reuse
     * path re-validates its conditions under the socket lock, where (RETIRING, 0) is stable.
     */
    bool reopen_from_retirement()
    {
        uint64_t expected = encode(worker_socket_lifecycle::RETIRING, 0U);
        return m_value.compare_exchange_strong(expected, encode(worker_socket_lifecycle::OPEN, 0U),
                                               std::memory_order_acq_rel,
                                               std::memory_order_acquire);
    }

    worker_socket_lifecycle state() const
    {
        return decode_state(m_value.load(std::memory_order_acquire));
    }

    uint32_t ref_count() const { return decode_refs(m_value.load(std::memory_order_acquire)); }

    struct snapshot {
        worker_socket_lifecycle state;
        uint32_t refs;
    };

    /**
     * Decode both fields from one atomic load so a predicate over the lifecycle and the
     * reference count observes a single consistent word instead of two independent loads.
     */
    snapshot load_snapshot() const
    {
        const uint64_t value = m_value.load(std::memory_order_acquire);
        return snapshot {decode_state(value), decode_refs(value)};
    }

private:
    static constexpr uint64_t REF_MASK = std::numeric_limits<uint32_t>::max();
    static constexpr unsigned STATE_SHIFT = 32U;

    static uint64_t encode(worker_socket_lifecycle lifecycle, uint32_t refs)
    {
        return (static_cast<uint64_t>(lifecycle) << STATE_SHIFT) | refs;
    }

    static worker_socket_lifecycle decode_state(uint64_t value)
    {
        return static_cast<worker_socket_lifecycle>(value >> STATE_SHIFT);
    }

    static uint32_t decode_refs(uint64_t value) { return static_cast<uint32_t>(value & REF_MASK); }

    static bool unlikely_ref_overflow(uint32_t refs)
    {
        assert(refs != std::numeric_limits<uint32_t>::max());
        return refs == std::numeric_limits<uint32_t>::max();
    }

    std::atomic<uint64_t> m_value {encode(worker_socket_lifecycle::OPEN, 0U)};
};

#endif // WORKER_SOCKET_LIFETIME_H
