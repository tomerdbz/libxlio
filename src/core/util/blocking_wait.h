/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef BLOCKING_WAIT_H
#define BLOCKING_WAIT_H

#include <algorithm>
#include <cerrno>
#include <chrono>

/**
 * App-thread park / worker-thread wake for worker-threads mode.
 * wait_until() is the one check-then-sleep loop: pred, arm, unlock, block,
 * relock, disarm, re-check.
 *
 * Lost-wakeup: pred() and waiter.arm() run in the same locked critical section
 * (no unlock between them). The worker takes that same lock, makes the
 * condition true, then posts the sticky token (wakeup_pipe::do_wakeup()).
 * block() runs unlocked so the worker can proceed. A wake between unlock and
 * block() still unblocks. Spurious wakes re-check pred().
 *
 * wait_until() is arm / block / disarm only; it never calls notify().
 * waiter.notify() is do_wakeup() when the caller has a Waiter (tests).
 * Production wakes have the socket pipe, not the stack Waiter.
 *
 * Bounded parking: each block() is at most WORKER_BLOCKING_EXIT_POLL_MS (100 ms).
 * Between slices pred() is re-evaluated under the lock, so an async terminal
 * in the predicate (process exit on another thread, no notify) is observed
 * within one slice. Slice expiry is not TIMEOUT; TIMEOUT is only the caller's
 * deadline. timeout_ms < 0 never returns TIMEOUT.
 *
 * Contract: caller holds lock on entry; wait_until() returns still holding it.
 * pred runs under lock. Worker do_wakeup() uses the same lock, after the
 * condition is true. Waiter is duck-typed (arm/block/disarm/notify).
 */
class blocking_wait {
public:
    enum class result {
        READY, // predicate satisfied
        TIMEOUT, // deadline elapsed with predicate still false
        INTERRUPTED, // block() interrupted by a signal (EINTR) and predicate still false
        ERROR, // unexpected error in block() (errno set)
    };

    // Upper bound on a single park. Mirrors worker_thread.cpp INTERRUPT_TIMEOUT_MS.
    static constexpr int WORKER_BLOCKING_EXIT_POLL_MS = 100;

    template <typename Lock, typename Waiter, typename Pred>
    static result wait_until(Lock &lock, Waiter &waiter, Pred pred, int timeout_ms)
    {
        using clock = std::chrono::steady_clock;
        const bool infinite = (timeout_ms < 0);
        const clock::time_point deadline =
            infinite ? clock::time_point() : clock::now() + std::chrono::milliseconds(timeout_ms);

        for (;;) {
            if (pred()) {
                return result::READY;
            }

            int slice_ms = WORKER_BLOCKING_EXIT_POLL_MS;
            if (!infinite) {
                const clock::time_point now = clock::now();
                if (now >= deadline) {
                    return result::TIMEOUT;
                }
                int remaining_ms = static_cast<int>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
                // now < deadline; sub-ms remainder truncates to 0. block(0) busy-spins.
                if (remaining_ms == 0) {
                    remaining_ms = 1;
                }
                // Copy before std::min: its const reference parameters odr-use the in-class
                // constexpr, which C++14 only allows with an out-of-line definition. -O3
                // folds the reference away, but an --enable-debug (-O0) build fails at load
                // with an undefined symbol. A local copy is a plain constant read.
                const int poll_slice_ms = WORKER_BLOCKING_EXIT_POLL_MS;
                slice_ms = std::min(remaining_ms, poll_slice_ms);
            }

            waiter.arm();
            lock.unlock();
            int r;
            try {
                r = waiter.block(slice_ms);
            } catch (...) {
                // pthread cancellation unwinds through C++ as a forced-unwind exception.
                // Restore the wait protocol before rethrowing so the caller regains the lock
                // and the waiter cannot remain armed after any block() exception.
                lock.lock();
                waiter.disarm();
                throw;
            }
            lock.lock();
            waiter.disarm();

            // READY beats timeout / EINTR.
            if (pred()) {
                return result::READY;
            }
            if (r < 0) {
                return (errno == EINTR) ? result::INTERRUPTED : result::ERROR;
            }
        }
    }
};

#endif /* BLOCKING_WAIT_H */
