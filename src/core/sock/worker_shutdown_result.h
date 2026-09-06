/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef WORKER_SHUTDOWN_RESULT_H
#define WORKER_SHUTDOWN_RESULT_H

#include <condition_variable>
#include <mutex>

class worker_shutdown_result {
public:
    void complete(int rc, int error)
    {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_rc = rc;
            m_error = error;
            m_complete = true;
        }
        m_condition.notify_one();
    }

    int wait(int &error)
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_condition.wait(lock, [this] { return m_complete; });
        error = m_error;
        return m_rc;
    }

private:
    std::mutex m_mutex;
    std::condition_variable m_condition;
    bool m_complete = false;
    int m_rc = -1;
    int m_error = 0;
};

#endif // WORKER_SHUTDOWN_RESULT_H
