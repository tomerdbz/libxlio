/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef WORKER_JOB_H
#define WORKER_JOB_H

#include <cstdint>

class sockinfo;
class mem_buf_desc_t;
class worker_shutdown_result;

/*
 * The worker job vocabulary lives outside entity_context so worker_socket_state can embed a
 * job_queue<worker_job_desc>::node without a header cycle (entity_context.h includes
 * sockinfo_tcp.h, which includes worker_socket_state.h).
 * entity_context re-exposes these names, so call sites keep the entity_context:: spelling.
 */
enum worker_job_type {
    JOB_TYPE_SOCK_ADD_AND_CONNECT,
    JOB_TYPE_SOCK_TX,
    JOB_TYPE_SOCK_RX_DATA_RECVD,
    JOB_TYPE_SOCK_ADD_AND_LISTEN,
    JOB_TYPE_SOCK_CLOSE,
    JOB_TYPE_SOCK_SHUTDOWN,
    // Token entry for the per-socket control node; the live control bits are read under the
    // socket's TCP lock when the entry is processed.
    JOB_TYPE_SOCK_CONTROL
};

enum worker_job_flag {
    JOB_FLAG_TX_LAST_CHUNK = 0x0001,
    JOB_FLAG_FORCE_CLOSE = 0x0002,
    JOB_FLAG_SOCK_BLOCKING = 0x0004, // ADD_AND_CONNECT: snapshot at post, not live is_blocking()
};

struct worker_job_desc {
    worker_job_type job_id;
    int flags;
    sockinfo *sock;
    mem_buf_desc_t *buf;
    uint32_t offset;
    uint32_t tot_size;
    int shutdown_how = 0;
    worker_shutdown_result *shutdown_result = nullptr;
};

#endif // WORKER_JOB_H
