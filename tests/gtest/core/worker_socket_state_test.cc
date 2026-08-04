/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "common/def.h"

#include "sock/sockinfo_tcp.h"

TEST(worker_socket_state, common_tcp_object_has_only_sidecar_pointer_overhead)
{
    if (sizeof(void *) != 8U) {
        GTEST_SKIP();
    }

    // Re-baseline procedure: these are the measured x86-64 sizes from before the worker
    // sidecar split. When a member is deliberately added to tcp_pcb or sockinfo_tcp, update
    // the corresponding constant here in the same commit; the guard exists to make common-path
    // footprint growth a conscious act, not to forbid it. Worker-only state belongs in the
    // worker_socket_state sidecar, which does not move these sizes.
    constexpr size_t pre_feature_tcp_pcb_size = 400U;
    constexpr size_t pre_feature_sockinfo_tcp_size = 1856U;
    constexpr size_t pointer_only_sockinfo_tcp_size =
        pre_feature_sockinfo_tcp_size + sizeof(void *);

    EXPECT_EQ(pre_feature_tcp_pcb_size, sizeof(tcp_pcb));
    EXPECT_EQ(pointer_only_sockinfo_tcp_size, sizeof(sockinfo_tcp));
}
