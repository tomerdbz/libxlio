/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <gtest/gtest.h>

#include <cstdlib>
#include <cstring>

#include "core/lwip/tcp_impl.h"

struct output_capture {
    unsigned calls;
    u32_t first_seqno;
    u32_t seqno;
    u32_t len;
    u32_t total_len;
    u16_t flags;
    int desc_attr;
    void *opaque;
};

static bool g_fail_next_seg_alloc;
static bool g_fail_next_pbuf_alloc;
static unsigned g_freed_opaque_count;
static void *g_last_freed_opaque;

extern "C" {

u16_t lwip_tcp_mss = CONST_TCP_MSS;
u32_t lwip_tcp_nodelay_treshold = 0;
int32_t enable_wnd_scale = 0;
u32_t rcv_wnd_scale = 0;
u8_t enable_push_flag = 0;
u32_t tcp_ticks = 1;

static struct tcp_seg *test_tcp_seg_alloc(void *)
{
    if (g_fail_next_seg_alloc) {
        g_fail_next_seg_alloc = false;
        return nullptr;
    }
    return static_cast<struct tcp_seg *>(std::calloc(1, sizeof(struct tcp_seg)));
}

static void test_tcp_seg_free(void *, struct tcp_seg *seg)
{
    std::free(seg);
}

tcp_seg_alloc_fn external_tcp_seg_alloc = test_tcp_seg_alloc;
tcp_seg_free_fn external_tcp_seg_free = test_tcp_seg_free;

struct pbuf *tcp_tx_pbuf_alloc(struct tcp_pcb *, u32_t length, pbuf_type type, pbuf_desc *desc,
                               struct pbuf *)
{
    if (g_fail_next_pbuf_alloc) {
        g_fail_next_pbuf_alloc = false;
        return nullptr;
    }
    // Back the payload with real storage (plus header room in front) so header-building
    // paths (tcp_enqueue_flags via tcp_in_timewait_test.cpp) can write through it; the
    // zero-copy paths overwrite p->payload with application memory and ignore it.
    constexpr u32_t kHeaderRoom = 128U;
    struct pbuf *p =
        static_cast<struct pbuf *>(std::calloc(1, sizeof(struct pbuf) + kHeaderRoom + length));

    if (p != nullptr) {
        p->payload = reinterpret_cast<unsigned char *>(p + 1) + kHeaderRoom;
        p->len = length;
        p->tot_len = length;
        p->type = type;
        p->ref = 1;
        if (desc != nullptr) {
            p->desc = *desc;
        }
    }
    return p;
}

void tcp_tx_pbuf_free(struct tcp_pcb *, struct pbuf *p)
{
    while (p != nullptr) {
        struct pbuf *next = p->next;

        if (p->desc.opaque != nullptr) {
            ++g_freed_opaque_count;
            g_last_freed_opaque = p->desc.opaque;
        }
        std::free(p);
        p = next;
    }
}

void tcp_tx_seg_free(struct tcp_pcb *pcb, struct tcp_seg *seg)
{
    if (seg != nullptr) {
        tcp_tx_pbuf_free(pcb, seg->p);
        external_tcp_seg_free(pcb, seg);
    }
}

void tcp_tx_segs_free(struct tcp_pcb *pcb, struct tcp_seg *seg)
{
    while (seg != nullptr) {
        struct tcp_seg *next = seg->next;

        seg->next = nullptr;
        tcp_tx_seg_free(pcb, seg);
        seg = next;
    }
}

u8_t pbuf_header(struct pbuf *p, s32_t header_size)
{
    // Real pbuf_header() semantics for a contiguous buffer: positive exposes header room in
    // front of the payload, negative hides bytes. tcp_in.c parses headers through it and
    // tcp_out.c builds them through it (tcp_in_timewait_test.cpp).
    p->payload = static_cast<unsigned char *>(p->payload) - header_size;
    p->len += header_size;
    p->tot_len += header_size;
    return 0;
}

u8_t pbuf_clen(struct pbuf *p)
{
    u8_t count = 0;

    while (p != nullptr) {
        ++count;
        p = p->next;
    }
    return count;
}

void pbuf_cat(struct pbuf *head, struct pbuf *tail)
{
    struct pbuf *p = head;

    while (p != nullptr) {
        p->tot_len += tail->tot_len;
        if (p->next == nullptr) {
            p->next = tail;
            return;
        }
        p = p->next;
    }
}

void cc_cong_signal(struct tcp_pcb *, uint32_t)
{
}

static err_t capture_output(struct pbuf *, struct tcp_seg *seg, void *p_conn, u16_t flags)
{
    struct tcp_pcb *pcb = static_cast<struct tcp_pcb *>(p_conn);
    output_capture *capture = static_cast<output_capture *>(pcb->callback_arg);

    if (capture->calls == 0U) {
        capture->first_seqno = seg->seqno;
    }
    ++capture->calls;
    capture->seqno = seg->seqno;
    capture->len = seg->len;
    capture->total_len += seg->len;
    capture->flags = flags;
    capture->desc_attr = seg->p->desc.attr;
    capture->opaque = seg->p->desc.opaque;
    return ERR_OK;
}

} // extern "C"

class tcp_output_test : public ::testing::Test {
protected:
    void SetUp() override
    {
        std::memset(&m_pcb, 0, sizeof(m_pcb));
        std::memset(&m_capture, 0, sizeof(m_capture));
        g_fail_next_seg_alloc = false;
        g_fail_next_pbuf_alloc = false;
        g_freed_opaque_count = 0;
        g_last_freed_opaque = nullptr;

        m_pcb.local_ip.ip4.addr = htonl(0x0a000001U);
        m_pcb.remote_ip.ip4.addr = htonl(0x0a000002U);
        m_pcb.private_state = ESTABLISHED;
        m_pcb.callback_arg = &m_capture;
        m_pcb.ip_output = capture_output;
        m_pcb.local_port = 10000;
        m_pcb.remote_port = 20000;
        m_pcb.rcv_ann_wnd = 65535;
        m_pcb.rtime = -1;
        m_pcb.ticks_since_data_sent = -1;
        m_pcb.mss = CONST_TCP_MSS;
        m_pcb.advtsd_mss = CONST_TCP_MSS;
        m_pcb.lastack = kInitialSeq;
        m_pcb.snd_nxt = kInitialSeq;
        m_pcb.snd_lbb = kInitialSeq;
        m_pcb.snd_wnd = kInitialWindow;
        m_pcb.snd_wnd_max = kInitialWindow;
        m_pcb.cwnd = kInitialWindow;
        m_pcb.tso.max_payload_sz = kExpressBytes;
        m_pcb.tso.max_send_sge = 16;
    }

    void TearDown() override
    {
        tcp_tx_segs_free(&m_pcb, m_pcb.unacked);
        tcp_tx_segs_free(&m_pcb, m_pcb.unsent);
        tcp_tx_seg_free(&m_pcb, m_pcb.seg_alloc);
    }

    err_t enqueue_express(void *data, size_t length, void *opaque)
    {
        struct iovec iov = {data, length};
        pbuf_desc desc = {};

        desc.attr = PBUF_DESC_EXPRESS;
        desc.opaque = opaque;
        return tcp_write_express(&m_pcb, &iov, 1, &desc);
    }

    err_t enqueue_express_iov(struct iovec *iov, u32_t iovcnt, void *opaque)
    {
        pbuf_desc desc = {};

        desc.attr = PBUF_DESC_EXPRESS;
        desc.opaque = opaque;
        return tcp_write_express(&m_pcb, iov, iovcnt, &desc);
    }

    void enable_worker_partial_window_split() { m_pcb.flags |= TF_WORKER_PARTIAL_WND_SPLIT; }

    static constexpr u32_t kInitialSeq = 1000;
    static constexpr u32_t kInitialWindow = 16384;
    static constexpr u32_t kFirstWriteBytes = 1000;
    static constexpr u32_t kConstrainedWindow = 4096;
    static constexpr u32_t kExpressBytes = 8192;
    static constexpr u32_t kExpectedPrefix = kConstrainedWindow - kFirstWriteBytes;

    struct tcp_pcb m_pcb;
    output_capture m_capture;
};

constexpr u32_t tcp_output_test::kInitialSeq;
constexpr u32_t tcp_output_test::kInitialWindow;
constexpr u32_t tcp_output_test::kFirstWriteBytes;
constexpr u32_t tcp_output_test::kConstrainedWindow;
constexpr u32_t tcp_output_test::kExpressBytes;
constexpr u32_t tcp_output_test::kExpectedPrefix;

TEST_F(tcp_output_test, splits_express_segment_behind_unacked_to_open_window)
{
    unsigned char first_data[kFirstWriteBytes] = {};
    unsigned char express_data[kExpressBytes] = {};
    int first_completion_token = 0;
    int express_completion_token = 0;

    enable_worker_partial_window_split();

    ASSERT_EQ(ERR_OK, enqueue_express(first_data, sizeof(first_data), &first_completion_token));
    ASSERT_EQ(ERR_OK, tcp_output(&m_pcb));
    ASSERT_EQ(1U, m_capture.calls);
    ASSERT_NE(nullptr, m_pcb.unacked);
    ASSERT_EQ(kInitialSeq + kFirstWriteBytes, m_pcb.snd_nxt);

    ASSERT_EQ(ERR_OK,
              enqueue_express(express_data, sizeof(express_data), &express_completion_token));
    ASSERT_NE(nullptr, m_pcb.unsent);
    ASSERT_EQ(m_pcb.unsent, m_pcb.last_unsent);
    ASSERT_EQ(kInitialSeq + kFirstWriteBytes, m_pcb.unsent->seqno);
    ASSERT_EQ(kExpressBytes, m_pcb.unsent->len);
    ASSERT_NE(0, m_pcb.unsent->flags & TF_SEG_OPTS_ZEROCOPY);
    ASSERT_EQ(PBUF_DESC_EXPRESS, m_pcb.unsent->p->desc.attr);
    ASSERT_EQ(&express_completion_token, m_pcb.unsent->p->desc.opaque);

    m_pcb.snd_wnd = kConstrainedWindow;
    m_pcb.cwnd = kConstrainedWindow;
    m_capture = {};

    ASSERT_EQ(ERR_OK, tcp_output(&m_pcb));

    ASSERT_EQ(1U, m_capture.calls)
        << "tcp_output must send the prefix that fits after the unacked bytes";
    EXPECT_EQ(kInitialSeq + kFirstWriteBytes, m_capture.seqno);
    EXPECT_EQ(kExpectedPrefix, m_capture.len);
    EXPECT_NE(0, m_capture.flags & TCP_WRITE_ZEROCOPY);
    EXPECT_NE(0, m_capture.flags & TCP_WRITE_TSO);
    EXPECT_EQ(PBUF_DESC_EXPRESS, m_capture.desc_attr);
    EXPECT_EQ(nullptr, m_capture.opaque);

    EXPECT_EQ(kInitialSeq + kConstrainedWindow, m_pcb.snd_nxt);
    ASSERT_NE(nullptr, m_pcb.unacked->next);
    EXPECT_EQ(kExpectedPrefix, m_pcb.unacked->next->len);
    EXPECT_EQ(m_pcb.unacked->next, m_pcb.last_unacked);

    ASSERT_NE(nullptr, m_pcb.unsent);
    EXPECT_EQ(kInitialSeq + kConstrainedWindow, m_pcb.unsent->seqno);
    EXPECT_EQ(kExpressBytes - kExpectedPrefix, m_pcb.unsent->len);
    EXPECT_EQ(m_pcb.unsent, m_pcb.last_unsent);
    EXPECT_EQ(PBUF_DESC_EXPRESS, m_pcb.unsent->p->desc.attr);
    EXPECT_EQ(&express_completion_token, m_pcb.unsent->p->desc.opaque);
}

TEST_F(tcp_output_test, legacy_mode_does_not_split_express_segment_behind_unacked)
{
    unsigned char first_data[kFirstWriteBytes] = {};
    unsigned char express_data[kExpressBytes] = {};
    int first_completion_token = 0;
    int express_completion_token = 0;

    ASSERT_EQ(ERR_OK, enqueue_express(first_data, sizeof(first_data), &first_completion_token));
    ASSERT_EQ(ERR_OK, tcp_output(&m_pcb));
    ASSERT_EQ(ERR_OK,
              enqueue_express(express_data, sizeof(express_data), &express_completion_token));

    m_pcb.snd_wnd = kConstrainedWindow;
    m_pcb.cwnd = kConstrainedWindow;
    m_capture = {};

    ASSERT_EQ(ERR_OK, tcp_output(&m_pcb));

    EXPECT_EQ(0U, m_capture.calls);
    EXPECT_EQ(kInitialSeq + kFirstWriteBytes, m_pcb.snd_nxt);
    ASSERT_NE(nullptr, m_pcb.unsent);
    EXPECT_EQ(kExpressBytes, m_pcb.unsent->len);
    EXPECT_EQ(&express_completion_token, m_pcb.unsent->p->desc.opaque);
}

TEST_F(tcp_output_test, worker_mode_does_not_split_retransmitted_express_segment)
{
    unsigned char first_data[kFirstWriteBytes] = {};
    unsigned char express_data[kExpressBytes] = {};
    int first_completion_token = 0;
    int express_completion_token = 0;

    enable_worker_partial_window_split();
    ASSERT_EQ(ERR_OK, enqueue_express(first_data, sizeof(first_data), &first_completion_token));
    ASSERT_EQ(ERR_OK, tcp_output(&m_pcb));
    ASSERT_EQ(ERR_OK,
              enqueue_express(express_data, sizeof(express_data), &express_completion_token));

    m_pcb.snd_wnd = kConstrainedWindow;
    m_pcb.cwnd = kConstrainedWindow;
    m_pcb.snd_nxt += 1U;
    m_capture = {};

    ASSERT_EQ(ERR_OK, tcp_output(&m_pcb));

    EXPECT_EQ(0U, m_capture.calls);
    ASSERT_NE(nullptr, m_pcb.unsent);
    EXPECT_EQ(kExpressBytes, m_pcb.unsent->len);
    EXPECT_EQ(&express_completion_token, m_pcb.unsent->p->desc.opaque);
}

TEST_F(tcp_output_test, worker_split_obeys_congestion_window)
{
    unsigned char first_data[kFirstWriteBytes] = {};
    unsigned char express_data[kExpressBytes] = {};
    int express_completion_token = 0;

    enable_worker_partial_window_split();
    ASSERT_EQ(ERR_OK, enqueue_express(first_data, sizeof(first_data), nullptr));
    ASSERT_EQ(ERR_OK, tcp_output(&m_pcb));
    ASSERT_EQ(ERR_OK,
              enqueue_express(express_data, sizeof(express_data), &express_completion_token));

    m_pcb.snd_wnd = kInitialWindow;
    m_pcb.cwnd = kConstrainedWindow;
    m_capture = {};

    ASSERT_EQ(ERR_OK, tcp_output(&m_pcb));

    ASSERT_EQ(1U, m_capture.calls);
    EXPECT_EQ(kExpectedPrefix, m_capture.total_len);
    EXPECT_EQ(kInitialSeq + kConstrainedWindow, m_pcb.snd_nxt);
    ASSERT_NE(nullptr, m_pcb.unsent);
    EXPECT_EQ(kExpressBytes - kExpectedPrefix, m_pcb.unsent->len);
    EXPECT_EQ(&express_completion_token, m_pcb.unsent->p->desc.opaque);
}

TEST_F(tcp_output_test, worker_split_fills_window_across_multiple_pbufs)
{
    unsigned char first_data[kFirstWriteBytes] = {};
    unsigned char express_head[kFirstWriteBytes] = {};
    unsigned char express_tail[kExpressBytes - kFirstWriteBytes] = {};
    struct iovec iov[] = {
        {express_head, sizeof(express_head)},
        {express_tail, sizeof(express_tail)},
    };
    int express_completion_token = 0;

    enable_worker_partial_window_split();
    ASSERT_EQ(ERR_OK, enqueue_express(first_data, sizeof(first_data), nullptr));
    ASSERT_EQ(ERR_OK, tcp_output(&m_pcb));
    ASSERT_EQ(ERR_OK,
              enqueue_express_iov(iov, sizeof(iov) / sizeof(iov[0]), &express_completion_token));
    ASSERT_NE(nullptr, m_pcb.unsent);
    ASSERT_NE(nullptr, m_pcb.unsent->p->next);

    m_pcb.snd_wnd = kConstrainedWindow;
    m_pcb.cwnd = kConstrainedWindow;
    m_capture = {};

    ASSERT_EQ(ERR_OK, tcp_output(&m_pcb));

    EXPECT_EQ(2U, m_capture.calls);
    EXPECT_EQ(kInitialSeq + kFirstWriteBytes, m_capture.first_seqno);
    EXPECT_EQ(kExpectedPrefix, m_capture.total_len);
    EXPECT_EQ(kInitialSeq + kConstrainedWindow, m_pcb.snd_nxt);
    ASSERT_NE(nullptr, m_pcb.unsent);
    EXPECT_EQ(kInitialSeq + kConstrainedWindow, m_pcb.unsent->seqno);
    EXPECT_EQ(kExpressBytes - kExpectedPrefix, m_pcb.unsent->len);
    EXPECT_EQ(&express_completion_token, m_pcb.unsent->p->desc.opaque);
}

TEST_F(tcp_output_test, split_completion_stays_with_rightmost_unsent_tail)
{
    unsigned char first_data[kFirstWriteBytes] = {};
    unsigned char express_data[kExpressBytes] = {};
    int express_completion_token = 0;

    enable_worker_partial_window_split();
    ASSERT_EQ(ERR_OK, enqueue_express(first_data, sizeof(first_data), nullptr));
    ASSERT_EQ(ERR_OK, tcp_output(&m_pcb));
    ASSERT_EQ(ERR_OK,
              enqueue_express(express_data, sizeof(express_data), &express_completion_token));
    m_pcb.snd_wnd = kConstrainedWindow;
    m_pcb.cwnd = kConstrainedWindow;

    ASSERT_EQ(ERR_OK, tcp_output(&m_pcb));
    ASSERT_NE(nullptr, m_pcb.unacked);
    ASSERT_NE(nullptr, m_pcb.unsent);

    tcp_tx_segs_free(&m_pcb, m_pcb.unacked);
    m_pcb.unacked = nullptr;
    m_pcb.last_unacked = nullptr;
    EXPECT_EQ(0U, g_freed_opaque_count);

    tcp_tx_segs_free(&m_pcb, m_pcb.unsent);
    m_pcb.unsent = nullptr;
    m_pcb.last_unsent = nullptr;
    EXPECT_EQ(1U, g_freed_opaque_count);
    EXPECT_EQ(&express_completion_token, g_last_freed_opaque);
}

TEST_F(tcp_output_test, split_keeps_fin_on_rightmost_unsent_tail)
{
    unsigned char first_data[kFirstWriteBytes] = {};
    unsigned char express_data[kExpressBytes] = {};

    enable_worker_partial_window_split();
    ASSERT_EQ(ERR_OK, enqueue_express(first_data, sizeof(first_data), nullptr));
    ASSERT_EQ(ERR_OK, tcp_output(&m_pcb));
    ASSERT_EQ(ERR_OK, enqueue_express(express_data, sizeof(express_data), nullptr));
    ASSERT_EQ(ERR_OK, tcp_send_fin(&m_pcb));
    ASSERT_NE(0U, TCPH_FLAGS(m_pcb.last_unsent->tcphdr) & TCP_FIN);

    m_pcb.snd_wnd = kConstrainedWindow;
    m_pcb.cwnd = kConstrainedWindow;
    ASSERT_EQ(ERR_OK, tcp_output(&m_pcb));

    ASSERT_NE(nullptr, m_pcb.unacked);
    ASSERT_NE(nullptr, m_pcb.unacked->next);
    EXPECT_EQ(0U, TCPH_FLAGS(m_pcb.unacked->next->tcphdr) & TCP_FIN);
    ASSERT_NE(nullptr, m_pcb.unsent);
    EXPECT_NE(0U, TCPH_FLAGS(m_pcb.unsent->tcphdr) & TCP_FIN);
}

TEST_F(tcp_output_test, legacy_split_success_keeps_single_express_completion)
{
    unsigned char express_data[kExpressBytes] = {};
    int express_completion_token = 0;

    ASSERT_EQ(ERR_OK,
              enqueue_express(express_data, sizeof(express_data), &express_completion_token));
    ASSERT_NE(nullptr, m_pcb.unsent);
    struct tcp_seg *const left = m_pcb.unsent;

    tcp_split_segment(&m_pcb, left, kConstrainedWindow);

    ASSERT_NE(nullptr, left->next);
    struct tcp_seg *const right = left->next;
    left->next = nullptr;
    m_pcb.unsent = nullptr;
    m_pcb.last_unsent = nullptr;

    tcp_tx_seg_free(&m_pcb, left);
    EXPECT_EQ(0U, g_freed_opaque_count);

    tcp_tx_seg_free(&m_pcb, right);
    EXPECT_EQ(1U, g_freed_opaque_count);
    EXPECT_EQ(&express_completion_token, g_last_freed_opaque);
}

TEST_F(tcp_output_test, worker_split_allocation_failure_preserves_express_completion)
{
    unsigned char express_data[kExpressBytes] = {};
    int express_completion_token = 0;

    enable_worker_partial_window_split();
    ASSERT_EQ(ERR_OK,
              enqueue_express(express_data, sizeof(express_data), &express_completion_token));
    ASSERT_NE(nullptr, m_pcb.unsent);
    struct tcp_seg *const original_seg = m_pcb.unsent;
    struct pbuf *const original_pbuf = original_seg->p;

    g_fail_next_seg_alloc = true;
    tcp_split_segment(&m_pcb, original_seg, kConstrainedWindow);

    EXPECT_EQ(original_seg, m_pcb.unsent);
    EXPECT_EQ(original_seg, m_pcb.last_unsent);
    EXPECT_EQ(nullptr, original_seg->next);
    EXPECT_EQ(original_pbuf, original_seg->p);
    EXPECT_EQ(kExpressBytes, original_seg->len);
    EXPECT_EQ(&express_completion_token, original_pbuf->desc.opaque);
    EXPECT_EQ(0U, g_freed_opaque_count);
    EXPECT_EQ(nullptr, g_last_freed_opaque);
}

TEST_F(tcp_output_test, worker_split_pbuf_allocation_failure_preserves_express_completion)
{
    unsigned char express_data[kExpressBytes] = {};
    int express_completion_token = 0;

    enable_worker_partial_window_split();
    ASSERT_EQ(ERR_OK,
              enqueue_express(express_data, sizeof(express_data), &express_completion_token));
    ASSERT_NE(nullptr, m_pcb.unsent);
    struct tcp_seg *const original_seg = m_pcb.unsent;
    struct pbuf *const original_pbuf = original_seg->p;

    g_fail_next_pbuf_alloc = true;
    tcp_split_segment(&m_pcb, original_seg, kConstrainedWindow);

    EXPECT_EQ(original_seg, m_pcb.unsent);
    EXPECT_EQ(original_seg, m_pcb.last_unsent);
    EXPECT_EQ(nullptr, original_seg->next);
    EXPECT_EQ(original_pbuf, original_seg->p);
    EXPECT_EQ(kExpressBytes, original_seg->len);
    EXPECT_EQ(&express_completion_token, original_pbuf->desc.opaque);
    EXPECT_EQ(0U, g_freed_opaque_count);
    EXPECT_EQ(nullptr, g_last_freed_opaque);
}
