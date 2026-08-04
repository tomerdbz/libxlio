/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <gtest/gtest.h>

#include <cstring>
#include <vector>

#include "core/lwip/tcp_impl.h"

/*
 * Pins the two-phase TIME_WAIT reuse contract of tcp_timewait_input()/tcp_pcb_reuse():
 * - An accepted SYN invokes syn_tw_handled_cb exactly twice: CLAIM before any pcb recycle or
 *   state change, COMMIT after the pcb is recycled to SYN_RCVD, both as (listen_sock, pcb, phase).
 * - CLAIM returning non-ERR_OK silently drops the SYN: no COMMIT, pcb untouched.
 * - A null callback never admits the reuse: silent drop, pcb untouched.
 * - COMMIT returning non-ERR_OK stops before the SYN|ACK; the recycle is not rolled back.
 *
 * The lwIP stubs cooperate with tcp_output_test.cpp, which owns the shared tcp_out.c seams
 * (tcp_tx_pbuf_alloc/free, pbuf_header, ...); this file adds only the tcp_in.c-specific ones.
 */

enum class tw_event {
    CLAIM,
    PCB_RECYCLE,
    STATE_CHANGE,
    COMMIT,
    ABANDON,
};

static std::vector<tw_event> g_tw_events;
static err_t g_claim_result;
static err_t g_commit_result;
static void *g_claim_arg;
static void *g_commit_arg;
static struct tcp_pcb *g_claim_pcb;
static struct tcp_pcb *g_commit_pcb;
static enum tcp_state g_claim_observed_state;
static enum tcp_state g_commit_observed_state;
static enum tcp_state g_last_observed_state;
static unsigned g_ip_output_calls;

extern "C" {

static err_t test_timewait_handled_cb(void *arg, struct tcp_pcb *newpcb,
                                      enum tcp_timewait_reuse_phase phase)
{
    if (phase == TCP_TIMEWAIT_REUSE_CLAIM) {
        g_tw_events.push_back(tw_event::CLAIM);
        g_claim_arg = arg;
        g_claim_pcb = newpcb;
        g_claim_observed_state = get_tcp_state(newpcb);
        return g_claim_result;
    }
    g_tw_events.push_back(tw_event::COMMIT);
    g_commit_arg = arg;
    g_commit_pcb = newpcb;
    g_commit_observed_state = get_tcp_state(newpcb);
    return g_commit_result;
}

static void test_tcp_state_observer(void *, enum tcp_state new_state)
{
    g_tw_events.push_back(tw_event::STATE_CHANGE);
    g_last_observed_state = new_state;
}

tcp_state_observer_fn external_tcp_state_observer = test_tcp_state_observer;

static void test_external_tcp_tx_pbuf_free(void *p_conn, struct pbuf *p)
{
    tcp_tx_pbuf_free(static_cast<struct tcp_pcb *>(p_conn), p);
}

tcp_tx_pbuf_free_fn external_tcp_tx_pbuf_free = test_external_tcp_tx_pbuf_free;

static err_t count_ip_output(struct pbuf *, struct tcp_seg *, void *, u16_t)
{
    ++g_ip_output_calls;
    return ERR_OK;
}

void tcp_pcb_recycle(struct tcp_pcb *pcb)
{
    g_tw_events.push_back(tw_event::PCB_RECYCLE);
    pcb->flags = 0;
    pcb->last_unsent = nullptr;
    pcb->last_unacked = nullptr;
}

void tcp_abandon(struct tcp_pcb *, int)
{
    g_tw_events.push_back(tw_event::ABANDON);
}

void tcp_abort(struct tcp_pcb *)
{
}

void tcp_pcb_purge(struct tcp_pcb *)
{
}

void tcp_pcb_remove(struct tcp_pcb *)
{
}

err_t tcp_recv_null(void *, struct tcp_pcb *, struct pbuf *, err_t)
{
    return ERR_OK;
}

struct tcp_seg *tcp_seg_copy(struct tcp_pcb *, struct tcp_seg *)
{
    return nullptr;
}

void tcp_seg_free(struct tcp_pcb *pcb, struct tcp_seg *seg)
{
    tcp_tx_seg_free(pcb, seg);
}

void tcp_segs_free(struct tcp_pcb *pcb, struct tcp_seg *seg)
{
    tcp_tx_segs_free(pcb, seg);
}

u16_t tcp_send_mss(struct tcp_pcb *)
{
    return CONST_TCP_MSS;
}

u32_t tcp_update_rcv_ann_wnd(struct tcp_pcb *pcb)
{
    return pcb->rcv_ann_wnd;
}

void cc_ack_received(struct tcp_pcb *, uint16_t)
{
}

void cc_conn_init(struct tcp_pcb *)
{
}

void cc_post_recovery(struct tcp_pcb *)
{
}

u8_t pbuf_free(struct pbuf *)
{
    // Input packets are test-owned storage.
    return 1;
}

void pbuf_realloc(struct pbuf *, u32_t)
{
}

} // extern "C"

class tcp_in_timewait_test : public ::testing::Test {
protected:
    void SetUp() override
    {
        g_tw_events.clear();
        g_claim_result = ERR_OK;
        g_commit_result = ERR_OK;
        g_claim_arg = nullptr;
        g_commit_arg = nullptr;
        g_claim_pcb = nullptr;
        g_commit_pcb = nullptr;
        g_claim_observed_state = CLOSED;
        g_commit_observed_state = CLOSED;
        g_last_observed_state = CLOSED;
        g_ip_output_calls = 0;

        std::memset(&m_pcb, 0, sizeof(m_pcb));
        // Assign the state directly: set_tcp_state() would fire the observer seam.
        m_pcb.private_state = TIME_WAIT;
        m_pcb.my_container = &m_pcb;
        m_pcb.listen_sock = &m_listen_token;
        m_pcb.syn_tw_handled_cb = test_timewait_handled_cb;
        m_pcb.ip_output = count_ip_output;
        m_pcb.local_port = 10000;
        m_pcb.remote_port = 20000;
        m_pcb.rcv_nxt = kOldRcvNxt;
        m_pcb.mss = CONST_TCP_MSS;
        m_pcb.advtsd_mss = CONST_TCP_MSS;
        m_pcb.snd_lbb = kInitialSeq;
        m_pcb.lastack = kInitialSeq;
    }

    void TearDown() override
    {
        tcp_tx_segs_free(&m_pcb, m_pcb.unacked);
        tcp_tx_segs_free(&m_pcb, m_pcb.unsent);
    }

    // A minimal IPv4+TCP SYN toward the TIME_WAIT pcb, sequence-wise reusable (RFC 6191).
    void input_syn()
    {
        std::memset(m_packet, 0, sizeof(m_packet));
        m_packet[0] = 0x45; /* IPv4, 20-byte header */
        const u16_t total_length = htons(sizeof(m_packet));
        std::memcpy(&m_packet[2], &total_length, sizeof(total_length));

        struct tcp_hdr *tcphdr = reinterpret_cast<struct tcp_hdr *>(&m_packet[20]);
        tcphdr->src = htons(m_pcb.remote_port);
        tcphdr->dest = htons(m_pcb.local_port);
        tcphdr->seqno = htonl(kSynSeqno);
        tcphdr->ackno = 0;
        TCPH_HDRLEN_FLAGS_SET(tcphdr, 5, TCP_SYN);
        tcphdr->wnd = htons(65535);

        std::memset(&m_pbuf, 0, sizeof(m_pbuf));
        m_pbuf.payload = m_packet;
        m_pbuf.len = sizeof(m_packet);
        m_pbuf.tot_len = sizeof(m_packet);
        m_pbuf.type = PBUF_RAM;
        m_pbuf.ref = 1;

        L3_level_tcp_input(&m_pbuf, &m_pcb);
    }

    static constexpr u32_t kInitialSeq = 1000;
    static constexpr u32_t kOldRcvNxt = 4000;
    static constexpr u32_t kSynSeqno = 5000;

    struct tcp_pcb m_pcb;
    struct pbuf m_pbuf;
    alignas(4) unsigned char m_packet[40];
    int m_listen_token = 0;
};

constexpr u32_t tcp_in_timewait_test::kInitialSeq;
constexpr u32_t tcp_in_timewait_test::kOldRcvNxt;
constexpr u32_t tcp_in_timewait_test::kSynSeqno;

TEST_F(tcp_in_timewait_test, syn_accept_runs_claim_before_recycle_and_commit_after)
{
    input_syn();

    const std::vector<tw_event> expected = {
        tw_event::CLAIM,
        tw_event::PCB_RECYCLE,
        tw_event::STATE_CHANGE,
        tw_event::COMMIT,
    };
    ASSERT_EQ(expected, g_tw_events)
        << "the accept path must run exactly one CLAIM before the pcb recycle/state change "
           "and exactly one COMMIT after";

    // Both phases carry (listen_sock, pcb).
    EXPECT_EQ(&m_listen_token, g_claim_arg);
    EXPECT_EQ(&m_listen_token, g_commit_arg);
    EXPECT_EQ(&m_pcb, g_claim_pcb);
    EXPECT_EQ(&m_pcb, g_commit_pcb);

    // CLAIM sees the untouched TIME_WAIT pcb; COMMIT sees the recycled SYN_RCVD incarnation.
    EXPECT_EQ(TIME_WAIT, g_claim_observed_state);
    EXPECT_EQ(SYN_RCVD, g_commit_observed_state);
    EXPECT_EQ(SYN_RCVD, g_last_observed_state);
    EXPECT_EQ(SYN_RCVD, get_tcp_state(&m_pcb));
    EXPECT_EQ(kSynSeqno + 1, m_pcb.rcv_nxt);

    // The SYN|ACK is produced only after a successful COMMIT. It occupies zero window
    // space (seg->len == 0), so tcp_output() transmits it immediately onto unacked.
    ASSERT_NE(nullptr, m_pcb.unacked);
    EXPECT_EQ(TCP_SYN | TCP_ACK, TCPH_FLAGS(m_pcb.unacked->tcphdr));
    EXPECT_EQ(nullptr, m_pcb.unsent);
    EXPECT_EQ(1U, g_ip_output_calls);
}

TEST_F(tcp_in_timewait_test, claim_reject_silently_drops_syn_without_commit)
{
    g_claim_result = ERR_VAL;

    struct tcp_pcb pcb_before;
    std::memcpy(&pcb_before, &m_pcb, sizeof(pcb_before));

    input_syn();

    const std::vector<tw_event> expected = {tw_event::CLAIM};
    ASSERT_EQ(expected, g_tw_events) << "a rejected CLAIM must not recycle or COMMIT";
    EXPECT_EQ(TIME_WAIT, g_claim_observed_state);
    EXPECT_EQ(0, std::memcmp(&pcb_before, &m_pcb, sizeof(pcb_before)))
        << "a rejected CLAIM must leave the pcb untouched";
    EXPECT_EQ(nullptr, m_pcb.unsent);
    EXPECT_EQ(0U, g_ip_output_calls);
}

TEST_F(tcp_in_timewait_test, null_callback_drops_syn_without_reuse)
{
    m_pcb.syn_tw_handled_cb = nullptr;

    struct tcp_pcb pcb_before;
    std::memcpy(&pcb_before, &m_pcb, sizeof(pcb_before));

    input_syn();

    EXPECT_TRUE(g_tw_events.empty()) << "no callback means no reuse admission at all";
    EXPECT_EQ(0, std::memcmp(&pcb_before, &m_pcb, sizeof(pcb_before)))
        << "an unadmitted SYN must leave the TIME_WAIT pcb untouched";
    EXPECT_EQ(nullptr, m_pcb.unsent);
    EXPECT_EQ(0U, g_ip_output_calls);
}

TEST_F(tcp_in_timewait_test, commit_failure_leaves_recycled_pcb_without_synack)
{
    g_commit_result = ERR_VAL;

    input_syn();

    const std::vector<tw_event> expected = {
        tw_event::CLAIM,
        tw_event::PCB_RECYCLE,
        tw_event::STATE_CHANGE,
        tw_event::COMMIT,
    };
    ASSERT_EQ(expected, g_tw_events);

    // The pcb is already recycled when COMMIT runs; there is no rollback path and no
    // SYN|ACK may be produced for an uncommitted reuse.
    EXPECT_EQ(SYN_RCVD, get_tcp_state(&m_pcb));
    EXPECT_EQ(nullptr, m_pcb.unsent);
    EXPECT_EQ(0U, g_ip_output_calls);
}
