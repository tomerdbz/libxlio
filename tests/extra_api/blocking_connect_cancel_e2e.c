/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_L2_HEADER   22U
#define MAX_PACKET_SIZE 2048U

#define ETHER_TYPE_VLAN 0x8100U
#define ETHER_TYPE_QINQ 0x88a8U
#define TCP_FLAG_FIN    0x01U
#define TCP_FLAG_SYN    0x02U
#define TCP_FLAG_RST    0x04U
#define TCP_FLAG_ACK    0x10U

struct arp_ipv4 {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_length;
    uint8_t protocol_length;
    uint16_t operation;
    uint8_t sender_hardware[ETHER_ADDR_LEN];
    uint32_t sender_ip;
    uint8_t target_hardware[ETHER_ADDR_LEN];
    uint32_t target_ip;
} __attribute__((packed));

struct ipv4_wire {
    uint8_t version_ihl;
    uint8_t type_of_service;
    uint16_t total_length;
    uint16_t identification;
    uint16_t fragment_offset;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t source;
    uint32_t destination;
} __attribute__((packed));

struct tcp_wire {
    uint16_t source;
    uint16_t destination;
    uint32_t sequence;
    uint32_t acknowledgment;
    uint16_t data_offset_flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
} __attribute__((packed));

struct pseudo_header {
    uint32_t source;
    uint32_t destination;
    uint8_t zero;
    uint8_t protocol;
    uint16_t length;
} __attribute__((packed));

enum role {
    ROLE_NONE,
    ROLE_PEER,
    ROLE_CLIENT,
};

struct options {
    enum role role;
    const char *interface_name;
    struct in_addr bind_ip;
    struct in_addr target_ip;
    uint16_t port;
    unsigned int cancel_delay_ms;
    unsigned int join_timeout_ms;
    unsigned int reply_delay_ms;
    unsigned int observe_ms;
    unsigned int timeout_ms;
    bool probe_socket_after_cancel;
};

struct connect_call {
    pthread_mutex_t lock;
    pthread_cond_t condition;
    struct sockaddr_in target;
    int fd;
    int result;
    int error;
    bool started;
    bool done;
};

struct captured_syn {
    uint8_t l2_header[MAX_L2_HEADER];
    size_t l2_length;
    uint8_t client_hardware[ETHER_ADDR_LEN];
    uint32_t client_ip;
    uint16_t client_port;
    uint32_t client_sequence;
    bool valid;
};

static int failures;

static void fail(const char *message)
{
    fprintf(stderr, "FAIL %s\n", message);
    ++failures;
}

static int monotonic_now(struct timespec *value)
{
    if (clock_gettime(CLOCK_MONOTONIC, value) != 0) {
        perror("clock_gettime");
        return -1;
    }
    return 0;
}

static void add_ms(struct timespec *value, unsigned int milliseconds)
{
    value->tv_sec += (time_t)(milliseconds / 1000U);
    value->tv_nsec += (long)(milliseconds % 1000U) * 1000000L;
    if (value->tv_nsec >= 1000000000L) {
        ++value->tv_sec;
        value->tv_nsec -= 1000000000L;
    }
}

static int compare_timespec(const struct timespec *left, const struct timespec *right)
{
    if (left->tv_sec != right->tv_sec) {
        return left->tv_sec < right->tv_sec ? -1 : 1;
    }
    if (left->tv_nsec == right->tv_nsec) {
        return 0;
    }
    return left->tv_nsec < right->tv_nsec ? -1 : 1;
}

static int remaining_ms(const struct timespec *deadline)
{
    struct timespec now;
    int64_t nanoseconds;

    if (monotonic_now(&now) != 0) {
        return -1;
    }
    if (compare_timespec(&now, deadline) >= 0) {
        return 0;
    }
    nanoseconds = (int64_t)(deadline->tv_sec - now.tv_sec) * 1000000000LL;
    nanoseconds += deadline->tv_nsec - now.tv_nsec;
    return (int)((nanoseconds + 999999LL) / 1000000LL);
}

static void sleep_ms(unsigned int milliseconds)
{
    struct timespec delay = {
        .tv_sec = (time_t)(milliseconds / 1000U),
        .tv_nsec = (long)(milliseconds % 1000U) * 1000000L,
    };

    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
    }
}

static uint16_t internet_checksum(const void *data, size_t length)
{
    const uint8_t *bytes = data;
    uint32_t sum = 0U;

    while (length >= 2U) {
        sum += ((uint32_t)bytes[0] << 8U) | bytes[1];
        bytes += 2;
        length -= 2U;
    }
    if (length != 0U) {
        sum += (uint32_t)bytes[0] << 8U;
    }
    while ((sum >> 16U) != 0U) {
        sum = (sum & 0xffffU) + (sum >> 16U);
    }
    return htons((uint16_t)~sum);
}

static int l2_payload(const uint8_t *packet, size_t length, size_t *offset, uint16_t *protocol)
{
    const struct ether_header *ethernet;
    size_t current = sizeof(*ethernet);
    uint16_t type;
    unsigned int vlan_depth = 0U;

    if (length < current) {
        return -1;
    }
    ethernet = (const struct ether_header *)packet;
    type = ntohs(ethernet->ether_type);
    while (type == ETHER_TYPE_VLAN || type == ETHER_TYPE_QINQ) {
        if (++vlan_depth > 2U || length < current + 4U) {
            return -1;
        }
        memcpy(&type, packet + current + 2U, sizeof(type));
        type = ntohs(type);
        current += 4U;
    }
    *offset = current;
    *protocol = type;
    return current <= MAX_L2_HEADER ? 0 : -1;
}

static int interface_identity(int fd, const char *interface_name, int *interface_index,
                              uint8_t hardware[ETHER_ADDR_LEN])
{
    struct ifreq request;

    memset(&request, 0, sizeof(request));
    if (strlen(interface_name) >= sizeof(request.ifr_name)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    strcpy(request.ifr_name, interface_name);
    if (ioctl(fd, SIOCGIFINDEX, &request) != 0) {
        return -1;
    }
    *interface_index = request.ifr_ifindex;
    if (ioctl(fd, SIOCGIFHWADDR, &request) != 0) {
        return -1;
    }
    memcpy(hardware, request.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
    return 0;
}

static int send_frame(int fd, int interface_index, const uint8_t destination[ETHER_ADDR_LEN],
                      const void *frame, size_t length)
{
    struct sockaddr_ll address = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex = interface_index,
        .sll_halen = ETHER_ADDR_LEN,
    };

    memcpy(address.sll_addr, destination, ETHER_ADDR_LEN);
    return sendto(fd, frame, length, 0, (const struct sockaddr *)&address, sizeof(address)) ==
            (ssize_t)length
        ? 0
        : -1;
}

static int reply_to_arp(int fd, int interface_index, const uint8_t local_hardware[ETHER_ADDR_LEN],
                        uint32_t fake_ip, const uint8_t *packet, size_t packet_length,
                        size_t l2_length)
{
    const struct arp_ipv4 *request;
    struct arp_ipv4 *reply;
    struct ether_header *ethernet;
    uint8_t frame[MAX_L2_HEADER + sizeof(*reply)];

    if (packet_length < l2_length + sizeof(*request)) {
        return 0;
    }
    request = (const struct arp_ipv4 *)(packet + l2_length);
    if (ntohs(request->hardware_type) != ARPHRD_ETHER ||
        ntohs(request->protocol_type) != ETH_P_IP || request->hardware_length != ETHER_ADDR_LEN ||
        request->protocol_length != 4U || ntohs(request->operation) != ARPOP_REQUEST ||
        request->target_ip != fake_ip) {
        return 0;
    }

    memcpy(frame, packet, l2_length);
    ethernet = (struct ether_header *)frame;
    memcpy(ethernet->ether_dhost, request->sender_hardware, ETHER_ADDR_LEN);
    memcpy(ethernet->ether_shost, local_hardware, ETHER_ADDR_LEN);
    reply = (struct arp_ipv4 *)(frame + l2_length);
    *reply = (struct arp_ipv4) {
        .hardware_type = htons(ARPHRD_ETHER),
        .protocol_type = htons(ETH_P_IP),
        .hardware_length = ETHER_ADDR_LEN,
        .protocol_length = 4U,
        .operation = htons(ARPOP_REPLY),
        .sender_ip = fake_ip,
        .target_ip = request->sender_ip,
    };
    memcpy(reply->sender_hardware, local_hardware, ETHER_ADDR_LEN);
    memcpy(reply->target_hardware, request->sender_hardware, ETHER_ADDR_LEN);
    if (send_frame(fd, interface_index, request->sender_hardware, frame,
                   l2_length + sizeof(*reply)) != 0) {
        perror("send ARP reply");
        return -1;
    }
    return 1;
}

static bool parse_tcp_to_fake(const uint8_t *packet, size_t packet_length, size_t l2_length,
                              uint32_t fake_ip, uint16_t port, const struct ipv4_wire **ip_out,
                              const struct tcp_wire **tcp_out)
{
    const struct ipv4_wire *ip;
    const struct tcp_wire *tcp;
    size_t ip_length;
    size_t tcp_offset;

    if (packet_length < l2_length + sizeof(*ip)) {
        return false;
    }
    ip = (const struct ipv4_wire *)(packet + l2_length);
    ip_length = (size_t)(ip->version_ihl & 0x0fU) * 4U;
    if ((ip->version_ihl >> 4U) != 4U || ip_length < sizeof(*ip) ||
        packet_length < l2_length + ip_length + sizeof(*tcp) || ip->protocol != IPPROTO_TCP ||
        ip->destination != fake_ip || (ntohs(ip->fragment_offset) & 0x3fffU) != 0U) {
        return false;
    }
    tcp_offset = l2_length + ip_length;
    tcp = (const struct tcp_wire *)(packet + tcp_offset);
    if (ntohs(tcp->destination) != port) {
        return false;
    }
    *ip_out = ip;
    *tcp_out = tcp;
    return true;
}

static bool capture_syn(const uint8_t *packet, size_t packet_length, size_t l2_length,
                        uint32_t fake_ip, uint16_t port, struct captured_syn *captured)
{
    const struct ipv4_wire *ip;
    const struct tcp_wire *tcp;
    uint16_t flags;

    if (!parse_tcp_to_fake(packet, packet_length, l2_length, fake_ip, port, &ip, &tcp)) {
        return false;
    }
    flags = ntohs(tcp->data_offset_flags) & 0x01ffU;
    if ((flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) != TCP_FLAG_SYN) {
        return false;
    }
    memcpy(captured->l2_header, packet, l2_length);
    captured->l2_length = l2_length;
    memcpy(captured->client_hardware, ((const struct ether_header *)packet)->ether_shost,
           ETHER_ADDR_LEN);
    captured->client_ip = ip->source;
    captured->client_port = tcp->source;
    captured->client_sequence = ntohl(tcp->sequence);
    captured->valid = true;
    return true;
}

static int send_syn_ack(int fd, int interface_index, const uint8_t local_hardware[ETHER_ADDR_LEN],
                        uint32_t fake_ip, uint16_t port, const struct captured_syn *captured)
{
    uint8_t frame[MAX_L2_HEADER + sizeof(struct ipv4_wire) + sizeof(struct tcp_wire)];
    struct ether_header *ethernet;
    struct ipv4_wire *ip;
    struct tcp_wire *tcp;
    struct {
        struct pseudo_header pseudo;
        struct tcp_wire tcp;
    } __attribute__((packed)) checksum_input;
    size_t frame_length = captured->l2_length + sizeof(*ip) + sizeof(*tcp);

    memset(frame, 0, sizeof(frame));
    memcpy(frame, captured->l2_header, captured->l2_length);
    ethernet = (struct ether_header *)frame;
    memcpy(ethernet->ether_dhost, captured->client_hardware, ETHER_ADDR_LEN);
    memcpy(ethernet->ether_shost, local_hardware, ETHER_ADDR_LEN);

    ip = (struct ipv4_wire *)(frame + captured->l2_length);
    *ip = (struct ipv4_wire) {
        .version_ihl = 0x45U,
        .total_length = htons((uint16_t)(sizeof(*ip) + sizeof(*tcp))),
        .identification = htons((uint16_t)getpid()),
        .fragment_offset = htons(0x4000U),
        .time_to_live = 64U,
        .protocol = IPPROTO_TCP,
        .source = fake_ip,
        .destination = captured->client_ip,
    };
    ip->checksum = internet_checksum(ip, sizeof(*ip));

    tcp = (struct tcp_wire *)(frame + captured->l2_length + sizeof(*ip));
    *tcp = (struct tcp_wire) {
        .source = htons(port),
        .destination = captured->client_port,
        .sequence = htonl(0x4930786U),
        .acknowledgment = htonl(captured->client_sequence + 1U),
        .data_offset_flags = htons((5U << 12U) | TCP_FLAG_SYN | TCP_FLAG_ACK),
        .window = htons(65535U),
    };
    checksum_input.pseudo = (struct pseudo_header) {
        .source = ip->source,
        .destination = ip->destination,
        .protocol = IPPROTO_TCP,
        .length = htons(sizeof(*tcp)),
    };
    checksum_input.tcp = *tcp;
    tcp->checksum = internet_checksum(&checksum_input, sizeof(checksum_input));

    return send_frame(fd, interface_index, captured->client_hardware, frame, frame_length);
}

static bool is_ack_for_syn_ack(const uint8_t *packet, size_t packet_length, size_t l2_length,
                               uint32_t fake_ip, uint16_t port)
{
    const struct ipv4_wire *ip;
    const struct tcp_wire *tcp;
    uint16_t flags;

    if (!parse_tcp_to_fake(packet, packet_length, l2_length, fake_ip, port, &ip, &tcp)) {
        return false;
    }
    (void)ip;
    flags = ntohs(tcp->data_offset_flags) & 0x01ffU;
    return (flags & TCP_FLAG_ACK) != 0U && (flags & (TCP_FLAG_SYN | TCP_FLAG_RST)) == 0U &&
        ntohl(tcp->acknowledgment) == 0x4930787U;
}

static int run_peer(const struct options *options)
{
    uint8_t packet[MAX_PACKET_SIZE];
    uint8_t local_hardware[ETHER_ADDR_LEN];
    struct captured_syn captured = {};
    struct timespec overall_deadline;
    struct timespec reply_deadline = {};
    struct timespec observe_deadline = {};
    int interface_index;
    int fd;
    bool reply_sent = false;
    unsigned int arp_replies = 0U;
    unsigned int syn_packets = 0U;
    unsigned int post_cancel_acks = 0U;

    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        perror("AF_PACKET socket");
        return EXIT_FAILURE;
    }
    if (interface_identity(fd, options->interface_name, &interface_index, local_hardware) != 0) {
        perror("interface identity");
        close(fd);
        return EXIT_FAILURE;
    }
    struct sockaddr_ll bind_address = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex = interface_index,
    };
    if (bind(fd, (const struct sockaddr *)&bind_address, sizeof(bind_address)) != 0) {
        perror("AF_PACKET bind");
        close(fd);
        return EXIT_FAILURE;
    }
    if (monotonic_now(&overall_deadline) != 0) {
        close(fd);
        return EXIT_FAILURE;
    }
    add_ms(&overall_deadline, options->timeout_ms);
    printf("READY peer interface=%s fake_ip=%s port=%u\n", options->interface_name,
           inet_ntoa(options->target_ip), options->port);
    fflush(stdout);

    while (true) {
        struct pollfd descriptor = {.fd = fd, .events = POLLIN};
        struct timespec *active_deadline = &overall_deadline;
        int wait_ms;
        int result;

        if (captured.valid && !reply_sent &&
            compare_timespec(&reply_deadline, active_deadline) < 0) {
            active_deadline = &reply_deadline;
        } else if (reply_sent && compare_timespec(&observe_deadline, active_deadline) < 0) {
            active_deadline = &observe_deadline;
        }
        wait_ms = remaining_ms(active_deadline);
        if (wait_ms < 0) {
            fail("peer clock failed");
            break;
        }
        if (wait_ms == 0) {
            if (captured.valid && !reply_sent &&
                compare_timespec(active_deadline, &reply_deadline) == 0) {
                if (send_syn_ack(fd, interface_index, local_hardware, options->target_ip.s_addr,
                                 options->port, &captured) != 0) {
                    perror("send SYN-ACK");
                    fail("peer could not send delayed SYN-ACK");
                    break;
                }
                reply_sent = true;
                if (monotonic_now(&observe_deadline) != 0) {
                    fail("peer clock failed after SYN-ACK");
                    break;
                }
                add_ms(&observe_deadline, options->observe_ms);
                printf("SYN_ACK_SENT after_ms=%u\n", options->reply_delay_ms);
                fflush(stdout);
                continue;
            }
            if (reply_sent && compare_timespec(active_deadline, &observe_deadline) == 0) {
                break;
            }
            fail("peer timed out before observing a SYN");
            break;
        }

        result = poll(&descriptor, 1U, wait_ms);
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("peer poll");
            fail("peer poll failed");
            break;
        }
        if (result == 0) {
            continue;
        }

        ssize_t length = recv(fd, packet, sizeof(packet), 0);
        size_t l2_length;
        uint16_t protocol;
        if (length < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("peer recv");
            fail("peer receive failed");
            break;
        }
        if (l2_payload(packet, (size_t)length, &l2_length, &protocol) != 0) {
            continue;
        }
        if (protocol == ETH_P_ARP) {
            result = reply_to_arp(fd, interface_index, local_hardware, options->target_ip.s_addr,
                                  packet, (size_t)length, l2_length);
            if (result < 0) {
                fail("peer ARP reply failed");
                break;
            }
            arp_replies += result > 0 ? 1U : 0U;
            continue;
        }
        if (protocol != ETH_P_IP) {
            continue;
        }
        if (!captured.valid &&
            capture_syn(packet, (size_t)length, l2_length, options->target_ip.s_addr, options->port,
                        &captured)) {
            ++syn_packets;
            if (monotonic_now(&reply_deadline) != 0) {
                fail("peer clock failed after SYN");
                break;
            }
            add_ms(&reply_deadline, options->reply_delay_ms);
            printf("SYN_SEEN sequence=%" PRIu32 "\n", captured.client_sequence);
            fflush(stdout);
            continue;
        }
        if (captured.valid &&
            capture_syn(packet, (size_t)length, l2_length, options->target_ip.s_addr, options->port,
                        &captured)) {
            ++syn_packets;
            continue;
        }
        if (reply_sent &&
            is_ack_for_syn_ack(packet, (size_t)length, l2_length, options->target_ip.s_addr,
                               options->port)) {
            ++post_cancel_acks;
        }
    }

    if (!captured.valid) {
        fail("peer did not observe the initial SYN");
    }
    if (!reply_sent) {
        fail("peer did not send the delayed SYN-ACK");
    }
    if (post_cancel_acks == 0U) {
        fail("client did not continue the open socket's connect after caller cancellation");
    }
    printf("SUMMARY peer failures=%d arp_replies=%u syn_packets=%u post_cancel_acks=%u\n", failures,
           arp_replies, syn_packets, post_cancel_acks);
    close(fd);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

static void *connect_thread(void *argument)
{
    struct connect_call *call = argument;
    int result;
    int saved_errno;

    pthread_mutex_lock(&call->lock);
    call->started = true;
    pthread_cond_broadcast(&call->condition);
    pthread_mutex_unlock(&call->lock);

    errno = 0;
    result = connect(call->fd, (const struct sockaddr *)&call->target, sizeof(call->target));
    saved_errno = result == -1 ? errno : 0;
    pthread_mutex_lock(&call->lock);
    call->result = result;
    call->error = saved_errno;
    call->done = true;
    pthread_cond_broadcast(&call->condition);
    pthread_mutex_unlock(&call->lock);
    return NULL;
}

static bool connect_call_done(struct connect_call *call)
{
    bool done;

    pthread_mutex_lock(&call->lock);
    done = call->done;
    pthread_mutex_unlock(&call->lock);
    return done;
}

static int wait_for_start(struct connect_call *call, unsigned int timeout_ms)
{
    struct timespec deadline;
    int result = 0;

    if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) {
        return -1;
    }
    add_ms(&deadline, timeout_ms);
    pthread_mutex_lock(&call->lock);
    while (!call->started && result == 0) {
        result = pthread_cond_timedwait(&call->condition, &call->lock, &deadline);
    }
    bool started = call->started;
    pthread_mutex_unlock(&call->lock);
    return started ? 0 : -1;
}

static int timed_join(pthread_t thread, unsigned int timeout_ms, void **thread_result)
{
    struct timespec deadline;

    if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) {
        return errno;
    }
    add_ms(&deadline, timeout_ms);
    return pthread_timedjoin_np(thread, thread_result, &deadline);
}

static int run_client(const struct options *options)
{
    struct connect_call call = {};
    struct sockaddr_in local = {
        .sin_family = AF_INET,
        .sin_addr = options->bind_ip,
    };
    struct timespec observe_deadline;
    pthread_t thread;
    void *thread_result = NULL;
    int fd;
    int result;

    signal(SIGPIPE, SIG_IGN);
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("client socket");
        return EXIT_FAILURE;
    }
    if (bind(fd, (const struct sockaddr *)&local, sizeof(local)) != 0) {
        perror("client bind");
        close(fd);
        return EXIT_FAILURE;
    }
    call.fd = fd;
    call.result = -1;
    call.target = (struct sockaddr_in) {
        .sin_family = AF_INET,
        .sin_addr = options->target_ip,
        .sin_port = htons(options->port),
    };
    if (pthread_mutex_init(&call.lock, NULL) != 0) {
        fail("client synchronization initialization failed");
        close(fd);
        return EXIT_FAILURE;
    }
    if (pthread_cond_init(&call.condition, NULL) != 0) {
        fail("client synchronization initialization failed");
        pthread_mutex_destroy(&call.lock);
        close(fd);
        return EXIT_FAILURE;
    }
    result = pthread_create(&thread, NULL, connect_thread, &call);
    if (result != 0) {
        fail("client could not create connector thread");
        goto cleanup_sync;
    }
    if (wait_for_start(&call, options->join_timeout_ms) != 0) {
        fail("connector thread did not start");
        (void)pthread_cancel(thread);
        if (timed_join(thread, options->join_timeout_ms, &thread_result) != 0) {
            printf("SUMMARY client failures=%d unjoined=1\n", failures);
            fflush(stdout);
            _exit(EXIT_FAILURE);
        }
        goto cleanup_sync;
    }
    sleep_ms(options->cancel_delay_ms);
    if (connect_call_done(&call)) {
        fail("connect returned before cancellation while the raw peer withheld SYN-ACK");
        if (timed_join(thread, options->join_timeout_ms, &thread_result) != 0) {
            printf("SUMMARY client failures=%d unjoined=1\n", failures);
            fflush(stdout);
            _exit(EXIT_FAILURE);
        }
        goto cleanup_sync;
    }
    result = pthread_cancel(thread);
    if (result != 0) {
        fail("pthread_cancel failed");
        printf("SUMMARY client failures=%d unjoined=1\n", failures);
        fflush(stdout);
        _exit(EXIT_FAILURE);
    }
    result = timed_join(thread, options->join_timeout_ms, &thread_result);
    if (result == ETIMEDOUT) {
        fail("connector did not acknowledge cancellation within the deadline");
        printf("SUMMARY client failures=%d unjoined=1\n", failures);
        fflush(stdout);
        _exit(EXIT_FAILURE);
    }
    if (result != 0) {
        fail("pthread_timedjoin_np failed");
        printf("SUMMARY client failures=%d unjoined=1\n", failures);
        fflush(stdout);
        _exit(EXIT_FAILURE);
    }
    if (thread_result != PTHREAD_CANCELED) {
        fail("connector returned instead of completing pthread cancellation");
        goto cleanup_sync;
    }
    printf("CANCELED join_ms_bound=%u\n", options->join_timeout_ms);
    fflush(stdout);

    if (monotonic_now(&observe_deadline) != 0) {
        fail("client clock failed");
        goto cleanup_sync;
    }
    add_ms(&observe_deadline, options->observe_ms);
    while (remaining_ms(&observe_deadline) > 0) {
        sleep_ms(10U);
    }

    if (!options->probe_socket_after_cancel) {
        printf("SUMMARY client failures=%d socket_probe=skipped\n", failures);
        fflush(stdout);
        _exit(failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
    }

    char byte = 'x';
    errno = 0;
    if (send(fd, &byte, sizeof(byte), MSG_DONTWAIT | MSG_NOSIGNAL) != 1) {
        fail("worker-owned connect did not remain usable after caller cancellation");
    }

cleanup_sync:
    errno = 0;
    if (close(fd) != 0) {
        fail("client close failed");
    }
    pthread_cond_destroy(&call.condition);
    pthread_mutex_destroy(&call.lock);
    printf("SUMMARY client failures=%d\n", failures);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int parse_unsigned(const char *text, unsigned long maximum, unsigned long *value)
{
    char *end = NULL;
    unsigned long parsed;

    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || text[0] == '\0' || end == NULL || *end != '\0' || parsed > maximum) {
        return -1;
    }
    *value = parsed;
    return 0;
}

static void usage(const char *program)
{
    fprintf(stderr,
            "Peer: %s --role peer --interface IFACE --target-ip IPV4 --port PORT "
            "[--reply-delay-ms MS] [--observe-ms MS] [--timeout-ms MS]\n"
            "Client: %s --role client --bind-ip IPV4 --target-ip IPV4 --port PORT "
            "[--cancel-delay-ms MS] [--join-timeout-ms MS] [--observe-ms MS] "
            "[--probe-socket]\n",
            program, program);
}

static int parse_options(int argc, char **argv, struct options *options)
{
    const char *bind_ip = NULL;
    const char *target_ip = NULL;
    bool observe_ms_set = false;
    unsigned long parsed;

    memset(options, 0, sizeof(*options));
    options->cancel_delay_ms = 250U;
    options->join_timeout_ms = 3000U;
    options->reply_delay_ms = 5000U;
    options->timeout_ms = 12000U;

    for (int index = 1; index < argc; ++index) {
        if (strcmp(argv[index], "--role") == 0 && index + 1 < argc) {
            const char *role = argv[++index];
            options->role = strcmp(role, "peer") == 0 ? ROLE_PEER
                : strcmp(role, "client") == 0         ? ROLE_CLIENT
                                                      : ROLE_NONE;
        } else if (strcmp(argv[index], "--interface") == 0 && index + 1 < argc) {
            options->interface_name = argv[++index];
        } else if (strcmp(argv[index], "--bind-ip") == 0 && index + 1 < argc) {
            bind_ip = argv[++index];
        } else if (strcmp(argv[index], "--target-ip") == 0 && index + 1 < argc) {
            target_ip = argv[++index];
        } else if (strcmp(argv[index], "--port") == 0 && index + 1 < argc) {
            if (parse_unsigned(argv[++index], UINT16_MAX, &parsed) != 0 || parsed == 0U) {
                return -1;
            }
            options->port = (uint16_t)parsed;
        } else if (strcmp(argv[index], "--cancel-delay-ms") == 0 && index + 1 < argc) {
            if (parse_unsigned(argv[++index], UINT32_MAX, &parsed) != 0) {
                return -1;
            }
            options->cancel_delay_ms = (unsigned int)parsed;
        } else if (strcmp(argv[index], "--join-timeout-ms") == 0 && index + 1 < argc) {
            if (parse_unsigned(argv[++index], UINT32_MAX, &parsed) != 0 || parsed == 0U) {
                return -1;
            }
            options->join_timeout_ms = (unsigned int)parsed;
        } else if (strcmp(argv[index], "--reply-delay-ms") == 0 && index + 1 < argc) {
            if (parse_unsigned(argv[++index], UINT32_MAX, &parsed) != 0 || parsed == 0U) {
                return -1;
            }
            options->reply_delay_ms = (unsigned int)parsed;
        } else if (strcmp(argv[index], "--observe-ms") == 0 && index + 1 < argc) {
            if (parse_unsigned(argv[++index], UINT32_MAX, &parsed) != 0 || parsed == 0U) {
                return -1;
            }
            options->observe_ms = (unsigned int)parsed;
            observe_ms_set = true;
        } else if (strcmp(argv[index], "--timeout-ms") == 0 && index + 1 < argc) {
            if (parse_unsigned(argv[++index], UINT32_MAX, &parsed) != 0 || parsed == 0U) {
                return -1;
            }
            options->timeout_ms = (unsigned int)parsed;
        } else if (strcmp(argv[index], "--probe-socket") == 0) {
            options->probe_socket_after_cancel = true;
        } else {
            return -1;
        }
    }

    if (options->role == ROLE_NONE || target_ip == NULL || options->port == 0U ||
        inet_pton(AF_INET, target_ip, &options->target_ip) != 1) {
        return -1;
    }
    if (!observe_ms_set) {
        options->observe_ms = options->role == ROLE_PEER ? 2000U : 7000U;
    }
    if (options->role == ROLE_PEER) {
        return options->interface_name != NULL ? 0 : -1;
    }
    if (bind_ip == NULL || inet_pton(AF_INET, bind_ip, &options->bind_ip) != 1) {
        return -1;
    }
    if (options->observe_ms <= options->reply_delay_ms) {
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct options options;

    if (parse_options(argc, argv, &options) != 0) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    return options.role == ROLE_PEER ? run_peer(&options) : run_client(&options);
}
