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
#include <fcntl.h>
#include <inttypes.h>
#include <linux/userfaultfd.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

/*
 * Standalone two-host regression test for worker-mode blocking sockets.
 *
 * Build:
 *   cc -O2 -g -Wall -Wextra -Werror -pthread \
 *      tests/extra_api/blocking_socket_workers_e2e.c \
 *      -o /tmp/blocking_socket_workers_e2e
 *
 * Start the server first, then the client. Run the same cases through LD_PRELOAD
 * first with R2C/default mode and then with worker mode. R2C is the behavior
 * target; a kernel-socket run is characterization only.
 */

enum {
    TEST_ACCEPT_PORT = 1,
    TEST_PEEK_PORT = 2,
    TEST_WAITALL_PORT = 3,
    TEST_CONCURRENT_RECV_PORT = 4,
    TEST_SEND_PORT = 5,
    TEST_ACCEPT_TIMEOUT_PORT = 6,
    TEST_ACCEPT4_PORT = 7,
    TEST_SEND_TIMEOUT_PORT = 8,
    TEST_TX_CLOSE_PORT = 9,
    TEST_EXIT_LISTENER_PORT = 10,
    TEST_PREFIX_EOF_PORT = 11,
    TEST_RCVTIMEO_PARTIAL_PORT = 12,
    TEST_DONTWAIT_PROGRESS_PORT = 13,
    TEST_PEEK_WAITALL_PORT = 14,
    TEST_MULTI_WRITER_PORT = 15,
    TEST_ACCEPT_INHERIT_PORT = 16,
    TEST_ACCEPT4_NONBLOCK_PORT = 17,
    TEST_READINESS_PORT = 18,
    TEST_SIGNAL_ACCEPT_PORT = 19,
    TEST_SIGNAL_ACCEPT_RESTART_PORT = 20,
    TEST_SIGNAL_RECV_PORT = 21,
    TEST_SIGNAL_RECV_RESTART_PORT = 22,
    TEST_SEND_AFTER_SHUT_WR_PORT = 23,
    TEST_CANCEL_ACCEPT_PORT = 24,
    TEST_CANCEL_RECV_PORT = 25,
    TEST_CANCEL_SEND_PORT = 26,
    TEST_TIMEWAIT_REUSE_PORT = 27,
    TEST_QUEUE_RESERVATION_PORT = 28,
    TEST_SEND_CLOSE_TAIL_PORT = 29,
    TEST_EPOLL_DISTINCT_CLOSE_PORT = 30,
    TEST_RECV_CLOSE_COPY_PORT = 31,
    TEST_RECV_CLOSE_FENCE_ORDER_PORT = 32,
    TEST_MIXED_ROUTE_ACCEPT_PORT = 33,
    TEST_WAITALL_SHUT_RD_PORT = 34,
    TEST_SHARED_CQ_IDLE_PORT = 35,
    TEST_MIXED_ROUTE_ACCEPT_TIMEOUT_PORT = 36,
    TEST_CONNECT_REPEAT_PORT = 37,
    TEST_MAX_PORT_OFFSET = TEST_CONNECT_REPEAT_PORT,
    SEND_BYTES = 32 * 1024 * 1024,
    CONCURRENT_RECV_ITERATIONS = 256,
    TX_CLOSE_THREADS = 4,
    EXIT_PENDING_CONNECTIONS = 64,
    IO_TIMEOUT_SECONDS = 5,
    SHORT_TIMEOUT_MS = 300,
    PEEK_WAITALL_TIMEOUT_MS = 1000,
    PEEK_WAITALL_PROMPT_MAX_MS = 500,
    BLOCKING_SEND_MAX_MS = 5000,
    MULTI_WRITER_THREADS = 4,
    MULTI_WRITER_CHUNK = 256 * 1024,
    TIMEWAIT_REUSE_ITERATIONS = 16,
    ADMISSION_CLOSE_ITERATIONS = 20000,
    EPOLL_DISTINCT_CLOSE_ITERATIONS = 256,
    RECV_CLOSE_EARLY_PROBE_MS = 500,
    SHARED_CQ_IDLE_WAITERS = 8,
};

static const uint64_t SHARED_CQ_FLOOD_BYTES = 2ULL * 1024U * 1024U * 1024U;

static const unsigned char CMD_ACCEPT_CONNECT = 'A';
static const unsigned char CMD_PEEK_CONNECT = 'P';
static const unsigned char CMD_PEEK_SENT = 'p';
static const unsigned char CMD_WAITALL_CONNECT = 'W';
static const unsigned char CMD_WAITALL_FIRST_SENT = '1';
static const unsigned char CMD_WAITALL_SECOND_SENT = '2';
static const unsigned char CMD_RECV_CONNECT = 'R';
static const unsigned char CMD_RECV_SEND = 'r';
static const unsigned char CMD_SEND_CONNECT = 'S';
static const unsigned char CMD_SEND_START = 's';
static const unsigned char CMD_ACCEPT_TIMEOUT_CONNECT = 'T';
static const unsigned char CMD_ACCEPT4_CONNECT = 'F';
static const unsigned char CMD_ACCEPT4_CONNECTED = 'f';
static const unsigned char CMD_ACCEPT4_CLOEXEC_CONNECT = 'G';
static const unsigned char CMD_SEND_TIMEOUT_CONNECT = 'O';
static const unsigned char CMD_SEND_TIMEOUT_START = 'o';
static const unsigned char CMD_TX_CLOSE_CONNECT = 'C';
static const unsigned char CMD_TX_CLOSE_START = 'c';
static const unsigned char CMD_EXIT_CONNECT = 'X';
static const unsigned char CMD_EXIT_CONNECTED = 'x';
static const unsigned char CMD_PREFIX_EOF_CONNECT = 'E';
static const unsigned char CMD_PREFIX_EOF_SENT = 'e';
static const unsigned char CMD_RCVTIMEO_PARTIAL_CONNECT = 'M';
static const unsigned char CMD_RCVTIMEO_PARTIAL_SENT = 'm';
static const unsigned char CMD_DONTWAIT_CONNECT = 'N';
static const unsigned char CMD_DONTWAIT_SENT = 'n';
static const unsigned char CMD_PEEK_WAITALL_CONNECT = 'Q';
static const unsigned char CMD_PEEK_WAITALL_FIRST_SENT = 'q';
static const unsigned char CMD_MULTI_WRITER_CONNECT = 'V';
static const unsigned char CMD_MULTI_WRITER_SENT = 'v';
static const unsigned char CMD_ACCEPT_INHERIT_CONNECT = 'H';
static const unsigned char CMD_ACCEPT4_NONBLOCK_CONNECT = 'B';
static const unsigned char CMD_READINESS_CONNECT = 'Y';
static const unsigned char CMD_READINESS_SEND = 'y';
static const unsigned char CMD_SIGNAL_ACCEPT_PROGRESS = 'L';
static const unsigned char CMD_SIGNAL_ACCEPT_CONNECTED = 'l';
static const unsigned char CMD_SIGNAL_RECV_CONNECT = 'U';
static const unsigned char CMD_SIGNAL_RECV_PROGRESS = 'u';
static const unsigned char CMD_SEND_AFTER_SHUT_WR_CONNECT = 0x81;
static const unsigned char CMD_SEND_AFTER_SHUT_WR_START = 0x82;
static const unsigned char CMD_PEEK_WAITALL_PEEK_RETURNED = 0x83;
static const unsigned char CMD_PEEK_WAITALL_SECOND_SENT = 0x84;
static const unsigned char CMD_CANCEL_ACCEPT_CONNECT = 0x85;
static const unsigned char CMD_CANCEL_RECV_CONNECT = 0x86;
static const unsigned char CMD_CANCEL_RECV_SEND = 0x87;
static const unsigned char CMD_CANCEL_SEND_CONNECT = 0x88;
static const unsigned char CMD_CANCEL_SEND_START = 0x89;
static const unsigned char CMD_CANCEL_SEND_DRAIN = 0x8a;
static const unsigned char CMD_TIMEWAIT_CONNECT = 0x8b;
static const unsigned char CMD_QUEUE_CONNECT = 0x8c;
static const unsigned char CMD_QUEUE_START = 0x8d;
static const unsigned char CMD_SEND_CLOSE_TAIL_CONNECT = 0x8e;
static const unsigned char CMD_RECV_CLEANUP = 0x8f;
static const unsigned char CMD_RECV_ABORT = 0x90;
/* connect-repeat and admission-close are both opt-in (run_by_default false) and each run is a
 * dedicated server/client process pair driving exactly one case over the control socket, so the
 * two commands can never appear on the same control stream; the value reuse is deliberate. */
static const unsigned char CMD_CONNECT_REPEAT_START = 0x91;
static const unsigned char CMD_ADMISSION_CLOSE_START = 0x91;
static const unsigned char CMD_ADMISSION_CLOSE_DONE = 0x92;
static const unsigned char CMD_EPOLL_DISTINCT_CONNECT = 0x93;
static const unsigned char CMD_EPOLL_DISTINCT_CLOSED = 0x94;
static const unsigned char CMD_RECV_CLOSE_COPY_CONNECT = 0x95;
static const unsigned char CMD_RECV_CLOSE_COPY_SENT = 0x96;
static const unsigned char CMD_RECV_CLOSE_COPY_CLOSED = 0x97;
static const unsigned char CMD_RECV_CLOSE_COPY_RELEASED = 0x98;
static const unsigned char CMD_MIXED_ROUTE_ACCEPT_START = 0x99;
static const unsigned char CMD_WAITALL_SHUT_RD_CONNECT = 0x9a;
static const unsigned char CMD_WAITALL_SHUT_RD_SENT = 0x9b;
static const unsigned char CMD_SHARED_CQ_CONNECT = 0x9c;
static const unsigned char CMD_SHARED_CQ_CONNECTED = 0x9d;
static const unsigned char CMD_SHARED_CQ_FLOOD = 0x9e;
static const unsigned char CMD_SHARED_CQ_FLOOD_DONE = 0x9f;
static const unsigned char CMD_ACK = 'K';
static const unsigned char CMD_DONE = 'D';

struct options {
    bool server;
    const char *bind_ip;
    const char *server_ip;
    const char *test_case;
    uint16_t port;
};

struct recv_call {
    int fd;
    int flags;
    size_t length;
    unsigned char data[128];
    ssize_t result;
    int error;
};

struct accept_call {
    int fd;
    int flags;
    bool use_accept4;
    int result;
    int error;
    uint64_t elapsed_ms;
    uint64_t cpu_ms;
};

struct idle_recv_call {
    int fd;
    atomic_bool entered;
    atomic_bool returned;
    ssize_t result;
    int error;
    unsigned char byte;
};

struct admission_close_call {
    pthread_barrier_t start;
    pthread_barrier_t finish;
    atomic_int fd;
    atomic_int failures;
};

struct send_report {
    uint32_t magic;
    int32_t result;
    int32_t error;
    uint64_t bytes_sent;
    uint64_t elapsed_ms;
};

struct send_timeout_report {
    uint32_t magic;
    int32_t result;
    int32_t error;
    int32_t getsockopt_result;
    int32_t getsockopt_error;
    int64_t observed_timeout_us;
    uint64_t bytes_sent;
    uint64_t elapsed_ms;
};

struct shutdown_send_report {
    uint32_t magic;
    int32_t shutdown_result;
    int32_t shutdown_error;
    int32_t send_result;
    int32_t send_error;
};

struct tx_close_call {
    int fd;
    atomic_uint calls;
    atomic_ullong bytes_sent;
    int result;
    int error;
};

struct close_call {
    int fd;
    atomic_int result;
    atomic_int error;
    atomic_ullong elapsed_ms;
};

struct recv_close_copy_call {
    int fd;
    void *fault_buffer;
    size_t fault_length;
    unsigned char tail[128];
    ssize_t result;
    int error;
};

struct recv_close_copy_report {
    uint32_t magic;
    int32_t early_result;
    int32_t early_error;
};

struct epoll_distinct_close_call {
    int fd;
    atomic_bool *start;
    atomic_int *ready;
    int result;
    int error;
};

struct signal_probe_call {
    int fd;
    bool is_accept;
    atomic_bool entered;
    ssize_t result;
    int error;
    unsigned char data;
};

enum cancellation_operation {
    CANCEL_OPERATION_ACCEPT,
    CANCEL_OPERATION_RECV,
    CANCEL_OPERATION_SEND,
};

struct cancellation_call {
    int fd;
    enum cancellation_operation operation;
    void *buffer;
    size_t length;
    atomic_bool entered;
    atomic_bool returned;
    ssize_t result;
    int error;
};

struct cancel_send_report {
    uint32_t magic;
    int32_t cancel_result;
    int32_t prompt_join_result;
    int32_t final_join_result;
    int32_t canceled;
    int32_t returned;
    int32_t canceled_result;
    int32_t canceled_error;
    int32_t follow_result;
    int32_t follow_error;
    uint64_t canceled_send_length;
};

struct shutdown_call {
    int fd;
    int how;
    atomic_bool entered;
    atomic_bool returned;
    int result;
    int error;
    uint64_t elapsed_ms;
};

struct queue_reservation_report {
    uint32_t magic;
    int32_t userfault_result;
    int32_t shutdown_result;
    int32_t shutdown_error;
    int32_t send_result;
    int32_t send_error;
    uint64_t shutdown_elapsed_ms;
};

struct tx_close_report {
    uint32_t magic;
    int32_t close_result;
    int32_t close_error;
    uint32_t joined_threads;
    uint32_t unexpected_errors;
    uint32_t send_calls;
    uint64_t bytes_sent;
    uint64_t close_elapsed_ms;
};

static int failures;
static volatile sig_atomic_t directed_signal_write_fd = -1;

static uint64_t monotonic_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime");
        exit(EXIT_FAILURE);
    }
    return (uint64_t)ts.tv_sec * 1000U + (uint64_t)ts.tv_nsec / 1000000U;
}

static void sleep_ms(unsigned int milliseconds)
{
    struct timespec delay = {
        .tv_sec = milliseconds / 1000U,
        .tv_nsec = (long)(milliseconds % 1000U) * 1000000L,
    };

    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
    }
}

static void pass(const char *name)
{
    printf("PASS %s\n", name);
    fflush(stdout);
}

static void fail(const char *name, const char *detail)
{
    printf("FAIL %s: %s\n", name, detail);
    fflush(stdout);
    ++failures;
}

static int set_recv_timeout(int fd, int seconds)
{
    const struct timeval timeout = {
        .tv_sec = seconds,
        .tv_usec = 0,
    };

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
        perror("setsockopt(SO_RCVTIMEO)");
        return -1;
    }
    return 0;
}

static int set_recv_timeout_ms(int fd, unsigned int milliseconds)
{
    const struct timeval timeout = {
        .tv_sec = milliseconds / 1000U,
        .tv_usec = (suseconds_t)(milliseconds % 1000U) * 1000,
    };

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
        perror("setsockopt(SO_RCVTIMEO)");
        return -1;
    }
    return 0;
}

static int set_send_timeout_ms(int fd, unsigned int milliseconds)
{
    const struct timeval timeout = {
        .tv_sec = milliseconds / 1000U,
        .tv_usec = (suseconds_t)(milliseconds % 1000U) * 1000,
    };

    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) {
        perror("setsockopt(SO_SNDTIMEO)");
        return -1;
    }
    return 0;
}

static int fill_address(struct sockaddr_in *address, const char *ip, uint16_t port)
{
    memset(address, 0, sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &address->sin_addr) != 1) {
        fprintf(stderr, "invalid IPv4 address: %s\n", ip);
        return -1;
    }
    return 0;
}

static int make_listener_with_options(const char *bind_ip, uint16_t port, int backlog,
                                      int receive_buffer_size)
{
    struct sockaddr_in address;
    int fd;
    int one = 1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket(listener)");
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0 ||
        (receive_buffer_size > 0 &&
         setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &receive_buffer_size, sizeof(receive_buffer_size)) !=
             0) ||
        fill_address(&address, bind_ip, port) != 0 ||
        bind(fd, (const struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(fd, backlog) != 0) {
        perror("listener setup");
        close(fd);
        return -1;
    }
    return fd;
}

static int make_listener(const char *bind_ip, uint16_t port)
{
    return make_listener_with_options(bind_ip, port, 8, 0);
}

static int connect_retry(const char *local_ip, const char *server_ip, uint16_t port)
{
    struct sockaddr_in local_address;
    struct sockaddr_in server_address;
    int last_error = ECONNREFUSED;

    if (fill_address(&local_address, local_ip, 0) != 0 ||
        fill_address(&server_address, server_ip, port) != 0) {
        return -1;
    }

    for (int attempt = 0; attempt < 100; ++attempt) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);

        if (fd < 0) {
            perror("socket(client)");
            return -1;
        }
        if (bind(fd, (const struct sockaddr *)&local_address, sizeof(local_address)) != 0) {
            perror("bind(client)");
            close(fd);
            return -1;
        }
        if (connect(fd, (const struct sockaddr *)&server_address, sizeof(server_address)) == 0) {
            return fd;
        }
        last_error = errno;
        close(fd);
        if (last_error != ECONNREFUSED && last_error != ETIMEDOUT && last_error != EHOSTUNREACH &&
            last_error != ENETUNREACH) {
            errno = last_error;
            perror("connect");
            return -1;
        }
        sleep_ms(50);
    }

    errno = last_error;
    perror("connect retries exhausted");
    return -1;
}

static ssize_t send_all_count(int fd, const void *buffer, size_t length, int *saved_error)
{
    const unsigned char *cursor = buffer;
    size_t sent = 0;

    while (sent < length) {
        ssize_t result = send(fd, cursor + sent, length - sent, MSG_NOSIGNAL);

        if (result > 0) {
            sent += (size_t)result;
            continue;
        }
        if (result < 0 && errno == EINTR) {
            continue;
        }
        *saved_error = result < 0 ? errno : EIO;
        return (ssize_t)sent;
    }
    *saved_error = 0;
    return (ssize_t)sent;
}

static int send_all(int fd, const void *buffer, size_t length)
{
    int error;
    ssize_t sent = send_all_count(fd, buffer, length, &error);

    if (sent != (ssize_t)length) {
        errno = error;
        return -1;
    }
    return 0;
}

static int recv_all(int fd, void *buffer, size_t length)
{
    unsigned char *cursor = buffer;
    size_t received = 0;

    while (received < length) {
        ssize_t result = recv(fd, cursor + received, length - received, 0);

        if (result > 0) {
            received += (size_t)result;
            continue;
        }
        if (result < 0 && errno == EINTR) {
            continue;
        }
        return -1;
    }
    return 0;
}

static int send_byte(int fd, unsigned char value)
{
    return send_all(fd, &value, sizeof(value));
}

static int write_byte(int fd, unsigned char value)
{
    ssize_t result;

    do {
        result = write(fd, &value, sizeof(value));
    } while (result < 0 && errno == EINTR);
    return result == (ssize_t)sizeof(value) ? 0 : -1;
}

static int read_byte(int fd, unsigned char *value)
{
    ssize_t result;

    do {
        result = read(fd, value, sizeof(*value));
    } while (result < 0 && errno == EINTR);
    return result == (ssize_t)sizeof(*value) ? 0 : -1;
}

static int expect_byte(int fd, unsigned char expected)
{
    unsigned char actual = 0;

    if (recv_all(fd, &actual, sizeof(actual)) != 0) {
        return -1;
    }
    if (actual != expected) {
        fprintf(stderr, "protocol error: expected 0x%02x, received 0x%02x\n", expected, actual);
        errno = EPROTO;
        return -1;
    }
    return 0;
}

static int wait_until_readable(int fd, int timeout_ms)
{
    struct pollfd poll_fd = {
        .fd = fd,
        .events = POLLIN,
    };
    int result;

    do {
        result = poll(&poll_fd, 1, timeout_ms);
    } while (result < 0 && errno == EINTR);
    if (result != 1 || !(poll_fd.revents & (POLLIN | POLLHUP | POLLERR))) {
        errno = result == 0 ? ETIMEDOUT : errno;
        return -1;
    }
    return 0;
}

static int timed_join_result(pthread_t thread, unsigned int milliseconds, void **thread_result)
{
    struct timespec deadline;

    if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) {
        return errno;
    }
    deadline.tv_sec += milliseconds / 1000U;
    deadline.tv_nsec += (long)(milliseconds % 1000U) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        ++deadline.tv_sec;
        deadline.tv_nsec -= 1000000000L;
    }
    return pthread_timedjoin_np(thread, thread_result, &deadline);
}

static int timed_join(pthread_t thread, unsigned int milliseconds)
{
    return timed_join_result(thread, milliseconds, NULL);
}

static void directed_signal_handler(int signal_number)
{
    const int saved_errno = errno;
    const unsigned char byte = 1U;

    (void)signal_number;
    if (directed_signal_write_fd >= 0) {
        (void)write(directed_signal_write_fd, &byte, sizeof(byte));
    }
    errno = saved_errno;
}

static int setup_directed_signal(bool restart, int signal_pipe[2], struct sigaction *old_action)
{
    struct sigaction action = {
        .sa_handler = directed_signal_handler,
        .sa_flags = restart ? SA_RESTART : 0,
    };

    if (pipe2(signal_pipe, O_CLOEXEC | O_NONBLOCK) != 0) {
        return -1;
    }
    sigemptyset(&action.sa_mask);
    directed_signal_write_fd = signal_pipe[1];
    if (sigaction(SIGUSR1, &action, old_action) != 0) {
        const int saved_errno = errno;

        directed_signal_write_fd = -1;
        close(signal_pipe[0]);
        close(signal_pipe[1]);
        errno = saved_errno;
        return -1;
    }
    return 0;
}

static void teardown_directed_signal(const int signal_pipe[2], const struct sigaction *old_action)
{
    (void)sigaction(SIGUSR1, old_action, NULL);
    directed_signal_write_fd = -1;
    close(signal_pipe[0]);
    close(signal_pipe[1]);
}

static int wait_for_probe_entry(const struct signal_probe_call *call)
{
    const uint64_t deadline = monotonic_ms() + 1000U;

    while (!atomic_load_explicit(&call->entered, memory_order_acquire)) {
        if (monotonic_ms() >= deadline) {
            return -1;
        }
        sleep_ms(1);
    }
    return 0;
}

static int wait_for_directed_signal(int signal_read_fd)
{
    struct pollfd poll_fd = {
        .fd = signal_read_fd,
        .events = POLLIN,
    };
    unsigned char byte;
    int result;

    do {
        result = poll(&poll_fd, 1, 1000);
    } while (result < 0 && errno == EINTR);
    if (result != 1 || !(poll_fd.revents & POLLIN) ||
        read(signal_read_fd, &byte, sizeof(byte)) != sizeof(byte)) {
        return -1;
    }
    return 0;
}

static void *signal_probe_thread(void *opaque)
{
    struct signal_probe_call *call = opaque;

    atomic_store_explicit(&call->entered, true, memory_order_release);
    errno = 0;
    if (call->is_accept) {
        call->result = accept(call->fd, NULL, NULL);
    } else {
        call->result = recv(call->fd, &call->data, sizeof(call->data), 0);
    }
    call->error = call->result < 0 ? errno : 0;
    return NULL;
}

static void *cancellation_thread(void *opaque)
{
    struct cancellation_call *call = opaque;

    (void)pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
    (void)pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    atomic_store_explicit(&call->entered, true, memory_order_release);
    errno = 0;
    switch (call->operation) {
    case CANCEL_OPERATION_ACCEPT:
        call->result = accept(call->fd, NULL, NULL);
        break;
    case CANCEL_OPERATION_RECV:
        call->result = recv(call->fd, call->buffer, call->length, 0);
        break;
    case CANCEL_OPERATION_SEND:
        call->result = send(call->fd, call->buffer, call->length, MSG_NOSIGNAL);
        break;
    }
    call->error = call->result < 0 ? errno : 0;
    atomic_store_explicit(&call->returned, true, memory_order_release);
    return NULL;
}

static void *shutdown_thread(void *opaque)
{
    struct shutdown_call *call = opaque;
    const uint64_t start = monotonic_ms();

    atomic_store_explicit(&call->entered, true, memory_order_release);
    errno = 0;
    call->result = shutdown(call->fd, call->how);
    call->error = call->result < 0 ? errno : 0;
    call->elapsed_ms = monotonic_ms() - start;
    atomic_store_explicit(&call->returned, true, memory_order_release);
    return NULL;
}

static int wait_for_atomic_bool(const atomic_bool *value, unsigned int timeout_ms)
{
    const uint64_t deadline = monotonic_ms() + timeout_ms;

    while (!atomic_load_explicit(value, memory_order_acquire)) {
        if (monotonic_ms() >= deadline) {
            return -1;
        }
        sleep_ms(1);
    }
    return 0;
}

static bool cancel_blocked_call(const char *case_name, const char *syscall_name, pthread_t thread,
                                struct cancellation_call *call)
{
    void *thread_result = NULL;
    int cancel_result;
    int join_result;

    if (wait_for_atomic_bool(&call->entered, 1000U) != 0) {
        fail(case_name, "the cancellation target did not enter its syscall");
        return false;
    }
    sleep_ms(100U);
    if (atomic_load_explicit(&call->returned, memory_order_acquire)) {
        (void)pthread_join(thread, &thread_result);
        fail(case_name, "the cancellation target returned before pthread_cancel");
        return false;
    }

    cancel_result = pthread_cancel(thread);
    join_result = cancel_result == 0 ? timed_join_result(thread, 3000U, &thread_result) : 0;
    printf("OBSERVE case=%s syscall=%s cancel_result=%d join_result=%d canceled=%d "
           "returned=%d\n",
           case_name, syscall_name, cancel_result, join_result,
           thread_result == PTHREAD_CANCELED ? 1 : 0,
           atomic_load_explicit(&call->returned, memory_order_acquire) ? 1 : 0);
    fflush(stdout);

    if (cancel_result != 0) {
        fail(case_name, "pthread_cancel failed");
        return false;
    }
    if (join_result == ETIMEDOUT) {
        fail(case_name, "the canceled syscall did not unwind within the deadline");
        fflush(stdout);
        fflush(stderr);
        _Exit(EXIT_FAILURE);
    }
    if (join_result != 0 || thread_result != PTHREAD_CANCELED ||
        atomic_load_explicit(&call->returned, memory_order_acquire)) {
        fail(case_name, "the target did not join with PTHREAD_CANCELED");
        return false;
    }
    return true;
}

static void *recv_thread(void *opaque)
{
    struct recv_call *call = opaque;

    errno = 0;
    call->result = recv(call->fd, call->data, call->length, call->flags);
    call->error = call->result < 0 ? errno : 0;
    return NULL;
}

static void *idle_recv_thread(void *opaque)
{
    struct idle_recv_call *call = opaque;

    atomic_store_explicit(&call->entered, true, memory_order_release);
    errno = 0;
    call->result = recv(call->fd, &call->byte, sizeof(call->byte), 0);
    call->error = call->result < 0 ? errno : 0;
    atomic_store_explicit(&call->returned, true, memory_order_release);
    return NULL;
}

static void *accept_thread(void *opaque)
{
    struct accept_call *call = opaque;
    struct timespec cpu_start = {0};
    struct timespec cpu_end = {0};
    uint64_t start = monotonic_ms();

    (void)clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpu_start);
    errno = 0;
    call->result = call->use_accept4 ? accept4(call->fd, NULL, NULL, call->flags)
                                     : accept(call->fd, NULL, NULL);
    call->error = call->result < 0 ? errno : 0;
    call->elapsed_ms = monotonic_ms() - start;
    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpu_end) == 0) {
        const uint64_t start_ns = (uint64_t)cpu_start.tv_sec * 1000000000U +
            (uint64_t)cpu_start.tv_nsec;
        const uint64_t end_ns =
            (uint64_t)cpu_end.tv_sec * 1000000000U + (uint64_t)cpu_end.tv_nsec;
        call->cpu_ms = (end_ns - start_ns) / 1000000U;
    }
    return NULL;
}

static void *tx_close_thread(void *opaque)
{
    static const unsigned char payload[64 * 1024] = {0xa5};
    struct tx_close_call *call = opaque;

    for (;;) {
        ssize_t result = send(call->fd, payload, sizeof(payload), MSG_NOSIGNAL);

        if (result > 0) {
            atomic_fetch_add_explicit(&call->calls, 1U, memory_order_relaxed);
            atomic_fetch_add_explicit(&call->bytes_sent, (unsigned long long)result,
                                      memory_order_relaxed);
            continue;
        }
        if (result < 0 && errno == EINTR) {
            continue;
        }
        call->result = result < 0 ? -1 : 0;
        call->error = result < 0 ? errno : EIO;
        return NULL;
    }
}

static void *close_thread(void *opaque)
{
    struct close_call *call = opaque;
    uint64_t start = monotonic_ms();
    int result;
    int error;

    errno = 0;
    result = close(call->fd);
    error = result < 0 ? errno : 0;
    atomic_store_explicit(&call->result, result, memory_order_relaxed);
    atomic_store_explicit(&call->error, error, memory_order_relaxed);
    atomic_store_explicit(&call->elapsed_ms, monotonic_ms() - start, memory_order_release);
    return NULL;
}

static void *recv_close_copy_thread(void *opaque)
{
    struct recv_close_copy_call *call = opaque;
    struct iovec iov[2] = {
        {
            .iov_base = call->fault_buffer,
            .iov_len = call->fault_length,
        },
        {
            .iov_base = call->tail,
            .iov_len = sizeof(call->tail),
        },
    };
    struct msghdr message = {
        .msg_iov = iov,
        .msg_iovlen = sizeof(iov) / sizeof(iov[0]),
    };

    errno = 0;
    call->result = recvmsg(call->fd, &message, 0);
    call->error = call->result < 0 ? errno : 0;
    return NULL;
}

static void *epoll_distinct_close_thread(void *opaque)
{
    struct epoll_distinct_close_call *call = opaque;

    atomic_fetch_add_explicit(call->ready, 1, memory_order_release);
    while (!atomic_load_explicit(call->start, memory_order_acquire)) {
    }
    errno = 0;
    call->result = close(call->fd);
    call->error = call->result < 0 ? errno : 0;
    return NULL;
}

static int server_accept_nonblocking(const struct options *options, int control)
{
    const char *name = "nonblocking accept returns prompt EAGAIN";
    struct accept_call call = {.fd = -1, .result = -2, .error = 0};
    pthread_t thread;
    int flags;
    int join_result;
    int listener = make_listener(options->bind_ip, options->port + TEST_ACCEPT_PORT);

    if (listener < 0) {
        fail(name, "listener setup failed");
        return -1;
    }
    flags = fcntl(listener, F_GETFL, 0);
    if (flags < 0 || fcntl(listener, F_SETFL, flags | O_NONBLOCK) != 0) {
        fail(name, "could not set O_NONBLOCK");
        close(listener);
        return -1;
    }

    call.fd = listener;
    if (pthread_create(&thread, NULL, accept_thread, &call) != 0) {
        fail(name, "pthread_create failed");
        close(listener);
        return -1;
    }
    join_result = timed_join(thread, 250);
    if (join_result == 0 && call.result < 0 &&
        (call.error == EAGAIN || call.error == EWOULDBLOCK)) {
        pass(name);
    } else if (join_result == ETIMEDOUT) {
        fail(name, "accept blocked for more than 250 ms");
    } else {
        fail(name, "accept returned an unexpected result");
    }

    if (fcntl(listener, F_SETFL, flags & ~O_NONBLOCK) != 0 ||
        send_byte(control, CMD_ACCEPT_CONNECT) != 0) {
        perror("accept test coordination");
        shutdown(listener, SHUT_RDWR);
        close(listener);
        if (join_result == ETIMEDOUT) {
            pthread_join(thread, NULL);
        }
        return -1;
    }

    if (join_result == ETIMEDOUT) {
        if (timed_join(thread, 5000) != 0) {
            fail(name, "blocked accept did not recover when a peer connected");
            shutdown(listener, SHUT_RDWR);
            pthread_join(thread, NULL);
        }
        if (call.result >= 0) {
            close(call.result);
        }
    } else {
        int accepted = accept(listener, NULL, NULL);

        if (accepted < 0) {
            perror("accept cleanup connection");
            close(listener);
            return -1;
        }
        close(accepted);
    }
    close(listener);
    return 0;
}

static int client_accept_nonblocking(const struct options *options, int control)
{
    int fd;

    if (expect_byte(control, CMD_ACCEPT_CONNECT) != 0) {
        return -1;
    }
    fd = connect_retry(options->bind_ip, options->server_ip, options->port + TEST_ACCEPT_PORT);
    if (fd < 0) {
        return -1;
    }
    close(fd);
    return 0;
}

static int server_accept_timeout(const struct options *options, int control)
{
    const char *name = "SO_RCVTIMEO bounds blocking accept";
    struct accept_call call = {.fd = -1, .result = -2};
    pthread_t thread;
    int join_result;
    int listener = make_listener(options->bind_ip, options->port + TEST_ACCEPT_TIMEOUT_PORT);
    bool ok = true;

    if (listener < 0 || set_recv_timeout_ms(listener, SHORT_TIMEOUT_MS) != 0) {
        fail(name, "listener setup failed");
        if (listener >= 0) {
            close(listener);
        }
        return -1;
    }
    call.fd = listener;
    if (pthread_create(&thread, NULL, accept_thread, &call) != 0) {
        fail(name, "pthread_create failed");
        close(listener);
        return -1;
    }
    join_result = timed_join(thread, SHORT_TIMEOUT_MS + 1200U);
    if (join_result == 0) {
        if (call.result >= 0 || (call.error != EAGAIN && call.error != EWOULDBLOCK)) {
            fail(name, "accept did not return EAGAIN after the receive timeout");
            ok = false;
        } else if (call.elapsed_ms < SHORT_TIMEOUT_MS - 100U ||
                   call.elapsed_ms > SHORT_TIMEOUT_MS + 900U) {
            fail(name, "accept timeout elapsed outside the bounded tolerance");
            ok = false;
        }
    } else if (join_result == ETIMEDOUT) {
        fail(name, "accept remained blocked after SO_RCVTIMEO expired");
        ok = false;
    } else {
        fail(name, "pthread_timedjoin_np failed");
        ok = false;
    }

    printf("OBSERVE case=accept-timeout join_result=%d result=%d errno=%d elapsed_ms=%" PRIu64 "\n",
           join_result, call.result, call.error, call.elapsed_ms);
    fflush(stdout);

    const unsigned char cleanup_command =
        join_result == ETIMEDOUT ? CMD_ACCEPT_TIMEOUT_CONNECT : CMD_ACK;
    if (send_byte(control, cleanup_command) != 0) {
        perror("accept timeout coordination");
        shutdown(listener, SHUT_RDWR);
        close(listener);
        if (join_result == ETIMEDOUT) {
            pthread_join(thread, NULL);
        }
        return -1;
    }
    if (join_result == ETIMEDOUT) {
        if (timed_join(thread, 5000) != 0) {
            fail(name, "timed-out accept did not recover when a peer connected");
            shutdown(listener, SHUT_RDWR);
            pthread_join(thread, NULL);
            ok = false;
        }
        if (call.result >= 0) {
            close(call.result);
        }
    }
    if (ok) {
        pass(name);
    }
    close(listener);
    return 0;
}

static int client_accept_timeout(const struct options *options, int control)
{
    unsigned char command = 0U;
    int fd;

    if (recv_all(control, &command, sizeof(command)) != 0) {
        return -1;
    }
    if (command == CMD_ACK) {
        return 0;
    }
    if (command != CMD_ACCEPT_TIMEOUT_CONNECT) {
        errno = EPROTO;
        return -1;
    }
    fd = connect_retry(options->bind_ip, options->server_ip,
                       options->port + TEST_ACCEPT_TIMEOUT_PORT);
    if (fd < 0) {
        return -1;
    }
    close(fd);
    return 0;
}

static int server_mixed_route_accept_impl(const struct options *options, int control,
                                          bool finite_timeout)
{
    const char *case_name =
        finite_timeout ? "mixed-route-accept-timeout" : "mixed-route-accept";
    const char *name = finite_timeout
        ? "timed blocking accept observes a kernel-routed connection"
        : "blocking accept observes a kernel-routed connection";
    const int port_offset = finite_timeout ? TEST_MIXED_ROUTE_ACCEPT_TIMEOUT_PORT
                                           : TEST_MIXED_ROUTE_ACCEPT_PORT;
    struct accept_call call = {.fd = -1, .result = -2};
    struct sockaddr_in loopback;
    pthread_t thread;
    int kernel_client = -1;
    int join_result = 0;
    int listener = make_listener("0.0.0.0", options->port + port_offset);
    bool listener_closed = false;
    bool thread_joined = false;
    bool ok = true;

    if (listener < 0 ||
        (finite_timeout && set_recv_timeout_ms(listener, SHORT_TIMEOUT_MS) != 0) ||
        send_byte(control, CMD_MIXED_ROUTE_ACCEPT_START) != 0 ||
        expect_byte(control, CMD_ACK) != 0) {
        if (listener >= 0) {
            close(listener);
        }
        return -1;
    }

    call.fd = listener;
    if (pthread_create(&thread, NULL, accept_thread, &call) != 0) {
        fail(name, "pthread_create failed");
        close(listener);
        return -1;
    }
    sleep_ms(100U);

    kernel_client = (int)syscall(SYS_socket, AF_INET, SOCK_STREAM, 0);
    if (kernel_client < 0 ||
        fill_address(&loopback, "127.0.0.1", options->port + port_offset) != 0 ||
        syscall(SYS_connect, kernel_client, &loopback, sizeof(loopback)) != 0) {
        fail(name, "direct kernel client could not connect to the shadow listener");
        ok = false;
    } else {
        join_result = timed_join(thread, 1500U);
        if (join_result == ETIMEDOUT) {
            fail(name, "accept did not return after the shadow socket became readable");
            ok = false;
        } else if (join_result != 0) {
            fail(name, "pthread_timedjoin_np failed");
            ok = false;
        } else {
            thread_joined = true;
            if (call.result < 0) {
                fail(name, "accept returned an error for the kernel-routed connection");
                ok = false;
            }
        }
    }

    printf("OBSERVE case=%s join_result=%d accept_result=%d accept_errno=%d "
           "elapsed_ms=%" PRIu64 "\n",
           case_name, join_result, call.result, call.error, call.elapsed_ms);
    fflush(stdout);

    if (!thread_joined) {
        close(listener);
        listener_closed = true;
        if (timed_join(thread, 5000U) != 0) {
            fail(name, "blocked accept did not unwind after listener close");
            fflush(stdout);
            fflush(stderr);
            _Exit(EXIT_FAILURE);
        }
        thread_joined = true;
    }
    printf("OBSERVE case=%s thread_cpu_ms=%" PRIu64 "\n", case_name, call.cpu_ms);
    fflush(stdout);
    if (call.result >= 0) {
        close(call.result);
    }
    if (kernel_client >= 0) {
        (void)syscall(SYS_close, kernel_client);
    }
    if (!listener_closed) {
        close(listener);
    }
    if (ok) {
        pass(name);
    }
    return 0;
}

static int server_mixed_route_accept(const struct options *options, int control)
{
    return server_mixed_route_accept_impl(options, control, false);
}

static int server_mixed_route_accept_timeout(const struct options *options, int control)
{
    return server_mixed_route_accept_impl(options, control, true);
}

static int client_mixed_route_accept(const struct options *options, int control)
{
    (void)options;

    if (expect_byte(control, CMD_MIXED_ROUTE_ACCEPT_START) != 0) {
        return -1;
    }
    return send_byte(control, CMD_ACK);
}

static int server_accept4_flags(const struct options *options, int control)
{
    const char *invalid_name = "accept4 rejects unsupported flags promptly";
    const char *cloexec_name = "accept4 applies SOCK_CLOEXEC to the accepted fd";
    struct accept_call call = {
        .fd = -1,
        .flags = 0x40000000,
        .use_accept4 = true,
        .result = -2,
    };
    pthread_t thread;
    int join_result;
    int listener = make_listener(options->bind_ip, options->port + TEST_ACCEPT4_PORT);
    bool invalid_ok = true;
    bool cloexec_ok = true;

    if (listener < 0) {
        fail(invalid_name, "listener setup failed");
        return -1;
    }
    call.fd = listener;
    if (pthread_create(&thread, NULL, accept_thread, &call) != 0) {
        fail(invalid_name, "pthread_create failed");
        close(listener);
        return -1;
    }
    join_result = timed_join(thread, 250);
    if (join_result == 0) {
        if (call.result >= 0 || call.error != EINVAL) {
            fail(invalid_name, "accept4 did not return EINVAL for unsupported flags");
            invalid_ok = false;
        }
    } else if (join_result == ETIMEDOUT) {
        fail(invalid_name, "accept4 validated flags only after waiting for a connection");
        invalid_ok = false;
    } else {
        fail(invalid_name, "pthread_timedjoin_np failed");
        invalid_ok = false;
    }

    if (send_byte(control, CMD_ACCEPT4_CONNECT) != 0) {
        perror("accept4 coordination");
        shutdown(listener, SHUT_RDWR);
        close(listener);
        if (join_result == ETIMEDOUT) {
            pthread_join(thread, NULL);
        }
        return -1;
    }
    if (expect_byte(control, CMD_ACCEPT4_CONNECTED) != 0) {
        shutdown(listener, SHUT_RDWR);
        close(listener);
        if (join_result == ETIMEDOUT) {
            pthread_join(thread, NULL);
        }
        return -1;
    }
    if (join_result == ETIMEDOUT && timed_join(thread, 5000) != 0) {
        fail(invalid_name, "invalid-flags accept4 did not recover when a peer connected");
        shutdown(listener, SHUT_RDWR);
        pthread_join(thread, NULL);
        close(listener);
        return -1;
    }
    if (call.result >= 0) {
        close(call.result);
    } else {
        int cleanup = accept(listener, NULL, NULL);

        if (cleanup < 0) {
            fail(cloexec_name, "could not consume the invalid-flags probe connection");
            close(listener);
            return -1;
        }
        close(cleanup);
    }
    if (send_byte(control, CMD_ACCEPT4_CLOEXEC_CONNECT) != 0) {
        close(listener);
        return -1;
    }

    int accepted = accept4(listener, NULL, NULL, SOCK_CLOEXEC);

    if (accepted < 0) {
        fail(cloexec_name, "accept4(SOCK_CLOEXEC) failed");
        cloexec_ok = false;
    } else {
        int descriptor_flags = fcntl(accepted, F_GETFD, 0);

        if (descriptor_flags < 0 || (descriptor_flags & FD_CLOEXEC) == 0) {
            fail(cloexec_name, "accepted fd is missing FD_CLOEXEC");
            cloexec_ok = false;
        }
        close(accepted);
    }
    if (invalid_ok) {
        pass(invalid_name);
    }
    if (cloexec_ok) {
        pass(cloexec_name);
    }
    send_byte(control, CMD_ACK);
    close(listener);
    return 0;
}

static int client_accept4_flags(const struct options *options, int control)
{
    int first_fd;
    int cloexec_fd;

    if (expect_byte(control, CMD_ACCEPT4_CONNECT) != 0) {
        return -1;
    }
    first_fd =
        connect_retry(options->bind_ip, options->server_ip, options->port + TEST_ACCEPT4_PORT);
    if (first_fd < 0 || send_byte(control, CMD_ACCEPT4_CONNECTED) != 0 ||
        expect_byte(control, CMD_ACCEPT4_CLOEXEC_CONNECT) != 0) {
        if (first_fd >= 0) {
            close(first_fd);
        }
        return -1;
    }
    cloexec_fd =
        connect_retry(options->bind_ip, options->server_ip, options->port + TEST_ACCEPT4_PORT);
    if (cloexec_fd < 0) {
        close(first_fd);
        return -1;
    }
    if (expect_byte(control, CMD_ACK) != 0) {
        close(first_fd);
        close(cloexec_fd);
        return -1;
    }
    close(first_fd);
    close(cloexec_fd);
    return 0;
}

static int server_peek(const struct options *options, int control)
{
    static const unsigned char payload[] = "peek-data-must-remain-queued";
    const char *name = "MSG_PEEK does not consume worker-mode receive data";
    struct recv_call peek_call = {.fd = -1, .flags = MSG_PEEK, .length = sizeof(payload) - 1};
    struct recv_call read_call = {.fd = -1, .flags = MSG_WAITALL, .length = sizeof(payload) - 1};
    pthread_t peek_thread;
    pthread_t read_thread_id;
    int listener = make_listener(options->bind_ip, options->port + TEST_PEEK_PORT);
    int fd;
    bool ok = true;

    if (listener < 0 || send_byte(control, CMD_PEEK_CONNECT) != 0) {
        return -1;
    }
    fd = accept(listener, NULL, NULL);
    close(listener);
    if (fd < 0 || expect_byte(control, CMD_PEEK_SENT) != 0) {
        perror("peek test setup");
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }

    peek_call.fd = fd;
    int create_result = pthread_create(&peek_thread, NULL, recv_thread, &peek_call);

    if (create_result != 0) {
        fail(name, "could not start MSG_PEEK receiver");
        ok = false;
    } else if (timed_join(peek_thread, 3000) != 0) {
        fail(name, "MSG_PEEK did not finish");
        shutdown(fd, SHUT_RDWR);
        pthread_join(peek_thread, NULL);
        ok = false;
    } else if (peek_call.result != (ssize_t)(sizeof(payload) - 1) ||
               memcmp(peek_call.data, payload, sizeof(payload) - 1) != 0) {
        fail(name, "MSG_PEEK returned the wrong payload");
        ok = false;
    }

    if (ok) {
        read_call.fd = fd;
        create_result = pthread_create(&read_thread_id, NULL, recv_thread, &read_call);
        if (create_result != 0) {
            fail(name, "could not start ordinary receiver");
            ok = false;
        } else if (timed_join(read_thread_id, 3000) != 0) {
            fail(name, "ordinary recv blocked after MSG_PEEK consumed the data");
            shutdown(fd, SHUT_RDWR);
            pthread_join(read_thread_id, NULL);
            ok = false;
        } else if (read_call.result != (ssize_t)(sizeof(payload) - 1) ||
                   memcmp(read_call.data, payload, sizeof(payload) - 1) != 0) {
            fail(name, "ordinary recv did not return the peeked payload");
            ok = false;
        }
    }
    if (ok) {
        pass(name);
    }
    send_byte(control, CMD_ACK);
    close(fd);
    return 0;
}

static int client_peek(const struct options *options, int control)
{
    static const unsigned char payload[] = "peek-data-must-remain-queued";
    int fd;

    if (expect_byte(control, CMD_PEEK_CONNECT) != 0) {
        return -1;
    }
    fd = connect_retry(options->bind_ip, options->server_ip, options->port + TEST_PEEK_PORT);
    if (fd < 0 || send_all(fd, payload, sizeof(payload) - 1) != 0 ||
        send_byte(control, CMD_PEEK_SENT) != 0 || expect_byte(control, CMD_ACK) != 0) {
        perror("peek client");
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }
    close(fd);
    return 0;
}

static int server_waitall(const struct options *options, int control)
{
    static const unsigned char payload[] = "fragmented-waitall-payload";
    const char *name = "MSG_WAITALL waits for a fragmented payload";
    struct recv_call call = {.fd = -1, .flags = MSG_WAITALL, .length = sizeof(payload) - 1};
    pthread_t thread;
    uint64_t start;
    uint64_t elapsed;
    int listener = make_listener(options->bind_ip, options->port + TEST_WAITALL_PORT);
    int fd;
    int first_join;
    bool ok = true;

    if (listener < 0 || send_byte(control, CMD_WAITALL_CONNECT) != 0) {
        return -1;
    }
    fd = accept(listener, NULL, NULL);
    close(listener);
    if (fd < 0 || expect_byte(control, CMD_WAITALL_FIRST_SENT) != 0) {
        perror("waitall test setup");
        return -1;
    }

    call.fd = fd;
    start = monotonic_ms();
    if (pthread_create(&thread, NULL, recv_thread, &call) != 0) {
        fail(name, "pthread_create failed");
        close(fd);
        return -1;
    }
    first_join = timed_join(thread, 250);
    if (first_join == 0) {
        fail(name, "recv(MSG_WAITALL) returned after only the first fragment");
        ok = false;
    } else if (first_join != ETIMEDOUT) {
        fail(name, "pthread_timedjoin_np failed");
        ok = false;
    }

    if (first_join == ETIMEDOUT) {
        if (timed_join(thread, 5000) != 0) {
            fail(name, "recv(MSG_WAITALL) did not finish after the second fragment");
            shutdown(fd, SHUT_RDWR);
            pthread_join(thread, NULL);
            ok = false;
        }
    }
    elapsed = monotonic_ms() - start;
    if (expect_byte(control, CMD_WAITALL_SECOND_SENT) != 0) {
        ok = false;
    }
    if (call.result != (ssize_t)(sizeof(payload) - 1) ||
        memcmp(call.data, payload, sizeof(payload) - 1) != 0) {
        if (ok) {
            fail(name, "recv(MSG_WAITALL) did not return the complete payload");
        }
        ok = false;
    }
    if (elapsed < 500) {
        if (ok) {
            fail(name, "recv(MSG_WAITALL) did not wait for the delayed fragment");
        }
        ok = false;
    }
    if (ok) {
        pass(name);
    }
    send_byte(control, CMD_ACK);
    close(fd);
    return 0;
}

static int client_waitall(const struct options *options, int control)
{
    static const unsigned char payload[] = "fragmented-waitall-payload";
    const size_t first_length = 7;
    int fd;

    if (expect_byte(control, CMD_WAITALL_CONNECT) != 0) {
        return -1;
    }
    fd = connect_retry(options->bind_ip, options->server_ip, options->port + TEST_WAITALL_PORT);
    if (fd < 0 || send_all(fd, payload, first_length) != 0 ||
        send_byte(control, CMD_WAITALL_FIRST_SENT) != 0) {
        perror("waitall first fragment");
        return -1;
    }
    sleep_ms(800);
    if (send_all(fd, payload + first_length, sizeof(payload) - 1 - first_length) != 0 ||
        send_byte(control, CMD_WAITALL_SECOND_SENT) != 0 || expect_byte(control, CMD_ACK) != 0) {
        perror("waitall second fragment");
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int server_waitall_shut_rd(const struct options *options, int control)
{
    const char *name = "MSG_WAITALL preserves a partial prefix across read shutdown";
    static const unsigned char payload[4] = {0x6d, 0x6d, 0x6d, 0x6d};
    struct recv_call call = {.fd = -1, .flags = MSG_WAITALL, .length = 8U};
    unsigned char buffer[8] = {0};
    ssize_t prefix_result;
    ssize_t eof_result;
    pthread_t thread;
    int join_result;
    int shutdown_result;
    int shutdown_error;
    int listener = make_listener(options->bind_ip, options->port + TEST_WAITALL_SHUT_RD_PORT);
    int fd;
    bool ok = true;

    if (listener < 0 || send_byte(control, CMD_WAITALL_SHUT_RD_CONNECT) != 0) {
        return -1;
    }
    fd = accept(listener, NULL, NULL);
    close(listener);
    if (fd < 0 || expect_byte(control, CMD_WAITALL_SHUT_RD_SENT) != 0) {
        perror("waitall-shut-rd setup");
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }

    call.fd = fd;
    if (pthread_create(&thread, NULL, recv_thread, &call) != 0) {
        fail(name, "pthread_create failed");
        close(fd);
        return -1;
    }
    sleep_ms(200U);
    errno = 0;
    shutdown_result = shutdown(fd, SHUT_RD);
    shutdown_error = shutdown_result < 0 ? errno : 0;
    join_result = timed_join(thread, 3000U);
    if (join_result != 0) {
        fail(name, "recv(MSG_WAITALL) did not return after shutdown(SHUT_RD)");
        close(fd);
        if (timed_join(thread, 3000U) != 0) {
            fflush(stdout);
            fflush(stderr);
            _Exit(EXIT_FAILURE);
        }
        return 0;
    }

    errno = 0;
    prefix_result = recv(fd, buffer, sizeof(buffer), 0);
    const int prefix_error = prefix_result < 0 ? errno : 0;
    errno = 0;
    eof_result = recv(fd, buffer + sizeof(payload), sizeof(buffer) - sizeof(payload), 0);
    const int eof_error = eof_result < 0 ? errno : 0;

    printf("OBSERVE case=waitall-shut-rd shutdown_result=%d shutdown_errno=%d "
           "waitall_result=%zd waitall_errno=%d prefix_result=%zd prefix_errno=%d "
           "eof_result=%zd eof_errno=%d\n",
           shutdown_result, shutdown_error, call.result, call.error, prefix_result, prefix_error,
           eof_result, eof_error);
    fflush(stdout);

    if (shutdown_result != 0) {
        fail(name, "shutdown(SHUT_RD) failed");
        ok = false;
    }
    if (call.result != 0) {
        fail(name, "terminal MSG_WAITALL returned or consumed the queued prefix");
        ok = false;
    }
    if (prefix_result != (ssize_t)sizeof(payload) ||
        memcmp(buffer, payload, sizeof(payload)) != 0) {
        fail(name, "the ordinary recv did not receive the preserved prefix");
        ok = false;
    }
    if (eof_result != 0) {
        fail(name, "the final recv did not report EOF");
        ok = false;
    }
    if (ok) {
        pass(name);
    }
    if (send_byte(control, CMD_ACK) != 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int client_waitall_shut_rd(const struct options *options, int control)
{
    static const unsigned char payload[4] = {0x6d, 0x6d, 0x6d, 0x6d};
    int fd;

    if (expect_byte(control, CMD_WAITALL_SHUT_RD_CONNECT) != 0) {
        return -1;
    }
    fd = connect_retry(options->bind_ip, options->server_ip,
                       options->port + TEST_WAITALL_SHUT_RD_PORT);
    if (fd < 0 || send_all(fd, payload, sizeof(payload)) != 0 ||
        send_byte(control, CMD_WAITALL_SHUT_RD_SENT) != 0) {
        perror("waitall-shut-rd client");
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }
    if (expect_byte(control, CMD_ACK) != 0) {
        perror("waitall-shut-rd client coordination");
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static uint64_t clock_cpu_ns(clockid_t clock_id)
{
    struct timespec value = {0};

    if (clock_gettime(clock_id, &value) != 0) {
        return 0U;
    }
    return (uint64_t)value.tv_sec * 1000000000U + (uint64_t)value.tv_nsec;
}

static int server_shared_cq_idle(const struct options *options, int control)
{
    const char *name = "shared CQ traffic does not wake idle worker receive waiters";
    struct idle_recv_call calls[SHARED_CQ_IDLE_WAITERS] = {0};
    pthread_t threads[SHARED_CQ_IDLE_WAITERS];
    clockid_t clocks[SHARED_CQ_IDLE_WAITERS];
    uint64_t cpu_before[SHARED_CQ_IDLE_WAITERS] = {0};
    unsigned char buffer[64 * 1024];
    int sockets[SHARED_CQ_IDLE_WAITERS + 1];
    int listener = make_listener_with_options(options->bind_ip,
                                              options->port + TEST_SHARED_CQ_IDLE_PORT,
                                              SHARED_CQ_IDLE_WAITERS + 4, 0);
    uint64_t received = 0U;
    uint64_t total_cpu_ns = 0U;
    uint64_t max_cpu_ns = 0U;
    int returned = 0;
    int created = 0;
    bool ok = true;

    for (int index = 0; index < SHARED_CQ_IDLE_WAITERS + 1; ++index) {
        sockets[index] = -1;
    }
    if (listener < 0 || send_byte(control, CMD_SHARED_CQ_CONNECT) != 0) {
        return -1;
    }
    for (int index = 0; index < SHARED_CQ_IDLE_WAITERS + 1; ++index) {
        sockets[index] = accept(listener, NULL, NULL);
        if (sockets[index] < 0) {
            perror("shared-cq-idle accept");
            ok = false;
            break;
        }
    }
    close(listener);
    if (!ok || expect_byte(control, CMD_SHARED_CQ_CONNECTED) != 0) {
        goto cleanup;
    }

    for (int index = 0; index < SHARED_CQ_IDLE_WAITERS; ++index) {
        calls[index].fd = sockets[index];
        if (pthread_create(&threads[index], NULL, idle_recv_thread, &calls[index]) != 0) {
            fail(name, "could not create every idle receive waiter");
            ok = false;
            break;
        }
        ++created;
    }
    for (int index = 0; index < created; ++index) {
        if (wait_for_atomic_bool(&calls[index].entered, 1000U) != 0 ||
            pthread_getcpuclockid(threads[index], &clocks[index]) != 0) {
            fail(name, "an idle receive waiter did not enter or expose its CPU clock");
            ok = false;
            break;
        }
    }
    sleep_ms(100U);
    for (int index = 0; index < created; ++index) {
        cpu_before[index] = clock_cpu_ns(clocks[index]);
    }

    if (!ok || send_byte(control, CMD_SHARED_CQ_FLOOD) != 0) {
        goto cleanup;
    }
    while (received < SHARED_CQ_FLOOD_BYTES) {
        const size_t requested =
            (size_t)((SHARED_CQ_FLOOD_BYTES - received) < sizeof(buffer)
                         ? (SHARED_CQ_FLOOD_BYTES - received)
                         : sizeof(buffer));
        const ssize_t result = recv(sockets[SHARED_CQ_IDLE_WAITERS], buffer, requested, 0);

        if (result <= 0) {
            fail(name, "the flooded connection ended before the byte target");
            ok = false;
            break;
        }
        received += (uint64_t)result;
    }
    if (ok && expect_byte(control, CMD_SHARED_CQ_FLOOD_DONE) != 0) {
        ok = false;
    }

    for (int index = 0; index < created; ++index) {
        const uint64_t after = clock_cpu_ns(clocks[index]);
        const uint64_t delta = after >= cpu_before[index] ? after - cpu_before[index] : 0U;

        total_cpu_ns += delta;
        if (delta > max_cpu_ns) {
            max_cpu_ns = delta;
        }
        returned += atomic_load_explicit(&calls[index].returned, memory_order_acquire) ? 1 : 0;
    }

    printf("OBSERVE case=shared-cq-idle idle_waiters=%d flood_bytes=%" PRIu64
           " idle_returned=%d total_idle_cpu_ms=%" PRIu64 " max_idle_cpu_ms=%" PRIu64 "\n",
           created, received, returned, total_cpu_ns / 1000000U, max_cpu_ns / 1000000U);
    fflush(stdout);

    if (returned != 0) {
        fail(name, "an idle receive returned during unrelated traffic");
        ok = false;
    }
    if (total_cpu_ns > 100U * 1000000U) {
        fail(name, "idle receive waiters consumed material CPU during unrelated traffic");
        ok = false;
    }

cleanup:
    for (int index = 0; index < created; ++index) {
        if (!atomic_load_explicit(&calls[index].returned, memory_order_acquire)) {
            (void)shutdown(sockets[index], SHUT_RD);
        }
    }
    for (int index = 0; index < created; ++index) {
        if (timed_join(threads[index], 3000U) != 0) {
            fail(name, "an idle receive waiter did not unwind during cleanup");
            fflush(stdout);
            fflush(stderr);
            _Exit(EXIT_FAILURE);
        }
    }
    for (int index = 0; index < SHARED_CQ_IDLE_WAITERS + 1; ++index) {
        if (sockets[index] >= 0) {
            close(sockets[index]);
        }
    }
    if (ok) {
        pass(name);
    }
    if (send_byte(control, CMD_ACK) != 0) {
        return -1;
    }
    return 0;
}

static int client_shared_cq_idle(const struct options *options, int control)
{
    static const unsigned char payload[64 * 1024] = {0xa5};
    int sockets[SHARED_CQ_IDLE_WAITERS + 1];
    uint64_t sent = 0U;

    if (expect_byte(control, CMD_SHARED_CQ_CONNECT) != 0) {
        return -1;
    }
    for (int index = 0; index < SHARED_CQ_IDLE_WAITERS + 1; ++index) {
        sockets[index] = connect_retry(options->bind_ip, options->server_ip,
                                       options->port + TEST_SHARED_CQ_IDLE_PORT);
        if (sockets[index] < 0) {
            return -1;
        }
    }
    if (send_byte(control, CMD_SHARED_CQ_CONNECTED) != 0 ||
        expect_byte(control, CMD_SHARED_CQ_FLOOD) != 0) {
        return -1;
    }
    while (sent < SHARED_CQ_FLOOD_BYTES) {
        const size_t requested =
            (size_t)((SHARED_CQ_FLOOD_BYTES - sent) < sizeof(payload)
                         ? (SHARED_CQ_FLOOD_BYTES - sent)
                         : sizeof(payload));

        if (send_all(sockets[SHARED_CQ_IDLE_WAITERS], payload, requested) != 0) {
            perror("shared-cq-idle flood");
            return -1;
        }
        sent += requested;
    }
    if (send_byte(control, CMD_SHARED_CQ_FLOOD_DONE) != 0 || expect_byte(control, CMD_ACK) != 0) {
        return -1;
    }
    for (int index = 0; index < SHARED_CQ_IDLE_WAITERS + 1; ++index) {
        close(sockets[index]);
    }
    return 0;
}

static int server_concurrent_recv(const struct options *options, int control)
{
    const char *name = "two concurrent recv calls each consume one byte during soak";
    bool ok = true;
    int listener = make_listener_with_options(options->bind_ip,
                                              options->port + TEST_CONCURRENT_RECV_PORT, 32, 0);
    int fd;

    if (listener < 0 || send_byte(control, CMD_RECV_CONNECT) != 0) {
        return -1;
    }
    fd = accept(listener, NULL, NULL);
    close(listener);
    if (fd < 0) {
        perror("concurrent recv accept");
        return -1;
    }

    for (int iteration = 0; iteration < CONCURRENT_RECV_ITERATIONS; ++iteration) {
        struct recv_call calls[2] = {
            {.fd = fd, .flags = 0, .length = 1},
            {.fd = fd, .flags = 0, .length = 1},
        };
        pthread_t threads[2];
        bool created[2] = {false, false};
        bool joined[2] = {false, false};
        int joined_count = 0;

        for (int index = 0; index < 2; ++index) {
            if (pthread_create(&threads[index], NULL, recv_thread, &calls[index]) != 0) {
                fail(name, "pthread_create failed during soak");
                ok = false;
                break;
            }
            created[index] = true;
        }
        if (send_byte(control, CMD_RECV_SEND) != 0) {
            shutdown(fd, SHUT_RDWR);
            for (int index = 0; index < 2; ++index) {
                if (created[index]) {
                    pthread_join(threads[index], NULL);
                }
            }
            close(fd);
            return -1;
        }

        uint64_t deadline = monotonic_ms() + 500U;

        do {
            for (int index = 0; index < 2; ++index) {
                if (!joined[index]) {
                    int result = pthread_tryjoin_np(threads[index], NULL);

                    if (result == 0) {
                        joined[index] = true;
                        ++joined_count;
                    } else if (result != EBUSY) {
                        fail(name, "pthread_tryjoin_np failed during soak");
                        ok = false;
                    }
                }
            }
            if (joined_count == 0) {
                sleep_ms(1);
            }
        } while (joined_count == 0 && monotonic_ms() < deadline);

        if (joined_count > 0) {
            sleep_ms(10);
            for (int index = 0; index < 2; ++index) {
                if (!joined[index]) {
                    int result = pthread_tryjoin_np(threads[index], NULL);

                    if (result == 0) {
                        joined[index] = true;
                        ++joined_count;
                    } else if (result != EBUSY) {
                        fail(name, "pthread_tryjoin_np failed during grace period");
                        ok = false;
                    }
                }
            }
        }

        if (!created[0] || !created[1] || joined_count != 1) {
            if (ok) {
                char detail[192];

                snprintf(detail, sizeof(detail),
                         "iteration %d: %s for the first byte (r0=%zd e0=%d r1=%zd e1=%d)",
                         iteration,
                         !created[0] || !created[1] ? "one recv thread was not created"
                             : joined_count == 2    ? "both recv calls returned"
                                                    : "neither recv call returned",
                         calls[0].result, calls[0].error, calls[1].result, calls[1].error);
                fail(name, detail);
            }
            ok = false;
        } else {
            int completed = joined[0] ? 0 : 1;

            if (calls[completed].result != 1 || calls[completed].data[0] != 0x5a) {
                if (ok) {
                    char detail[160];

                    snprintf(detail, sizeof(detail),
                             "iteration %d: completed recv returned %zd errno=%d", iteration,
                             calls[completed].result, calls[completed].error);
                    fail(name, detail);
                }
                ok = false;
            }
        }

        if (!ok) {
            (void)send_byte(control, CMD_RECV_ABORT);
            shutdown(fd, SHUT_RDWR);
            for (int index = 0; index < 2; ++index) {
                if (created[index] && !joined[index]) {
                    pthread_join(threads[index], NULL);
                }
            }
            close(fd);
            return 0;
        }

        int pending = joined[0] ? 1 : 0;

        if (send_byte(control, CMD_RECV_CLEANUP) != 0) {
            shutdown(fd, SHUT_RDWR);
            pthread_join(threads[pending], NULL);
            close(fd);
            return -1;
        }
        int cleanup_join = timed_join(threads[pending], 3000U);

        if (cleanup_join != 0) {
            char detail[128];

            snprintf(detail, sizeof(detail), "iteration %d: cleanup recv did not finish, join=%d",
                     iteration, cleanup_join);
            fail(name, detail);
            ok = false;
            shutdown(fd, SHUT_RDWR);
            pthread_join(threads[pending], NULL);
        } else if (calls[pending].result != 1 || calls[pending].data[0] != 0xa5) {
            char detail[160];

            snprintf(detail, sizeof(detail),
                     "iteration %d: cleanup recv returned %zd errno=%d byte=0x%02x", iteration,
                     calls[pending].result, calls[pending].error, calls[pending].data[0]);
            fail(name, detail);
            ok = false;
        }
        if (send_byte(control, CMD_ACK) != 0) {
            close(fd);
            return -1;
        }
        if (!ok) {
            if (iteration + 1 < CONCURRENT_RECV_ITERATIONS) {
                (void)send_byte(control, CMD_RECV_ABORT);
            }
            close(fd);
            return 0;
        }
    }
    if (ok) {
        pass(name);
    }
    close(fd);
    return 0;
}

static int client_concurrent_recv(const struct options *options, int control)
{
    const unsigned char first_byte = 0x5a;
    const unsigned char cleanup_byte = 0xa5;
    unsigned char command;
    int fd;

    if (expect_byte(control, CMD_RECV_CONNECT) != 0) {
        return -1;
    }
    fd = connect_retry(options->bind_ip, options->server_ip,
                       options->port + TEST_CONCURRENT_RECV_PORT);
    if (fd < 0) {
        perror("concurrent recv connect");
        return -1;
    }

    for (int iteration = 0; iteration < CONCURRENT_RECV_ITERATIONS; ++iteration) {
        if (recv_all(control, &command, sizeof(command)) != 0) {
            perror("concurrent recv client");
            close(fd);
            return -1;
        }
        if (command == CMD_RECV_ABORT) {
            close(fd);
            return 0;
        }
        if (command != CMD_RECV_SEND || send_all(fd, &first_byte, sizeof(first_byte)) != 0 ||
            recv_all(control, &command, sizeof(command)) != 0) {
            errno = command == CMD_RECV_SEND ? errno : EPROTO;
            perror("concurrent recv first byte");
            close(fd);
            return -1;
        }
        if (command == CMD_RECV_ABORT) {
            close(fd);
            return 0;
        }
        if (command != CMD_RECV_CLEANUP || send_all(fd, &cleanup_byte, sizeof(cleanup_byte)) != 0 ||
            expect_byte(control, CMD_ACK) != 0) {
            errno = command == CMD_RECV_CLEANUP ? errno : EPROTO;
            perror("concurrent recv cleanup byte");
            close(fd);
            return -1;
        }
    }
    close(fd);
    return 0;
}

static int server_blocking_send(const struct options *options, int control)
{
    const char *name = "one blocking send completes its full request after backpressure";
    struct send_report report;
    struct rusage drain_usage_before = {0};
    struct rusage drain_usage_after = {0};
    unsigned char buffer[64 * 1024];
    uint64_t received = 0;
    uint64_t drain_start_ms = 0;
    uint64_t last_recv_ms = 0;
    uint64_t max_recv_gap_ms = 0;
    uint64_t recv_calls = 0;
    uint64_t recv_gaps_ge_50ms = 0;
    uint64_t recv_gaps_ge_90ms = 0;
    int receive_buffer_size = 4 * 1024;
    int listener = make_listener_with_options(options->bind_ip, options->port + TEST_SEND_PORT, 8,
                                              receive_buffer_size);
    int fd;
    bool ok = true;

    if (listener < 0 || send_byte(control, CMD_SEND_CONNECT) != 0) {
        return -1;
    }
    fd = accept(listener, NULL, NULL);
    close(listener);
    if (fd < 0 || set_recv_timeout(fd, IO_TIMEOUT_SECONDS) != 0 ||
        send_byte(control, CMD_SEND_START) != 0) {
        perror("send test setup");
        return -1;
    }

    sleep_ms(1500);
    drain_start_ms = monotonic_ms();
    (void)getrusage(RUSAGE_THREAD, &drain_usage_before);
    while (received < SEND_BYTES) {
        ssize_t result = recv(fd, buffer, sizeof(buffer), 0);

        if (result > 0) {
            const uint64_t now_ms = monotonic_ms();
            if (last_recv_ms != 0U) {
                const uint64_t gap_ms = now_ms - last_recv_ms;
                if (gap_ms > max_recv_gap_ms) {
                    max_recv_gap_ms = gap_ms;
                }
                recv_gaps_ge_50ms += gap_ms >= 50U;
                recv_gaps_ge_90ms += gap_ms >= 90U;
            }
            last_recv_ms = now_ms;
            ++recv_calls;
            received += (uint64_t)result;
            continue;
        }
        if (result < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    (void)getrusage(RUSAGE_THREAD, &drain_usage_after);
    if (recv_all(control, &report, sizeof(report)) != 0) {
        fail(name, "did not receive the sender result");
        ok = false;
        memset(&report, 0, sizeof(report));
    }
    if (report.magic != 0x42534f43U) {
        fail(name, "sender result had an invalid magic value");
        ok = false;
    } else if (report.result != SEND_BYTES || report.error != 0) {
        fail(name, "the single blocking send did not return the complete request");
        ok = false;
    } else if (report.bytes_sent != SEND_BYTES || received != SEND_BYTES) {
        fail(name, "the single send did not deliver the complete payload");
        ok = false;
    } else if (report.elapsed_ms < 1000) {
        fail(name, "the single send returned before the delayed peer read");
        ok = false;
    } else if (report.elapsed_ms > BLOCKING_SEND_MAX_MS) {
        fail(name, "the single blocking send exceeded the R2C performance envelope");
        ok = false;
    }
    printf("OBSERVE case=blocking-send syscall=send calls=1 result=%d errno=%d "
           "bytes_received=%" PRIu64 " elapsed_ms=%" PRIu64 " recv_calls=%" PRIu64
           " drain_elapsed_ms=%" PRIu64 " max_recv_gap_ms=%" PRIu64 " recv_gaps_ge_50ms=%" PRIu64
           " recv_gaps_ge_90ms=%" PRIu64 " drain_nvcsw=%ld drain_nivcsw=%ld\n",
           report.result, report.error, received, report.elapsed_ms, recv_calls,
           monotonic_ms() - drain_start_ms, max_recv_gap_ms, recv_gaps_ge_50ms, recv_gaps_ge_90ms,
           drain_usage_after.ru_nvcsw - drain_usage_before.ru_nvcsw,
           drain_usage_after.ru_nivcsw - drain_usage_before.ru_nivcsw);
    fflush(stdout);
    if (ok) {
        pass(name);
    }
    send_byte(control, CMD_ACK);
    close(fd);
    return 0;
}

static int client_blocking_send(const struct options *options, int control)
{
    struct send_report report = {
        .magic = 0x42534f43U,
        .result = -1,
    };
    unsigned char *buffer;
    uint64_t start;
    int send_buffer_size = 64 * 1024;
    int fd;
    ssize_t sent;

    if (expect_byte(control, CMD_SEND_CONNECT) != 0) {
        return -1;
    }
    fd = connect_retry(options->bind_ip, options->server_ip, options->port + TEST_SEND_PORT);
    if (fd < 0) {
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &send_buffer_size, sizeof(send_buffer_size)) != 0 ||
        expect_byte(control, CMD_SEND_START) != 0) {
        perror("send client setup");
        close(fd);
        return -1;
    }

    buffer = malloc(SEND_BYTES);
    if (buffer == NULL) {
        perror("malloc");
        close(fd);
        return -1;
    }
    memset(buffer, 0xa5, SEND_BYTES);
    start = monotonic_ms();
    errno = 0;
    sent = send(fd, buffer, SEND_BYTES, MSG_NOSIGNAL);
    report.elapsed_ms = monotonic_ms() - start;
    report.bytes_sent = sent >= 0 ? (uint64_t)sent : 0;
    report.error = sent < 0 ? errno : 0;
    report.result = (int32_t)sent;
    shutdown(fd, SHUT_WR);
    free(buffer);

    if (send_all(control, &report, sizeof(report)) != 0 || expect_byte(control, CMD_ACK) != 0) {
        perror("send client report");
        close(fd);
        return -1;
    }
    close(fd);
    return sent == SEND_BYTES ? 0 : -1;
}

static int server_send_after_shut_wr(const struct options *options, int control)
{
    const char *name = "send after SHUT_WR fails with EPIPE and sends no peer byte";
    struct shutdown_send_report report;
    unsigned char byte = 0;
    int peer_error = 0;
    ssize_t peer_result;
    int listener = make_listener(options->bind_ip, options->port + TEST_SEND_AFTER_SHUT_WR_PORT);
    int fd;
    bool ok = true;

    if (listener < 0 || send_byte(control, CMD_SEND_AFTER_SHUT_WR_CONNECT) != 0) {
        return -1;
    }
    fd = accept(listener, NULL, NULL);
    close(listener);
    if (fd < 0 || set_recv_timeout(fd, IO_TIMEOUT_SECONDS) != 0 ||
        send_byte(control, CMD_SEND_AFTER_SHUT_WR_START) != 0) {
        perror("send-after-SHUT_WR setup");
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }

    if (recv_all(control, &report, sizeof(report)) != 0) {
        fail(name, "client did not report shutdown and send results");
        close(fd);
        return -1;
    }
    errno = 0;
    peer_result = recv(fd, &byte, sizeof(byte), 0);
    peer_error = peer_result < 0 ? errno : 0;

    printf("OBSERVE case=send-after-shut-wr shutdown_result=%d shutdown_errno=%d "
           "send_result=%d send_errno=%d peer_result=%zd peer_errno=%d peer_byte=0x%02x\n",
           report.shutdown_result, report.shutdown_error, report.send_result, report.send_error,
           peer_result, peer_error, byte);
    fflush(stdout);

    if (report.magic != 0x53575254U) {
        fail(name, "client report had an invalid magic value");
        ok = false;
    } else if (report.shutdown_result != 0 || report.shutdown_error != 0) {
        fail(name, "SHUT_WR failed before the post-shutdown send");
        ok = false;
    } else if (report.send_result != -1 || report.send_error != EPIPE) {
        fail(name, "post-SHUT_WR send did not return -1/EPIPE");
        ok = false;
    } else if (peer_result != 0) {
        fail(name, "peer observed data or an error instead of clean EOF");
        ok = false;
    }
    if (ok) {
        pass(name);
    }
    if (send_byte(control, CMD_ACK) != 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int client_send_after_shut_wr(const struct options *options, int control)
{
    struct shutdown_send_report report = {
        .magic = 0x53575254U,
        .shutdown_result = -1,
        .send_result = -2,
    };
    const unsigned char byte = 0xa5;
    int fd;

    if (expect_byte(control, CMD_SEND_AFTER_SHUT_WR_CONNECT) != 0) {
        return -1;
    }
    fd = connect_retry(options->bind_ip, options->server_ip,
                       options->port + TEST_SEND_AFTER_SHUT_WR_PORT);
    if (fd < 0 || expect_byte(control, CMD_SEND_AFTER_SHUT_WR_START) != 0) {
        perror("send-after-SHUT_WR client setup");
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }

    errno = 0;
    report.shutdown_result = shutdown(fd, SHUT_WR);
    report.shutdown_error = report.shutdown_result < 0 ? errno : 0;
    errno = 0;
    report.send_result = (int32_t)send(fd, &byte, sizeof(byte), MSG_NOSIGNAL);
    report.send_error = report.send_result < 0 ? errno : 0;

    if (send_all(control, &report, sizeof(report)) != 0 || expect_byte(control, CMD_ACK) != 0) {
        perror("send-after-SHUT_WR client report");
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int server_send_timeout(const struct options *options, int control)
{
    const char *roundtrip_name = "SO_SNDTIMEO round-trips through getsockopt";
    const char *behavior_name = "SO_SNDTIMEO bounds a backpressured blocking send";
    struct send_timeout_report report;
    int receive_buffer_size = 4 * 1024;
    int listener = make_listener_with_options(
        options->bind_ip, options->port + TEST_SEND_TIMEOUT_PORT, 8, receive_buffer_size);
    int fd;
    bool roundtrip_ok = true;
    bool behavior_ok = true;

    if (listener < 0 || send_byte(control, CMD_SEND_TIMEOUT_CONNECT) != 0) {
        return -1;
    }
    fd = accept(listener, NULL, NULL);
    close(listener);
    if (fd < 0 || send_byte(control, CMD_SEND_TIMEOUT_START) != 0) {
        perror("send timeout setup");
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }
    if (recv_all(control, &report, sizeof(report)) != 0) {
        fail(behavior_name, "did not receive the sender timeout report");
        close(fd);
        return -1;
    }
    if (report.magic != 0x53544d4fU) {
        fail(behavior_name, "sender timeout report had an invalid magic value");
        roundtrip_ok = false;
        behavior_ok = false;
    } else {
        printf("INFO send-timeout report: result=%d error=%d bytes=%llu elapsed=%llu ms "
               "getsockopt=%d timeout_us=%lld\n",
               report.result, report.error, (unsigned long long)report.bytes_sent,
               (unsigned long long)report.elapsed_ms, report.getsockopt_result,
               (long long)report.observed_timeout_us);
        fflush(stdout);
        if (report.getsockopt_result != 0 || report.observed_timeout_us < 250000 ||
            report.observed_timeout_us > 600000) {
            fail(roundtrip_name, "getsockopt did not return the configured send timeout");
            roundtrip_ok = false;
        }
        if (report.result != -1 || (report.error != EAGAIN && report.error != EWOULDBLOCK)) {
            fail(behavior_name, "backpressured send did not end with EAGAIN");
            behavior_ok = false;
        } else if (report.bytes_sent == 0 || report.bytes_sent >= SEND_BYTES) {
            fail(behavior_name, "send timeout did not stop a partially completed transfer");
            behavior_ok = false;
        } else if (report.elapsed_ms < SHORT_TIMEOUT_MS - 100U ||
                   report.elapsed_ms > IO_TIMEOUT_SECONDS * 1000U) {
            fail(behavior_name, "send timeout elapsed outside the bounded tolerance");
            behavior_ok = false;
        }
    }
    if (roundtrip_ok) {
        pass(roundtrip_name);
    }
    if (behavior_ok) {
        pass(behavior_name);
    }
    shutdown(fd, SHUT_RDWR);
    close(fd);
    if (send_byte(control, CMD_ACK) != 0) {
        return -1;
    }
    return 0;
}

static int client_send_timeout(const struct options *options, int control)
{
    struct send_timeout_report report = {
        .magic = 0x53544d4fU,
        .result = -1,
        .getsockopt_result = -1,
    };
    struct timeval observed_timeout = {0};
    socklen_t observed_length = sizeof(observed_timeout);
    unsigned char *buffer;
    int send_buffer_size = 32 * 1024;
    int error = 0;
    int fd;
    ssize_t sent;
    uint64_t start;

    if (expect_byte(control, CMD_SEND_TIMEOUT_CONNECT) != 0) {
        return -1;
    }
    fd =
        connect_retry(options->bind_ip, options->server_ip, options->port + TEST_SEND_TIMEOUT_PORT);
    if (fd < 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &send_buffer_size, sizeof(send_buffer_size)) != 0 ||
        set_send_timeout_ms(fd, SHORT_TIMEOUT_MS) != 0 ||
        expect_byte(control, CMD_SEND_TIMEOUT_START) != 0) {
        perror("send timeout client setup");
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }

    errno = 0;
    report.getsockopt_result =
        getsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &observed_timeout, &observed_length);
    report.getsockopt_error = report.getsockopt_result < 0 ? errno : 0;
    if (report.getsockopt_result == 0 && observed_length == sizeof(observed_timeout)) {
        report.observed_timeout_us =
            (int64_t)observed_timeout.tv_sec * 1000000LL + (int64_t)observed_timeout.tv_usec;
    }

    buffer = malloc(SEND_BYTES);
    if (buffer == NULL) {
        perror("malloc");
        close(fd);
        return -1;
    }
    memset(buffer, 0x5a, SEND_BYTES);
    start = monotonic_ms();
    sent = send_all_count(fd, buffer, SEND_BYTES, &error);
    report.elapsed_ms = monotonic_ms() - start;
    report.bytes_sent = sent >= 0 ? (uint64_t)sent : 0;
    report.error = error;
    report.result = sent == SEND_BYTES ? 0 : -1;
    free(buffer);

    if (send_all(control, &report, sizeof(report)) != 0 || expect_byte(control, CMD_ACK) != 0) {
        perror("send timeout client report");
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static bool tx_close_error_is_expected(int error)
{
    return error == EBADF || error == EPIPE || error == ECONNRESET || error == ENOTCONN;
}

static int server_tx_close(const struct options *options, int control)
{
    const char *name = "concurrent TX and close drain queued worker jobs safely";
    struct tx_close_report report;
    int receive_buffer_size = 4 * 1024;
    int listener = make_listener_with_options(options->bind_ip, options->port + TEST_TX_CLOSE_PORT,
                                              8, receive_buffer_size);
    int fd;
    bool ok = true;

    if (listener < 0 || send_byte(control, CMD_TX_CLOSE_CONNECT) != 0) {
        return -1;
    }
    fd = accept(listener, NULL, NULL);
    close(listener);
    if (fd < 0 || send_byte(control, CMD_TX_CLOSE_START) != 0) {
        perror("TX-close setup");
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }

    sleep_ms(1000);
    shutdown(fd, SHUT_RDWR);
    close(fd);
    if (recv_all(control, &report, sizeof(report)) != 0) {
        fail(name, "client crashed, hung, or failed to report");
        return -1;
    }
    if (report.magic != 0x5458434cU) {
        fail(name, "TX-close report had an invalid magic value");
        ok = false;
    } else if (report.close_result != 0 || report.close_error != 0) {
        fail(name, "close failed while TX calls were active");
        ok = false;
    } else if (report.joined_threads != TX_CLOSE_THREADS) {
        fail(name, "one or more TX threads remained blocked after peer shutdown");
        ok = false;
    } else if (report.unexpected_errors != 0) {
        fail(name, "a blocking TX returned an unexpected error during close");
        ok = false;
    } else if (report.send_calls == 0 || report.bytes_sent == 0) {
        fail(name, "stress did not queue any traffic before close");
        ok = false;
    } else if (report.close_elapsed_ms > 2500U) {
        fail(name, "close did not complete within the bounded deadline");
        ok = false;
    }
    if (ok) {
        pass(name);
    }
    if (send_byte(control, CMD_ACK) != 0) {
        return -1;
    }
    return 0;
}

static int client_tx_close(const struct options *options, int control)
{
    struct tx_close_report report = {
        .magic = 0x5458434cU,
        .close_result = -2,
    };
    struct tx_close_call *calls = calloc(TX_CLOSE_THREADS, sizeof(*calls));
    struct close_call *close_call_data = calloc(1, sizeof(*close_call_data));
    pthread_t send_threads[TX_CLOSE_THREADS];
    pthread_t close_thread_id;
    bool send_created[TX_CLOSE_THREADS] = {false};
    bool close_created = false;
    bool all_joined = true;
    int send_buffer_size = 64 * 1024;
    int fd;

    if (calls == NULL || close_call_data == NULL) {
        perror("calloc");
        free(calls);
        free(close_call_data);
        return -1;
    }
    if (expect_byte(control, CMD_TX_CLOSE_CONNECT) != 0) {
        free(calls);
        free(close_call_data);
        return -1;
    }
    fd = connect_retry(options->bind_ip, options->server_ip, options->port + TEST_TX_CLOSE_PORT);
    if (fd < 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &send_buffer_size, sizeof(send_buffer_size)) != 0 ||
        expect_byte(control, CMD_TX_CLOSE_START) != 0) {
        perror("TX-close client setup");
        if (fd >= 0) {
            close(fd);
        }
        free(calls);
        free(close_call_data);
        return -1;
    }

    for (int index = 0; index < TX_CLOSE_THREADS; ++index) {
        calls[index].fd = fd;
        calls[index].result = -2;
        atomic_init(&calls[index].calls, 0U);
        atomic_init(&calls[index].bytes_sent, 0U);
        if (pthread_create(&send_threads[index], NULL, tx_close_thread, &calls[index]) != 0) {
            break;
        }
        send_created[index] = true;
    }
    sleep_ms(50);
    close_call_data->fd = fd;
    atomic_init(&close_call_data->result, -2);
    atomic_init(&close_call_data->error, 0);
    atomic_init(&close_call_data->elapsed_ms, 0U);
    if (pthread_create(&close_thread_id, NULL, close_thread, close_call_data) == 0) {
        close_created = true;
    } else {
        close(fd);
    }

    if (close_created) {
        int join_result = timed_join(close_thread_id, 3000);

        if (join_result == 0) {
            report.close_result =
                atomic_load_explicit(&close_call_data->result, memory_order_relaxed);
            report.close_error =
                atomic_load_explicit(&close_call_data->error, memory_order_relaxed);
            report.close_elapsed_ms =
                atomic_load_explicit(&close_call_data->elapsed_ms, memory_order_acquire);
        } else {
            pthread_detach(close_thread_id);
            all_joined = false;
        }
    }

    for (int index = 0; index < TX_CLOSE_THREADS; ++index) {
        if (!send_created[index]) {
            ++report.unexpected_errors;
            continue;
        }
        int join_result = timed_join(send_threads[index], 3000);

        if (join_result == 0) {
            ++report.joined_threads;
            if (calls[index].result != -1 || !tx_close_error_is_expected(calls[index].error)) {
                fprintf(stderr, "INFO tx-close thread %d unexpected: result=%d error=%d calls=%u\n",
                        index, calls[index].result, calls[index].error,
                        atomic_load_explicit(&calls[index].calls, memory_order_relaxed));
                fflush(stderr);
                ++report.unexpected_errors;
            }
        } else {
            pthread_detach(send_threads[index]);
            all_joined = false;
        }
        report.send_calls += atomic_load_explicit(&calls[index].calls, memory_order_relaxed);
        report.bytes_sent += atomic_load_explicit(&calls[index].bytes_sent, memory_order_relaxed);
    }

    if (send_all(control, &report, sizeof(report)) != 0 || expect_byte(control, CMD_ACK) != 0) {
        perror("TX-close client report");
        if (!all_joined) {
            fflush(stdout);
            fflush(stderr);
            _Exit(EXIT_FAILURE);
        }
        free(calls);
        free(close_call_data);
        return -1;
    }
    if (!all_joined) {
        fflush(stdout);
        fflush(stderr);
        _Exit(EXIT_FAILURE);
    }
    free(calls);
    free(close_call_data);
    return 0;
}

static int server_prefix_eof(const struct options *options, int control)
{
    const char *name = "recv returns a prefix then EOF after peer FIN";
    unsigned char buffer[64];
    ssize_t first;
    ssize_t second;
    int listener = make_listener(options->bind_ip, options->port + TEST_PREFIX_EOF_PORT);
    int fd;
    bool ok = true;

    if (listener < 0 || send_byte(control, CMD_PREFIX_EOF_CONNECT) != 0) {
        return -1;
    }
    fd = accept(listener, NULL, NULL);
    close(listener);
    if (fd < 0 || set_recv_timeout(fd, IO_TIMEOUT_SECONDS) != 0 ||
        expect_byte(control, CMD_PREFIX_EOF_SENT) != 0) {
        perror("prefix-eof setup");
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }

    memset(buffer, 0, sizeof(buffer));
    first = recv(fd, buffer, sizeof(buffer), 0);
    if (first != 4 || buffer[0] != 0x5a || buffer[1] != 0x5a || buffer[2] != 0x5a ||
        buffer[3] != 0x5a) {
        fail(name, "first recv did not return the 4-byte prefix");
        ok = false;
    }
    if (send_byte(control, CMD_ACK) != 0) {
        close(fd);
        return -1;
    }

    second = recv(fd, buffer, sizeof(buffer), 0);
    if (second != 0) {
        if (ok) {
            fail(name, "second recv did not report EOF after peer FIN");
        }
        ok = false;
    }
    if (ok) {
        pass(name);
    }
    if (send_byte(control, CMD_ACK) != 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int client_prefix_eof(const struct options *options, int control)
{
    static const unsigned char payload[4] = {0x5a, 0x5a, 0x5a, 0x5a};
    int fd;

    if (expect_byte(control, CMD_PREFIX_EOF_CONNECT) != 0) {
        return -1;
    }
    fd = connect_retry(options->bind_ip, options->server_ip, options->port + TEST_PREFIX_EOF_PORT);
    if (fd < 0 || send_all(fd, payload, sizeof(payload)) != 0 ||
        send_byte(control, CMD_PREFIX_EOF_SENT) != 0 || expect_byte(control, CMD_ACK) != 0) {
        perror("prefix-eof client");
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }
    close(fd);
    if (expect_byte(control, CMD_ACK) != 0) {
        return -1;
    }
    return 0;
}

static int server_rcvtimeo_partial(const struct options *options, int control)
{
    const char *name = "R2C MSG_WAITALL timeout leaves its partial prefix queued";
    unsigned char buffer[8];
    static const unsigned char payload[4] = {0x5a, 0x5a, 0x5a, 0x5a};
    ssize_t first_result;
    ssize_t second_result;
    int first_error;
    int second_error;
    uint64_t start;
    uint64_t elapsed;
    int listener = make_listener(options->bind_ip, options->port + TEST_RCVTIMEO_PARTIAL_PORT);
    int fd;
    bool ok = true;

    if (listener < 0 || send_byte(control, CMD_RCVTIMEO_PARTIAL_CONNECT) != 0) {
        return -1;
    }
    fd = accept(listener, NULL, NULL);
    close(listener);
    if (fd < 0 || set_recv_timeout_ms(fd, SHORT_TIMEOUT_MS) != 0 ||
        expect_byte(control, CMD_RCVTIMEO_PARTIAL_SENT) != 0) {
        perror("rcvtimeo-partial setup");
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }

    if (wait_until_readable(fd, 1000) != 0) {
        fail(name, "the 4-byte prefix was not readable before the timed receive");
        send_byte(control, CMD_ACK);
        close(fd);
        return 0;
    }

    memset(buffer, 0, sizeof(buffer));
    start = monotonic_ms();
    errno = 0;
    first_result = recv(fd, buffer, sizeof(buffer), MSG_WAITALL);
    first_error = first_result < 0 ? errno : 0;
    elapsed = monotonic_ms() - start;
    errno = 0;
    second_result = recv(fd, buffer, sizeof(payload), MSG_DONTWAIT);
    second_error = second_result < 0 ? errno : 0;

    printf("OBSERVE case=rcvtimeo-partial first_result=%zd first_errno=%d elapsed_ms=%" PRIu64
           " second_result=%zd second_errno=%d\n",
           first_result, first_error, elapsed, second_result, second_error);
    fflush(stdout);

    if (first_result != -1 || (first_error != EAGAIN && first_error != EWOULDBLOCK)) {
        fail(name, "the first MSG_WAITALL did not return -1/EAGAIN at the deadline");
        ok = false;
    } else if (elapsed < SHORT_TIMEOUT_MS - 50U || elapsed >= 2000U) {
        fail(name, "the first MSG_WAITALL elapsed outside the timeout tolerance");
        ok = false;
    } else if (second_result != (ssize_t)sizeof(payload) ||
               memcmp(buffer, payload, sizeof(payload)) != 0) {
        fail(name, "the second nonblocking recv did not obtain the queued prefix");
        ok = false;
    }
    if (ok) {
        pass(name);
    }
    if (send_byte(control, CMD_ACK) != 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int client_rcvtimeo_partial(const struct options *options, int control)
{
    static const unsigned char payload[4] = {0x5a, 0x5a, 0x5a, 0x5a};
    int fd;

    if (expect_byte(control, CMD_RCVTIMEO_PARTIAL_CONNECT) != 0) {
        return -1;
    }
    fd = connect_retry(options->bind_ip, options->server_ip,
                       options->port + TEST_RCVTIMEO_PARTIAL_PORT);
    if (fd < 0 || send_all(fd, payload, sizeof(payload)) != 0 ||
        send_byte(control, CMD_RCVTIMEO_PARTIAL_SENT) != 0 || expect_byte(control, CMD_ACK) != 0) {
        perror("rcvtimeo-partial client");
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }
    close(fd);
    return 0;
}

static int server_dontwait_progress(const struct options *options, int control)
{
    const char *name = "MSG_DONTWAIT|MSG_WAITALL returns available progress promptly";
    unsigned char buffer[8];
    ssize_t result;
    int listener = make_listener(options->bind_ip, options->port + TEST_DONTWAIT_PROGRESS_PORT);
    int fd;
    bool ok = true;

    if (listener < 0 || send_byte(control, CMD_DONTWAIT_CONNECT) != 0) {
        return -1;
    }
    fd = accept(listener, NULL, NULL);
    close(listener);
    if (fd < 0 || expect_byte(control, CMD_DONTWAIT_SENT) != 0) {
        perror("dontwait-progress setup");
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }

    /* The client signalled after its send returned; settle so the 4 bytes are queued. */
    sleep_ms(100);
    memset(buffer, 0, sizeof(buffer));
    errno = 0;
    result = recv(fd, buffer, sizeof(buffer), MSG_WAITALL | MSG_DONTWAIT);
    if (result != 4) {
        fail(name, "recv did not return the available 4-byte progress");
        ok = false;
    }
    if (ok) {
        pass(name);
    }
    if (send_byte(control, CMD_ACK) != 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int client_dontwait_progress(const struct options *options, int control)
{
    static const unsigned char payload[4] = {0x5a, 0x5a, 0x5a, 0x5a};
    int fd;

    if (expect_byte(control, CMD_DONTWAIT_CONNECT) != 0) {
        return -1;
    }
    fd = connect_retry(options->bind_ip, options->server_ip,
                       options->port + TEST_DONTWAIT_PROGRESS_PORT);
    if (fd < 0 || send_all(fd, payload, sizeof(payload)) != 0 ||
        send_byte(control, CMD_DONTWAIT_SENT) != 0 || expect_byte(control, CMD_ACK) != 0) {
        perror("dontwait-progress client");
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }
    close(fd);
    return 0;
}

static int server_peek_waitall(const struct options *options, int control)
{
    static const unsigned char payload[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    const char *name = "R2C MSG_PEEK|MSG_WAITALL returns the held first fragment without consuming";
    unsigned char peeked[8];
    unsigned char first_consumed[4];
    unsigned char second_consumed[4];
    ssize_t peek_result;
    ssize_t first_read_result;
    ssize_t second_read_result;
    int peek_error;
    uint64_t start;
    uint64_t elapsed;
    int listener = make_listener(options->bind_ip, options->port + TEST_PEEK_WAITALL_PORT);
    int fd;
    bool ok = true;

    if (listener < 0 || send_byte(control, CMD_PEEK_WAITALL_CONNECT) != 0) {
        return -1;
    }
    fd = accept(listener, NULL, NULL);
    close(listener);
    if (fd < 0 || set_recv_timeout_ms(fd, PEEK_WAITALL_TIMEOUT_MS) != 0 ||
        expect_byte(control, CMD_PEEK_WAITALL_FIRST_SENT) != 0) {
        perror("peek-waitall setup");
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }

    if (wait_until_readable(fd, 1000) != 0) {
        fail(name, "the held first fragment was not readable before MSG_PEEK");
        if (send_byte(control, CMD_PEEK_WAITALL_PEEK_RETURNED) == 0 &&
            expect_byte(control, CMD_PEEK_WAITALL_SECOND_SENT) == 0) {
            send_byte(control, CMD_ACK);
        }
        close(fd);
        return 0;
    }

    memset(peeked, 0, sizeof(peeked));
    start = monotonic_ms();
    errno = 0;
    peek_result = recv(fd, peeked, sizeof(peeked), MSG_PEEK | MSG_WAITALL);
    peek_error = peek_result < 0 ? errno : 0;
    elapsed = monotonic_ms() - start;

    memset(first_consumed, 0, sizeof(first_consumed));
    first_read_result = recv(fd, first_consumed, sizeof(first_consumed), MSG_WAITALL);
    if (send_byte(control, CMD_PEEK_WAITALL_PEEK_RETURNED) != 0 ||
        expect_byte(control, CMD_PEEK_WAITALL_SECOND_SENT) != 0) {
        perror("peek-waitall held-fragment coordination");
        close(fd);
        return -1;
    }
    memset(second_consumed, 0, sizeof(second_consumed));
    if (wait_until_readable(fd, 1000) != 0) {
        second_read_result = -1;
    } else {
        second_read_result = recv(fd, second_consumed, sizeof(second_consumed), MSG_WAITALL);
    }

    printf("OBSERVE case=peek-waitall peek_result=%zd peek_errno=%d elapsed_ms=%" PRIu64
           " first_read=%zd second_read=%zd\n",
           peek_result, peek_error, elapsed, first_read_result, second_read_result);
    fflush(stdout);

    if (peek_result != 4 || memcmp(peeked, payload, 4) != 0) {
        fail(name, "MSG_PEEK|MSG_WAITALL did not return only the held first fragment");
        ok = false;
    } else if (elapsed >= PEEK_WAITALL_PROMPT_MAX_MS) {
        fail(name, "MSG_PEEK|MSG_WAITALL waited for its receive timeout");
        ok = false;
    } else if (first_read_result != 4 || memcmp(first_consumed, payload, 4) != 0) {
        if (ok) {
            fail(name, "ordinary recv did not obtain the peeked first fragment");
        }
        ok = false;
    } else if (second_read_result != 4 || memcmp(second_consumed, payload + 4, 4) != 0) {
        fail(name, "ordinary recv did not obtain the released second fragment");
        ok = false;
    }
    if (ok) {
        pass(name);
    }
    if (send_byte(control, CMD_ACK) != 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int client_peek_waitall(const struct options *options, int control)
{
    static const unsigned char payload[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    int fd;

    if (expect_byte(control, CMD_PEEK_WAITALL_CONNECT) != 0) {
        return -1;
    }
    fd =
        connect_retry(options->bind_ip, options->server_ip, options->port + TEST_PEEK_WAITALL_PORT);
    if (fd < 0 || send_all(fd, payload, 4) != 0 ||
        send_byte(control, CMD_PEEK_WAITALL_FIRST_SENT) != 0) {
        perror("peek-waitall first fragment");
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }
    if (expect_byte(control, CMD_PEEK_WAITALL_PEEK_RETURNED) != 0 ||
        send_all(fd, payload + 4, 4) != 0 ||
        send_byte(control, CMD_PEEK_WAITALL_SECOND_SENT) != 0 ||
        expect_byte(control, CMD_ACK) != 0) {
        perror("peek-waitall second fragment");
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

struct multi_writer_call {
    int fd;
    unsigned char fill;
    int result;
    int error;
};

static void *multi_writer_thread(void *opaque)
{
    struct multi_writer_call *call = opaque;
    unsigned char *buffer = malloc(MULTI_WRITER_CHUNK);
    int error = 0;
    ssize_t sent;

    if (buffer == NULL) {
        call->result = -1;
        call->error = ENOMEM;
        return NULL;
    }
    memset(buffer, call->fill, MULTI_WRITER_CHUNK);
    sent = send_all_count(call->fd, buffer, MULTI_WRITER_CHUNK, &error);
    call->result = sent == MULTI_WRITER_CHUNK ? 0 : -1;
    call->error = error;
    free(buffer);
    return NULL;
}

static int server_multi_writer(const struct options *options, int control)
{
    const char *name = "multiple concurrent writers conserve every byte";
    const uint64_t total = (uint64_t)MULTI_WRITER_THREADS * MULTI_WRITER_CHUNK;
    unsigned char *buffer = malloc(64 * 1024);
    uint64_t histogram[MULTI_WRITER_THREADS] = {0};
    uint64_t received = 0;
    int listener = make_listener(options->bind_ip, options->port + TEST_MULTI_WRITER_PORT);
    int fd;
    bool ok = true;

    if (buffer == NULL || listener < 0 || send_byte(control, CMD_MULTI_WRITER_CONNECT) != 0) {
        free(buffer);
        if (listener >= 0) {
            close(listener);
        }
        return -1;
    }
    fd = accept(listener, NULL, NULL);
    close(listener);
    if (fd < 0 || set_recv_timeout(fd, IO_TIMEOUT_SECONDS) != 0) {
        perror("multi-writer setup");
        free(buffer);
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }

    while (received < total) {
        ssize_t result = recv(fd, buffer, 64 * 1024, 0);

        if (result > 0) {
            for (ssize_t index = 0; index < result; ++index) {
                unsigned char value = buffer[index];

                if (value < 0x40 || value >= 0x40 + MULTI_WRITER_THREADS) {
                    if (ok) {
                        fail(name, "received a byte outside the per-thread fill range");
                    }
                    ok = false;
                } else {
                    ++histogram[value - 0x40];
                }
            }
            received += (uint64_t)result;
            continue;
        }
        if (result < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    if (expect_byte(control, CMD_MULTI_WRITER_SENT) != 0) {
        free(buffer);
        close(fd);
        return -1;
    }
    if (received != total) {
        if (ok) {
            fail(name, "did not receive exactly THREADS*CHUNK bytes");
        }
        ok = false;
    }
    for (int index = 0; index < MULTI_WRITER_THREADS; ++index) {
        if (histogram[index] != MULTI_WRITER_CHUNK) {
            if (ok) {
                fail(name, "a per-thread byte count did not conserve to CHUNK");
            }
            ok = false;
        }
    }
    if (ok) {
        pass(name);
    }
    free(buffer);
    if (send_byte(control, CMD_ACK) != 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int client_multi_writer(const struct options *options, int control)
{
    struct multi_writer_call calls[MULTI_WRITER_THREADS];
    pthread_t threads[MULTI_WRITER_THREADS];
    bool created[MULTI_WRITER_THREADS] = {false};
    int fd;
    int rc = 0;

    if (expect_byte(control, CMD_MULTI_WRITER_CONNECT) != 0) {
        return -1;
    }
    fd =
        connect_retry(options->bind_ip, options->server_ip, options->port + TEST_MULTI_WRITER_PORT);
    if (fd < 0) {
        return -1;
    }
    for (int index = 0; index < MULTI_WRITER_THREADS; ++index) {
        calls[index].fd = fd;
        calls[index].fill = (unsigned char)(0x40 + index);
        calls[index].result = -2;
        calls[index].error = 0;
        if (pthread_create(&threads[index], NULL, multi_writer_thread, &calls[index]) != 0) {
            rc = -1;
            break;
        }
        created[index] = true;
    }
    for (int index = 0; index < MULTI_WRITER_THREADS; ++index) {
        if (created[index]) {
            pthread_join(threads[index], NULL);
            if (calls[index].result != 0) {
                rc = -1;
            }
        }
    }
    if (rc != 0 || send_byte(control, CMD_MULTI_WRITER_SENT) != 0 ||
        expect_byte(control, CMD_ACK) != 0) {
        perror("multi-writer client");
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int server_accept_inherit(const struct options *options, int control)
{
    const char *name = "plain accept returns a blocking child from a nonblocking listener";
    int listener = make_listener(options->bind_ip, options->port + TEST_ACCEPT_INHERIT_PORT);
    int accepted = -1;
    int flags;
    uint64_t deadline;
    bool ok = true;

    if (listener < 0) {
        fail(name, "listener setup failed");
        return -1;
    }
    flags = fcntl(listener, F_GETFL, 0);
    if (flags < 0 || fcntl(listener, F_SETFL, flags | O_NONBLOCK) != 0) {
        fail(name, "could not set listener O_NONBLOCK");
        close(listener);
        return -1;
    }
    if (send_byte(control, CMD_ACCEPT_INHERIT_CONNECT) != 0) {
        close(listener);
        return -1;
    }

    deadline = monotonic_ms() + 2000U;
    do {
        accepted = accept(listener, NULL, NULL);
        if (accepted >= 0) {
            break;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            break;
        }
        sleep_ms(10);
    } while (monotonic_ms() < deadline);

    if (accepted < 0) {
        fail(name, "accept did not return a connection within the deadline");
        ok = false;
    } else {
        int accepted_flags = fcntl(accepted, F_GETFL, 0);

        if (accepted_flags < 0 || (accepted_flags & O_NONBLOCK) != 0) {
            fail(name, "accepted child inherited O_NONBLOCK from the listener");
            ok = false;
        }
        close(accepted);
    }
    if (ok) {
        pass(name);
    }
    close(listener);
    if (send_byte(control, CMD_ACK) != 0) {
        return -1;
    }
    return 0;
}

static int client_accept_inherit(const struct options *options, int control)
{
    int fd;

    if (expect_byte(control, CMD_ACCEPT_INHERIT_CONNECT) != 0) {
        return -1;
    }
    fd = connect_retry(options->bind_ip, options->server_ip,
                       options->port + TEST_ACCEPT_INHERIT_PORT);
    if (fd < 0 || expect_byte(control, CMD_ACK) != 0) {
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }
    close(fd);
    return 0;
}

static int server_accept4_nonblock(const struct options *options, int control)
{
    const char *name = "accept4(SOCK_NONBLOCK) sets only the child nonblocking";
    int listener = make_listener(options->bind_ip, options->port + TEST_ACCEPT4_NONBLOCK_PORT);
    int accepted;
    int listener_flags;
    int accepted_flags;
    bool ok = true;

    if (listener < 0) {
        fail(name, "listener setup failed");
        return -1;
    }
    if (send_byte(control, CMD_ACCEPT4_NONBLOCK_CONNECT) != 0) {
        close(listener);
        return -1;
    }
    accepted = accept4(listener, NULL, NULL, SOCK_NONBLOCK);
    if (accepted < 0) {
        fail(name, "accept4(SOCK_NONBLOCK) failed");
        close(listener);
        return -1;
    }
    accepted_flags = fcntl(accepted, F_GETFL, 0);
    if (accepted_flags < 0 || (accepted_flags & O_NONBLOCK) == 0) {
        fail(name, "accepted child is not O_NONBLOCK");
        ok = false;
    }
    listener_flags = fcntl(listener, F_GETFL, 0);
    if (listener_flags < 0 || (listener_flags & O_NONBLOCK) != 0) {
        if (ok) {
            fail(name, "listener became O_NONBLOCK after accept4");
        }
        ok = false;
    }
    if (ok) {
        pass(name);
    }
    close(accepted);
    close(listener);
    if (send_byte(control, CMD_ACK) != 0) {
        return -1;
    }
    return 0;
}

static int client_accept4_nonblock(const struct options *options, int control)
{
    int fd;

    if (expect_byte(control, CMD_ACCEPT4_NONBLOCK_CONNECT) != 0) {
        return -1;
    }
    fd = connect_retry(options->bind_ip, options->server_ip,
                       options->port + TEST_ACCEPT4_NONBLOCK_PORT);
    if (fd < 0 || expect_byte(control, CMD_ACK) != 0) {
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }
    close(fd);
    return 0;
}

static int poll_readable(int fd, int timeout_ms)
{
    struct pollfd pfd = {.fd = fd, .events = POLLIN, .revents = 0};
    int result = poll(&pfd, 1, timeout_ms);

    if (result < 0) {
        return -1;
    }
    return (result > 0 && (pfd.revents & POLLIN) != 0) ? 1 : 0;
}

static int select_readable(int fd, int timeout_ms)
{
    fd_set readfds;
    struct timeval timeout = {
        .tv_sec = timeout_ms / 1000,
        .tv_usec = (suseconds_t)(timeout_ms % 1000) * 1000,
    };
    int result;

    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);
    result = select(fd + 1, &readfds, NULL, NULL, &timeout);
    if (result < 0) {
        return -1;
    }
    return (result > 0 && FD_ISSET(fd, &readfds)) ? 1 : 0;
}

static int epoll_readable(int epfd, int fd, int timeout_ms)
{
    struct epoll_event event = {0};
    int result = epoll_wait(epfd, &event, 1, timeout_ms);

    if (result < 0) {
        return -1;
    }
    return (result > 0 && event.data.fd == fd && (event.events & EPOLLIN) != 0) ? 1 : 0;
}

static int server_readiness(const struct options *options, int control)
{
    const char *name = "poll, select and epoll readiness match the kernel";
    struct epoll_event registration = {.events = EPOLLIN};
    unsigned char byte = 0;
    ssize_t got;
    int listener = make_listener(options->bind_ip, options->port + TEST_READINESS_PORT);
    int fd;
    int epfd = -1;
    bool ok = true;

    if (listener < 0 || send_byte(control, CMD_READINESS_CONNECT) != 0) {
        return -1;
    }
    fd = accept(listener, NULL, NULL);
    close(listener);
    if (fd < 0) {
        perror("readiness accept");
        return -1;
    }
    epfd = epoll_create1(0);
    registration.data.fd = fd;
    if (epfd < 0 || epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &registration) != 0) {
        perror("readiness epoll setup");
        if (epfd >= 0) {
            close(epfd);
        }
        close(fd);
        return -1;
    }

    /* Before any data: all three must report not-ready (timeout). */
    if (poll_readable(fd, 100) != 0 || select_readable(fd, 100) != 0 ||
        epoll_readable(epfd, fd, 100) != 0) {
        fail(name, "a mechanism reported readable before any data arrived");
        ok = false;
    }

    if (send_byte(control, CMD_READINESS_SEND) != 0) {
        close(epfd);
        close(fd);
        return -1;
    }

    /* After 1 byte arrives: all three must report readable. */
    if (poll_readable(fd, 1000) != 1) {
        if (ok) {
            fail(name, "poll did not report readable after the byte arrived");
        }
        ok = false;
    }
    if (select_readable(fd, 1000) != 1 || epoll_readable(epfd, fd, 1000) != 1) {
        if (ok) {
            fail(name, "select or epoll did not report readable after the byte arrived");
        }
        ok = false;
    }
    got = recv(fd, &byte, sizeof(byte), 0);
    if (got != 1) {
        if (ok) {
            fail(name, "recv did not consume the single byte");
        }
        ok = false;
    }

    /* After peer FIN: EOF is a readable condition for all three. */
    if (poll_readable(fd, 1000) != 1 || select_readable(fd, 1000) != 1 ||
        epoll_readable(epfd, fd, 1000) != 1) {
        if (ok) {
            fail(name, "a mechanism did not report readable at EOF after peer FIN");
        }
        ok = false;
    }
    if (ok) {
        pass(name);
    }
    close(epfd);
    close(fd);
    if (send_byte(control, CMD_ACK) != 0) {
        return -1;
    }
    return 0;
}

static int client_readiness(const struct options *options, int control)
{
    const unsigned char byte = 0x5a;
    int fd;

    if (expect_byte(control, CMD_READINESS_CONNECT) != 0) {
        return -1;
    }
    fd = connect_retry(options->bind_ip, options->server_ip, options->port + TEST_READINESS_PORT);
    if (fd < 0 || expect_byte(control, CMD_READINESS_SEND) != 0 ||
        send_all(fd, &byte, sizeof(byte)) != 0) {
        perror("readiness client");
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }
    close(fd);
    if (expect_byte(control, CMD_ACK) != 0) {
        return -1;
    }
    return 0;
}

static int accept_pending_connection(int listener)
{
    const uint64_t deadline = monotonic_ms() + 1000U;
    const int original_flags = fcntl(listener, F_GETFL, 0);
    int accepted = -1;

    if (original_flags < 0 || fcntl(listener, F_SETFL, original_flags | O_NONBLOCK) != 0) {
        return -1;
    }
    do {
        accepted = accept(listener, NULL, NULL);
        if (accepted >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
            break;
        }
        sleep_ms(1);
    } while (monotonic_ms() < deadline);
    (void)fcntl(listener, F_SETFL, original_flags);
    return accepted;
}

static void observe_signal_probe(const char *case_name, const char *syscall_name, bool restart,
                                 ssize_t result, int error, bool completed_after_peer_progress)
{
    printf("OBSERVE case=%s syscall=%s sa_restart=%d result=%zd errno=%d "
           "completed_after_peer_progress=%d\n",
           case_name, syscall_name, restart ? 1 : 0, result, error,
           completed_after_peer_progress ? 1 : 0);
    fflush(stdout);
}

static bool join_probe_after_failure(pthread_t thread, int fd)
{
    (void)shutdown(fd, SHUT_RDWR);
    if (timed_join(thread, 1000) == 0) {
        return true;
    }
    (void)pthread_cancel(thread);
    if (timed_join(thread, 1000) == 0) {
        return true;
    }
    (void)pthread_detach(thread);
    return false;
}

static int server_signal_accept_probe(const struct options *options, int control, bool restart,
                                      uint16_t port_offset, const char *case_name)
{
    struct signal_probe_call *call = calloc(1, sizeof(*call));
    struct sigaction old_action;
    int signal_pipe[2] = {-1, -1};
    pthread_t thread;
    bool thread_created = false;
    bool thread_joined = false;
    bool joined_before_progress = false;
    bool peer_connected = false;
    bool handler_observed = false;
    bool safe_result = false;
    int listener = make_listener(options->bind_ip, options->port + port_offset);

    if (call == NULL || listener < 0 ||
        setup_directed_signal(restart, signal_pipe, &old_action) != 0) {
        perror("signal accept probe setup");
        free(call);
        if (listener >= 0) {
            close(listener);
        }
        return -1;
    }

    call->fd = listener;
    call->is_accept = true;
    call->result = -2;
    atomic_init(&call->entered, false);
    if (pthread_create(&thread, NULL, signal_probe_thread, call) == 0) {
        thread_created = true;
    } else {
        fail(case_name, "could not create the blocking accept thread");
    }

    if (thread_created && wait_for_probe_entry(call) == 0) {
        int signal_result;

        sleep_ms(50);
        signal_result = pthread_kill(thread, SIGUSR1);
        if (signal_result == 0 && wait_for_directed_signal(signal_pipe[0]) == 0) {
            handler_observed = true;
        } else {
            fail(case_name, "the directed signal was not observed by the target thread");
        }
        if (handler_observed) {
            const int join_result = timed_join(thread, 250);

            if (join_result == 0) {
                thread_joined = true;
                joined_before_progress = true;
            } else if (join_result != ETIMEDOUT) {
                fail(case_name, "pthread_timedjoin_np failed during the signal observation window");
            }
        }
    } else if (thread_created) {
        fail(case_name, "the blocking accept thread did not enter its syscall");
    }

    if (send_byte(control, CMD_SIGNAL_ACCEPT_PROGRESS) == 0 &&
        expect_byte(control, CMD_SIGNAL_ACCEPT_CONNECTED) == 0) {
        peer_connected = true;
    } else {
        fail(case_name, "peer progress coordination failed");
    }

    if (thread_created && !thread_joined) {
        const int join_result = timed_join(thread, 3000);

        if (join_result == 0) {
            thread_joined = true;
        } else {
            fail(case_name, "blocking accept did not complete after bounded peer progress");
            thread_joined = join_probe_after_failure(thread, listener);
        }
    }

    if (thread_joined && call->result >= 0) {
        close((int)call->result);
    } else if (peer_connected) {
        const int cleanup_fd = accept_pending_connection(listener);

        if (cleanup_fd >= 0) {
            close(cleanup_fd);
        } else {
            fail(case_name, "could not consume the peer connection after interrupted accept");
        }
    }

    if (thread_joined) {
        const bool completed_after_peer_progress = !joined_before_progress;

        safe_result = (call->result == -1 && call->error == EINTR) ||
            (call->result >= 0 && completed_after_peer_progress);
        observe_signal_probe(case_name, "accept", restart, call->result, call->error,
                             completed_after_peer_progress);
    } else {
        observe_signal_probe(case_name, "accept", restart, -2, ETIMEDOUT, false);
    }
    if (!safe_result) {
        fail(case_name, "accept returned an unsafe result for the observed signal/progress phase");
    } else {
        pass(case_name);
    }

    (void)send_byte(control, CMD_ACK);
    teardown_directed_signal(signal_pipe, &old_action);
    close(listener);
    if (thread_joined) {
        free(call);
    }
    return 0;
}

static int client_signal_accept_probe(const struct options *options, int control,
                                      uint16_t port_offset)
{
    int fd;

    if (expect_byte(control, CMD_SIGNAL_ACCEPT_PROGRESS) != 0) {
        return -1;
    }
    fd = connect_retry(options->bind_ip, options->server_ip, options->port + port_offset);
    if (fd < 0 || send_byte(control, CMD_SIGNAL_ACCEPT_CONNECTED) != 0 ||
        expect_byte(control, CMD_ACK) != 0) {
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }
    close(fd);
    return 0;
}

static int server_signal_recv_probe(const struct options *options, int control, bool restart,
                                    uint16_t port_offset, const char *case_name)
{
    static const unsigned char expected_data = 0x6d;
    struct signal_probe_call *call = calloc(1, sizeof(*call));
    struct sigaction old_action;
    int signal_pipe[2] = {-1, -1};
    pthread_t thread;
    bool thread_created = false;
    bool thread_joined = false;
    bool joined_before_progress = false;
    bool handler_observed = false;
    bool safe_result = false;
    int listener = make_listener(options->bind_ip, options->port + port_offset);
    int fd = -1;

    if (call == NULL || listener < 0 || send_byte(control, CMD_SIGNAL_RECV_CONNECT) != 0) {
        free(call);
        if (listener >= 0) {
            close(listener);
        }
        return -1;
    }
    fd = accept(listener, NULL, NULL);
    close(listener);
    if (fd < 0 || setup_directed_signal(restart, signal_pipe, &old_action) != 0) {
        perror("signal recv probe setup");
        free(call);
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }

    call->fd = fd;
    call->result = -2;
    atomic_init(&call->entered, false);
    if (pthread_create(&thread, NULL, signal_probe_thread, call) == 0) {
        thread_created = true;
    } else {
        fail(case_name, "could not create the blocking recv thread");
    }

    if (thread_created && wait_for_probe_entry(call) == 0) {
        int signal_result;

        sleep_ms(50);
        signal_result = pthread_kill(thread, SIGUSR1);
        if (signal_result == 0 && wait_for_directed_signal(signal_pipe[0]) == 0) {
            handler_observed = true;
        } else {
            fail(case_name, "the directed signal was not observed by the target thread");
        }
        if (handler_observed) {
            const int join_result = timed_join(thread, 250);

            if (join_result == 0) {
                thread_joined = true;
                joined_before_progress = true;
            } else if (join_result != ETIMEDOUT) {
                fail(case_name, "pthread_timedjoin_np failed during the signal observation window");
            }
        }
    } else if (thread_created) {
        fail(case_name, "the blocking recv thread did not enter its syscall");
    }

    if (send_byte(control, CMD_SIGNAL_RECV_PROGRESS) != 0) {
        fail(case_name, "peer progress coordination failed");
    }
    if (thread_created && !thread_joined) {
        const int join_result = timed_join(thread, 3000);

        if (join_result == 0) {
            thread_joined = true;
        } else {
            fail(case_name, "blocking recv did not complete after bounded peer progress");
            thread_joined = join_probe_after_failure(thread, fd);
        }
    }

    if (thread_joined && call->result == -1 && call->error == EINTR) {
        unsigned char cleanup_data = 0U;

        if (set_recv_timeout_ms(fd, 1000U) != 0 ||
            recv(fd, &cleanup_data, sizeof(cleanup_data), 0) != (ssize_t)sizeof(cleanup_data) ||
            cleanup_data != expected_data) {
            fail(case_name, "could not consume peer data after interrupted recv");
        }
    }

    if (thread_joined) {
        const bool completed_after_peer_progress = !joined_before_progress;

        safe_result = (call->result == -1 && call->error == EINTR) ||
            (call->result == 1 && call->error == 0 && call->data == expected_data &&
             completed_after_peer_progress);
        observe_signal_probe(case_name, "recv", restart, call->result, call->error,
                             completed_after_peer_progress);
    } else {
        observe_signal_probe(case_name, "recv", restart, -2, ETIMEDOUT, false);
    }
    if (!safe_result) {
        fail(case_name, "recv returned an unsafe result for the observed signal/progress phase");
    } else {
        pass(case_name);
    }

    (void)send_byte(control, CMD_ACK);
    teardown_directed_signal(signal_pipe, &old_action);
    close(fd);
    if (thread_joined) {
        free(call);
    }
    return 0;
}

static int client_signal_recv_probe(const struct options *options, int control,
                                    uint16_t port_offset)
{
    static const unsigned char data = 0x6d;
    int fd;

    if (expect_byte(control, CMD_SIGNAL_RECV_CONNECT) != 0) {
        return -1;
    }
    fd = connect_retry(options->bind_ip, options->server_ip, options->port + port_offset);
    if (fd < 0 || expect_byte(control, CMD_SIGNAL_RECV_PROGRESS) != 0 ||
        send_all(fd, &data, sizeof(data)) != 0 || expect_byte(control, CMD_ACK) != 0) {
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }
    close(fd);
    return 0;
}

static int server_signal_accept(const struct options *options, int control)
{
    return server_signal_accept_probe(options, control, false, TEST_SIGNAL_ACCEPT_PORT,
                                      "signal-accept");
}

static int client_signal_accept(const struct options *options, int control)
{
    return client_signal_accept_probe(options, control, TEST_SIGNAL_ACCEPT_PORT);
}

static int server_signal_accept_restart(const struct options *options, int control)
{
    return server_signal_accept_probe(options, control, true, TEST_SIGNAL_ACCEPT_RESTART_PORT,
                                      "signal-accept-restart");
}

static int client_signal_accept_restart(const struct options *options, int control)
{
    return client_signal_accept_probe(options, control, TEST_SIGNAL_ACCEPT_RESTART_PORT);
}

static int server_signal_recv(const struct options *options, int control)
{
    return server_signal_recv_probe(options, control, false, TEST_SIGNAL_RECV_PORT, "signal-recv");
}

static int client_signal_recv(const struct options *options, int control)
{
    return client_signal_recv_probe(options, control, TEST_SIGNAL_RECV_PORT);
}

static int server_signal_recv_restart(const struct options *options, int control)
{
    return server_signal_recv_probe(options, control, true, TEST_SIGNAL_RECV_RESTART_PORT,
                                    "signal-recv-restart");
}

static int client_signal_recv_restart(const struct options *options, int control)
{
    return client_signal_recv_probe(options, control, TEST_SIGNAL_RECV_RESTART_PORT);
}

static int server_cancel_accept(const struct options *options, int control)
{
    const char *name = "cancel-accept";
    struct cancellation_call call = {
        .fd = -1,
        .operation = CANCEL_OPERATION_ACCEPT,
        .result = -2,
    };
    struct accept_call fresh_call = {.fd = -1, .result = -2};
    pthread_t canceled_thread;
    pthread_t fresh_thread;
    int listener = make_listener(options->bind_ip, options->port + TEST_CANCEL_ACCEPT_PORT);
    bool ok = true;

    if (listener < 0) {
        return -1;
    }
    call.fd = listener;
    atomic_init(&call.entered, false);
    atomic_init(&call.returned, false);
    if (pthread_create(&canceled_thread, NULL, cancellation_thread, &call) != 0) {
        close(listener);
        return -1;
    }
    ok = cancel_blocked_call(name, "accept", canceled_thread, &call);

    fresh_call.fd = listener;
    if (send_byte(control, CMD_CANCEL_ACCEPT_CONNECT) != 0 ||
        pthread_create(&fresh_thread, NULL, accept_thread, &fresh_call) != 0) {
        close(listener);
        return -1;
    }
    const int join_result = timed_join(fresh_thread, 3000U);

    if (join_result == ETIMEDOUT) {
        fail(name, "the listener lock remained stranded after cancellation");
        fflush(stdout);
        fflush(stderr);
        _Exit(EXIT_FAILURE);
    }
    if (join_result != 0 || fresh_call.result < 0) {
        fail(name, "a fresh accept failed after cancellation");
        ok = false;
    } else {
        close(fresh_call.result);
    }
    if (ok) {
        pass(name);
    }
    close(listener);
    return send_byte(control, CMD_ACK);
}

static int client_cancel_accept(const struct options *options, int control)
{
    int fd;

    if (expect_byte(control, CMD_CANCEL_ACCEPT_CONNECT) != 0) {
        return -1;
    }
    fd = connect_retry(options->bind_ip, options->server_ip,
                       options->port + TEST_CANCEL_ACCEPT_PORT);
    if (fd < 0 || expect_byte(control, CMD_ACK) != 0) {
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }
    close(fd);
    return 0;
}

static int server_cancel_recv(const struct options *options, int control)
{
    static const unsigned char expected = 0xc7;
    const char *name = "cancel-recv";
    unsigned char canceled_byte = 0U;
    struct cancellation_call call = {
        .fd = -1,
        .operation = CANCEL_OPERATION_RECV,
        .buffer = &canceled_byte,
        .length = sizeof(canceled_byte),
        .result = -2,
    };
    struct recv_call fresh_call = {.fd = -1, .length = 1U, .result = -2};
    pthread_t canceled_thread;
    pthread_t fresh_thread;
    int listener = make_listener(options->bind_ip, options->port + TEST_CANCEL_RECV_PORT);
    int fd = -1;
    bool ok = true;

    if (listener < 0 || send_byte(control, CMD_CANCEL_RECV_CONNECT) != 0) {
        if (listener >= 0) {
            close(listener);
        }
        return -1;
    }
    fd = accept(listener, NULL, NULL);
    close(listener);
    if (fd < 0) {
        return -1;
    }
    call.fd = fd;
    atomic_init(&call.entered, false);
    atomic_init(&call.returned, false);
    if (pthread_create(&canceled_thread, NULL, cancellation_thread, &call) != 0) {
        close(fd);
        return -1;
    }
    ok = cancel_blocked_call(name, "recv", canceled_thread, &call);

    fresh_call.fd = fd;
    if (send_byte(control, CMD_CANCEL_RECV_SEND) != 0 ||
        pthread_create(&fresh_thread, NULL, recv_thread, &fresh_call) != 0) {
        close(fd);
        return -1;
    }
    const int join_result = timed_join(fresh_thread, 3000U);

    if (join_result == ETIMEDOUT) {
        fail(name, "the socket lock remained stranded after recv cancellation");
        fflush(stdout);
        fflush(stderr);
        _Exit(EXIT_FAILURE);
    }
    if (join_result != 0 || fresh_call.result != 1 || fresh_call.data[0] != expected) {
        fail(name, "a fresh recv failed after cancellation");
        ok = false;
    }
    if (ok) {
        pass(name);
    }
    close(fd);
    return send_byte(control, CMD_ACK);
}

static int client_cancel_recv(const struct options *options, int control)
{
    static const unsigned char data = 0xc7;
    int fd;

    if (expect_byte(control, CMD_CANCEL_RECV_CONNECT) != 0) {
        return -1;
    }
    fd = connect_retry(options->bind_ip, options->server_ip, options->port + TEST_CANCEL_RECV_PORT);
    if (fd < 0 || expect_byte(control, CMD_CANCEL_RECV_SEND) != 0 ||
        send_all(fd, &data, sizeof(data)) != 0 || expect_byte(control, CMD_ACK) != 0) {
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }
    close(fd);
    return 0;
}

static int server_cancel_send(const struct options *options, int control)
{
    static const unsigned char marker = 0xd9;
    const char *name = "cancel-send";
    struct cancel_send_report report;
    unsigned char buffer[64 * 1024];
    uint64_t received = 0U;
    unsigned char last_byte = 0U;
    int receive_buffer_size = 4 * 1024;
    int listener = make_listener_with_options(
        options->bind_ip, options->port + TEST_CANCEL_SEND_PORT, 8, receive_buffer_size);
    int fd;
    bool ok = true;

    if (listener < 0 || send_byte(control, CMD_CANCEL_SEND_CONNECT) != 0) {
        return -1;
    }
    fd = accept(listener, NULL, NULL);
    close(listener);
    if (fd < 0 || set_recv_timeout(fd, IO_TIMEOUT_SECONDS) != 0 ||
        send_byte(control, CMD_CANCEL_SEND_START) != 0 ||
        expect_byte(control, CMD_CANCEL_SEND_DRAIN) != 0) {
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }

    for (;;) {
        const ssize_t result = recv(fd, buffer, sizeof(buffer), 0);

        if (result > 0) {
            received += (uint64_t)result;
            last_byte = buffer[result - 1];
            continue;
        }
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result < 0) {
            fail(name, "the peer stream did not drain to EOF");
            ok = false;
        }
        break;
    }
    if (recv_all(control, &report, sizeof(report)) != 0) {
        close(fd);
        return -1;
    }

    printf("OBSERVE case=cancel-send cancel_result=%d prompt_join_result=%d "
           "final_join_result=%d canceled=%d returned=%d canceled_result=%d "
           "canceled_errno=%d follow_result=%d follow_errno=%d bytes_received=%" PRIu64
           " last_byte=0x%02x\n",
           report.cancel_result, report.prompt_join_result, report.final_join_result,
           report.canceled, report.returned, report.canceled_result, report.canceled_error,
           report.follow_result, report.follow_error, received, last_byte);
    fflush(stdout);
    if (report.magic != 0x43414e53U || report.cancel_result != 0 ||
        (report.prompt_join_result != 0 && report.prompt_join_result != ETIMEDOUT) ||
        report.final_join_result != 0 || ((report.canceled == 0) == (report.returned == 0))) {
        fail(name, "the blocked send did not reach a valid bounded terminal state");
        ok = false;
    } else if (report.follow_result != 1 || report.follow_error != 0 || received == 0U ||
               last_byte != marker) {
        fail(name, "the socket was not usable after send cancellation");
        ok = false;
    }
    if (ok) {
        pass(name);
    }
    close(fd);
    return send_byte(control, CMD_ACK);
}

static int client_cancel_send(const struct options *options, int control)
{
    static unsigned char marker = 0xd9;
    const char *name = "cancel-send";
    struct cancel_send_report report = {
        .magic = 0x43414e53U,
        .follow_result = -2,
        .canceled_send_length = SEND_BYTES,
    };
    struct cancellation_call canceled_call = {
        .fd = -1,
        .operation = CANCEL_OPERATION_SEND,
        .length = SEND_BYTES,
        .result = -2,
    };
    struct cancellation_call follow_call = {
        .fd = -1,
        .operation = CANCEL_OPERATION_SEND,
        .buffer = &marker,
        .length = sizeof(marker),
        .result = -2,
    };
    pthread_t canceled_thread;
    pthread_t follow_thread;
    void *canceled_thread_result = NULL;
    unsigned char *buffer = NULL;
    int send_buffer_size = 32 * 1024;
    int fd = -1;

    if (expect_byte(control, CMD_CANCEL_SEND_CONNECT) != 0) {
        return -1;
    }
    fd = connect_retry(options->bind_ip, options->server_ip, options->port + TEST_CANCEL_SEND_PORT);
    buffer = malloc(SEND_BYTES);
    if (fd < 0 || buffer == NULL ||
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &send_buffer_size, sizeof(send_buffer_size)) != 0 ||
        expect_byte(control, CMD_CANCEL_SEND_START) != 0) {
        free(buffer);
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }
    memset(buffer, 0x63, SEND_BYTES);
    canceled_call.fd = fd;
    canceled_call.buffer = buffer;
    atomic_init(&canceled_call.entered, false);
    atomic_init(&canceled_call.returned, false);
    if (pthread_create(&canceled_thread, NULL, cancellation_thread, &canceled_call) != 0) {
        free(buffer);
        close(fd);
        return -1;
    }
    if (wait_for_atomic_bool(&canceled_call.entered, 1000U) != 0) {
        fail(name, "the send cancellation target did not enter its syscall");
        fflush(stdout);
        fflush(stderr);
        _Exit(EXIT_FAILURE);
    }
    sleep_ms(100U);
    if (atomic_load_explicit(&canceled_call.returned, memory_order_acquire)) {
        (void)pthread_join(canceled_thread, &canceled_thread_result);
        fail(name, "the backpressured send returned before pthread_cancel");
        free(buffer);
        close(fd);
        return -1;
    }

    report.cancel_result = pthread_cancel(canceled_thread);
    report.prompt_join_result = report.cancel_result == 0
        ? timed_join_result(canceled_thread, 500U, &canceled_thread_result)
        : report.cancel_result;
    if (send_byte(control, CMD_CANCEL_SEND_DRAIN) != 0) {
        fflush(stdout);
        fflush(stderr);
        _Exit(EXIT_FAILURE);
    }
    report.final_join_result = report.prompt_join_result;
    if (report.prompt_join_result == ETIMEDOUT) {
        report.final_join_result =
            timed_join_result(canceled_thread, 5000U, &canceled_thread_result);
    }
    report.canceled =
        report.final_join_result == 0 && canceled_thread_result == PTHREAD_CANCELED ? 1 : 0;
    report.returned = atomic_load_explicit(&canceled_call.returned, memory_order_acquire) ? 1 : 0;
    report.canceled_result = (int32_t)canceled_call.result;
    report.canceled_error = canceled_call.error;
    printf("OBSERVE case=cancel-send-client cancel_result=%d prompt_join_result=%d "
           "final_join_result=%d canceled=%d returned=%d send_result=%d send_errno=%d\n",
           report.cancel_result, report.prompt_join_result, report.final_join_result,
           report.canceled, report.returned, report.canceled_result, report.canceled_error);
    fflush(stdout);
    if (report.cancel_result != 0 ||
        (report.prompt_join_result != 0 && report.prompt_join_result != ETIMEDOUT) ||
        report.final_join_result != 0 || ((report.canceled == 0) == (report.returned == 0))) {
        fail(name, "the canceled send did not terminate safely after peer progress");
        fflush(stdout);
        fflush(stderr);
        _Exit(EXIT_FAILURE);
    }

    if (report.prompt_join_result == ETIMEDOUT && report.final_join_result != 0) {
        free(buffer);
        close(fd);
        return -1;
    }
    follow_call.fd = fd;
    atomic_init(&follow_call.entered, false);
    atomic_init(&follow_call.returned, false);
    if (pthread_create(&follow_thread, NULL, cancellation_thread, &follow_call) != 0) {
        free(buffer);
        close(fd);
        return -1;
    }
    const int join_result = timed_join(follow_thread, 3000U);

    if (join_result == ETIMEDOUT) {
        fail(name, "a fresh send remained blocked after cancellation");
        fflush(stdout);
        fflush(stderr);
        _Exit(EXIT_FAILURE);
    }
    if (join_result != 0) {
        fail(name, "joining the fresh send failed");
    }
    report.follow_result = (int32_t)follow_call.result;
    report.follow_error = follow_call.error;
    (void)shutdown(fd, SHUT_WR);
    free(buffer);

    if (send_all(control, &report, sizeof(report)) != 0 || expect_byte(control, CMD_ACK) != 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return report.final_join_result == 0 && report.follow_result == 1 ? 0 : -1;
}

static int connect_reused_tuple(const char *local_ip, uint16_t local_port, const char *server_ip,
                                uint16_t server_port)
{
    struct sockaddr_in local_address;
    struct sockaddr_in server_address;
    int one = 1;
    const uint64_t admission_deadline = monotonic_ms() + 3000U;
    int last_error = EADDRNOTAVAIL;
    int fd = -1;

    if (fill_address(&local_address, local_ip, local_port) != 0 ||
        fill_address(&server_address, server_ip, server_port) != 0) {
        return -1;
    }
    do {
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0 || setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0) {
            break;
        }
        if (bind(fd, (const struct sockaddr *)&local_address, sizeof(local_address)) != 0) {
            last_error = errno;
        } else if (connect(fd, (const struct sockaddr *)&server_address, sizeof(server_address)) ==
                   0) {
            return fd;
        } else {
            last_error = errno;
        }

        close(fd);
        fd = -1;
        if (last_error != EADDRINUSE && last_error != EADDRNOTAVAIL) {
            errno = last_error;
            break;
        }
        sleep_ms(2U);
    } while (monotonic_ms() < admission_deadline);

    if (fd < 0) {
        errno = last_error;
        return -1;
    }
    {
        const int saved_errno = errno;

        close(fd);
        errno = saved_errno;
        return -1;
    }
}

static int server_timewait_reuse(const struct options *options, int control)
{
    static const unsigned char byte = 0xe3;
    const char *name = "timewait-reuse";
    int listener = make_listener(options->bind_ip, options->port + TEST_TIMEWAIT_REUSE_PORT);
    bool ok = true;

    if (listener < 0) {
        return -1;
    }
    for (int iteration = 0; iteration < TIMEWAIT_REUSE_ITERATIONS; ++iteration) {
        unsigned char peer_byte = 0U;
        int fd;

        if (send_byte(control, CMD_TIMEWAIT_CONNECT) != 0) {
            close(listener);
            return -1;
        }
        fd = accept(listener, NULL, NULL);
        if (fd < 0) {
            fprintf(stderr, "timewait-reuse server iteration=%d step=accept errno=%d\n", iteration,
                    errno);
        } else if (set_recv_timeout(fd, IO_TIMEOUT_SECONDS) != 0) {
            fprintf(stderr, "timewait-reuse server iteration=%d step=rcvtimeo errno=%d\n",
                    iteration, errno);
        } else if (send_all(fd, &byte, sizeof(byte)) != 0) {
            fprintf(stderr, "timewait-reuse server iteration=%d step=send errno=%d\n", iteration,
                    errno);
        } else if (shutdown(fd, SHUT_WR) != 0) {
            fprintf(stderr, "timewait-reuse server iteration=%d step=shutdown errno=%d\n",
                    iteration, errno);
        } else if (recv(fd, &peer_byte, sizeof(peer_byte), 0) != 0) {
            fprintf(stderr, "timewait-reuse server iteration=%d step=recv-eof errno=%d\n",
                    iteration, errno);
        } else if (expect_byte(control, CMD_ACK) != 0) {
            fprintf(stderr, "timewait-reuse server iteration=%d step=control-ack errno=%d\n",
                    iteration, errno);
        } else {
            close(fd);
            continue;
        }
        {
            fail(name, "same-tuple reconnect or active-close handshake failed");
            ok = false;
            if (fd >= 0) {
                close(fd);
            }
            break;
        }
    }
    printf("OBSERVE case=timewait-reuse iterations=%d completed=%d\n", TIMEWAIT_REUSE_ITERATIONS,
           ok ? TIMEWAIT_REUSE_ITERATIONS : 0);
    fflush(stdout);
    if (ok) {
        pass(name);
    }
    close(listener);
    return ok ? 0 : -1;
}

static int client_timewait_reuse(const struct options *options, int control)
{
    static const unsigned char expected = 0xe3;
    const uint16_t local_port =
        options->port > 54000U ? options->port - 1000U : options->port + 1000U;

    for (int iteration = 0; iteration < TIMEWAIT_REUSE_ITERATIONS; ++iteration) {
        unsigned char byte = 0U;
        int fd;

        if (expect_byte(control, CMD_TIMEWAIT_CONNECT) != 0) {
            return -1;
        }
        fd = connect_reused_tuple(options->bind_ip, local_port, options->server_ip,
                                  options->port + TEST_TIMEWAIT_REUSE_PORT);
        if (fd < 0) {
            fprintf(stderr, "timewait-reuse client iteration=%d step=connect errno=%d\n", iteration,
                    errno);
        } else if (set_recv_timeout(fd, IO_TIMEOUT_SECONDS) != 0) {
            fprintf(stderr, "timewait-reuse client iteration=%d step=rcvtimeo errno=%d\n",
                    iteration, errno);
        } else if (recv(fd, &byte, sizeof(byte), MSG_WAITALL) != 1 || byte != expected) {
            fprintf(stderr,
                    "timewait-reuse client iteration=%d step=recv-byte errno=%d byte=0x%02x\n",
                    iteration, errno, byte);
        } else if (recv(fd, &byte, sizeof(byte), 0) != 0) {
            fprintf(stderr, "timewait-reuse client iteration=%d step=recv-eof errno=%d\n",
                    iteration, errno);
        } else {
            close(fd);
            if (send_byte(control, CMD_ACK) == 0) {
                continue;
            }
            fprintf(stderr, "timewait-reuse client iteration=%d step=control-ack errno=%d\n",
                    iteration, errno);
        }
        {
            if (fd >= 0) {
                close(fd);
            }
            return -1;
        }
    }
    return 0;
}

static int setup_missing_userfault(void *address, size_t length)
{
    struct uffdio_api api = {
        .api = UFFD_API,
    };
    struct uffdio_register registration = {
        .range =
            {
                .start = (uintptr_t)address,
                .len = length,
            },
        .mode = UFFDIO_REGISTER_MODE_MISSING,
    };
    int fd = (int)syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);

    if (fd < 0 || ioctl(fd, UFFDIO_API, &api) != 0 ||
        ioctl(fd, UFFDIO_REGISTER, &registration) != 0) {
        const int saved_errno = errno;

        if (fd >= 0) {
            close(fd);
        }
        errno = saved_errno;
        return -1;
    }
    return fd;
}

static int wait_for_userfault(int userfault_fd, uintptr_t *fault_address)
{
    struct pollfd poll_fd = {
        .fd = userfault_fd,
        .events = POLLIN,
    };
    struct uffd_msg message;
    int result;

    do {
        result = poll(&poll_fd, 1, 3000);
    } while (result < 0 && errno == EINTR);
    if (result != 1 || !(poll_fd.revents & POLLIN) ||
        read(userfault_fd, &message, sizeof(message)) != (ssize_t)sizeof(message) ||
        message.event != UFFD_EVENT_PAGEFAULT) {
        errno = result == 0 ? ETIMEDOUT : EIO;
        return -1;
    }
    *fault_address = (uintptr_t)message.arg.pagefault.address;
    return 0;
}

static int resolve_userfault(int userfault_fd, uintptr_t fault_address, const void *source,
                             size_t page_size)
{
    struct uffdio_copy copy = {
        .dst = fault_address & ~(uintptr_t)(page_size - 1U),
        .src = (uintptr_t)source,
        .len = page_size,
    };

    return ioctl(userfault_fd, UFFDIO_COPY, &copy);
}

static int server_queue_reservation(const struct options *options, int control)
{
    const char *name = "queue-reservation";
    struct queue_reservation_report report;
    unsigned char buffer[8192];
    uint64_t received = 0U;
    int listener = make_listener(options->bind_ip, options->port + TEST_QUEUE_RESERVATION_PORT);
    int send_fd = -1;
    int shutdown_fd = -1;
    bool ok = true;

    if (listener < 0 || send_byte(control, CMD_QUEUE_CONNECT) != 0) {
        return -1;
    }
    send_fd = accept(listener, NULL, NULL);
    shutdown_fd = accept(listener, NULL, NULL);
    close(listener);
    if (send_fd < 0 || shutdown_fd < 0 || set_recv_timeout(send_fd, IO_TIMEOUT_SECONDS) != 0 ||
        set_recv_timeout(shutdown_fd, IO_TIMEOUT_SECONDS) != 0 ||
        send_byte(control, CMD_QUEUE_START) != 0) {
        if (send_fd >= 0) {
            close(send_fd);
        }
        if (shutdown_fd >= 0) {
            close(shutdown_fd);
        }
        return -1;
    }

    if (recv(shutdown_fd, buffer, sizeof(buffer), 0) != 0) {
        fail(name, "the independent shutdown socket did not reach EOF");
        ok = false;
    }
    for (;;) {
        const ssize_t result = recv(send_fd, buffer, sizeof(buffer), 0);

        if (result > 0) {
            received += (uint64_t)result;
            continue;
        }
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result < 0) {
            fail(name, "the fault-stalled send socket did not drain");
            ok = false;
        }
        break;
    }
    if (recv_all(control, &report, sizeof(report)) != 0) {
        close(send_fd);
        close(shutdown_fd);
        return -1;
    }

    printf("OBSERVE case=queue-reservation userfault_result=%d shutdown_result=%d "
           "shutdown_errno=%d shutdown_elapsed_ms=%" PRIu64 " send_result=%d "
           "send_errno=%d bytes_received=%" PRIu64 "\n",
           report.userfault_result, report.shutdown_result, report.shutdown_error,
           report.shutdown_elapsed_ms, report.send_result, report.send_error, received);
    fflush(stdout);
    if (report.magic != 0x51524553U || report.userfault_result != 0) {
        fail(name, "userfaultfd did not establish the deterministic stalled reservation");
        ok = false;
    } else if (report.shutdown_result != 0 || report.shutdown_error != 0 ||
               report.shutdown_elapsed_ms > 750U) {
        fail(name, "an unpublished TX reservation stalled another socket's shutdown");
        ok = false;
    } else if (report.send_result <= 0 || report.send_error != 0 ||
               received != (uint64_t)report.send_result) {
        fail(name, "the resolved TX reservation did not complete exactly once");
        ok = false;
    }
    if (ok) {
        pass(name);
    }
    close(send_fd);
    close(shutdown_fd);
    if (send_byte(control, CMD_ACK) != 0) {
        return -1;
    }
    return ok ? 0 : -1;
}

static int client_queue_reservation(const struct options *options, int control)
{
    const char *name = "queue-reservation";
    struct queue_reservation_report report = {
        .magic = 0x51524553U,
        .userfault_result = -1,
        .shutdown_result = -2,
        .send_result = -2,
    };
    struct cancellation_call send_call = {
        .fd = -1,
        .operation = CANCEL_OPERATION_SEND,
        .result = -2,
    };
    struct shutdown_call shutdown_call_data = {
        .fd = -1,
        .how = SHUT_WR,
        .result = -2,
    };
    pthread_t send_thread;
    pthread_t shutdown_thread_id;
    void *missing_page = MAP_FAILED;
    unsigned char *source_page = NULL;
    uintptr_t fault_address = 0U;
    long page_size_long = sysconf(_SC_PAGESIZE);
    size_t page_size;
    int userfault_fd = -1;
    int send_fd = -1;
    int shutdown_fd = -1;
    int first_shutdown_join;

    if (page_size_long <= 0) {
        return -1;
    }
    page_size = (size_t)page_size_long;
    if (expect_byte(control, CMD_QUEUE_CONNECT) != 0) {
        return -1;
    }
    send_fd = connect_retry(options->bind_ip, options->server_ip,
                            options->port + TEST_QUEUE_RESERVATION_PORT);
    shutdown_fd = connect_retry(options->bind_ip, options->server_ip,
                                options->port + TEST_QUEUE_RESERVATION_PORT);
    if (send_fd < 0 || shutdown_fd < 0 || expect_byte(control, CMD_QUEUE_START) != 0) {
        goto fail;
    }

    missing_page =
        mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    source_page = malloc(page_size);
    if (missing_page == MAP_FAILED || source_page == NULL) {
        goto fail;
    }
    memset(source_page, 0x79, page_size);
    userfault_fd = setup_missing_userfault(missing_page, page_size);
    if (userfault_fd < 0) {
        perror("userfaultfd setup");
        goto fail;
    }

    send_call.fd = send_fd;
    send_call.buffer = missing_page;
    send_call.length = page_size;
    atomic_init(&send_call.entered, false);
    atomic_init(&send_call.returned, false);
    if (pthread_create(&send_thread, NULL, cancellation_thread, &send_call) != 0 ||
        wait_for_userfault(userfault_fd, &fault_address) != 0) {
        goto fail;
    }
    report.userfault_result = 0;

    shutdown_call_data.fd = shutdown_fd;
    atomic_init(&shutdown_call_data.entered, false);
    atomic_init(&shutdown_call_data.returned, false);
    if (pthread_create(&shutdown_thread_id, NULL, shutdown_thread, &shutdown_call_data) != 0) {
        goto fail;
    }
    first_shutdown_join = timed_join(shutdown_thread_id, 1000U);

    if (resolve_userfault(userfault_fd, fault_address, source_page, page_size) != 0) {
        goto fail;
    }
    if (timed_join(send_thread, 3000U) != 0) {
        fail(name, "the send did not complete after resolving its source page");
        fflush(stdout);
        fflush(stderr);
        _Exit(EXIT_FAILURE);
    }
    if (first_shutdown_join == ETIMEDOUT && timed_join(shutdown_thread_id, 3000U) != 0) {
        fail(name, "shutdown remained blocked after resolving the TX reservation");
        fflush(stdout);
        fflush(stderr);
        _Exit(EXIT_FAILURE);
    }
    if (first_shutdown_join != 0 && first_shutdown_join != ETIMEDOUT) {
        goto fail;
    }

    report.shutdown_result = shutdown_call_data.result;
    report.shutdown_error = shutdown_call_data.error;
    report.shutdown_elapsed_ms = shutdown_call_data.elapsed_ms;
    report.send_result = (int32_t)send_call.result;
    report.send_error = send_call.error;
    (void)shutdown(send_fd, SHUT_WR);

    close(userfault_fd);
    munmap(missing_page, page_size);
    free(source_page);
    close(send_fd);
    close(shutdown_fd);
    if (send_all(control, &report, sizeof(report)) != 0 || expect_byte(control, CMD_ACK) != 0) {
        return -1;
    }
    return report.shutdown_result == 0 && report.shutdown_elapsed_ms <= 750U &&
            report.send_result == (int32_t)page_size
        ? 0
        : -1;

fail:
    if (userfault_fd >= 0) {
        close(userfault_fd);
    }
    if (missing_page != MAP_FAILED) {
        munmap(missing_page, page_size);
    }
    free(source_page);
    if (send_fd >= 0) {
        close(send_fd);
    }
    if (shutdown_fd >= 0) {
        close(shutdown_fd);
    }
    return -1;
}

static void fill_recv_close_copy_payload(unsigned char *payload, size_t length)
{
    for (size_t index = 0U; index < length; ++index) {
        payload[index] = (unsigned char)(index % 251U);
    }
}

/*
 * Debug scheduling hook shared with src/core/event/entity_context.cpp. A -D_DEBUG worker
 * pauses in control_socket_job() after dequeuing the close control from the job queue and
 * before taking the socket TCP lock ('D' plus a release wait), then reports the
 * receive-completion and close processing order ('R' in rx_data_recvd_job(), 'C' in
 * close_socket_job()). Release builds compile the hook to an empty stub and carry none of
 * the XLIO_TEST_WORKER_CONTROL_* names in the binary, so the fence-order case probes the
 * loaded image for the arming variable and refuses to arm a pause that cannot fire.
 */
#define WORKER_CONTROL_HOOK_ARM_VARIABLE "XLIO_TEST_WORKER_CONTROL_TARGET_FD"

enum fence_hook_probe_state {
    FENCE_HOOK_PROBE_ERROR = -2,
    FENCE_HOOK_NO_LIBXLIO = -1,
    FENCE_HOOK_ABSENT = 0,
    FENCE_HOOK_PRESENT = 1,
};

static int scan_file_for_bytes(const char *path, const char *needle)
{
    enum {
        SCAN_WINDOW_BYTES = 65536,
    };
    const size_t needle_length = strlen(needle);
    unsigned char *window = NULL;
    size_t carry = 0U;
    int found = 0;
    int fd = -1;

    if (needle_length == 0U || needle_length > SCAN_WINDOW_BYTES / 2U) {
        return -1;
    }
    window = malloc(SCAN_WINDOW_BYTES);
    if (window == NULL) {
        return -1;
    }
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        free(window);
        return -1;
    }
    for (;;) {
        const ssize_t bytes = read(fd, window + carry, SCAN_WINDOW_BYTES - carry);
        size_t filled;

        if (bytes < 0) {
            if (errno == EINTR) {
                continue;
            }
            found = -1;
            break;
        }
        if (bytes == 0) {
            break;
        }
        filled = carry + (size_t)bytes;
        if (filled >= needle_length && memmem(window, filled, needle, needle_length) != NULL) {
            found = 1;
            break;
        }
        carry = needle_length - 1U;
        if (carry > filled) {
            carry = filled;
        }
        memmove(window, window + (filled - carry), carry);
    }
    close(fd);
    free(window);
    return found;
}

static int preloaded_libxlio_fence_hook_state(void)
{
    char line[4096];
    char scanned_path[4096];
    FILE *maps = fopen("/proc/self/maps", "r");
    bool saw_libxlio = false;
    int verdict = FENCE_HOOK_PROBE_ERROR;

    if (maps == NULL) {
        return FENCE_HOOK_PROBE_ERROR;
    }
    scanned_path[0] = '\0';
    while (fgets(line, sizeof(line), maps) != NULL) {
        char *path = strchr(line, '/');
        char *line_end;
        const char *base_name;
        size_t path_length;
        int scan_result;

        if (path == NULL) {
            continue;
        }
        line_end = strchr(path, '\n');
        if (line_end != NULL) {
            *line_end = '\0';
        }
        base_name = strrchr(path, '/') + 1;
        if (strncmp(base_name, "libxlio", 7U) != 0) {
            continue;
        }
        path_length = strlen(path);
        if (path_length >= sizeof(scanned_path) || strcmp(path, scanned_path) == 0) {
            continue;
        }
        memcpy(scanned_path, path, path_length + 1U);
        saw_libxlio = true;
        scan_result = scan_file_for_bytes(path, WORKER_CONTROL_HOOK_ARM_VARIABLE);
        if (scan_result == 1) {
            verdict = FENCE_HOOK_PRESENT;
            break;
        }
        if (scan_result == 0) {
            verdict = FENCE_HOOK_ABSENT;
        }
    }
    fclose(maps);
    if (!saw_libxlio) {
        return FENCE_HOOK_NO_LIBXLIO;
    }
    return verdict;
}

static void clear_worker_control_test_hook(void)
{
    unsetenv(WORKER_CONTROL_HOOK_ARM_VARIABLE);
    unsetenv("XLIO_TEST_WORKER_CONTROL_EVENT_FD");
    unsetenv("XLIO_TEST_WORKER_CONTROL_RELEASE_FD");
}

static int set_worker_control_test_hook(int target_fd, int event_fd, int release_fd)
{
    char target[32];
    char event[32];
    char release[32];

    if (snprintf(target, sizeof(target), "%d", target_fd) < 0 ||
        snprintf(event, sizeof(event), "%d", event_fd) < 0 ||
        snprintf(release, sizeof(release), "%d", release_fd) < 0) {
        return -1;
    }
    if (setenv(WORKER_CONTROL_HOOK_ARM_VARIABLE, target, 1) != 0 ||
        setenv("XLIO_TEST_WORKER_CONTROL_EVENT_FD", event, 1) != 0 ||
        setenv("XLIO_TEST_WORKER_CONTROL_RELEASE_FD", release, 1) != 0) {
        clear_worker_control_test_hook();
        return -1;
    }
    return 0;
}

static int server_recv_close_copy_impl(const struct options *options, int control,
                                       bool verify_fence_order)
{
    enum {
        FAULT_COPY_BYTES = 128,
        TOTAL_COPY_BYTES = FAULT_COPY_BYTES + 128,
        PAYLOAD_BYTES = 512,
    };
    const char *name = verify_fence_order ? "recv-close-fence-order" : "recv-close-copy";
    const int port_offset =
        verify_fence_order ? TEST_RECV_CLOSE_FENCE_ORDER_PORT : TEST_RECV_CLOSE_COPY_PORT;
    unsigned char expected[PAYLOAD_BYTES];
    unsigned char first = 0U;
    struct recv_close_copy_report report = {0};
    struct recv_close_copy_call call = {
        .fd = -1,
        .result = -2,
    };
    pthread_t recv_thread_id;
    bool recv_started = false;
    bool recv_joined = false;
    bool fault_resolved = false;
    void *missing_page = MAP_FAILED;
    unsigned char *source_page = NULL;
    uintptr_t fault_address = 0U;
    long page_size_long = sysconf(_SC_PAGESIZE);
    size_t page_size = 0U;
    int userfault_fd = -1;
    int listener = -1;
    int fd = -1;
    int hook_events[2] = {-1, -1};
    int hook_release[2] = {-1, -1};
    int close_result = -2;
    int close_error = 0;
    unsigned char dequeue_event = 0U;
    unsigned char order[2] = {0U, 0U};
    bool hook_armed = false;
    bool hook_released = false;
    bool peer_observed_close_early = false;
    bool peer_observed_close = false;
    bool ok = true;

    fill_recv_close_copy_payload(expected, sizeof(expected));
    if (page_size_long <= 0 || (size_t)page_size_long < FAULT_COPY_BYTES) {
        fail(name, "the host page size cannot hold the fault-stalled copy");
        return -1;
    }
    page_size = (size_t)page_size_long;
    if (verify_fence_order) {
        const int hook_state = preloaded_libxlio_fence_hook_state();

        if (hook_state == FENCE_HOOK_NO_LIBXLIO) {
            fail(name, "no libxlio image is loaded; the fence-order pause needs an "
                       "--enable-debug libxlio preload");
            return -1;
        }
        if (hook_state == FENCE_HOOK_ABSENT) {
            fail(name, "the preloaded libxlio has no debug worker-control hook; fence order "
                       "is qualified only against --enable-debug (-D_DEBUG) builds");
            return -1;
        }
        if (hook_state != FENCE_HOOK_PRESENT) {
            /* Probe I/O failed, so the build flavor is unknown. Arming a pause that may never
             * fire would hang the case, so fail fast with the truthful probe verdict instead. */
            fail(name, "could not probe the preloaded libxlio for the debug worker-control "
                       "hook; fence order is qualified only against --enable-debug builds");
            return -1;
        }
        printf("TRACE case=%s checkpoint=hook-probe state=present\n", name);
        fflush(stdout);
    }
    listener = make_listener(options->bind_ip, options->port + port_offset);
    if (listener < 0 || send_byte(control, CMD_RECV_CLOSE_COPY_CONNECT) != 0) {
        goto out;
    }
    fd = accept(listener, NULL, NULL);
    close(listener);
    listener = -1;
    if (fd < 0 || expect_byte(control, CMD_RECV_CLOSE_COPY_SENT) != 0 ||
        recv(fd, &first, sizeof(first), MSG_WAITALL) != (ssize_t)sizeof(first)) {
        goto out;
    }

    missing_page =
        mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    source_page = calloc(1U, page_size);
    if (missing_page == MAP_FAILED || source_page == NULL) {
        goto out;
    }
    userfault_fd = setup_missing_userfault(missing_page, page_size);
    if (userfault_fd < 0) {
        perror("userfaultfd setup");
        goto out;
    }

    call.fd = fd;
    call.fault_buffer = missing_page;
    call.fault_length = FAULT_COPY_BYTES;
    if (pthread_create(&recv_thread_id, NULL, recv_close_copy_thread, &call) != 0) {
        goto out;
    }
    recv_started = true;
    if (wait_for_userfault(userfault_fd, &fault_address) != 0) {
        fail(name, "recvmsg did not fault while copying detached RX data");
        ok = false;
        goto out;
    }

    if (verify_fence_order) {
        if (pipe2(hook_events, O_CLOEXEC) != 0 || pipe2(hook_release, O_CLOEXEC) != 0 ||
            set_worker_control_test_hook(fd, hook_events[1], hook_release[0]) != 0) {
            fail(name, "could not arm the debug worker-control scheduling hook");
            ok = false;
            goto out;
        }
        hook_armed = true;
        printf("TRACE case=%s checkpoint=hook-armed target_fd=%d event_fd=%d release_fd=%d\n", name,
               fd, hook_events[1], hook_release[0]);
        fflush(stdout);
        printf("TRACE case=%s checkpoint=before-close\n", name);
        fflush(stdout);
    }

    errno = 0;
    close_result = close(fd);
    close_error = close_result < 0 ? errno : 0;
    fd = -1;
    if (verify_fence_order) {
        printf("TRACE case=%s checkpoint=after-close result=%d error=%d\n", name, close_result,
               close_error);
        fflush(stdout);
        if (wait_until_readable(hook_events[0], 3000) != 0 ||
            read_byte(hook_events[0], &dequeue_event) != 0 || dequeue_event != 'D') {
            fail(name, "the debug hook did not stop close after dequeue and before the TCP lock");
            ok = false;
            goto out;
        }
        printf("TRACE case=%s checkpoint=control-dequeued\n", name);
        fflush(stdout);
    }

    if (!verify_fence_order &&
        (recv_all(control, &report, sizeof(report)) != 0 || report.magic != 0x52434350U)) {
        fail(name, "the peer did not report its pre-release close observation");
        ok = false;
        goto out;
    }

    if (resolve_userfault(userfault_fd, fault_address, source_page, page_size) != 0) {
        fail(name, "could not resolve the receive destination page fault");
        ok = false;
        goto out;
    }
    fault_resolved = true;
    if (timed_join(recv_thread_id, 3000U) != 0) {
        fail(name, "recvmsg did not finish after its destination page was supplied");
        fflush(stdout);
        fflush(stderr);
        _Exit(EXIT_FAILURE);
    }
    recv_joined = true;
    if (verify_fence_order) {
        printf("TRACE case=%s checkpoint=recv-complete result=%zd error=%d\n", name, call.result,
               call.error);
        fflush(stdout);

        // The pause is one-shot. Keep target/event reporting armed for the subsequent R and C
        // markers, but prevent the deferred close control's second dequeue from emitting another
        // D marker and waiting for a second release.
        unsetenv("XLIO_TEST_WORKER_CONTROL_RELEASE_FD");
        if (write_byte(hook_release[1], 'G') != 0) {
            fail(name, "could not release the dequeued worker close control");
            ok = false;
            goto out;
        }
        hook_released = true;
        printf("TRACE case=%s checkpoint=control-released\n", name);
        fflush(stdout);
        if (wait_until_readable(hook_events[0], 3000) != 0 ||
            read_byte(hook_events[0], &order[0]) != 0 ||
            wait_until_readable(hook_events[0], 3000) != 0 ||
            read_byte(hook_events[0], &order[1]) != 0) {
            fail(name, "the worker did not report RX-job and close processing order");
            ok = false;
            goto out;
        }
        printf("TRACE case=%s checkpoint=order-observed order=%c%c\n", name, order[0], order[1]);
        fflush(stdout);
        if (order[0] != 'R' || order[1] != 'C') {
            printf("OBSERVE case=%s worker_order=%c%c recv_result=%zd recv_errno=%d\n", name,
                   order[0], order[1], call.result, call.error);
            fail(name, "close processed before the admitted receive completion job");
            fflush(stdout);
            fflush(stderr);
            _Exit(EXIT_FAILURE);
        }
        if (recv_all(control, &report, sizeof(report)) != 0 || report.magic != 0x52434350U) {
            fail(name, "the peer did not report its close observation after worker release");
            ok = false;
            goto out;
        }
    }

    peer_observed_close_early =
        report.early_result == 0 || (report.early_result < 0 && report.early_error == ECONNRESET);
    if (send_byte(control, CMD_RECV_CLOSE_COPY_RELEASED) != 0 ||
        expect_byte(control, CMD_RECV_CLOSE_COPY_CLOSED) != 0) {
        fail(name, "the peer did not observe close after the admitted receive completed");
        ok = false;
        goto out;
    }
    peer_observed_close = true;

    printf("OBSERVE case=%s close_result=%d close_errno=%d "
           "peer_observed_close_early=%d early_result=%d early_errno=%d "
           "peer_observed_close=%d recv_result=%zd recv_errno=%d worker_order=%c%c\n",
           name, close_result, close_error, peer_observed_close_early ? 1 : 0, report.early_result,
           report.early_error, peer_observed_close ? 1 : 0, call.result, call.error,
           order[0] ? order[0] : '-', order[1] ? order[1] : '-');
    fflush(stdout);
    if (close_result != 0 || close_error != 0) {
        fail(name, "close failed while recvmsg held an admitted RX operation");
        ok = false;
    } else if (!verify_fence_order && peer_observed_close_early) {
        fail(name, "close overtook a receive that still owned detached RX state");
        ok = false;
    } else if (!verify_fence_order &&
               !(report.early_result < 0 &&
                 (report.early_error == EAGAIN || report.early_error == EWOULDBLOCK))) {
        fail(name, "the peer's pre-release close probe returned an unexpected result");
        ok = false;
    } else if (first != expected[0]) {
        fail(name, "the prefix receive returned the wrong stream byte");
        ok = false;
    } else if (call.result != TOTAL_COPY_BYTES || call.error != 0) {
        fail(name, "the admitted recvmsg did not complete exactly once");
        ok = false;
    } else if (memcmp(missing_page, expected + 1U, FAULT_COPY_BYTES) != 0) {
        fail(name, "the fault-stalled receive segment was corrupted");
        ok = false;
    } else if (memcmp(call.tail, expected + 1U + FAULT_COPY_BYTES, sizeof(call.tail)) != 0) {
        fail(name, "close reset the detached RX offset during recvmsg copy");
        ok = false;
    }
    if (ok) {
        pass(name);
    }

out:
    if (hook_armed && !hook_released && hook_release[1] >= 0) {
        (void)write_byte(hook_release[1], 'G');
        hook_released = true;
    }
    if (recv_started && !recv_joined) {
        if (!fault_resolved && userfault_fd >= 0 && source_page != NULL && fault_address != 0U) {
            (void)resolve_userfault(userfault_fd, fault_address, source_page, page_size);
        }
        if (fd >= 0) {
            close(fd);
            fd = -1;
        }
        if (timed_join(recv_thread_id, 3000U) != 0) {
            fflush(stdout);
            fflush(stderr);
            _Exit(EXIT_FAILURE);
        }
    }
    if (userfault_fd >= 0) {
        close(userfault_fd);
    }
    if (missing_page != MAP_FAILED) {
        munmap(missing_page, page_size);
    }
    free(source_page);
    if (fd >= 0) {
        close(fd);
    }
    if (listener >= 0) {
        close(listener);
    }
    clear_worker_control_test_hook();
    for (size_t index = 0U; index < 2U; ++index) {
        if (hook_events[index] >= 0) {
            close(hook_events[index]);
        }
        if (hook_release[index] >= 0) {
            close(hook_release[index]);
        }
    }
    if (peer_observed_close && send_byte(control, CMD_ACK) != 0) {
        return -1;
    }
    return ok && recv_joined ? 0 : -1;
}

static int server_recv_close_copy(const struct options *options, int control)
{
    return server_recv_close_copy_impl(options, control, false);
}

static int server_recv_close_fence_order(const struct options *options, int control)
{
    return server_recv_close_copy_impl(options, control, true);
}

static int client_recv_close_copy_impl(const struct options *options, int control,
                                       bool verify_fence_order)
{
    enum {
        PAYLOAD_BYTES = 512,
    };
    unsigned char payload[PAYLOAD_BYTES];
    unsigned char byte = 0U;
    struct recv_close_copy_report report = {
        .magic = 0x52434350U,
        .early_result = -2,
    };
    int fd = -1;
    const int port_offset =
        verify_fence_order ? TEST_RECV_CLOSE_FENCE_ORDER_PORT : TEST_RECV_CLOSE_COPY_PORT;
    ssize_t close_observation;
    int close_observation_error;

    fill_recv_close_copy_payload(payload, sizeof(payload));
    if (expect_byte(control, CMD_RECV_CLOSE_COPY_CONNECT) != 0) {
        return -1;
    }
    fd = connect_retry(options->bind_ip, options->server_ip, options->port + port_offset);
    if (fd < 0 || set_recv_timeout_ms(fd, RECV_CLOSE_EARLY_PROBE_MS) != 0 ||
        send(fd, payload, sizeof(payload), MSG_NOSIGNAL) != (ssize_t)sizeof(payload) ||
        send_byte(control, CMD_RECV_CLOSE_COPY_SENT) != 0) {
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }

    errno = 0;
    close_observation = recv(fd, &byte, sizeof(byte), 0);
    close_observation_error = close_observation < 0 ? errno : 0;
    report.early_result = (int32_t)close_observation;
    report.early_error = close_observation_error;
    if (!((close_observation == 0) ||
          (close_observation < 0 &&
           (close_observation_error == ECONNRESET || close_observation_error == EAGAIN ||
            close_observation_error == EWOULDBLOCK))) ||
        send_all(control, &report, sizeof(report)) != 0 ||
        expect_byte(control, CMD_RECV_CLOSE_COPY_RELEASED) != 0) {
        close(fd);
        return -1;
    }

    if (close_observation < 0 &&
        (close_observation_error == EAGAIN || close_observation_error == EWOULDBLOCK)) {
        if (set_recv_timeout(fd, IO_TIMEOUT_SECONDS) != 0) {
            close(fd);
            return -1;
        }
        errno = 0;
        close_observation = recv(fd, &byte, sizeof(byte), 0);
        close_observation_error = close_observation < 0 ? errno : 0;
    }
    if (!((close_observation == 0) ||
          (close_observation < 0 && close_observation_error == ECONNRESET)) ||
        send_byte(control, CMD_RECV_CLOSE_COPY_CLOSED) != 0 || expect_byte(control, CMD_ACK) != 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int client_recv_close_copy(const struct options *options, int control)
{
    return client_recv_close_copy_impl(options, control, false);
}

static int client_recv_close_fence_order(const struct options *options, int control)
{
    return client_recv_close_copy_impl(options, control, true);
}

static int server_send_close_tail(const struct options *options, int control)
{
    const uint32_t zero_failures = 0U;
    unsigned char expected[1U + sizeof(zero_failures)];
    const char *name = "send-close-tail";
    unsigned char received[sizeof(expected)];
    size_t received_bytes = 0U;
    bool ok = true;

    (void)options;
    expected[0] = CMD_DONE;
    memcpy(expected + 1U, &zero_failures, sizeof(zero_failures));

    if (send_byte(control, CMD_SEND_CLOSE_TAIL_CONNECT) != 0) {
        return -1;
    }
    while (received_bytes < sizeof(received)) {
        const ssize_t result =
            recv(control, received + received_bytes, sizeof(received) - received_bytes, 0);

        if (result > 0) {
            received_bytes += (size_t)result;
            continue;
        }
        if (result == 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        break;
    }
    if (received_bytes != sizeof(received) || memcmp(received, expected, received_bytes) != 0) {
        fail(name, "the payload queued before close was not delivered");
        ok = false;
    }
    printf("OBSERVE case=send-close-tail payload_bytes=%zu delivered=%d "
           "eof_contract=not-required\n",
           received_bytes,
           received_bytes == sizeof(received) && memcmp(received, expected, sizeof(received)) == 0
               ? 1
               : 0);
    fflush(stdout);
    if (ok) {
        pass(name);
    }
    return 0;
}

static int client_send_close_tail(const struct options *options, int control)
{
    const uint32_t zero_failures = 0U;
    ssize_t first_result;
    int first_error;
    ssize_t second_result;
    int second_error;
    int close_result;
    int close_error;

    if (expect_byte(control, CMD_SEND_CLOSE_TAIL_CONNECT) != 0) {
        return -1;
    }
    (void)options;
    errno = 0;
    first_result = send(control, &CMD_DONE, sizeof(CMD_DONE), MSG_NOSIGNAL);
    first_error = first_result < 0 ? errno : 0;
    errno = 0;
    second_result = send(control, &zero_failures, sizeof(zero_failures), MSG_NOSIGNAL);
    second_error = second_result < 0 ? errno : 0;
    errno = 0;
    close_result = close(control);
    close_error = close_result < 0 ? errno : 0;
    printf("OBSERVE case=send-close-tail-client first_result=%zd first_errno=%d "
           "second_result=%zd second_errno=%d close_result=%d close_errno=%d\n",
           first_result, first_error, second_result, second_error, close_result, close_error);
    fflush(stdout);
    if (first_result != (ssize_t)sizeof(CMD_DONE) ||
        second_result != (ssize_t)sizeof(zero_failures) || close_result != 0) {
        return -1;
    }
    return 0;
}

static bool barrier_wait_ok(pthread_barrier_t *barrier)
{
    int result = pthread_barrier_wait(barrier);
    return result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD;
}

static void *admission_close_shutdown_thread(void *opaque)
{
    struct admission_close_call *call = opaque;

    for (int iteration = 0; iteration < ADMISSION_CLOSE_ITERATIONS; ++iteration) {
        if (!barrier_wait_ok(&call->start)) {
            atomic_fetch_add_explicit(&call->failures, 1, memory_order_relaxed);
            return NULL;
        }

        int fd = atomic_load_explicit(&call->fd, memory_order_acquire);
        errno = 0;
        int result = shutdown(fd, SHUT_RD);
        int error = result < 0 ? errno : 0;
        if (result != 0 && error != EBADF && error != ENOTCONN && error != ENOTSOCK) {
            atomic_fetch_add_explicit(&call->failures, 1, memory_order_relaxed);
        }

        if (!barrier_wait_ok(&call->finish)) {
            atomic_fetch_add_explicit(&call->failures, 1, memory_order_relaxed);
            return NULL;
        }
    }
    return NULL;
}

static int server_admission_close(const struct options *options, int control)
{
    (void)options;
    const char *name = "close racing worker API admission preserves socket lifetime";
    struct admission_close_call call;
    pthread_t thread;
    bool thread_started = false;
    bool barriers_ready = false;
    int result = -1;

    memset(&call, 0, sizeof(call));
    atomic_init(&call.fd, -1);
    atomic_init(&call.failures, 0);

    if (pthread_barrier_init(&call.start, NULL, 2) != 0) {
        fail(name, "could not initialize start barrier");
        return -1;
    }
    if (pthread_barrier_init(&call.finish, NULL, 2) != 0) {
        fail(name, "could not initialize finish barrier");
        pthread_barrier_destroy(&call.start);
        return -1;
    }
    barriers_ready = true;

    if (pthread_create(&thread, NULL, admission_close_shutdown_thread, &call) != 0) {
        fail(name, "could not start shutdown thread");
        goto out;
    }
    thread_started = true;

    if (send_byte(control, CMD_ADMISSION_CLOSE_START) != 0) {
        fail(name, "could not synchronize client");
        goto out;
    }

    for (int iteration = 0; iteration < ADMISSION_CLOSE_ITERATIONS; ++iteration) {
        int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            fail(name, "socket creation failed");
            goto out;
        }
        atomic_store_explicit(&call.fd, fd, memory_order_release);

        if (!barrier_wait_ok(&call.start)) {
            close(fd);
            fail(name, "start barrier failed");
            goto out;
        }

        if (close(fd) != 0) {
            atomic_fetch_add_explicit(&call.failures, 1, memory_order_relaxed);
        }

        if (!barrier_wait_ok(&call.finish)) {
            fail(name, "finish barrier failed");
            goto out;
        }
    }

    if (pthread_join(thread, NULL) != 0) {
        fail(name, "could not join shutdown thread");
        thread_started = false;
        goto out;
    }
    thread_started = false;

    if (atomic_load_explicit(&call.failures, memory_order_relaxed) != 0) {
        fail(name, "close or shutdown returned an unexpected result");
        goto out;
    }
    if (send_byte(control, CMD_ADMISSION_CLOSE_DONE) != 0) {
        fail(name, "could not report completion");
        goto out;
    }

    pass(name);
    result = 0;

out:
    if (thread_started) {
        pthread_cancel(thread);
        pthread_join(thread, NULL);
    }
    if (barriers_ready) {
        pthread_barrier_destroy(&call.finish);
        pthread_barrier_destroy(&call.start);
    }
    return result;
}

static int client_admission_close(const struct options *options, int control)
{
    (void)options;

    if (expect_byte(control, CMD_ADMISSION_CLOSE_START) != 0 ||
        expect_byte(control, CMD_ADMISSION_CLOSE_DONE) != 0) {
        return -1;
    }
    return 0;
}

static int register_epoll_socket(int epfd, int fd, uint64_t identity)
{
    struct epoll_event event = {
        .events = EPOLLIN,
        .data.u64 = identity,
    };

    return epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event);
}

static int server_epoll_distinct_close_iteration(int listener, int control)
{
    static const unsigned char label_b = 0xb1;
    static const unsigned char label_c = 0xc1;
    static const unsigned char label_a = 0xa1;
    static const unsigned char marker = 0x5a;
    static const uint64_t identity_b = UINT64_C(0xb100000000000001);
    static const uint64_t identity_c = UINT64_C(0xc100000000000002);
    static const uint64_t identity_a = UINT64_C(0xa100000000000003);
    int sockets[3] = {-1, -1, -1};
    int fd_b = -1;
    int fd_c = -1;
    int fd_a = -1;
    int epfd = -1;
    pthread_t close_threads[2];
    bool thread_started[2] = {false, false};
    bool thread_joined[2] = {false, false};
    atomic_bool start;
    atomic_int ready;
    struct epoll_distinct_close_call calls[2];
    int result = -1;

    atomic_init(&start, false);
    atomic_init(&ready, 0);
    memset(calls, 0, sizeof(calls));

    for (size_t index = 0; index < 3U; ++index) {
        unsigned char label = 0U;

        sockets[index] = accept(listener, NULL, NULL);
        if (sockets[index] < 0 || set_recv_timeout(sockets[index], IO_TIMEOUT_SECONDS) != 0 ||
            recv_all(sockets[index], &label, sizeof(label)) != 0) {
            goto out;
        }
        if (label == label_b && fd_b < 0) {
            fd_b = sockets[index];
        } else if (label == label_c && fd_c < 0) {
            fd_c = sockets[index];
        } else if (label == label_a && fd_a < 0) {
            fd_a = sockets[index];
        } else {
            errno = EPROTO;
            goto out;
        }
    }

    epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0 || register_epoll_socket(epfd, fd_b, identity_b) != 0 ||
        register_epoll_socket(epfd, fd_c, identity_c) != 0 ||
        register_epoll_socket(epfd, fd_a, identity_a) != 0) {
        goto out;
    }

    calls[0].fd = fd_b;
    calls[0].start = &start;
    calls[0].ready = &ready;
    calls[1].fd = fd_a;
    calls[1].start = &start;
    calls[1].ready = &ready;
    for (size_t index = 0; index < 2U; ++index) {
        if (pthread_create(&close_threads[index], NULL, epoll_distinct_close_thread,
                           &calls[index]) != 0) {
            atomic_store_explicit(&start, true, memory_order_release);
            goto out;
        }
        thread_started[index] = true;
    }

    {
        const uint64_t ready_deadline = monotonic_ms() + 1000U;

        while (atomic_load_explicit(&ready, memory_order_acquire) != 2) {
            if (monotonic_ms() >= ready_deadline) {
                atomic_store_explicit(&start, true, memory_order_release);
                errno = ETIMEDOUT;
                goto out;
            }
            sleep_ms(1U);
        }
    }
    atomic_store_explicit(&start, true, memory_order_release);

    for (size_t index = 0; index < 2U; ++index) {
        const int join_result = timed_join(close_threads[index], 5000U);

        if (join_result == ETIMEDOUT) {
            fail("distinct worker closes preserve epoll compaction",
                 "a close thread did not complete within the deadline");
            fflush(stdout);
            fflush(stderr);
            _Exit(EXIT_FAILURE);
        }
        if (join_result != 0) {
            fail("distinct worker closes preserve epoll compaction",
                 "pthread_join failed for a close thread");
            fflush(stdout);
            fflush(stderr);
            _Exit(EXIT_FAILURE);
        }
        thread_joined[index] = true;
        if (calls[index].result == 0) {
            for (size_t socket_index = 0; socket_index < 3U; ++socket_index) {
                if (sockets[socket_index] == calls[index].fd) {
                    sockets[socket_index] = -1;
                }
            }
        }
    }
    if (calls[0].result != 0 || calls[1].result != 0) {
        errno = calls[0].result != 0 ? calls[0].error : calls[1].error;
        goto out;
    }

    if (send_byte(control, CMD_EPOLL_DISTINCT_CLOSED) != 0) {
        goto out;
    }

    {
        struct epoll_event events[4];
        const uint64_t deadline = monotonic_ms() + 5000U;
        bool observed_c = false;

        while (!observed_c) {
            const uint64_t now = monotonic_ms();
            const int remaining = now < deadline ? (int)(deadline - now) : 0;
            int event_count;

            do {
                event_count = epoll_wait(epfd, events, 4, remaining);
            } while (event_count < 0 && errno == EINTR);
            if (event_count <= 0) {
                errno = event_count == 0 ? ETIMEDOUT : errno;
                goto out;
            }
            for (int index = 0; index < event_count; ++index) {
                if (events[index].data.u64 != identity_c || !(events[index].events & EPOLLIN)) {
                    errno = EPROTO;
                    goto out;
                }
                observed_c = true;
            }
        }
    }

    {
        unsigned char received = 0U;

        if (recv_all(fd_c, &received, sizeof(received)) != 0) {
            goto out;
        }
        if (received != marker) {
            errno = EPROTO;
            goto out;
        }
        if (send_byte(control, CMD_ACK) != 0) {
            goto out;
        }
    }
    result = 0;

out:
    atomic_store_explicit(&start, true, memory_order_release);
    for (size_t index = 0; index < 2U; ++index) {
        if (thread_started[index] && !thread_joined[index]) {
            const int join_result = timed_join(close_threads[index], 5000U);

            if (join_result != 0) {
                fflush(stdout);
                fflush(stderr);
                _Exit(EXIT_FAILURE);
            }
            thread_joined[index] = true;
            if (calls[index].result == 0) {
                for (size_t socket_index = 0; socket_index < 3U; ++socket_index) {
                    if (sockets[socket_index] == calls[index].fd) {
                        sockets[socket_index] = -1;
                    }
                }
            }
        }
    }
    for (size_t index = 0; index < 3U; ++index) {
        if (sockets[index] >= 0) {
            close(sockets[index]);
        }
    }
    if (epfd >= 0) {
        close(epfd);
    }
    return result;
}

static int server_epoll_distinct_close(const struct options *options, int control)
{
    const char *name = "distinct worker closes preserve epoll compaction";
    int listener = make_listener_with_options(
        options->bind_ip, options->port + TEST_EPOLL_DISTINCT_CLOSE_PORT, 16, 0);

    if (listener < 0 || send_byte(control, CMD_EPOLL_DISTINCT_CONNECT) != 0) {
        if (listener >= 0) {
            close(listener);
        }
        fail(name, "listener setup or client synchronization failed");
        return -1;
    }

    for (int iteration = 0; iteration < EPOLL_DISTINCT_CLOSE_ITERATIONS; ++iteration) {
        if (server_epoll_distinct_close_iteration(listener, control) != 0) {
            printf("OBSERVE case=epoll-distinct-close iteration=%d errno=%d\n", iteration, errno);
            fflush(stdout);
            close(listener);
            fail(name, "a close-compaction iteration failed");
            return -1;
        }
    }

    close(listener);
    pass(name);
    return 0;
}

static int client_epoll_distinct_close(const struct options *options, int control)
{
    static const unsigned char labels[3] = {0xb1, 0xc1, 0xa1};
    static const unsigned char marker = 0x5a;

    if (expect_byte(control, CMD_EPOLL_DISTINCT_CONNECT) != 0) {
        return -1;
    }

    for (int iteration = 0; iteration < EPOLL_DISTINCT_CLOSE_ITERATIONS; ++iteration) {
        int sockets[3] = {-1, -1, -1};
        int result = -1;

        for (size_t index = 0; index < 3U; ++index) {
            sockets[index] = connect_retry(options->bind_ip, options->server_ip,
                                           options->port + TEST_EPOLL_DISTINCT_CLOSE_PORT);
            if (sockets[index] < 0 ||
                send_all(sockets[index], &labels[index], sizeof(labels[index])) != 0) {
                goto iteration_out;
            }
        }
        if (expect_byte(control, CMD_EPOLL_DISTINCT_CLOSED) != 0 ||
            send_all(sockets[1], &marker, sizeof(marker)) != 0 ||
            expect_byte(control, CMD_ACK) != 0) {
            goto iteration_out;
        }
        result = 0;

    iteration_out:
        for (size_t index = 0; index < 3U; ++index) {
            if (sockets[index] >= 0) {
                close(sockets[index]);
            }
        }
        if (result != 0) {
            return -1;
        }
    }
    return 0;
}

static void handle_sigint(int signal_number)
{
    (void)signal_number;
}

static int server_exit_listener_close(const struct options *options, int control)
{
    const char *name = "active-listener close and SIGINT shutdown do not deadlock";
    struct close_call *call = calloc(1, sizeof(*call));
    pthread_t thread;
    int listener = make_listener_with_options(
        options->bind_ip, options->port + TEST_EXIT_LISTENER_PORT, EXIT_PENDING_CONNECTIONS, 0);
    bool joined = false;
    bool ok = true;

    if (call == NULL || listener < 0 || send_byte(control, CMD_EXIT_CONNECT) != 0 ||
        expect_byte(control, CMD_EXIT_CONNECTED) != 0) {
        perror("exit-listener setup");
        free(call);
        if (listener >= 0) {
            close(listener);
        }
        return -1;
    }

    call->fd = listener;
    atomic_init(&call->result, -2);
    atomic_init(&call->error, 0);
    atomic_init(&call->elapsed_ms, 0U);
    if (pthread_create(&thread, NULL, close_thread, call) != 0) {
        fail(name, "could not start listener close thread");
        close(listener);
        free(call);
        return -1;
    }

    sleep_ms(1);
    if (raise(SIGINT) != 0) {
        fail(name, "raise(SIGINT) failed");
        ok = false;
    }
    int join_result = timed_join(thread, 3000);

    if (join_result == 0) {
        joined = true;
        if (atomic_load_explicit(&call->result, memory_order_relaxed) != 0) {
            fail(name, "active listener close failed during SIGINT shutdown");
            ok = false;
        }
    } else if (join_result == ETIMEDOUT) {
        /* The 3000 ms join budget already covers the bounded blocking-wait slice (100 ms):
         * after SIGINT, sleepers observe the exit flag on their next slice re-check. */
        fail(name, "listener close deadlocked with the SIGINT shutdown");
        pthread_detach(thread);
        ok = false;
    } else {
        fail(name, "pthread_timedjoin_np failed");
        pthread_detach(thread);
        ok = false;
    }
    if (ok) {
        pass(name);
    }
    if (joined) {
        free(call);
    }
    return 0;
}

static int client_exit_listener_close(const struct options *options, int control)
{
    int fds[EXIT_PENDING_CONNECTIONS];
    int connected = 0;

    memset(fds, -1, sizeof(fds));
    if (expect_byte(control, CMD_EXIT_CONNECT) != 0) {
        return -1;
    }
    for (; connected < EXIT_PENDING_CONNECTIONS; ++connected) {
        fds[connected] = connect_retry(options->bind_ip, options->server_ip,
                                       options->port + TEST_EXIT_LISTENER_PORT);
        if (fds[connected] < 0) {
            break;
        }
    }
    if (connected != EXIT_PENDING_CONNECTIONS || send_byte(control, CMD_EXIT_CONNECTED) != 0) {
        for (int index = 0; index < connected; ++index) {
            close(fds[index]);
        }
        return -1;
    }

    sleep_ms(3500);
    for (int index = 0; index < connected; ++index) {
        close(fds[index]);
    }
    return 0;
}

struct connect_repeat_report {
    uint32_t magic;
    int32_t first_result;
    int32_t first_error;
    int32_t second_result;
    int32_t second_error;
};

static int server_connect_repeat(const struct options *options, int control)
{
    const char *first_name = "blocking connect to a refused port fails with ECONNREFUSED";
    const char *repeat_name = "repeat connect on the failed socket maps to ECONNABORTED";
    struct connect_repeat_report report;

    /* No listener is opened on options->port + TEST_CONNECT_REPEAT_PORT: the server host
     * answers the client's SYN with RST, which is the refused first attempt. */
    (void)options;
    if (send_byte(control, CMD_CONNECT_REPEAT_START) != 0) {
        return -1;
    }
    if (recv_all(control, &report, sizeof(report)) != 0) {
        fail(repeat_name, "did not receive the connect-repeat report");
        return -1;
    }
    if (report.magic != 0x434e5250U) {
        fail(first_name, "connect-repeat report had an invalid magic value");
        fail(repeat_name, "connect-repeat report had an invalid magic value");
    } else {
        printf("INFO connect-repeat report: first=%d errno=%d second=%d errno=%d\n",
               report.first_result, report.first_error, report.second_result,
               report.second_error);
        fflush(stdout);
        if (report.first_result != -1 || report.first_error != ECONNREFUSED) {
            fail(first_name, "first connect did not fail with ECONNREFUSED");
        } else {
            pass(first_name);
        }
        if (report.second_result != -1 || report.second_error != ECONNABORTED) {
            fail(repeat_name, "second connect did not fail with ECONNABORTED");
        } else {
            pass(repeat_name);
        }
    }
    if (send_byte(control, CMD_ACK) != 0) {
        return -1;
    }
    return 0;
}

static int client_connect_repeat(const struct options *options, int control)
{
    struct connect_repeat_report report = {
        .magic = 0x434e5250U,
        .first_result = 0,
        .first_error = 0,
        .second_result = 0,
        .second_error = 0,
    };
    struct sockaddr_in local_address;
    struct sockaddr_in server_address;
    int fd;

    if (expect_byte(control, CMD_CONNECT_REPEAT_START) != 0) {
        return -1;
    }
    if (fill_address(&local_address, options->bind_ip, 0) != 0 ||
        fill_address(&server_address, options->server_ip,
                     options->port + TEST_CONNECT_REPEAT_PORT) != 0) {
        return -1;
    }
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket(connect-repeat)");
        return -1;
    }
    if (bind(fd, (const struct sockaddr *)&local_address, sizeof(local_address)) != 0) {
        perror("bind(connect-repeat)");
        close(fd);
        return -1;
    }

    /* Nothing listens on the target port, so the first blocking connect() is refused (RST). */
    errno = 0;
    report.first_result =
        connect(fd, (const struct sockaddr *)&server_address, sizeof(server_address));
    report.first_error = report.first_result == 0 ? 0 : errno;

    /* Single-attempt contract (RM#4930786): a worker socket never re-enters
     * TCP_CONN_CONNECTING. The refused attempt left this socket in a terminal m_conn_state,
     * so a second connect() on the same fd must not start a new handshake; it returns
     * through the shared default-mode state-to-errno mapping at the top of
     * sockinfo_tcp::connect() (report_connected && is_errorable() -> ECONNABORTED).
     * Default-XLIO R2C takes the exact same branch, which keeps R2C the behavior oracle for
     * this case. A failed socket must be replaced with a new one. */
    errno = 0;
    report.second_result =
        connect(fd, (const struct sockaddr *)&server_address, sizeof(server_address));
    report.second_error = report.second_result == 0 ? 0 : errno;

    if (send_all(control, &report, sizeof(report)) != 0 || expect_byte(control, CMD_ACK) != 0) {
        perror("connect-repeat client report");
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

typedef int (*test_case_fn)(const struct options *, int);

struct test_case_entry {
    const char *name;
    test_case_fn server;
    test_case_fn client;
    bool run_by_default;
};

static const struct test_case_entry test_cases[] = {
    {"accept-nonblocking", server_accept_nonblocking, client_accept_nonblocking, true},
    {"accept-timeout", server_accept_timeout, client_accept_timeout, true},
    {"mixed-route-accept", server_mixed_route_accept, client_mixed_route_accept, false},
    /* Deliberate row reuse: the timeout variant changes only the server side (SO_RCVTIMEO on the
     * listener); the client behavior is identical, so it shares client_mixed_route_accept. */
    {"mixed-route-accept-timeout", server_mixed_route_accept_timeout,
     client_mixed_route_accept, false},
    {"accept4-flags", server_accept4_flags, client_accept4_flags, false},
    {"peek", server_peek, client_peek, true},
    {"waitall", server_waitall, client_waitall, true},
    {"waitall-shut-rd", server_waitall_shut_rd, client_waitall_shut_rd, false},
    {"shared-cq-idle", server_shared_cq_idle, client_shared_cq_idle, false},
    {"concurrent-recv", server_concurrent_recv, client_concurrent_recv, false},
    {"blocking-send", server_blocking_send, client_blocking_send, true},
    {"send-after-shut-wr", server_send_after_shut_wr, client_send_after_shut_wr, true},
    {"send-timeout", server_send_timeout, client_send_timeout, false},
    {"tx-close", server_tx_close, client_tx_close, true},
    {"prefix-eof", server_prefix_eof, client_prefix_eof, true},
    {"rcvtimeo-partial", server_rcvtimeo_partial, client_rcvtimeo_partial, false},
    {"dontwait-progress", server_dontwait_progress, client_dontwait_progress, false},
    {"peek-waitall", server_peek_waitall, client_peek_waitall, true},
    {"multi-writer", server_multi_writer, client_multi_writer, true},
    {"accept-inherit", server_accept_inherit, client_accept_inherit, true},
    {"accept4-nonblock", server_accept4_nonblock, client_accept4_nonblock, true},
    {"readiness", server_readiness, client_readiness, true},
    {"signal-accept", server_signal_accept, client_signal_accept, false},
    {"signal-accept-restart", server_signal_accept_restart, client_signal_accept_restart, false},
    {"signal-recv", server_signal_recv, client_signal_recv, false},
    {"signal-recv-restart", server_signal_recv_restart, client_signal_recv_restart, false},
    {"cancel-accept", server_cancel_accept, client_cancel_accept, false},
    {"cancel-recv", server_cancel_recv, client_cancel_recv, false},
    {"cancel-send", server_cancel_send, client_cancel_send, false},
    {"timewait-reuse", server_timewait_reuse, client_timewait_reuse, false},
    {"queue-reservation", server_queue_reservation, client_queue_reservation, false},
    {"recv-close-copy", server_recv_close_copy, client_recv_close_copy, false},
    {"recv-close-fence-order", server_recv_close_fence_order, client_recv_close_fence_order, false},
    {"send-close-tail", server_send_close_tail, client_send_close_tail, false},
    {"admission-close", server_admission_close, client_admission_close, false},
    {"epoll-distinct-close", server_epoll_distinct_close, client_epoll_distinct_close, false},
    {"connect-repeat", server_connect_repeat, client_connect_repeat, false},
};

static bool case_selected(const struct options *options, const char *name, bool run_by_default)
{
    return options->test_case == NULL ? run_by_default : strcmp(options->test_case, name) == 0;
}

static bool case_exists(const char *name)
{
    if (name == NULL || strcmp(name, "exit-listener") == 0) {
        return true;
    }
    for (size_t index = 0; index < sizeof(test_cases) / sizeof(test_cases[0]); ++index) {
        if (strcmp(name, test_cases[index].name) == 0) {
            return true;
        }
    }
    return false;
}

static int run_server(const struct options *options)
{
    int listener = make_listener(options->bind_ip, options->port);
    int control;
    uint32_t client_failures = 0;

    if (listener < 0) {
        return EXIT_FAILURE;
    }
    printf("READY server %s:%u\n", options->bind_ip, options->port);
    fflush(stdout);
    control = accept(listener, NULL, NULL);
    close(listener);
    if (control < 0 || set_recv_timeout(control, 120) != 0) {
        perror("control accept");
        return EXIT_FAILURE;
    }

    int protocol_error = 0;
    for (size_t index = 0; index < sizeof(test_cases) / sizeof(test_cases[0]); ++index) {
        if (case_selected(options, test_cases[index].name, test_cases[index].run_by_default) &&
            test_cases[index].server(options, control) != 0) {
            protocol_error = -1;
            break;
        }
    }
    if (options->test_case != NULL && strcmp(options->test_case, "send-close-tail") == 0) {
        close(control);
        printf("SUMMARY server failures=%d\n", failures);
        return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    if (protocol_error != 0) {
        fail("test protocol", "a case-specific coordination step failed");
    }
    if (expect_byte(control, CMD_DONE) != 0) {
        fail("test protocol", "server did not receive the final client marker");
        protocol_error = -1;
    }
    /* exit-listener stays outside test_cases[] on purpose: it raise(SIGINT)s this very
     * process, so it must run after every table case and after the final CMD_DONE marker -
     * the table has no ordering guarantee. Only the failure-count exchange follows it. */
    if (case_selected(options, "exit-listener", true) &&
        server_exit_listener_close(options, control) != 0) {
        fail("test protocol", "exit-listener coordination failed");
        protocol_error = -1;
    }
    if (recv_all(control, &client_failures, sizeof(client_failures)) != 0) {
        fail("test protocol", "server did not receive the client failure count");
        protocol_error = -1;
    }
    if (protocol_error == 0 && send_byte(control, CMD_ACK) != 0) {
        fail("test protocol", "server could not acknowledge the final client report");
        protocol_error = -1;
    }
    if (protocol_error != 0) {
        fail("test protocol", "server/client coordination failed");
    }
    if (client_failures != 0) {
        char detail[96];

        snprintf(detail, sizeof(detail), "client reported %" PRIu32 " local failure(s)",
                 client_failures);
        fail("client role", detail);
    }
    close(control);
    printf("SUMMARY server failures=%d\n", failures);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int run_client(const struct options *options)
{
    int control = connect_retry(options->bind_ip, options->server_ip, options->port);
    uint32_t client_failures = 0;

    if (control < 0 || set_recv_timeout(control, 120) != 0) {
        return EXIT_FAILURE;
    }
    for (size_t index = 0; index < sizeof(test_cases) / sizeof(test_cases[0]); ++index) {
        if (case_selected(options, test_cases[index].name, test_cases[index].run_by_default) &&
            test_cases[index].client(options, control) != 0) {
            ++client_failures;
        }
    }
    if (options->test_case != NULL && strcmp(options->test_case, "send-close-tail") == 0) {
        printf("SUMMARY client failures=%" PRIu32 "\n", client_failures);
        return client_failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    if (send_byte(control, CMD_DONE) != 0) {
        ++client_failures;
    }
    /* Post-CMD_DONE on purpose; see the exit-listener note in run_server(). */
    if (case_selected(options, "exit-listener", true) &&
        client_exit_listener_close(options, control) != 0) {
        ++client_failures;
    }
    if (send_all(control, &client_failures, sizeof(client_failures)) != 0 ||
        expect_byte(control, CMD_ACK) != 0) {
        ++client_failures;
    }
    close(control);
    printf("SUMMARY client failures=%" PRIu32 "\n", client_failures);
    return client_failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

static void usage(const char *program)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s server --bind IP [--port PORT] [--case NAME]\n"
            "  %s client --bind IP --server IP [--port PORT] [--case NAME]\n",
            program, program);
}

static int parse_options(int argc, char **argv, struct options *options)
{
    if (argc < 2) {
        return -1;
    }
    memset(options, 0, sizeof(*options));
    options->server = strcmp(argv[1], "server") == 0;
    if (!options->server && strcmp(argv[1], "client") != 0) {
        return -1;
    }
    options->port = 19500;

    for (int index = 2; index < argc; ++index) {
        if (strcmp(argv[index], "--bind") == 0 && index + 1 < argc) {
            options->bind_ip = argv[++index];
        } else if (strcmp(argv[index], "--server") == 0 && index + 1 < argc) {
            options->server_ip = argv[++index];
        } else if (strcmp(argv[index], "--case") == 0 && index + 1 < argc) {
            options->test_case = argv[++index];
        } else if (strcmp(argv[index], "--port") == 0 && index + 1 < argc) {
            char *end = NULL;
            unsigned long value = strtoul(argv[++index], &end, 10);

            if (end == argv[index] || *end != '\0' || value < 1024 ||
                value > UINT16_MAX - TEST_MAX_PORT_OFFSET) {
                return -1;
            }
            options->port = (uint16_t)value;
        } else {
            return -1;
        }
    }
    if (options->bind_ip == NULL || (!options->server && options->server_ip == NULL) ||
        !case_exists(options->test_case)) {
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct options options;
    struct sigaction action = {
        .sa_handler = handle_sigint,
    };

    signal(SIGPIPE, SIG_IGN);
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) != 0) {
        perror("sigaction(SIGINT)");
        return EXIT_FAILURE;
    }
    if (parse_options(argc, argv, &options) != 0) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    return options.server ? run_server(&options) : run_client(&options);
}
