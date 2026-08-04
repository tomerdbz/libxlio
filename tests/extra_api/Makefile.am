noinst_PROGRAMS = blocking_socket_workers_e2e blocking_connect_cancel_e2e

blocking_socket_workers_e2e_SOURCES = blocking_socket_workers_e2e.c
blocking_socket_workers_e2e_CFLAGS = -g -O2 -std=gnu11 -pthread -Wall -Wextra -Werror
blocking_socket_workers_e2e_LDFLAGS = -pthread

blocking_connect_cancel_e2e_SOURCES = blocking_connect_cancel_e2e.c
blocking_connect_cancel_e2e_CFLAGS = -g -O2 -std=gnu11 -pthread -Wall -Wextra -Werror
blocking_connect_cancel_e2e_LDFLAGS = -pthread

EXTRA_DIST = \
	xlio_ultra_api.c \
	xlio_ultra_api_migrate.c \
	xlio_ultra_api_server.c \
	README
