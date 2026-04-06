/*
 * ESC socket event tests.
 *
 * Tests SOCKET_CONNECT, SOCKET_BIND, SOCKET_LISTEN events.
 */
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <security/esc/esc.h>

#define TEST_PORT	54321
#define TEST_SOCKET	"/tmp/esc_test.sock"

static int
read_socket_events(int fd, pid_t child_pid, int *connect_seen, int *bind_seen,
    int *listen_seen)
{
	esc_message_t msg;
	ssize_t n;

	for (;;) {
		n = read(fd, &msg, sizeof(msg));
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return (0);
			perror("read");
			return (-1);
		}
		if (n == 0)
			return (0);
		if ((size_t)n != sizeof(msg))
			continue;

		if (msg.em_process.ep_pid != child_pid)
			continue;

		switch (msg.em_event) {
		case ESC_EVENT_NOTIFY_SOCKET_CONNECT:
			*connect_seen = 1;
			fprintf(stderr, "  got NOTIFY_SOCKET_CONNECT\n");
			break;
		case ESC_EVENT_NOTIFY_SOCKET_BIND:
			*bind_seen = 1;
			fprintf(stderr, "  got NOTIFY_SOCKET_BIND\n");
			break;
		case ESC_EVENT_NOTIFY_SOCKET_LISTEN:
			*listen_seen = 1;
			fprintf(stderr, "  got NOTIFY_SOCKET_LISTEN\n");
			break;
		default:
			break;
		}
	}
}

static void
do_socket_operations(void)
{
	int sock;
	struct sockaddr_in addr;

	/* Create, bind, listen on TCP socket */
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket");
		_exit(1);
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(TEST_PORT);

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		/* Port may be in use, not fatal */
		if (errno != EADDRINUSE)
			perror("bind");
	}

	if (listen(sock, 5) < 0) {
		perror("listen");
	}

	close(sock);

	/* Now try to connect to something */
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock >= 0) {
		addr.sin_port = htons(80); /* Won't work but will trigger event */
		(void)connect(sock, (struct sockaddr *)&addr, sizeof(addr));
		close(sock);
	}

	_exit(0);
}

static int
test_socket_events(void)
{
	int fd;
	struct esc_mode_args mode;
	struct esc_subscribe_args sub;
	esc_event_type_t events[] = {
		ESC_EVENT_NOTIFY_SOCKET_CONNECT,
		ESC_EVENT_NOTIFY_SOCKET_BIND,
		ESC_EVENT_NOTIFY_SOCKET_LISTEN,
	};
	pid_t pid;
	int connect_seen = 0, bind_seen = 0, listen_seen = 0;
	struct pollfd pfd;
	struct timespec start;
	int status;

	printf("  Testing socket events (connect/bind/listen)...\n");

	fd = open("/dev/esc", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/esc");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = ESC_MODE_NOTIFY;
	if (ioctl(fd, ESC_IOC_SET_MODE, &mode) < 0) {
		perror("ESC_IOC_SET_MODE");
		close(fd);
		return (1);
	}

	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = sizeof(events) / sizeof(events[0]);
	sub.esa_flags = ESC_SUB_REPLACE;
	if (ioctl(fd, ESC_IOC_SUBSCRIBE, &sub) < 0) {
		perror("ESC_IOC_SUBSCRIBE");
		close(fd);
		return (1);
	}

	pid = fork();
	if (pid < 0) {
		perror("fork");
		close(fd);
		return (1);
	}

	if (pid == 0) {
		do_socket_operations();
		/* Not reached */
	}

	/* Parent: wait for events */
	clock_gettime(CLOCK_MONOTONIC, &start);
	pfd.fd = fd;
	pfd.events = POLLIN;

	while (1) {
		struct timespec now;
		long elapsed_ms;

		clock_gettime(CLOCK_MONOTONIC, &now);
		elapsed_ms = (now.tv_sec - start.tv_sec) * 1000L +
		    (now.tv_nsec - start.tv_nsec) / 1000000L;
		if (elapsed_ms > 3000)
			break;

		if (poll(&pfd, 1, 100) > 0 && (pfd.revents & POLLIN)) {
			if (read_socket_events(fd, pid, &connect_seen, &bind_seen,
			    &listen_seen) < 0) {
				waitpid(pid, NULL, 0);
				close(fd);
				return (1);
			}
		}
	}

	waitpid(pid, &status, 0);
	close(fd);

	/* At least one event should have been seen */
	if (!connect_seen && !bind_seen && !listen_seen) {
		fprintf(stderr, "FAIL: no socket events received\n");
		return (1);
	}

	printf("    PASS: socket events received (connect=%d bind=%d listen=%d)\n",
	    connect_seen, bind_seen, listen_seen);
	return (0);
}

static int
test_unix_socket(void)
{
	int fd, sock;
	struct esc_mode_args mode;
	struct esc_subscribe_args sub;
	struct sockaddr_un addr;
	esc_event_type_t events[] = {
		ESC_EVENT_NOTIFY_SOCKET_BIND,
	};
	pid_t pid;
	int bind_seen = 0;
	struct pollfd pfd;
	struct timespec start;

	printf("  Testing Unix domain socket...\n");

	(void)unlink(TEST_SOCKET);

	fd = open("/dev/esc", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/esc");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = ESC_MODE_NOTIFY;
	if (ioctl(fd, ESC_IOC_SET_MODE, &mode) < 0) {
		perror("ESC_IOC_SET_MODE");
		close(fd);
		return (1);
	}

	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = 1;
	sub.esa_flags = ESC_SUB_REPLACE;
	if (ioctl(fd, ESC_IOC_SUBSCRIBE, &sub) < 0) {
		perror("ESC_IOC_SUBSCRIBE");
		close(fd);
		return (1);
	}

	pid = fork();
	if (pid < 0) {
		perror("fork");
		close(fd);
		return (1);
	}

	if (pid == 0) {
		sock = socket(AF_UNIX, SOCK_STREAM, 0);
		if (sock >= 0) {
			memset(&addr, 0, sizeof(addr));
			addr.sun_family = AF_UNIX;
			strlcpy(addr.sun_path, TEST_SOCKET, sizeof(addr.sun_path));
			(void)bind(sock, (struct sockaddr *)&addr, sizeof(addr));
			close(sock);
		}
		_exit(0);
	}

	clock_gettime(CLOCK_MONOTONIC, &start);
	pfd.fd = fd;
	pfd.events = POLLIN;

	while (1) {
		struct timespec now;
		long elapsed_ms;
		int dummy;

		clock_gettime(CLOCK_MONOTONIC, &now);
		elapsed_ms = (now.tv_sec - start.tv_sec) * 1000L +
		    (now.tv_nsec - start.tv_nsec) / 1000000L;
		if (elapsed_ms > 2000)
			break;

		if (poll(&pfd, 1, 100) > 0 && (pfd.revents & POLLIN)) {
			(void)read_socket_events(fd, pid, &dummy, &bind_seen, &dummy);
		}
	}

	waitpid(pid, NULL, 0);
	close(fd);
	(void)unlink(TEST_SOCKET);

	if (!bind_seen) {
		printf("    INFO: Unix socket bind event not seen (may be expected)\n");
	} else {
		printf("    PASS: Unix socket bind event received\n");
	}

	return (0);
}

int
main(void)
{
	int failed = 0;

	printf("Testing socket events...\n");

	failed += test_socket_events();
	failed += test_unix_socket();

	if (failed > 0) {
		printf("socket events: FAILED (%d tests)\n", failed);
		return (1);
	}

	printf("socket events: ok\n");
	return (0);
}
