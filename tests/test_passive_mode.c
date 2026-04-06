/*
 * ESC PASSIVE mode smoke test (AUTH -> NOTIFY conversion).
 */
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <security/esc/esc.h>

static int
wait_for_exec(int fd, pid_t pid, int timeout_ms)
{
	struct pollfd pfd;
	struct timespec start;

	pfd.fd = fd;
	pfd.events = POLLIN;
	clock_gettime(CLOCK_MONOTONIC, &start);

	for (;;) {
		struct timespec now;
		long elapsed_ms;

		clock_gettime(CLOCK_MONOTONIC, &now);
		elapsed_ms = (now.tv_sec - start.tv_sec) * 1000L +
		    (now.tv_nsec - start.tv_nsec) / 1000000L;
		if (elapsed_ms >= timeout_ms)
			break;

		if (poll(&pfd, 1, 100) > 0 && (pfd.revents & POLLIN)) {
			esc_message_t msg;
			ssize_t n = read(fd, &msg, sizeof(msg));
			if (n < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					continue;
				perror("read");
				return (-1);
			}
			if ((size_t)n != sizeof(msg))
				continue;

			if (msg.em_process.ep_pid != pid)
				continue;

			if (msg.em_event == ESC_EVENT_AUTH_EXEC) {
				fprintf(stderr, "received AUTH exec in PASSIVE mode\n");
				return (-1);
			}

			if (msg.em_event == ESC_EVENT_NOTIFY_EXEC &&
			    msg.em_action == ESC_ACTION_NOTIFY) {
				return (0);
			}
		}
	}

	return (ETIMEDOUT);
}

int
main(void)
{
	int fd;
	struct esc_mode_args mode;
	struct esc_subscribe_args sub;
	esc_event_type_t events[] = {
		ESC_EVENT_AUTH_EXEC,
	};
	pid_t pid;
	int status;
	int rc;

	fd = open("/dev/esc", O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		perror("open /dev/esc");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = ESC_MODE_PASSIVE;
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
		close(fd);
		execl("/usr/bin/true", "true", (char *)NULL);
		_exit(127);
	}

	rc = wait_for_exec(fd, pid, 5000);
	(void)waitpid(pid, &status, 0);
	close(fd);

	if (rc != 0) {
		if (rc == ETIMEDOUT)
			fprintf(stderr, "PASSIVE exec timeout\n");
		return (1);
	}

	printf("passive mode: ok\n");
	return (0);
}
