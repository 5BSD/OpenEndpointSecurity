/*
 * ESC process event smoke test (fork/exec/exit).
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

static const char *
event_name(uint32_t ev)
{
	switch (ev) {
	case ESC_EVENT_NOTIFY_FORK:
		return "NOTIFY_FORK";
	case ESC_EVENT_NOTIFY_EXEC:
		return "NOTIFY_EXEC";
	case ESC_EVENT_NOTIFY_EXIT:
		return "NOTIFY_EXIT";
	default:
		return "UNKNOWN";
	}
}

static int
read_events(int fd, pid_t child_pid, int *fork_seen, int *exec_seen,
    int *exit_seen)
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

		fprintf(stderr, "got event 0x%x pid=%d (want %d)\n",
		    msg.em_event, msg.em_process.ep_pid, child_pid);

		switch (msg.em_event) {
		case ESC_EVENT_NOTIFY_FORK:
			if (msg.em_event_data.fork.child.ep_pid == child_pid)
				*fork_seen = 1;
			break;
		case ESC_EVENT_NOTIFY_EXEC:
			if (msg.em_process.ep_pid == child_pid)
				*exec_seen = 1;
			break;
		case ESC_EVENT_NOTIFY_EXIT:
			if (msg.em_process.ep_pid == child_pid)
				*exit_seen = 1;
			break;
		default:
			break;
		}
	}
}

int
main(void)
{
	int fd;
	struct esc_mode_args mode;
	struct esc_subscribe_args sub;
	esc_event_type_t events[] = {
		ESC_EVENT_NOTIFY_FORK,
		ESC_EVENT_NOTIFY_EXEC,
		ESC_EVENT_NOTIFY_EXIT,
	};
	pid_t pid;
	int fork_seen = 0;
	int exec_seen = 0;
	int exit_seen = 0;
	int status;
	struct pollfd pfd;
	struct timespec start;

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

	/*
	 * Unmute ourselves so we receive NOTIFY_FORK events.
	 * By default (security.esc.default_self_mute=1), the client process
	 * is self-muted. FORK events have em_process set to the parent (us),
	 * so they would be filtered out unless we unmute.
	 *
	 * Use UNMUTE_ALL_PROCESSES which clears the self-mute flag.
	 */
	if (ioctl(fd, ESC_IOC_UNMUTE_ALL_PROCESSES, NULL) < 0) {
		perror("ESC_IOC_UNMUTE_ALL_PROCESSES");
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
		/* O_CLOEXEC will close fd during exec */
		execl("/usr/bin/true", "true", (char *)NULL);
		_exit(127);
	}

	clock_gettime(CLOCK_MONOTONIC, &start);
	pfd.fd = fd;
	pfd.events = POLLIN;

	while (1) {
		struct timespec now;
		long elapsed_ms;

		clock_gettime(CLOCK_MONOTONIC, &now);
		elapsed_ms = (now.tv_sec - start.tv_sec) * 1000L +
		    (now.tv_nsec - start.tv_nsec) / 1000000L;
		if (elapsed_ms > 5000)
			break;

		if (poll(&pfd, 1, 100) > 0 && (pfd.revents & POLLIN)) {
			if (read_events(fd, pid, &fork_seen, &exec_seen,
			    &exit_seen) < 0) {
				close(fd);
				return (1);
			}
		}

		if (fork_seen && exec_seen && exit_seen)
			break;
	}

	(void)waitpid(pid, &status, 0);
	if (WIFEXITED(status)) {
		int code = WEXITSTATUS(status);
		if (code == 127)
			fprintf(stderr, "child exec failed (exit 127)\n");
		else if (code != 0)
			fprintf(stderr, "child exited with status %d\n", code);
	} else if (WIFSIGNALED(status)) {
		fprintf(stderr, "child killed by signal %d\n", WTERMSIG(status));
	}
	close(fd);

	if (!fork_seen || !exec_seen || !exit_seen) {
		fprintf(stderr, "missing:");
		if (!fork_seen)
			fprintf(stderr, " %s", event_name(ESC_EVENT_NOTIFY_FORK));
		if (!exec_seen)
			fprintf(stderr, " %s", event_name(ESC_EVENT_NOTIFY_EXEC));
		if (!exit_seen)
			fprintf(stderr, " %s", event_name(ESC_EVENT_NOTIFY_EXIT));
		fprintf(stderr, "\n");
		return (1);
	}

	printf("process events: ok\n");
	return (0);
}
