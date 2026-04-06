/*
 * ESC multi-client AUTH arbitration test.
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

#define RESP_NONE 2

static int
wait_for_auth_open(int fd, pid_t pid, int timeout_ms, esc_message_t *out)
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
			if (msg.em_event != ESC_EVENT_AUTH_OPEN)
				continue;
			if (msg.em_action != ESC_ACTION_AUTH)
				continue;
			if (msg.em_process.ep_pid != pid)
				continue;
			if (out != NULL)
				*out = msg;
			return (0);
		}
	}

	return (ETIMEDOUT);
}

static int
setup_auth_client(int *out_fd, uint32_t timeout_ms,
    esc_auth_result_t timeout_action)
{
	int fd;
	struct esc_mode_args mode;
	struct esc_timeout_action_args action;
	struct esc_subscribe_args sub;
	esc_event_type_t events[] = {
		ESC_EVENT_AUTH_OPEN,
	};

	fd = open("/dev/esc", O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		perror("open /dev/esc");
		return (-1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = ESC_MODE_AUTH;
	mode.ema_timeout_ms = timeout_ms;
	if (ioctl(fd, ESC_IOC_SET_MODE, &mode) < 0) {
		perror("ESC_IOC_SET_MODE");
		close(fd);
		return (-1);
	}

	memset(&action, 0, sizeof(action));
	action.eta_action = timeout_action;
	if (ioctl(fd, ESC_IOC_SET_TIMEOUT_ACTION, &action) < 0) {
		perror("ESC_IOC_SET_TIMEOUT_ACTION");
		close(fd);
		return (-1);
	}

	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = sizeof(events) / sizeof(events[0]);
	sub.esa_flags = ESC_SUB_REPLACE;
	if (ioctl(fd, ESC_IOC_SUBSCRIBE, &sub) < 0) {
		perror("ESC_IOC_SUBSCRIBE");
		close(fd);
		return (-1);
	}

	*out_fd = fd;
	return (0);
}

static int
run_scenario(const char *name, esc_auth_result_t r1, esc_auth_result_t r2,
    int timeout2, int expect_errno)
{
	int fd1;
	int fd2;
	int ctl_pipe[2];
	int res_pipe[2];
	pid_t child;
	esc_message_t msg1;
	esc_message_t msg2;
	esc_response_t resp;
	int err = 0;
	int status;
	char cmd = 'g';

	if (setup_auth_client(&fd1, 500, ESC_AUTH_ALLOW) != 0)
		return (1);
	if (setup_auth_client(&fd2, timeout2, ESC_AUTH_DENY) != 0) {
		close(fd1);
		return (1);
	}

	if (pipe(ctl_pipe) != 0 || pipe(res_pipe) != 0) {
		perror("pipe");
		close(fd1);
		close(fd2);
		return (1);
	}

	child = fork();
	if (child < 0) {
		perror("fork");
		close(fd1);
		close(fd2);
		return (1);
	}
	if (child == 0) {
		int child_err = 0;
		int child_fd;

		close(fd1);
		close(fd2);
		close(ctl_pipe[1]);
		close(res_pipe[0]);
		if (read(ctl_pipe[0], &cmd, 1) != 1)
			_exit(1);
		child_fd = open("/etc/hosts", O_RDONLY);
		if (child_fd < 0)
			child_err = errno;
		else
			close(child_fd);
		(void)write(res_pipe[1], &child_err, sizeof(child_err));
		_exit(0);
	}

	close(ctl_pipe[0]);
	close(res_pipe[1]);

	(void)write(ctl_pipe[1], &cmd, 1);

	if (wait_for_auth_open(fd1, child, 2000, &msg1) != 0 ||
	    wait_for_auth_open(fd2, child, 2000, &msg2) != 0) {
		fprintf(stderr, "%s: missing AUTH open event\n", name);
		goto fail;
	}

	memset(&resp, 0, sizeof(resp));
	resp.er_id = msg1.em_id;
	resp.er_result = r1;
	if (write(fd1, &resp, sizeof(resp)) != (ssize_t)sizeof(resp)) {
		fprintf(stderr, "%s: failed to respond fd1\n", name);
		goto fail;
	}

	if (r2 != ESC_AUTH_ALLOW && r2 != ESC_AUTH_DENY) {
		/* No response for fd2 (timeout scenario). */
	} else {
		memset(&resp, 0, sizeof(resp));
		resp.er_id = msg2.em_id;
		resp.er_result = r2;
		if (write(fd2, &resp, sizeof(resp)) != (ssize_t)sizeof(resp)) {
			fprintf(stderr, "%s: failed to respond fd2\n", name);
			goto fail;
		}
	}

	if (read(res_pipe[0], &err, sizeof(err)) != (ssize_t)sizeof(err)) {
		fprintf(stderr, "%s: failed to read child result\n", name);
		goto fail;
	}

	(void)waitpid(child, &status, 0);
	close(ctl_pipe[1]);
	close(res_pipe[0]);
	close(fd1);
	close(fd2);

	if (err != expect_errno) {
		fprintf(stderr, "%s: expected errno %d, got %d\n",
		    name, expect_errno, err);
		return (1);
	}

	return (0);

fail:
	(void)waitpid(child, &status, 0);
	close(ctl_pipe[1]);
	close(res_pipe[0]);
	close(fd1);
	close(fd2);
	return (1);
}

int
main(void)
{
	if (run_scenario("allow", ESC_AUTH_ALLOW, ESC_AUTH_ALLOW,
	    500, 0) != 0)
		return (1);
	if (run_scenario("deny", ESC_AUTH_ALLOW, ESC_AUTH_DENY,
	    500, EACCES) != 0)
		return (1);
	if (run_scenario("timeout", ESC_AUTH_ALLOW, RESP_NONE, 200, EACCES) != 0)
		return (1);

	printf("multi-client auth: ok\n");
	return (0);
}
