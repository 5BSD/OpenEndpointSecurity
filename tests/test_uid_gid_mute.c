/*
 * ESC UID/GID muting test.
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
wait_for_event(int fd, pid_t pid, esc_event_type_t event, int timeout_ms,
    esc_message_t *out)
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
			if (msg.em_event != event)
				continue;
			if (out != NULL)
				*out = msg;
			return (0);
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
	struct esc_mute_args mute;
	struct esc_mute_uid_args uid_mute;
	struct esc_mute_gid_args gid_mute;
	esc_event_type_t events[] = {
		ESC_EVENT_NOTIFY_OPEN,
	};
	int pipefd[2];
	pid_t child;
	int status;
	char cmd;
	int ret;

	fd = open("/dev/esc", O_RDWR | O_NONBLOCK);
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

	/* Self-mute to avoid noise from this process. */
	memset(&mute, 0, sizeof(mute));
	mute.emu_flags = ESC_MUTE_SELF;
	if (ioctl(fd, ESC_IOC_MUTE_PROCESS, &mute) < 0) {
		perror("ESC_IOC_MUTE_PROCESS (self)");
		close(fd);
		return (1);
	}

	if (pipe(pipefd) != 0) {
		perror("pipe");
		close(fd);
		return (1);
	}

	child = fork();
	if (child < 0) {
		perror("fork");
		close(fd);
		return (1);
	}

	if (child == 0) {
		close(fd);
		close(pipefd[1]);
		for (;;) {
			if (read(pipefd[0], &cmd, 1) != 1)
				break;
			if (cmd == 'q')
				break;
			if (cmd == 'o')
				(void)open("/etc/hosts", O_RDONLY);
		}
		close(pipefd[0]);
		_exit(0);
	}

	close(pipefd[0]);

	/* Test 1: Verify child events are received normally. */
	cmd = 'o';
	(void)write(pipefd[1], &cmd, 1);
	ret = wait_for_event(fd, child, ESC_EVENT_NOTIFY_OPEN, 2000, NULL);
	if (ret != 0) {
		fprintf(stderr, "expected child open event (baseline)\n");
		goto fail;
	}

	/* Test 2: Mute our own UID and verify child events are suppressed. */
	memset(&uid_mute, 0, sizeof(uid_mute));
	uid_mute.emu_uid = getuid();
	if (ioctl(fd, ESC_IOC_MUTE_UID, &uid_mute) < 0) {
		perror("ESC_IOC_MUTE_UID");
		goto fail;
	}

	cmd = 'o';
	(void)write(pipefd[1], &cmd, 1);
	ret = wait_for_event(fd, child, ESC_EVENT_NOTIFY_OPEN, 500, NULL);
	if (ret == 0) {
		fprintf(stderr, "UID mute failed (event still delivered)\n");
		goto fail;
	}

	/* Test 3: Unmute UID and verify events resume. */
	if (ioctl(fd, ESC_IOC_UNMUTE_UID, &uid_mute) < 0) {
		perror("ESC_IOC_UNMUTE_UID");
		goto fail;
	}

	cmd = 'o';
	(void)write(pipefd[1], &cmd, 1);
	ret = wait_for_event(fd, child, ESC_EVENT_NOTIFY_OPEN, 2000, NULL);
	if (ret != 0) {
		fprintf(stderr, "UID unmute failed (event missing)\n");
		goto fail;
	}

	/* Test 4: Mute our own GID and verify child events are suppressed. */
	memset(&gid_mute, 0, sizeof(gid_mute));
	gid_mute.emg_gid = getgid();
	if (ioctl(fd, ESC_IOC_MUTE_GID, &gid_mute) < 0) {
		perror("ESC_IOC_MUTE_GID");
		goto fail;
	}

	cmd = 'o';
	(void)write(pipefd[1], &cmd, 1);
	ret = wait_for_event(fd, child, ESC_EVENT_NOTIFY_OPEN, 500, NULL);
	if (ret == 0) {
		fprintf(stderr, "GID mute failed (event still delivered)\n");
		goto fail;
	}

	/* Test 5: Unmute GID and verify events resume. */
	if (ioctl(fd, ESC_IOC_UNMUTE_GID, &gid_mute) < 0) {
		perror("ESC_IOC_UNMUTE_GID");
		goto fail;
	}

	cmd = 'o';
	(void)write(pipefd[1], &cmd, 1);
	ret = wait_for_event(fd, child, ESC_EVENT_NOTIFY_OPEN, 2000, NULL);
	if (ret != 0) {
		fprintf(stderr, "GID unmute failed (event missing)\n");
		goto fail;
	}

	/* Test 6: Mute both UID and GID, then unmute all. */
	if (ioctl(fd, ESC_IOC_MUTE_UID, &uid_mute) < 0) {
		perror("ESC_IOC_MUTE_UID (2)");
		goto fail;
	}
	if (ioctl(fd, ESC_IOC_MUTE_GID, &gid_mute) < 0) {
		perror("ESC_IOC_MUTE_GID (2)");
		goto fail;
	}

	cmd = 'o';
	(void)write(pipefd[1], &cmd, 1);
	ret = wait_for_event(fd, child, ESC_EVENT_NOTIFY_OPEN, 500, NULL);
	if (ret == 0) {
		fprintf(stderr, "UID+GID mute failed (event still delivered)\n");
		goto fail;
	}

	if (ioctl(fd, ESC_IOC_UNMUTE_ALL_UIDS, NULL) < 0) {
		perror("ESC_IOC_UNMUTE_ALL_UIDS");
		goto fail;
	}
	if (ioctl(fd, ESC_IOC_UNMUTE_ALL_GIDS, NULL) < 0) {
		perror("ESC_IOC_UNMUTE_ALL_GIDS");
		goto fail;
	}

	cmd = 'o';
	(void)write(pipefd[1], &cmd, 1);
	ret = wait_for_event(fd, child, ESC_EVENT_NOTIFY_OPEN, 2000, NULL);
	if (ret != 0) {
		fprintf(stderr, "unmute all UIDs/GIDs failed (event missing)\n");
		goto fail;
	}

	cmd = 'q';
	(void)write(pipefd[1], &cmd, 1);
	(void)waitpid(child, &status, 0);
	close(pipefd[1]);
	close(fd);

	printf("uid_gid_mute: ok\n");
	return (0);

fail:
	cmd = 'q';
	(void)write(pipefd[1], &cmd, 1);
	(void)waitpid(child, &status, 0);
	close(pipefd[1]);
	close(fd);
	return (1);
}
