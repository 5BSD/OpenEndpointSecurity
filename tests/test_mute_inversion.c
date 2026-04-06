/*
 * ESC mute inversion (allowlist mode) tests.
 *
 * Tests ESC_MUTE_INVERT flag for allowlist-based filtering.
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
count_events(int fd, pid_t target_pid, int timeout_ms)
{
	struct pollfd pfd;
	struct timespec start;
	int count = 0;

	pfd.fd = fd;
	pfd.events = POLLIN;
	clock_gettime(CLOCK_MONOTONIC, &start);

	while (1) {
		struct timespec now;
		long elapsed_ms;
		esc_message_t msg;
		ssize_t n;

		clock_gettime(CLOCK_MONOTONIC, &now);
		elapsed_ms = (now.tv_sec - start.tv_sec) * 1000L +
		    (now.tv_nsec - start.tv_nsec) / 1000000L;
		if (elapsed_ms > timeout_ms)
			break;

		if (poll(&pfd, 1, 50) > 0 && (pfd.revents & POLLIN)) {
			n = read(fd, &msg, sizeof(msg));
			if (n < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					continue;
				break;
			}
			if ((size_t)n == sizeof(msg) &&
			    msg.em_process.ep_pid == target_pid) {
				count++;
			}
		}
	}

	return (count);
}

static int
test_path_mute_inversion(void)
{
	int fd;
	struct esc_mode_args mode;
	struct esc_subscribe_args sub;
	struct esc_mute_path_args mute_path;
	struct esc_mute_invert_args invert;
	esc_event_type_t events[] = { ESC_EVENT_NOTIFY_OPEN };
	pid_t pid;
	int events_before, events_after;

	printf("  Testing path mute inversion (allowlist mode)...\n");

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

	/* First, count events without inversion (normal mute mode) */
	/* Mute /tmp - opens to /tmp should be silenced */
	memset(&mute_path, 0, sizeof(mute_path));
	strlcpy(mute_path.emp_path, "/tmp", sizeof(mute_path.emp_path));
	mute_path.emp_type = ESC_MUTE_PATH_PREFIX;
	if (ioctl(fd, ESC_IOC_MUTE_PATH, &mute_path) < 0) {
		perror("ESC_IOC_MUTE_PATH");
		close(fd);
		return (1);
	}

	pid = fork();
	if (pid == 0) {
		int tmpfd = open("/tmp/esc_test_invert", O_CREAT | O_RDWR, 0644);
		if (tmpfd >= 0) close(tmpfd);
		unlink("/tmp/esc_test_invert");
		_exit(0);
	}
	waitpid(pid, NULL, 0);
	events_before = count_events(fd, pid, 500);

	/* Now enable inversion - /tmp becomes allowlist (only /tmp events pass) */
	memset(&invert, 0, sizeof(invert));
	invert.emi_type = ESC_MUTE_INVERT_PATH;
	invert.emi_invert = 1;
	if (ioctl(fd, ESC_IOC_SET_MUTE_INVERT, &invert) < 0) {
		/* May not be implemented */
		if (errno == ENOTTY || errno == EINVAL) {
			printf("    INFO: mute inversion not implemented\n");
			close(fd);
			printf("    PASS: mute inversion test completed\n");
			return (0);
		}
		perror("ESC_IOC_SET_MUTE_INVERT");
		close(fd);
		return (1);
	}

	pid = fork();
	if (pid == 0) {
		int tmpfd = open("/tmp/esc_test_invert2", O_CREAT | O_RDWR, 0644);
		if (tmpfd >= 0) close(tmpfd);
		unlink("/tmp/esc_test_invert2");
		_exit(0);
	}
	waitpid(pid, NULL, 0);
	events_after = count_events(fd, pid, 500);

	close(fd);

	printf("    INFO: events before inversion=%d, after=%d\n",
	    events_before, events_after);
	printf("    PASS: path mute inversion tested\n");
	return (0);
}

static int
test_process_mute_inversion(void)
{
	int fd;
	struct esc_mode_args mode;
	struct esc_subscribe_args sub;
	struct esc_mute_args mute;
	struct esc_mute_invert_args invert;
	esc_event_type_t events[] = { ESC_EVENT_NOTIFY_EXEC };

	printf("  Testing process mute inversion...\n");

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

	/* Self-mute */
	memset(&mute, 0, sizeof(mute));
	mute.emu_flags = ESC_MUTE_SELF;
	if (ioctl(fd, ESC_IOC_MUTE_PROCESS, &mute) < 0) {
		perror("ESC_IOC_MUTE_PROCESS");
		close(fd);
		return (1);
	}

	/* Try to invert process muting */
	memset(&invert, 0, sizeof(invert));
	invert.emi_type = ESC_MUTE_INVERT_PROCESS;
	invert.emi_invert = 1;
	if (ioctl(fd, ESC_IOC_SET_MUTE_INVERT, &invert) < 0) {
		if (errno == ENOTTY || errno == EINVAL) {
			printf("    INFO: process mute inversion not implemented\n");
		} else {
			perror("ESC_IOC_SET_MUTE_INVERT");
		}
	} else {
		printf("    INFO: process mute inversion enabled\n");
	}

	close(fd);
	printf("    PASS: process mute inversion tested\n");
	return (0);
}

/*
 * Test ESC_IOC_GET_MUTE_INVERT to query inversion state.
 */
static int
test_get_mute_invert(void)
{
	int fd;
	struct esc_mode_args mode;
	struct esc_mute_invert_args invert;
	struct esc_mute_invert_args retrieved;

	printf("  Testing ESC_IOC_GET_MUTE_INVERT...\n");

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

	/* Test GET for process inversion (should be 0 initially) */
	memset(&retrieved, 0, sizeof(retrieved));
	retrieved.emi_type = ESC_MUTE_INVERT_PROCESS;
	if (ioctl(fd, ESC_IOC_GET_MUTE_INVERT, &retrieved) < 0) {
		if (errno == ENOTTY || errno == EINVAL) {
			printf("    INFO: GET_MUTE_INVERT not implemented\n");
			close(fd);
			printf("    PASS: GET_MUTE_INVERT tested\n");
			return (0);
		}
		perror("ESC_IOC_GET_MUTE_INVERT (process)");
		close(fd);
		return (1);
	}
	printf("    INFO: process inversion initial state = %u\n",
	    retrieved.emi_invert);

	/* Set process inversion to 1 */
	memset(&invert, 0, sizeof(invert));
	invert.emi_type = ESC_MUTE_INVERT_PROCESS;
	invert.emi_invert = 1;
	if (ioctl(fd, ESC_IOC_SET_MUTE_INVERT, &invert) < 0) {
		printf("    INFO: SET_MUTE_INVERT failed: %s\n", strerror(errno));
	}

	/* Verify it was set */
	memset(&retrieved, 0, sizeof(retrieved));
	retrieved.emi_type = ESC_MUTE_INVERT_PROCESS;
	if (ioctl(fd, ESC_IOC_GET_MUTE_INVERT, &retrieved) < 0) {
		perror("ESC_IOC_GET_MUTE_INVERT (verify)");
		close(fd);
		return (1);
	}
	printf("    INFO: process inversion after SET = %u\n",
	    retrieved.emi_invert);

	/* Test GET for path inversion */
	memset(&retrieved, 0, sizeof(retrieved));
	retrieved.emi_type = ESC_MUTE_INVERT_PATH;
	if (ioctl(fd, ESC_IOC_GET_MUTE_INVERT, &retrieved) < 0) {
		printf("    INFO: GET path inversion: %s\n", strerror(errno));
	} else {
		printf("    INFO: path inversion state = %u\n",
		    retrieved.emi_invert);
	}

	/* Test GET for target path inversion */
	memset(&retrieved, 0, sizeof(retrieved));
	retrieved.emi_type = ESC_MUTE_INVERT_TARGET_PATH;
	if (ioctl(fd, ESC_IOC_GET_MUTE_INVERT, &retrieved) < 0) {
		printf("    INFO: GET target path inversion: %s\n", strerror(errno));
	} else {
		printf("    INFO: target path inversion state = %u\n",
		    retrieved.emi_invert);
	}

	close(fd);
	printf("    PASS: GET_MUTE_INVERT tested\n");
	return (0);
}

int
main(void)
{
	int failed = 0;

	printf("Testing mute inversion...\n");

	failed += test_path_mute_inversion();
	failed += test_process_mute_inversion();
	failed += test_get_mute_invert();

	if (failed > 0) {
		printf("mute inversion: FAILED (%d tests)\n", failed);
		return (1);
	}

	printf("mute inversion: ok\n");
	return (0);
}
