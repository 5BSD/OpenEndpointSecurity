/*
 * ESC vnode event smoke test for common VFS operations.
 */
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/extattr.h>
#include <sys/acl.h>

#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <security/esc/esc.h>

#define EVT_OPEN		(1u << 0)
#define EVT_CREATE		(1u << 1)
#define EVT_UNLINK		(1u << 2)
#define EVT_RENAME		(1u << 3)
#define EVT_ACCESS		(1u << 4)
#define EVT_READ		(1u << 5)
#define EVT_WRITE		(1u << 6)
#define EVT_LOOKUP		(1u << 7)
#define EVT_SETMODE		(1u << 8)
#define EVT_SETOWNER		(1u << 9)
#define EVT_SETFLAGS		(1u << 10)
#define EVT_SETUTIMES		(1u << 11)
#define EVT_STAT		(1u << 12)
#define EVT_POLL		(1u << 13)
#define EVT_REVOKE		(1u << 14)
#define EVT_READDIR		(1u << 15)
#define EVT_READLINK		(1u << 16)
#define EVT_SETEXTATTR		(1u << 17)
#define EVT_GETEXTATTR		(1u << 18)
#define EVT_DELETEEXTATTR	(1u << 19)
#define EVT_LISTEXTATTR		(1u << 20)
#define EVT_GETACL		(1u << 21)
#define EVT_SETACL		(1u << 22)
#define EVT_DELETEACL		(1u << 23)
#define EVT_RELABEL		(1u << 24)

static int
read_events(int fd, pid_t child_pid, uint64_t *seen_mask)
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
		case ESC_EVENT_NOTIFY_OPEN:
			*seen_mask |= EVT_OPEN;
			break;
		case ESC_EVENT_NOTIFY_CREATE:
			*seen_mask |= EVT_CREATE;
			break;
		case ESC_EVENT_NOTIFY_UNLINK:
			*seen_mask |= EVT_UNLINK;
			break;
		case ESC_EVENT_NOTIFY_RENAME:
			*seen_mask |= EVT_RENAME;
			break;
		case ESC_EVENT_NOTIFY_ACCESS:
			*seen_mask |= EVT_ACCESS;
			break;
		case ESC_EVENT_NOTIFY_READ:
			*seen_mask |= EVT_READ;
			break;
		case ESC_EVENT_NOTIFY_WRITE:
			*seen_mask |= EVT_WRITE;
			break;
		case ESC_EVENT_NOTIFY_LOOKUP:
			*seen_mask |= EVT_LOOKUP;
			break;
		case ESC_EVENT_NOTIFY_SETMODE:
			*seen_mask |= EVT_SETMODE;
			break;
		case ESC_EVENT_NOTIFY_SETOWNER:
			*seen_mask |= EVT_SETOWNER;
			break;
		case ESC_EVENT_NOTIFY_SETFLAGS:
			*seen_mask |= EVT_SETFLAGS;
			break;
		case ESC_EVENT_NOTIFY_SETUTIMES:
			*seen_mask |= EVT_SETUTIMES;
			break;
		case ESC_EVENT_NOTIFY_SETEXTATTR:
			*seen_mask |= EVT_SETEXTATTR;
			break;
		case ESC_EVENT_NOTIFY_STAT:
			*seen_mask |= EVT_STAT;
			break;
		case ESC_EVENT_NOTIFY_POLL:
			*seen_mask |= EVT_POLL;
			break;
		case ESC_EVENT_NOTIFY_REVOKE:
			*seen_mask |= EVT_REVOKE;
			break;
		case ESC_EVENT_NOTIFY_READDIR:
			*seen_mask |= EVT_READDIR;
			break;
		case ESC_EVENT_NOTIFY_READLINK:
			*seen_mask |= EVT_READLINK;
			break;
		case ESC_EVENT_NOTIFY_GETEXTATTR:
			*seen_mask |= EVT_GETEXTATTR;
			break;
		case ESC_EVENT_NOTIFY_DELETEEXTATTR:
			*seen_mask |= EVT_DELETEEXTATTR;
			break;
		case ESC_EVENT_NOTIFY_LISTEXTATTR:
			*seen_mask |= EVT_LISTEXTATTR;
			break;
		case ESC_EVENT_NOTIFY_GETACL:
			*seen_mask |= EVT_GETACL;
			break;
		case ESC_EVENT_NOTIFY_SETACL:
			*seen_mask |= EVT_SETACL;
			break;
		case ESC_EVENT_NOTIFY_DELETEACL:
			*seen_mask |= EVT_DELETEACL;
			break;
		case ESC_EVENT_NOTIFY_RELABEL:
			*seen_mask |= EVT_RELABEL;
			break;
		default:
			break;
		}
	}
}

static int
child_ops(int write_fd)
{
	uint64_t ok = 0;
	char path[] = "/tmp/esc-vnode.XXXXXX";
	char newpath[PATH_MAX];
	char linkpath[PATH_MAX];
	char linktarget[PATH_MAX];
	int fd;
	char buf[16];
	struct timeval tv[2];
	struct stat st;
	struct timeval now;
	struct pollfd pfd;
	DIR *dirp;
	struct dirent *dent;
	ssize_t rlen;
	acl_t acl;
	ssize_t extlen;
	char extbuf[64];

	fd = mkstemp(path);
	if (fd < 0)
		goto done;
	ok |= EVT_CREATE;
	ok |= EVT_OPEN;

	pfd.fd = fd;
	pfd.events = POLLIN;
	if (poll(&pfd, 1, 0) >= 0)
		ok |= EVT_POLL;

	if (write(fd, "esc", 3) == 3)
		ok |= EVT_WRITE;

	if (lseek(fd, 0, SEEK_SET) >= 0) {
		if (read(fd, buf, sizeof(buf)) > 0)
			ok |= EVT_READ;
	}

	if (access(path, R_OK) == 0)
		ok |= EVT_ACCESS;

	if (stat(path, &st) == 0)
		ok |= EVT_LOOKUP;
	if (stat(path, &st) == 0)
		ok |= EVT_STAT;

	if (chmod(path, 0640) == 0)
		ok |= EVT_SETMODE;

	if (chown(path, getuid(), getgid()) == 0)
		ok |= EVT_SETOWNER;

	if (chflags(path, UF_NODUMP) == 0)
		ok |= EVT_SETFLAGS;

	if (stat(path, &st) == 0) {
		tv[0].tv_sec = st.st_atime;
		tv[0].tv_usec = 0;
		tv[1].tv_sec = st.st_mtime;
		tv[1].tv_usec = 0;
	} else if (gettimeofday(&now, NULL) == 0) {
		tv[0] = now;
		tv[1] = now;
	} else {
		tv[0].tv_sec = 0;
		tv[0].tv_usec = 0;
		tv[1].tv_sec = 0;
		tv[1].tv_usec = 0;
	}
	if (utimes(path, tv) == 0)
		ok |= EVT_SETUTIMES;

	dirp = opendir("/tmp");
	if (dirp != NULL) {
		dent = readdir(dirp);
		if (dent != NULL)
			ok |= EVT_READDIR;
		closedir(dirp);
	}

	snprintf(linkpath, sizeof(linkpath), "%s.link", path);
	if (symlink(path, linkpath) == 0) {
		rlen = readlink(linkpath, linktarget, sizeof(linktarget) - 1);
		if (rlen >= 0)
			ok |= EVT_READLINK;
		unlink(linkpath);
	}

	extlen = extattr_set_file(path, EXTATTR_NAMESPACE_USER,
	    "esc.test", "x", 1);
	if (extlen >= 0)
		ok |= EVT_SETEXTATTR;
	extlen = extattr_get_file(path, EXTATTR_NAMESPACE_USER,
	    "esc.test", extbuf, sizeof(extbuf));
	if (extlen >= 0)
		ok |= EVT_GETEXTATTR;
	extlen = extattr_list_file(path, EXTATTR_NAMESPACE_USER,
	    extbuf, sizeof(extbuf));
	if (extlen >= 0)
		ok |= EVT_LISTEXTATTR;
	if (extattr_delete_file(path, EXTATTR_NAMESPACE_USER,
	    "esc.test") == 0)
		ok |= EVT_DELETEEXTATTR;

	acl = acl_get_file(path, ACL_TYPE_ACCESS);
	if (acl != NULL) {
		ok |= EVT_GETACL;
		if (acl_set_file(path, ACL_TYPE_ACCESS, acl) == 0)
			ok |= EVT_SETACL;
		acl_free(acl);
	}
	if (acl_delete_file_np(path, ACL_TYPE_ACCESS) == 0)
		ok |= EVT_DELETEACL;

	close(fd);

	snprintf(newpath, sizeof(newpath), "%s.renamed", path);
	if (rename(path, newpath) == 0)
		ok |= EVT_RENAME;
	else
		strlcpy(newpath, path, sizeof(newpath));

	if (revoke(newpath) == 0)
		ok |= EVT_REVOKE;

	if (unlink(newpath) == 0)
		ok |= EVT_UNLINK;

done:
	(void)write(write_fd, &ok, sizeof(ok));
	return (0);
}

int
main(void)
{
	int fd;
	int pipefd[2];
	struct esc_mode_args mode;
	struct esc_subscribe_args sub;
	esc_event_type_t events[] = {
		ESC_EVENT_NOTIFY_OPEN,
		ESC_EVENT_NOTIFY_CREATE,
		ESC_EVENT_NOTIFY_UNLINK,
		ESC_EVENT_NOTIFY_RENAME,
		ESC_EVENT_NOTIFY_ACCESS,
		ESC_EVENT_NOTIFY_READ,
		ESC_EVENT_NOTIFY_WRITE,
		ESC_EVENT_NOTIFY_LOOKUP,
		ESC_EVENT_NOTIFY_SETMODE,
		ESC_EVENT_NOTIFY_SETOWNER,
		ESC_EVENT_NOTIFY_SETFLAGS,
		ESC_EVENT_NOTIFY_SETUTIMES,
		ESC_EVENT_NOTIFY_SETEXTATTR,
		ESC_EVENT_NOTIFY_STAT,
		ESC_EVENT_NOTIFY_POLL,
		ESC_EVENT_NOTIFY_REVOKE,
		ESC_EVENT_NOTIFY_READDIR,
		ESC_EVENT_NOTIFY_READLINK,
		ESC_EVENT_NOTIFY_GETEXTATTR,
		ESC_EVENT_NOTIFY_DELETEEXTATTR,
		ESC_EVENT_NOTIFY_LISTEXTATTR,
		ESC_EVENT_NOTIFY_GETACL,
		ESC_EVENT_NOTIFY_SETACL,
		ESC_EVENT_NOTIFY_DELETEACL,
		ESC_EVENT_NOTIFY_RELABEL,
	};
	pid_t pid;
	int status;
	struct pollfd pfd;
	struct timespec start;
	uint64_t seen_mask = 0;
	uint64_t ok_mask = 0;
	uint64_t expected_mask = 0;
	int ok_received = 0;
	int child_done = 0;

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

	if (pipe(pipefd) != 0) {
		perror("pipe");
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
		close(pipefd[0]);
		(void)child_ops(pipefd[1]);
		close(pipefd[1]);
		_exit(0);
	}

	close(pipefd[1]);
	(void)fcntl(pipefd[0], F_SETFL, O_NONBLOCK);

	clock_gettime(CLOCK_MONOTONIC, &start);
	pfd.fd = fd;
	pfd.events = POLLIN;

	while (1) {
		struct timespec now;
		long elapsed_ms;
		ssize_t nread;

		clock_gettime(CLOCK_MONOTONIC, &now);
		elapsed_ms = (now.tv_sec - start.tv_sec) * 1000L +
		    (now.tv_nsec - start.tv_nsec) / 1000000L;
		if (elapsed_ms > 5000)
			break;

		if (poll(&pfd, 1, 100) > 0 && (pfd.revents & POLLIN)) {
			if (read_events(fd, pid, &seen_mask) < 0) {
				close(fd);
				close(pipefd[0]);
				return (1);
			}
		}

		if (!ok_received) {
			nread = read(pipefd[0], &ok_mask, sizeof(ok_mask));
			if (nread == (ssize_t)sizeof(ok_mask))
				ok_received = 1;
		}

		if (!child_done) {
			if (waitpid(pid, &status, WNOHANG) > 0)
				child_done = 1;
		}

		if (ok_received) {
			expected_mask = ok_mask;
			if ((seen_mask & expected_mask) == expected_mask &&
			    child_done)
				break;
		}
	}

	if (!child_done)
		(void)waitpid(pid, &status, 0);
	if (!ok_received) {
		ssize_t nread = read(pipefd[0], &ok_mask, sizeof(ok_mask));
		if (nread == (ssize_t)sizeof(ok_mask))
			ok_received = 1;
	}

	close(pipefd[0]);
	close(fd);

	if (!ok_received) {
		fprintf(stderr, "failed to read child status\n");
		return (1);
	}

	expected_mask = ok_mask;
	if ((seen_mask & expected_mask) != expected_mask) {
		fprintf(stderr, "missing vnode events:");
		if ((expected_mask & EVT_OPEN) && !(seen_mask & EVT_OPEN))
			fprintf(stderr, " OPEN");
		if ((expected_mask & EVT_CREATE) && !(seen_mask & EVT_CREATE))
			fprintf(stderr, " CREATE");
		if ((expected_mask & EVT_UNLINK) && !(seen_mask & EVT_UNLINK))
			fprintf(stderr, " UNLINK");
		if ((expected_mask & EVT_RENAME) && !(seen_mask & EVT_RENAME))
			fprintf(stderr, " RENAME");
		if ((expected_mask & EVT_ACCESS) && !(seen_mask & EVT_ACCESS))
			fprintf(stderr, " ACCESS");
		if ((expected_mask & EVT_READ) && !(seen_mask & EVT_READ))
			fprintf(stderr, " READ");
		if ((expected_mask & EVT_WRITE) && !(seen_mask & EVT_WRITE))
			fprintf(stderr, " WRITE");
		if ((expected_mask & EVT_LOOKUP) && !(seen_mask & EVT_LOOKUP))
			fprintf(stderr, " LOOKUP");
		if ((expected_mask & EVT_SETMODE) && !(seen_mask & EVT_SETMODE))
			fprintf(stderr, " SETMODE");
		if ((expected_mask & EVT_SETOWNER) && !(seen_mask & EVT_SETOWNER))
			fprintf(stderr, " SETOWNER");
		if ((expected_mask & EVT_SETFLAGS) && !(seen_mask & EVT_SETFLAGS))
			fprintf(stderr, " SETFLAGS");
		if ((expected_mask & EVT_SETUTIMES) && !(seen_mask & EVT_SETUTIMES))
			fprintf(stderr, " SETUTIMES");
		if ((expected_mask & EVT_SETEXTATTR) && !(seen_mask & EVT_SETEXTATTR))
			fprintf(stderr, " SETEXTATTR");
		if ((expected_mask & EVT_STAT) && !(seen_mask & EVT_STAT))
			fprintf(stderr, " STAT");
		if ((expected_mask & EVT_POLL) && !(seen_mask & EVT_POLL))
			fprintf(stderr, " POLL");
		if ((expected_mask & EVT_REVOKE) && !(seen_mask & EVT_REVOKE))
			fprintf(stderr, " REVOKE");
		if ((expected_mask & EVT_READDIR) && !(seen_mask & EVT_READDIR))
			fprintf(stderr, " READDIR");
		if ((expected_mask & EVT_READLINK) && !(seen_mask & EVT_READLINK))
			fprintf(stderr, " READLINK");
		if ((expected_mask & EVT_GETEXTATTR) && !(seen_mask & EVT_GETEXTATTR))
			fprintf(stderr, " GETEXTATTR");
		if ((expected_mask & EVT_DELETEEXTATTR) && !(seen_mask & EVT_DELETEEXTATTR))
			fprintf(stderr, " DELETEEXTATTR");
		if ((expected_mask & EVT_LISTEXTATTR) && !(seen_mask & EVT_LISTEXTATTR))
			fprintf(stderr, " LISTEXTATTR");
		if ((expected_mask & EVT_GETACL) && !(seen_mask & EVT_GETACL))
			fprintf(stderr, " GETACL");
		if ((expected_mask & EVT_SETACL) && !(seen_mask & EVT_SETACL))
			fprintf(stderr, " SETACL");
		if ((expected_mask & EVT_DELETEACL) && !(seen_mask & EVT_DELETEACL))
			fprintf(stderr, " DELETEACL");
		if ((expected_mask & EVT_RELABEL) && !(seen_mask & EVT_RELABEL))
			fprintf(stderr, " RELABEL");
		fprintf(stderr, "\n");
		return (1);
	}

	printf("vnode events: ok\n");
	return (0);
}
