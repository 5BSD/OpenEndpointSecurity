/*
 * Simple OES test program
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>

#include <security/oes/oes.h>
#include "lib/liboes/liboes.h"

static void print_sockaddr(const oes_sockaddr_t *sa)
{
	char buf[INET6_ADDRSTRLEN];

	switch (sa->esa_family) {
	case AF_INET:
		inet_ntop(AF_INET, &sa->esa_addr.v4, buf, sizeof(buf));
		printf(" addr=%s:%u", buf, ntohs(sa->esa_port));
		break;
	case AF_INET6:
		inet_ntop(AF_INET6, sa->esa_addr.v6, buf, sizeof(buf));
		printf(" addr=[%s]:%u", buf, ntohs(sa->esa_port));
		break;
	case AF_UNIX:
		printf(" path=%s", sa->esa_addr.path);
		break;
	default:
		printf(" family=%u", sa->esa_family);
		break;
	}
}

int main(int argc, char **argv)
{
	int fd;
	struct oes_subscribe_args sub;
	struct oes_mode_args mode;
	int use_auth_mode = 0;
	int auth_all = 0;
	int verbose = 0;
	oes_event_type_t notify_events[] = {
		OES_EVENT_NOTIFY_EXEC,
		OES_EVENT_NOTIFY_EXIT,
		OES_EVENT_NOTIFY_FORK,
		OES_EVENT_NOTIFY_OPEN,
		OES_EVENT_NOTIFY_CREATE,
		OES_EVENT_NOTIFY_UNLINK,
		OES_EVENT_NOTIFY_RENAME,
		OES_EVENT_NOTIFY_LINK,
		OES_EVENT_NOTIFY_MOUNT,
		OES_EVENT_NOTIFY_UNMOUNT,
		OES_EVENT_NOTIFY_KLDLOAD,
		OES_EVENT_NOTIFY_KLDUNLOAD,
		OES_EVENT_NOTIFY_MMAP,
		OES_EVENT_NOTIFY_MPROTECT,
		OES_EVENT_NOTIFY_CHDIR,
		OES_EVENT_NOTIFY_CHROOT,
		OES_EVENT_NOTIFY_SIGNAL,
		OES_EVENT_NOTIFY_PTRACE,
		OES_EVENT_NOTIFY_SETUID,
		OES_EVENT_NOTIFY_SETGID,
		OES_EVENT_NOTIFY_ACCESS,
		OES_EVENT_NOTIFY_READ,
		OES_EVENT_NOTIFY_WRITE,
		OES_EVENT_NOTIFY_LOOKUP,
		OES_EVENT_NOTIFY_SETMODE,
		OES_EVENT_NOTIFY_SETOWNER,
		OES_EVENT_NOTIFY_SETFLAGS,
		OES_EVENT_NOTIFY_SETUTIMES,
		OES_EVENT_NOTIFY_STAT,
		OES_EVENT_NOTIFY_POLL,
		OES_EVENT_NOTIFY_REVOKE,
		OES_EVENT_NOTIFY_READDIR,
		OES_EVENT_NOTIFY_READLINK,
		OES_EVENT_NOTIFY_SETEXTATTR,
		OES_EVENT_NOTIFY_GETEXTATTR,
		OES_EVENT_NOTIFY_DELETEEXTATTR,
		OES_EVENT_NOTIFY_LISTEXTATTR,
		OES_EVENT_NOTIFY_GETACL,
		OES_EVENT_NOTIFY_SETACL,
		OES_EVENT_NOTIFY_DELETEACL,
		OES_EVENT_NOTIFY_RELABEL,
		OES_EVENT_NOTIFY_SOCKET_CONNECT,
		OES_EVENT_NOTIFY_SOCKET_BIND,
		OES_EVENT_NOTIFY_SOCKET_LISTEN,
		OES_EVENT_NOTIFY_REBOOT,
		OES_EVENT_NOTIFY_SYSCTL,
		OES_EVENT_NOTIFY_KENV,
		OES_EVENT_NOTIFY_SWAPON,
		OES_EVENT_NOTIFY_SWAPOFF,
	};
	oes_event_type_t auth_events[] = {
		OES_EVENT_AUTH_EXEC,
	};
	oes_event_type_t auth_events_all[] = {
		OES_EVENT_AUTH_EXEC,
		OES_EVENT_AUTH_OPEN,
		OES_EVENT_AUTH_ACCESS,
		OES_EVENT_AUTH_READ,
		OES_EVENT_AUTH_WRITE,
		OES_EVENT_AUTH_LOOKUP,
		OES_EVENT_AUTH_CREATE,
		OES_EVENT_AUTH_UNLINK,
		OES_EVENT_AUTH_RENAME,
		OES_EVENT_AUTH_LINK,
		OES_EVENT_AUTH_CHDIR,
		OES_EVENT_AUTH_CHROOT,
		OES_EVENT_AUTH_MMAP,
		OES_EVENT_AUTH_MPROTECT,
		OES_EVENT_AUTH_SETMODE,
		OES_EVENT_AUTH_SETOWNER,
		OES_EVENT_AUTH_SETFLAGS,
		OES_EVENT_AUTH_SETUTIMES,
		OES_EVENT_AUTH_SETEXTATTR,
		OES_EVENT_AUTH_STAT,
		OES_EVENT_AUTH_POLL,
		OES_EVENT_AUTH_REVOKE,
		OES_EVENT_AUTH_READDIR,
		OES_EVENT_AUTH_READLINK,
		OES_EVENT_AUTH_GETEXTATTR,
		OES_EVENT_AUTH_DELETEEXTATTR,
		OES_EVENT_AUTH_LISTEXTATTR,
		OES_EVENT_AUTH_GETACL,
		OES_EVENT_AUTH_SETACL,
		OES_EVENT_AUTH_DELETEACL,
		OES_EVENT_AUTH_RELABEL,
		OES_EVENT_AUTH_KLDLOAD,
		OES_EVENT_AUTH_PTRACE,
		/* Note: SOCKET_*, REBOOT, SYSCTL, KENV are NOTIFY-only (NOSLEEP hooks) */
		OES_EVENT_AUTH_SWAPON,
		OES_EVENT_AUTH_SWAPOFF,
	};
	uint8_t readbuf[OES_MSG_MAX_SIZE] __attribute__((aligned(__alignof__(oes_message_t))));
	union {
		oes_message_t	msg;
		uint8_t		_pad[OES_MSG_MAX_SIZE];
	} cur;
	oes_message_t *msg = &cur.msg;
	ssize_t n;

	/* Check for -a flag (AUTH mode) */
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-a") == 0) {
			use_auth_mode = 1;
		} else if (strcmp(argv[i], "-A") == 0) {
			use_auth_mode = 1;
			auth_all = 1;
		} else if (strcmp(argv[i], "-v") == 0) {
			verbose = 1;
		}
	}

	fd = open("/dev/oes", O_RDWR);
	if (fd < 0) {
		perror("open /dev/oes");
		return 1;
	}
	printf("Opened /dev/oes (fd=%d)\n", fd);

	/* Set mode */
	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = use_auth_mode ? OES_MODE_AUTH : OES_MODE_NOTIFY;
	mode.ema_timeout_ms = 5000;  /* 5 second timeout for AUTH mode */
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		return 1;
	}
	printf("Set %s mode\n", use_auth_mode ? "AUTH" : "NOTIFY");

	/* Subscribe to events */
	memset(&sub, 0, sizeof(sub));
	if (use_auth_mode) {
		if (auth_all) {
			sub.esa_events = auth_events_all;
			sub.esa_count = sizeof(auth_events_all) /
			    sizeof(auth_events_all[0]);
		} else {
			sub.esa_events = auth_events;
			sub.esa_count = sizeof(auth_events) /
			    sizeof(auth_events[0]);
		}
	} else {
		sub.esa_events = notify_events;
		sub.esa_count = sizeof(notify_events) / sizeof(notify_events[0]);
	}
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		perror("OES_IOC_SUBSCRIBE");
		close(fd);
		return 1;
	}
	printf("Subscribed to %zu events\n", sub.esa_count);

	/* Read events */
	printf("Waiting for events (run commands in another terminal)...\n");
	if (use_auth_mode) {
		printf("NOTE: AUTH mode - commands will block until we respond!\n");
		if (auth_all)
			printf("NOTE: AUTH all enabled - many operations will block.\n");
	}

	while ((n = read(fd, readbuf, sizeof(readbuf))) >= (ssize_t)sizeof(*msg)) {
	    size_t batch_off = 0;
	    while (batch_off + sizeof(oes_message_t) <= (size_t)n) {
		/* Copy header to check em_size, then full message */
		memcpy(msg, readbuf + batch_off, sizeof(oes_message_t));
		if (msg->em_size < sizeof(oes_message_t) ||
		    batch_off + msg->em_size > (size_t)n)
			break;
		memcpy(msg, readbuf + batch_off, msg->em_size);
		{
		const char *path = "";

		/* Get path based on event type */
		switch (msg->em_event) {
		case OES_EVENT_NOTIFY_EXEC:
		case OES_EVENT_AUTH_EXEC:
			path = oes_file_path(msg, &msg->em_event_data.exec.executable);
			break;
		case OES_EVENT_NOTIFY_OPEN:
		case OES_EVENT_AUTH_OPEN:
			path = oes_file_path(msg, &msg->em_event_data.open.file);
			break;
		case OES_EVENT_NOTIFY_ACCESS:
		case OES_EVENT_AUTH_ACCESS:
			path = oes_file_path(msg, &msg->em_event_data.access.file);
			break;
		case OES_EVENT_NOTIFY_READ:
		case OES_EVENT_AUTH_READ:
		case OES_EVENT_NOTIFY_WRITE:
		case OES_EVENT_AUTH_WRITE:
			path = oes_file_path(msg, &msg->em_event_data.rw.file);
			break;
		case OES_EVENT_NOTIFY_LOOKUP:
		case OES_EVENT_AUTH_LOOKUP:
			path = oes_file_path(msg, &msg->em_event_data.lookup.dir);
			break;
		case OES_EVENT_NOTIFY_STAT:
		case OES_EVENT_AUTH_STAT:
			path = oes_file_path(msg, &msg->em_event_data.stat.file);
			break;
		case OES_EVENT_NOTIFY_POLL:
		case OES_EVENT_AUTH_POLL:
			path = oes_file_path(msg, &msg->em_event_data.poll.file);
			break;
		case OES_EVENT_NOTIFY_REVOKE:
		case OES_EVENT_AUTH_REVOKE:
			path = oes_file_path(msg, &msg->em_event_data.revoke.file);
			break;
		case OES_EVENT_NOTIFY_READDIR:
		case OES_EVENT_AUTH_READDIR:
			path = oes_file_path(msg, &msg->em_event_data.readdir.dir);
			break;
		case OES_EVENT_NOTIFY_READLINK:
		case OES_EVENT_AUTH_READLINK:
			path = oes_file_path(msg, &msg->em_event_data.readlink.file);
			break;
		case OES_EVENT_NOTIFY_SETEXTATTR:
		case OES_EVENT_AUTH_SETEXTATTR:
			path = oes_file_path(msg, &msg->em_event_data.setextattr.file);
			break;
		case OES_EVENT_NOTIFY_GETEXTATTR:
		case OES_EVENT_AUTH_GETEXTATTR:
			path = oes_file_path(msg, &msg->em_event_data.getextattr.file);
			break;
		case OES_EVENT_NOTIFY_DELETEEXTATTR:
		case OES_EVENT_AUTH_DELETEEXTATTR:
			path = oes_file_path(msg, &msg->em_event_data.deleteextattr.file);
			break;
		case OES_EVENT_NOTIFY_LISTEXTATTR:
		case OES_EVENT_AUTH_LISTEXTATTR:
			path = oes_file_path(msg, &msg->em_event_data.listextattr.file);
			break;
		case OES_EVENT_NOTIFY_GETACL:
		case OES_EVENT_AUTH_GETACL:
			path = oes_file_path(msg, &msg->em_event_data.getacl.file);
			break;
		case OES_EVENT_NOTIFY_SETACL:
		case OES_EVENT_AUTH_SETACL:
			path = oes_file_path(msg, &msg->em_event_data.setacl.file);
			break;
		case OES_EVENT_NOTIFY_DELETEACL:
		case OES_EVENT_AUTH_DELETEACL:
			path = oes_file_path(msg, &msg->em_event_data.deleteacl.file);
			break;
		case OES_EVENT_NOTIFY_RELABEL:
		case OES_EVENT_AUTH_RELABEL:
			path = oes_file_path(msg, &msg->em_event_data.relabel.file);
			break;
		case OES_EVENT_NOTIFY_CREATE:
		case OES_EVENT_AUTH_CREATE:
			path = oes_file_path(msg, &msg->em_event_data.create.file);
			break;
		case OES_EVENT_NOTIFY_UNLINK:
		case OES_EVENT_AUTH_UNLINK:
			path = oes_file_path(msg, &msg->em_event_data.unlink.file);
			break;
		case OES_EVENT_NOTIFY_RENAME:
		case OES_EVENT_AUTH_RENAME:
			path = oes_file_path(msg, &msg->em_event_data.rename.src_file);
			break;
		case OES_EVENT_AUTH_LINK:
			path = oes_file_path(msg, &msg->em_event_data.link.target);
			break;
		case OES_EVENT_AUTH_CHDIR:
			path = oes_file_path(msg, &msg->em_event_data.chdir.dir);
			break;
		case OES_EVENT_AUTH_CHROOT:
			path = oes_file_path(msg, &msg->em_event_data.chroot.dir);
			break;
		case OES_EVENT_NOTIFY_SETMODE:
		case OES_EVENT_AUTH_SETMODE:
			path = oes_file_path(msg, &msg->em_event_data.setmode.file);
			break;
		case OES_EVENT_NOTIFY_SETOWNER:
		case OES_EVENT_AUTH_SETOWNER:
			path = oes_file_path(msg, &msg->em_event_data.setowner.file);
			break;
		case OES_EVENT_NOTIFY_SETFLAGS:
		case OES_EVENT_AUTH_SETFLAGS:
			path = oes_file_path(msg, &msg->em_event_data.setflags.file);
			break;
		case OES_EVENT_NOTIFY_SETUTIMES:
		case OES_EVENT_AUTH_SETUTIMES:
			path = oes_file_path(msg, &msg->em_event_data.setutimes.file);
			break;
		case OES_EVENT_AUTH_MMAP:
			path = oes_file_path(msg, &msg->em_event_data.mmap.file);
			break;
		case OES_EVENT_AUTH_MPROTECT:
			path = oes_file_path(msg, &msg->em_event_data.mprotect.file);
			break;
		case OES_EVENT_NOTIFY_KLDLOAD:
		case OES_EVENT_AUTH_KLDLOAD:
			path = oes_file_path(msg, &msg->em_event_data.kldload.file);
			break;
		default:
			break;
		}

		printf("Event: type=0x%04x pid=%d uid=%d comm=%s",
		    msg->em_event, msg->em_process.ep_pid,
		    msg->em_process.ep_uid, msg->em_process.ep_comm);

		/* Show jail ID if jailed */
		if (msg->em_process.ep_flags & EP_FLAG_JAILED)
			printf(" jid=%d", msg->em_process.ep_jid);

		/* Show capability mode */
		if (msg->em_process.ep_flags & EP_FLAG_CAPMODE)
			printf(" [CAPMODE]");

		/* Show path if available */
		if (path[0] != '\0')
			printf(" path=%s", path);

		/* Show argc for exec events */
		if ((msg->em_event & 0x0FFF) == (OES_EVENT_AUTH_EXEC & 0x0FFF)) {
			printf(" argc=%u envc=%u",
			    msg->em_event_data.exec.argc,
			    msg->em_event_data.exec.envc);
		}

		switch (msg->em_event) {
		case OES_EVENT_AUTH_OPEN:
		case OES_EVENT_NOTIFY_OPEN:
			printf(" flags=0x%x", msg->em_event_data.open.flags);
			break;
		case OES_EVENT_AUTH_CREATE:
		case OES_EVENT_NOTIFY_CREATE:
			printf(" mode=0%o", msg->em_event_data.create.mode);
			break;
		case OES_EVENT_AUTH_RENAME:
		case OES_EVENT_NOTIFY_RENAME:
			if (msg->em_event_data.rename.dst_name_off != 0)
				printf(" dst=%s", oes_msg_string(msg,
				    msg->em_event_data.rename.dst_name_off));
			break;
		case OES_EVENT_AUTH_LINK:
			if (msg->em_event_data.link.name_off != 0)
				printf(" link=%s", oes_msg_string(msg,
				    msg->em_event_data.link.name_off));
			break;
		case OES_EVENT_AUTH_MMAP:
			printf(" prot=0x%x flags=0x%x",
			    msg->em_event_data.mmap.prot,
			    msg->em_event_data.mmap.flags);
			break;
		case OES_EVENT_AUTH_MPROTECT:
			printf(" prot=0x%x", msg->em_event_data.mprotect.prot);
			break;
		case OES_EVENT_AUTH_ACCESS:
		case OES_EVENT_NOTIFY_ACCESS:
			printf(" accmode=0x%x",
			    msg->em_event_data.access.accmode);
			break;
		case OES_EVENT_NOTIFY_LOOKUP:
		case OES_EVENT_AUTH_LOOKUP:
			if (msg->em_event_data.lookup.name_off != 0)
				printf(" name=%s",
				    oes_msg_string(msg,
				    msg->em_event_data.lookup.name_off));
			break;
		case OES_EVENT_NOTIFY_SETMODE:
		case OES_EVENT_AUTH_SETMODE:
			printf(" mode=0%o", msg->em_event_data.setmode.mode);
			break;
		case OES_EVENT_NOTIFY_SETOWNER:
		case OES_EVENT_AUTH_SETOWNER:
			printf(" uid=%d gid=%d",
			    msg->em_event_data.setowner.uid,
			    msg->em_event_data.setowner.gid);
			break;
		case OES_EVENT_NOTIFY_SETFLAGS:
		case OES_EVENT_AUTH_SETFLAGS:
			printf(" flags=0x%lx",
			    msg->em_event_data.setflags.flags);
			break;
		case OES_EVENT_NOTIFY_SETUTIMES:
		case OES_EVENT_AUTH_SETUTIMES:
			printf(" atime=%lld mtime=%lld",
			    (long long)msg->em_event_data.setutimes.atime.tv_sec,
			    (long long)msg->em_event_data.setutimes.mtime.tv_sec);
			break;
		case OES_EVENT_NOTIFY_SETEXTATTR:
		case OES_EVENT_AUTH_SETEXTATTR:
			printf(" ns=%d name=%s",
			    msg->em_event_data.setextattr.attrnamespace,
			    oes_msg_string(msg,
			    msg->em_event_data.setextattr.name_off));
			break;
		case OES_EVENT_NOTIFY_SIGNAL:
			printf(" signum=%d target_pid=%d",
			    msg->em_event_data.signal.signum,
			    msg->em_event_data.signal.target.ep_pid);
			break;
		case OES_EVENT_AUTH_PTRACE:
		case OES_EVENT_NOTIFY_PTRACE:
			printf(" target_pid=%d",
			    msg->em_event_data.ptrace.target.ep_pid);
			break;
		case OES_EVENT_NOTIFY_SETUID:
			printf(" uid=%d", msg->em_event_data.setuid.uid);
			break;
		case OES_EVENT_NOTIFY_SETGID:
			printf(" gid=%d", msg->em_event_data.setgid.gid);
			break;
		/* SOCKET_*, REBOOT, SYSCTL, KENV are NOTIFY-only (NOSLEEP hooks) */
		case OES_EVENT_NOTIFY_SOCKET_CONNECT:
			printf(" domain=%d type=%d proto=%d",
			    msg->em_event_data.socket_connect.socket.es_domain,
			    msg->em_event_data.socket_connect.socket.es_type,
			    msg->em_event_data.socket_connect.socket.es_protocol);
			print_sockaddr(&msg->em_event_data.socket_connect.address);
			break;
		case OES_EVENT_NOTIFY_SOCKET_BIND:
			printf(" domain=%d type=%d proto=%d",
			    msg->em_event_data.socket_bind.socket.es_domain,
			    msg->em_event_data.socket_bind.socket.es_type,
			    msg->em_event_data.socket_bind.socket.es_protocol);
			print_sockaddr(&msg->em_event_data.socket_bind.address);
			break;
		case OES_EVENT_NOTIFY_SOCKET_LISTEN:
			printf(" domain=%d type=%d proto=%d",
			    msg->em_event_data.socket_listen.socket.es_domain,
			    msg->em_event_data.socket_listen.socket.es_type,
			    msg->em_event_data.socket_listen.socket.es_protocol);
			break;
		case OES_EVENT_NOTIFY_REBOOT:
			printf(" howto=0x%x", msg->em_event_data.reboot.howto);
			break;
		case OES_EVENT_NOTIFY_SYSCTL:
			printf(" name=%s op=%s",
			    oes_msg_string(msg,
			    msg->em_event_data.sysctl.name_off),
			    msg->em_event_data.sysctl.op ? "write" : "read");
			break;
		case OES_EVENT_NOTIFY_KENV:
			printf(" name=%s op=%s",
			    oes_msg_string(msg,
			    msg->em_event_data.kenv.name_off),
			    msg->em_event_data.kenv.op == 1 ? "set" :
			    msg->em_event_data.kenv.op == 2 ? "unset" : "get");
			break;
		case OES_EVENT_AUTH_SWAPON:
		case OES_EVENT_NOTIFY_SWAPON:
			printf(" path=%s", oes_file_path(msg, &msg->em_event_data.swapon.file));
			break;
		case OES_EVENT_AUTH_SWAPOFF:
		case OES_EVENT_NOTIFY_SWAPOFF:
			printf(" path=%s", oes_file_path(msg, &msg->em_event_data.swapoff.file));
			break;
		default:
			break;
		}

		if (verbose) {
			printf(" ruid=%d suid=%d rgid=%d sgid=%d auid=%d asid=%u",
			    msg->em_process.ep_ruid,
			    msg->em_process.ep_suid,
			    msg->em_process.ep_rgid,
			    msg->em_process.ep_sgid,
			    msg->em_process.ep_auid,
			    msg->em_process.ep_asid);
		}

		printf("\n");

		/* In AUTH mode, send allow response */
		if (use_auth_mode && OES_EVENT_IS_AUTH(msg->em_event)) {
			oes_response_t resp;
			resp.er_id = msg->em_id;
			resp.er_result = OES_AUTH_ALLOW;
			resp.er_flags = 0;
			if (write(fd, &resp, sizeof(resp)) < 0) {
				perror("write response");
			}
		}
		} /* end const char *path scope */
		batch_off += msg->em_size;
	    } /* end batch iteration */
	}

	if (n < 0 && errno != EAGAIN) {
		perror("read");
	}

	close(fd);
	return 0;
}
