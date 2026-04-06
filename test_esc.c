/*
 * Simple ESC test program
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

#include <security/esc/esc.h>

static void print_sockaddr(const esc_sockaddr_t *sa)
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
	struct esc_subscribe_args sub;
	struct esc_mode_args mode;
	int use_auth_mode = 0;
	int auth_all = 0;
	int verbose = 0;
	esc_event_type_t notify_events[] = {
		ESC_EVENT_NOTIFY_EXEC,
		ESC_EVENT_NOTIFY_EXIT,
		ESC_EVENT_NOTIFY_FORK,
		ESC_EVENT_NOTIFY_OPEN,
		ESC_EVENT_NOTIFY_CREATE,
		ESC_EVENT_NOTIFY_UNLINK,
		ESC_EVENT_NOTIFY_RENAME,
		ESC_EVENT_NOTIFY_LINK,
		ESC_EVENT_NOTIFY_MOUNT,
		ESC_EVENT_NOTIFY_UNMOUNT,
		ESC_EVENT_NOTIFY_KLDLOAD,
		ESC_EVENT_NOTIFY_KLDUNLOAD,
		ESC_EVENT_NOTIFY_MMAP,
		ESC_EVENT_NOTIFY_MPROTECT,
		ESC_EVENT_NOTIFY_CHDIR,
		ESC_EVENT_NOTIFY_CHROOT,
		ESC_EVENT_NOTIFY_SIGNAL,
		ESC_EVENT_NOTIFY_PTRACE,
		ESC_EVENT_NOTIFY_SETUID,
		ESC_EVENT_NOTIFY_SETGID,
		ESC_EVENT_NOTIFY_ACCESS,
		ESC_EVENT_NOTIFY_READ,
		ESC_EVENT_NOTIFY_WRITE,
		ESC_EVENT_NOTIFY_LOOKUP,
		ESC_EVENT_NOTIFY_SETMODE,
		ESC_EVENT_NOTIFY_SETOWNER,
		ESC_EVENT_NOTIFY_SETFLAGS,
		ESC_EVENT_NOTIFY_SETUTIMES,
		ESC_EVENT_NOTIFY_STAT,
		ESC_EVENT_NOTIFY_POLL,
		ESC_EVENT_NOTIFY_REVOKE,
		ESC_EVENT_NOTIFY_READDIR,
		ESC_EVENT_NOTIFY_READLINK,
		ESC_EVENT_NOTIFY_SETEXTATTR,
		ESC_EVENT_NOTIFY_GETEXTATTR,
		ESC_EVENT_NOTIFY_DELETEEXTATTR,
		ESC_EVENT_NOTIFY_LISTEXTATTR,
		ESC_EVENT_NOTIFY_GETACL,
		ESC_EVENT_NOTIFY_SETACL,
		ESC_EVENT_NOTIFY_DELETEACL,
		ESC_EVENT_NOTIFY_RELABEL,
		ESC_EVENT_NOTIFY_SOCKET_CONNECT,
		ESC_EVENT_NOTIFY_SOCKET_BIND,
		ESC_EVENT_NOTIFY_SOCKET_LISTEN,
		ESC_EVENT_NOTIFY_REBOOT,
		ESC_EVENT_NOTIFY_SYSCTL,
		ESC_EVENT_NOTIFY_KENV,
		ESC_EVENT_NOTIFY_SWAPON,
		ESC_EVENT_NOTIFY_SWAPOFF,
	};
	esc_event_type_t auth_events[] = {
		ESC_EVENT_AUTH_EXEC,
	};
	esc_event_type_t auth_events_all[] = {
		ESC_EVENT_AUTH_EXEC,
		ESC_EVENT_AUTH_OPEN,
		ESC_EVENT_AUTH_ACCESS,
		ESC_EVENT_AUTH_READ,
		ESC_EVENT_AUTH_WRITE,
		ESC_EVENT_AUTH_LOOKUP,
		ESC_EVENT_AUTH_CREATE,
		ESC_EVENT_AUTH_UNLINK,
		ESC_EVENT_AUTH_RENAME,
		ESC_EVENT_AUTH_LINK,
		ESC_EVENT_AUTH_CHDIR,
		ESC_EVENT_AUTH_CHROOT,
		ESC_EVENT_AUTH_MMAP,
		ESC_EVENT_AUTH_MPROTECT,
		ESC_EVENT_AUTH_SETMODE,
		ESC_EVENT_AUTH_SETOWNER,
		ESC_EVENT_AUTH_SETFLAGS,
		ESC_EVENT_AUTH_SETUTIMES,
		ESC_EVENT_AUTH_SETEXTATTR,
		ESC_EVENT_AUTH_STAT,
		ESC_EVENT_AUTH_POLL,
		ESC_EVENT_AUTH_REVOKE,
		ESC_EVENT_AUTH_READDIR,
		ESC_EVENT_AUTH_READLINK,
		ESC_EVENT_AUTH_GETEXTATTR,
		ESC_EVENT_AUTH_DELETEEXTATTR,
		ESC_EVENT_AUTH_LISTEXTATTR,
		ESC_EVENT_AUTH_GETACL,
		ESC_EVENT_AUTH_SETACL,
		ESC_EVENT_AUTH_DELETEACL,
		ESC_EVENT_AUTH_RELABEL,
		ESC_EVENT_AUTH_KLDLOAD,
		ESC_EVENT_AUTH_PTRACE,
		/* Note: SOCKET_*, REBOOT, SYSCTL, KENV are NOTIFY-only (NOSLEEP hooks) */
		ESC_EVENT_AUTH_SWAPON,
		ESC_EVENT_AUTH_SWAPOFF,
	};
	esc_message_t msg;
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

	fd = open("/dev/esc", O_RDWR);
	if (fd < 0) {
		perror("open /dev/esc");
		return 1;
	}
	printf("Opened /dev/esc (fd=%d)\n", fd);

	/* Set mode */
	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = use_auth_mode ? ESC_MODE_AUTH : ESC_MODE_NOTIFY;
	mode.ema_timeout_ms = 5000;  /* 5 second timeout for AUTH mode */
	if (ioctl(fd, ESC_IOC_SET_MODE, &mode) < 0) {
		perror("ESC_IOC_SET_MODE");
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
	sub.esa_flags = ESC_SUB_REPLACE;
	if (ioctl(fd, ESC_IOC_SUBSCRIBE, &sub) < 0) {
		perror("ESC_IOC_SUBSCRIBE");
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

	while ((n = read(fd, &msg, sizeof(msg))) > 0) {
		const char *path = "";

		/* Get path based on event type */
		switch (msg.em_event) {
		case ESC_EVENT_NOTIFY_EXEC:
		case ESC_EVENT_AUTH_EXEC:
			path = msg.em_event_data.exec.executable.ef_path;
			break;
		case ESC_EVENT_NOTIFY_OPEN:
		case ESC_EVENT_AUTH_OPEN:
			path = msg.em_event_data.open.file.ef_path;
			break;
		case ESC_EVENT_NOTIFY_ACCESS:
		case ESC_EVENT_AUTH_ACCESS:
			path = msg.em_event_data.access.file.ef_path;
			break;
		case ESC_EVENT_NOTIFY_READ:
		case ESC_EVENT_AUTH_READ:
		case ESC_EVENT_NOTIFY_WRITE:
		case ESC_EVENT_AUTH_WRITE:
			path = msg.em_event_data.rw.file.ef_path;
			break;
		case ESC_EVENT_NOTIFY_LOOKUP:
		case ESC_EVENT_AUTH_LOOKUP:
			path = msg.em_event_data.lookup.dir.ef_path;
			break;
		case ESC_EVENT_NOTIFY_STAT:
		case ESC_EVENT_AUTH_STAT:
			path = msg.em_event_data.stat.file.ef_path;
			break;
		case ESC_EVENT_NOTIFY_POLL:
		case ESC_EVENT_AUTH_POLL:
			path = msg.em_event_data.poll.file.ef_path;
			break;
		case ESC_EVENT_NOTIFY_REVOKE:
		case ESC_EVENT_AUTH_REVOKE:
			path = msg.em_event_data.revoke.file.ef_path;
			break;
		case ESC_EVENT_NOTIFY_READDIR:
		case ESC_EVENT_AUTH_READDIR:
			path = msg.em_event_data.readdir.dir.ef_path;
			break;
		case ESC_EVENT_NOTIFY_READLINK:
		case ESC_EVENT_AUTH_READLINK:
			path = msg.em_event_data.readlink.file.ef_path;
			break;
		case ESC_EVENT_NOTIFY_SETEXTATTR:
		case ESC_EVENT_AUTH_SETEXTATTR:
			path = msg.em_event_data.setextattr.file.ef_path;
			break;
		case ESC_EVENT_NOTIFY_GETEXTATTR:
		case ESC_EVENT_AUTH_GETEXTATTR:
			path = msg.em_event_data.getextattr.file.ef_path;
			break;
		case ESC_EVENT_NOTIFY_DELETEEXTATTR:
		case ESC_EVENT_AUTH_DELETEEXTATTR:
			path = msg.em_event_data.deleteextattr.file.ef_path;
			break;
		case ESC_EVENT_NOTIFY_LISTEXTATTR:
		case ESC_EVENT_AUTH_LISTEXTATTR:
			path = msg.em_event_data.listextattr.file.ef_path;
			break;
		case ESC_EVENT_NOTIFY_GETACL:
		case ESC_EVENT_AUTH_GETACL:
			path = msg.em_event_data.getacl.file.ef_path;
			break;
		case ESC_EVENT_NOTIFY_SETACL:
		case ESC_EVENT_AUTH_SETACL:
			path = msg.em_event_data.setacl.file.ef_path;
			break;
		case ESC_EVENT_NOTIFY_DELETEACL:
		case ESC_EVENT_AUTH_DELETEACL:
			path = msg.em_event_data.deleteacl.file.ef_path;
			break;
		case ESC_EVENT_NOTIFY_RELABEL:
		case ESC_EVENT_AUTH_RELABEL:
			path = msg.em_event_data.relabel.file.ef_path;
			break;
		case ESC_EVENT_NOTIFY_CREATE:
		case ESC_EVENT_AUTH_CREATE:
			path = msg.em_event_data.create.file.ef_path;
			break;
		case ESC_EVENT_NOTIFY_UNLINK:
		case ESC_EVENT_AUTH_UNLINK:
			path = msg.em_event_data.unlink.file.ef_path;
			break;
		case ESC_EVENT_NOTIFY_RENAME:
		case ESC_EVENT_AUTH_RENAME:
			path = msg.em_event_data.rename.src_file.ef_path;
			break;
		case ESC_EVENT_AUTH_LINK:
			path = msg.em_event_data.link.target.ef_path;
			break;
		case ESC_EVENT_AUTH_CHDIR:
			path = msg.em_event_data.chdir.dir.ef_path;
			break;
		case ESC_EVENT_AUTH_CHROOT:
			path = msg.em_event_data.chroot.dir.ef_path;
			break;
		case ESC_EVENT_NOTIFY_SETMODE:
		case ESC_EVENT_AUTH_SETMODE:
			path = msg.em_event_data.setmode.file.ef_path;
			break;
		case ESC_EVENT_NOTIFY_SETOWNER:
		case ESC_EVENT_AUTH_SETOWNER:
			path = msg.em_event_data.setowner.file.ef_path;
			break;
		case ESC_EVENT_NOTIFY_SETFLAGS:
		case ESC_EVENT_AUTH_SETFLAGS:
			path = msg.em_event_data.setflags.file.ef_path;
			break;
		case ESC_EVENT_NOTIFY_SETUTIMES:
		case ESC_EVENT_AUTH_SETUTIMES:
			path = msg.em_event_data.setutimes.file.ef_path;
			break;
		case ESC_EVENT_AUTH_MMAP:
			path = msg.em_event_data.mmap.file.ef_path;
			break;
		case ESC_EVENT_AUTH_MPROTECT:
			path = msg.em_event_data.mprotect.file.ef_path;
			break;
		case ESC_EVENT_NOTIFY_KLDLOAD:
		case ESC_EVENT_AUTH_KLDLOAD:
			path = msg.em_event_data.kldload.file.ef_path;
			break;
		default:
			break;
		}

		printf("Event: type=0x%04x pid=%d uid=%d comm=%s",
		    msg.em_event, msg.em_process.ep_pid,
		    msg.em_process.ep_uid, msg.em_process.ep_comm);

		/* Show jail ID if jailed */
		if (msg.em_process.ep_flags & EP_FLAG_JAILED)
			printf(" jid=%d", msg.em_process.ep_jid);

		/* Show capability mode */
		if (msg.em_process.ep_flags & EP_FLAG_CAPMODE)
			printf(" [CAPMODE]");

		/* Show path if available */
		if (path[0] != '\0')
			printf(" path=%s", path);

		/* Show argc for exec events */
		if ((msg.em_event & 0x0FFF) == (ESC_EVENT_AUTH_EXEC & 0x0FFF)) {
			printf(" argc=%u envc=%u",
			    msg.em_event_data.exec.argc,
			    msg.em_event_data.exec.envc);
		}

		switch (msg.em_event) {
		case ESC_EVENT_AUTH_OPEN:
		case ESC_EVENT_NOTIFY_OPEN:
			printf(" flags=0x%x", msg.em_event_data.open.flags);
			break;
		case ESC_EVENT_AUTH_CREATE:
		case ESC_EVENT_NOTIFY_CREATE:
			printf(" mode=0%o", msg.em_event_data.create.mode);
			break;
		case ESC_EVENT_AUTH_RENAME:
		case ESC_EVENT_NOTIFY_RENAME:
			if (msg.em_event_data.rename.dst_name[0] != '\0')
				printf(" dst=%s", msg.em_event_data.rename.dst_name);
			break;
		case ESC_EVENT_AUTH_LINK:
			if (msg.em_event_data.link.name[0] != '\0')
				printf(" link=%s", msg.em_event_data.link.name);
			break;
		case ESC_EVENT_AUTH_MMAP:
			printf(" prot=0x%x flags=0x%x",
			    msg.em_event_data.mmap.prot,
			    msg.em_event_data.mmap.flags);
			break;
		case ESC_EVENT_AUTH_MPROTECT:
			printf(" prot=0x%x", msg.em_event_data.mprotect.prot);
			break;
		case ESC_EVENT_AUTH_ACCESS:
		case ESC_EVENT_NOTIFY_ACCESS:
			printf(" accmode=0x%x",
			    msg.em_event_data.access.accmode);
			break;
		case ESC_EVENT_NOTIFY_LOOKUP:
		case ESC_EVENT_AUTH_LOOKUP:
			if (msg.em_event_data.lookup.name[0] != '\0')
				printf(" name=%s",
				    msg.em_event_data.lookup.name);
			break;
		case ESC_EVENT_NOTIFY_SETMODE:
		case ESC_EVENT_AUTH_SETMODE:
			printf(" mode=0%o", msg.em_event_data.setmode.mode);
			break;
		case ESC_EVENT_NOTIFY_SETOWNER:
		case ESC_EVENT_AUTH_SETOWNER:
			printf(" uid=%d gid=%d",
			    msg.em_event_data.setowner.uid,
			    msg.em_event_data.setowner.gid);
			break;
		case ESC_EVENT_NOTIFY_SETFLAGS:
		case ESC_EVENT_AUTH_SETFLAGS:
			printf(" flags=0x%lx",
			    msg.em_event_data.setflags.flags);
			break;
		case ESC_EVENT_NOTIFY_SETUTIMES:
		case ESC_EVENT_AUTH_SETUTIMES:
			printf(" atime=%lld mtime=%lld",
			    (long long)msg.em_event_data.setutimes.atime.tv_sec,
			    (long long)msg.em_event_data.setutimes.mtime.tv_sec);
			break;
		case ESC_EVENT_NOTIFY_SETEXTATTR:
		case ESC_EVENT_AUTH_SETEXTATTR:
			printf(" ns=%d name=%s",
			    msg.em_event_data.setextattr.attrnamespace,
			    msg.em_event_data.setextattr.name);
			break;
		case ESC_EVENT_NOTIFY_SIGNAL:
			printf(" signum=%d target_pid=%d",
			    msg.em_event_data.signal.signum,
			    msg.em_event_data.signal.target.ep_pid);
			break;
		case ESC_EVENT_AUTH_PTRACE:
		case ESC_EVENT_NOTIFY_PTRACE:
			printf(" target_pid=%d",
			    msg.em_event_data.ptrace.target.ep_pid);
			break;
		case ESC_EVENT_NOTIFY_SETUID:
			printf(" uid=%d", msg.em_event_data.setuid.uid);
			break;
		case ESC_EVENT_NOTIFY_SETGID:
			printf(" gid=%d", msg.em_event_data.setgid.gid);
			break;
		/* SOCKET_*, REBOOT, SYSCTL, KENV are NOTIFY-only (NOSLEEP hooks) */
		case ESC_EVENT_NOTIFY_SOCKET_CONNECT:
			printf(" domain=%d type=%d proto=%d",
			    msg.em_event_data.socket_connect.socket.es_domain,
			    msg.em_event_data.socket_connect.socket.es_type,
			    msg.em_event_data.socket_connect.socket.es_protocol);
			print_sockaddr(&msg.em_event_data.socket_connect.address);
			break;
		case ESC_EVENT_NOTIFY_SOCKET_BIND:
			printf(" domain=%d type=%d proto=%d",
			    msg.em_event_data.socket_bind.socket.es_domain,
			    msg.em_event_data.socket_bind.socket.es_type,
			    msg.em_event_data.socket_bind.socket.es_protocol);
			print_sockaddr(&msg.em_event_data.socket_bind.address);
			break;
		case ESC_EVENT_NOTIFY_SOCKET_LISTEN:
			printf(" domain=%d type=%d proto=%d",
			    msg.em_event_data.socket_listen.socket.es_domain,
			    msg.em_event_data.socket_listen.socket.es_type,
			    msg.em_event_data.socket_listen.socket.es_protocol);
			break;
		case ESC_EVENT_NOTIFY_REBOOT:
			printf(" howto=0x%x", msg.em_event_data.reboot.howto);
			break;
		case ESC_EVENT_NOTIFY_SYSCTL:
			printf(" name=%s op=%s",
			    msg.em_event_data.sysctl.name,
			    msg.em_event_data.sysctl.op ? "write" : "read");
			break;
		case ESC_EVENT_NOTIFY_KENV:
			printf(" name=%s op=%s",
			    msg.em_event_data.kenv.name,
			    msg.em_event_data.kenv.op == 1 ? "set" :
			    msg.em_event_data.kenv.op == 2 ? "unset" : "get");
			break;
		case ESC_EVENT_AUTH_SWAPON:
		case ESC_EVENT_NOTIFY_SWAPON:
			printf(" path=%s", msg.em_event_data.swapon.file.ef_path);
			break;
		case ESC_EVENT_AUTH_SWAPOFF:
		case ESC_EVENT_NOTIFY_SWAPOFF:
			printf(" path=%s", msg.em_event_data.swapoff.file.ef_path);
			break;
		default:
			break;
		}

		if (verbose) {
			printf(" ruid=%d suid=%d rgid=%d sgid=%d auid=%d asid=%u",
			    msg.em_process.ep_ruid,
			    msg.em_process.ep_suid,
			    msg.em_process.ep_rgid,
			    msg.em_process.ep_sgid,
			    msg.em_process.ep_auid,
			    msg.em_process.ep_asid);
		}

		printf("\n");

		/* In AUTH mode, send allow response */
		if (use_auth_mode && ESC_EVENT_IS_AUTH(msg.em_event)) {
			esc_response_t resp;
			resp.er_id = msg.em_id;
			resp.er_result = ESC_AUTH_ALLOW;
			resp.er_flags = 0;
			if (write(fd, &resp, sizeof(resp)) < 0) {
				perror("write response");
			}
		}
	}

	if (n < 0 && errno != EAGAIN) {
		perror("read");
	}

	close(fd);
	return 0;
}
