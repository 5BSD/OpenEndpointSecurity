/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 * All rights reserved.
 *
 * vendor_client - Example third-party ESC client
 *
 * Demonstrates how a third-party security vendor would:
 * 1. Connect to escd and receive a restricted fd
 * 2. Subscribe to events
 * 3. Process events in a loop
 *
 * Note: This client cannot enter AUTH mode because escd
 * restricts the ioctls available on the fd it provides.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libesc.h"

#define DEFAULT_SOCKET_PATH	"/var/run/escd.sock"

/*
 * Receive a file descriptor over a Unix socket
 */
static int
recv_fd(int sock)
{
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	char buf[CMSG_SPACE(sizeof(int))];
	char dummy;
	int fd;

	memset(&msg, 0, sizeof(msg));
	memset(buf, 0, sizeof(buf));

	iov.iov_base = &dummy;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	if (recvmsg(sock, &msg, 0) < 0)
		return (-1);

	if (msg.msg_flags & MSG_CTRUNC)
		return (-1);

	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg == NULL || cmsg->cmsg_level != SOL_SOCKET ||
	    cmsg->cmsg_type != SCM_RIGHTS)
		return (-1);

	memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
	return (fd);
}

/*
 * Connect to escd and get a restricted esc fd
 */
static int
connect_to_escd(const char *socket_path)
{
	struct sockaddr_un sun;
	int sock, fd;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		return (-1);

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, socket_path, sizeof(sun.sun_path));

	if (connect(sock, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		close(sock);
		return (-1);
	}

	fd = recv_fd(sock);
	close(sock);

	return (fd);
}

/*
 * Event handler
 */
static bool
event_handler(esc_client_t *client __unused, const esc_message_t *msg,
    void *ctx __unused)
{

	printf("[%s] pid=%d uid=%d comm=%s",
	    esc_event_name(msg->em_event),
	    msg->em_process.ep_pid,
	    msg->em_process.ep_uid,
	    msg->em_process.ep_comm);

	/* Print file path for file events */
	switch (msg->em_event) {
	case ESC_EVENT_NOTIFY_EXEC:
	case ESC_EVENT_AUTH_EXEC:
		if (msg->em_event_data.exec.executable.ef_path[0])
			printf(" exe=%s", msg->em_event_data.exec.executable.ef_path);
		break;
	case ESC_EVENT_NOTIFY_OPEN:
	case ESC_EVENT_AUTH_OPEN:
		if (msg->em_event_data.open.file.ef_path[0])
			printf(" file=%s", msg->em_event_data.open.file.ef_path);
		break;
	default:
		break;
	}

	printf("\n");

	/*
	 * Note: If we receive AUTH events (in PASSIVE mode), we don't
	 * respond - they're informational only. The system daemon
	 * handles the actual responses.
	 *
	 * If we try to call esc_respond() or esc_set_mode(ESC_MODE_AUTH),
	 * we'll get ENOTCAPABLE because escd restricted our ioctls.
	 */

	return (true);  /* Continue processing */
}

int
main(int argc, char *argv[])
{
	esc_client_t *client;
	const char *socket_path = DEFAULT_SOCKET_PATH;
	int fd;
	int ch;

	while ((ch = getopt(argc, argv, "s:")) != -1) {
		switch (ch) {
		case 's':
			socket_path = optarg;
			break;
		default:
			fprintf(stderr, "usage: vendor_client [-s socket_path]\n");
			return (1);
		}
	}

	/* Connect to escd and get restricted fd */
	printf("Connecting to escd at %s...\n", socket_path);
	fd = connect_to_escd(socket_path);
	if (fd < 0)
		err(1, "connect_to_escd");

	printf("Received restricted fd %d\n", fd);

	/* Create client from the received fd */
	client = esc_client_create_from_fd(fd);
	if (client == NULL)
		err(1, "esc_client_create_from_fd");

	/*
	 * Try to set AUTH mode - this should fail with ENOTCAPABLE
	 * because escd restricted our ioctls.
	 */
	printf("Attempting to set AUTH mode (should fail)...\n");
	if (esc_set_mode(client, ESC_MODE_AUTH, 0, 0) < 0) {
		printf("  Failed as expected: %s\n", strerror(errno));
	} else {
		printf("  Unexpectedly succeeded!\n");
	}

	/* Subscribe to NOTIFY events only (we can't do AUTH) */
	printf("Subscribing to NOTIFY events...\n");
	if (esc_subscribe_all(client, false, true) < 0)
		err(1, "esc_subscribe_all");

	/* Mute ourselves */
	if (esc_mute_self(client) < 0)
		err(1, "esc_mute_self");

	printf("Listening for events (Ctrl+C to stop)...\n\n");

	/* Process events */
	if (esc_dispatch(client, event_handler, NULL) < 0)
		err(1, "esc_dispatch");

	esc_client_destroy(client);
	close(fd);

	return (0);
}
