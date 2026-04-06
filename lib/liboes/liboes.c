/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 * All rights reserved.
 *
 * liboes - Userspace library for Endpoint Security Capabilities
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/capsicum.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "liboes.h"

/*
 * Client structure
 */
struct oes_client {
	int		ec_fd;		/* File descriptor */
	bool		ec_owned;	/* We own the fd (close on destroy) */
	uint32_t	ec_mode;	/* Current mode */
};

/*
 * oes_client_create - Create a new OES client
 */
oes_client_t *
oes_client_create(void)
{
	oes_client_t *client;
	int fd;

	fd = open(OES_DEVICE_PATH, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return (NULL);

	client = calloc(1, sizeof(*client));
	if (client == NULL) {
		close(fd);
		return (NULL);
	}

	client->ec_fd = fd;
	client->ec_owned = true;
	client->ec_mode = OES_MODE_NOTIFY;

	return (client);
}

/*
 * oes_client_create_from_fd - Create client from existing fd
 */
oes_client_t *
oes_client_create_from_fd(int fd)
{
	oes_client_t *client;

	if (fd < 0) {
		errno = EBADF;
		return (NULL);
	}

	client = calloc(1, sizeof(*client));
	if (client == NULL)
		return (NULL);

	client->ec_fd = fd;
	client->ec_owned = false;
	client->ec_mode = OES_MODE_NOTIFY;

	return (client);
}

/*
 * oes_client_destroy - Destroy a client
 */
void
oes_client_destroy(oes_client_t *client)
{

	if (client == NULL)
		return;

	if (client->ec_owned && client->ec_fd >= 0)
		close(client->ec_fd);

	free(client);
}

/*
 * oes_client_fd - Get the underlying file descriptor
 */
int
oes_client_fd(oes_client_t *client)
{

	return (client->ec_fd);
}

/*
 * oes_set_mode - Set client operating mode
 */
int
oes_set_mode(oes_client_t *client, uint32_t mode,
    uint32_t timeout_ms, uint32_t queue_size)
{
	struct oes_mode_args args;

	memset(&args, 0, sizeof(args));
	args.ema_mode = mode;
	args.ema_timeout_ms = timeout_ms;
	args.ema_queue_size = queue_size;

	if (ioctl(client->ec_fd, OES_IOC_SET_MODE, &args) < 0)
		return (-1);

	client->ec_mode = mode;
	return (0);
}

/*
 * oes_get_mode - Get current client mode and configuration
 */
int
oes_get_mode(oes_client_t *client, uint32_t *mode,
    uint32_t *timeout_ms, uint32_t *queue_size)
{
	struct oes_mode_args args;

	memset(&args, 0, sizeof(args));
	if (ioctl(client->ec_fd, OES_IOC_GET_MODE, &args) < 0)
		return (-1);

	if (mode != NULL)
		*mode = args.ema_mode;
	if (timeout_ms != NULL)
		*timeout_ms = args.ema_timeout_ms;
	if (queue_size != NULL)
		*queue_size = args.ema_queue_size;

	return (0);
}

/*
 * oes_set_timeout - Set AUTH timeout independently of mode
 */
int
oes_set_timeout(oes_client_t *client, uint32_t timeout_ms)
{
	struct oes_timeout_args args;

	memset(&args, 0, sizeof(args));
	args.eta_timeout_ms = timeout_ms;

	return (ioctl(client->ec_fd, OES_IOC_SET_TIMEOUT, &args));
}

/*
 * oes_get_timeout - Get current AUTH timeout
 */
int
oes_get_timeout(oes_client_t *client, uint32_t *timeout_ms)
{
	struct oes_timeout_args args;

	memset(&args, 0, sizeof(args));
	if (ioctl(client->ec_fd, OES_IOC_GET_TIMEOUT, &args) < 0)
		return (-1);

	if (timeout_ms != NULL)
		*timeout_ms = args.eta_timeout_ms;

	return (0);
}

/*
 * oes_set_timeout_action - Set default action when AUTH times out
 */
int
oes_set_timeout_action(oes_client_t *client, oes_auth_result_t action)
{
	struct oes_timeout_action_args args;

	memset(&args, 0, sizeof(args));
	args.eta_action = action;

	if (ioctl(client->ec_fd, OES_IOC_SET_TIMEOUT_ACTION, &args) < 0)
		return (-1);

	return (0);
}

/*
 * oes_get_timeout_action - Get default action when AUTH times out
 */
int
oes_get_timeout_action(oes_client_t *client, oes_auth_result_t *action)
{
	struct oes_timeout_action_args args;

	memset(&args, 0, sizeof(args));
	if (ioctl(client->ec_fd, OES_IOC_GET_TIMEOUT_ACTION, &args) < 0)
		return (-1);

	if (action != NULL)
		*action = (oes_auth_result_t)args.eta_action;

	return (0);
}

/*
 * oes_cache_add - Add or update a decision cache entry
 */
int
oes_cache_add(oes_client_t *client, const oes_cache_entry_t *entry)
{

	return (ioctl(client->ec_fd, OES_IOC_CACHE_ADD, entry));
}

/*
 * oes_cache_remove - Remove decision cache entries matching key
 */
int
oes_cache_remove(oes_client_t *client, const oes_cache_key_t *key)
{

	return (ioctl(client->ec_fd, OES_IOC_CACHE_REMOVE, key));
}

/*
 * oes_cache_clear - Clear the decision cache for this client
 */
int
oes_cache_clear(oes_client_t *client)
{

	return (ioctl(client->ec_fd, OES_IOC_CACHE_CLEAR));
}

/*
 * oes_subscribe - Subscribe to event types
 */
int
oes_subscribe(oes_client_t *client, const oes_event_type_t *events,
    size_t count, uint32_t flags)
{
	struct oes_subscribe_args args;

	memset(&args, 0, sizeof(args));
	args.esa_events = events;
	args.esa_count = count;
	args.esa_flags = flags;

	return (ioctl(client->ec_fd, OES_IOC_SUBSCRIBE, &args));
}

/*
 * oes_subscribe_bitmap - Subscribe using bitmaps directly
 *
 * This uses the bitmap ioctl for efficient bulk subscription.
 * Bit positions correspond to (event_type & 0x0FFF).
 */
int
oes_subscribe_bitmap(oes_client_t *client, uint64_t auth_bitmap,
    uint64_t notify_bitmap, uint32_t flags)
{
	struct oes_subscribe_bitmap_args args;

	if (client == NULL) {
		errno = EINVAL;
		return (-1);
	}

	memset(&args, 0, sizeof(args));
	args.esba_auth = auth_bitmap;
	args.esba_notify = notify_bitmap;
	args.esba_flags = flags;

	return (ioctl(client->ec_fd, OES_IOC_SUBSCRIBE_BITMAP, &args));
}

/*
 * oes_subscribe_bitmap_ex - Subscribe using 128-bit bitmaps
 *
 * Extended version supporting events with bit positions >= 64.
 */
int
oes_subscribe_bitmap_ex(oes_client_t *client, const uint64_t auth_bitmap[2],
    const uint64_t notify_bitmap[2], uint32_t flags)
{
	struct oes_subscribe_bitmap_ex_args args;

	if (client == NULL) {
		errno = EINVAL;
		return (-1);
	}

	memset(&args, 0, sizeof(args));
	args.esba_auth[0] = auth_bitmap[0];
	args.esba_auth[1] = auth_bitmap[1];
	args.esba_notify[0] = notify_bitmap[0];
	args.esba_notify[1] = notify_bitmap[1];
	args.esba_flags = flags;

	return (ioctl(client->ec_fd, OES_IOC_SUBSCRIBE_BITMAP_EX, &args));
}

/*
 * oes_subscribe_all - Subscribe to all events of a type
 *
 * Uses the extended bitmap ioctl for a single atomic operation.
 */
int
oes_subscribe_all(oes_client_t *client, bool auth, bool notify)
{
	/* AUTH bitmap: bits 1-34 + bits 41-56 */
	const uint64_t all_auth[2] = { 0x1FE007FFFFFFEULL, 0 };

	/*
	 * NOTIFY bitmap: bits 1-4,6-9,11,13-66
	 * (gaps at bits 0,5,10,12 - no events defined there)
	 * Low 64 bits: 0xFFFFFFFFFFFFEBDEULL
	 * High bits: 64,65,66 -> 0x7
	 */
	const uint64_t all_notify[2] = { 0xFFFFFFFFFFFFEBDEULL, 0x7ULL };

	return (oes_subscribe_bitmap_ex(client,
	    auth ? all_auth : (const uint64_t[2]){0, 0},
	    notify ? all_notify : (const uint64_t[2]){0, 0},
	    OES_SUB_REPLACE));
}

/*
 * oes_mute_self - Mute events from the current process
 */
int
oes_mute_self(oes_client_t *client)
{
	struct oes_mute_args args;

	memset(&args, 0, sizeof(args));
	args.emu_flags = OES_MUTE_SELF;

	return (ioctl(client->ec_fd, OES_IOC_MUTE_PROCESS, &args));
}

/*
 * oes_mute_process - Mute events from a specific process
 */
int
oes_mute_process(oes_client_t *client, const oes_proc_token_t *token)
{
	struct oes_mute_args args;

	memset(&args, 0, sizeof(args));
	args.emu_token = *token;
	args.emu_flags = 0;

	return (ioctl(client->ec_fd, OES_IOC_MUTE_PROCESS, &args));
}

/*
 * oes_unmute_process - Unmute a previously muted process
 */
int
oes_unmute_process(oes_client_t *client, const oes_proc_token_t *token)
{
	struct oes_mute_args args;

	memset(&args, 0, sizeof(args));
	args.emu_token = *token;

	return (ioctl(client->ec_fd, OES_IOC_UNMUTE_PROCESS, &args));
}

/*
 * oes_mute_path - Mute events by path
 */
int
oes_mute_path(oes_client_t *client, const char *path, uint32_t type)
{
	struct oes_mute_path_args args;

	memset(&args, 0, sizeof(args));
	if (path != NULL)
		strlcpy(args.emp_path, path, sizeof(args.emp_path));
	args.emp_type = type;
	args.emp_flags = 0;

	return (ioctl(client->ec_fd, OES_IOC_MUTE_PATH, &args));
}

/*
 * oes_unmute_path - Unmute events by path
 */
int
oes_unmute_path(oes_client_t *client, const char *path, uint32_t type)
{
	struct oes_mute_path_args args;

	memset(&args, 0, sizeof(args));
	if (path != NULL)
		strlcpy(args.emp_path, path, sizeof(args.emp_path));
	args.emp_type = type;
	args.emp_flags = 0;

	return (ioctl(client->ec_fd, OES_IOC_UNMUTE_PATH, &args));
}

/*
 * oes_mute_target_path - Mute events by target path
 */
int
oes_mute_target_path(oes_client_t *client, const char *path, uint32_t type)
{
	struct oes_mute_path_args args;

	memset(&args, 0, sizeof(args));
	if (path != NULL)
		strlcpy(args.emp_path, path, sizeof(args.emp_path));
	args.emp_type = type;
	args.emp_flags = OES_MUTE_PATH_FLAG_TARGET;

	return (ioctl(client->ec_fd, OES_IOC_MUTE_PATH, &args));
}

/*
 * oes_unmute_target_path - Unmute events by target path
 */
int
oes_unmute_target_path(oes_client_t *client, const char *path, uint32_t type)
{
	struct oes_mute_path_args args;

	memset(&args, 0, sizeof(args));
	if (path != NULL)
		strlcpy(args.emp_path, path, sizeof(args.emp_path));
	args.emp_type = type;
	args.emp_flags = OES_MUTE_PATH_FLAG_TARGET;

	return (ioctl(client->ec_fd, OES_IOC_UNMUTE_PATH, &args));
}

/*
 * oes_set_mute_invert - Enable/disable mute inversion for a type
 */
int
oes_set_mute_invert(oes_client_t *client, uint32_t type, bool invert)
{
	struct oes_mute_invert_args args;

	memset(&args, 0, sizeof(args));
	args.emi_type = type;
	args.emi_invert = invert ? 1 : 0;

	return (ioctl(client->ec_fd, OES_IOC_SET_MUTE_INVERT, &args));
}

/*
 * oes_get_mute_invert - Query mute inversion for a type
 */
int
oes_get_mute_invert(oes_client_t *client, uint32_t type, bool *invert)
{
	struct oes_mute_invert_args args;

	if (invert == NULL)
		return (-1);

	memset(&args, 0, sizeof(args));
	args.emi_type = type;
	if (ioctl(client->ec_fd, OES_IOC_GET_MUTE_INVERT, &args) < 0)
		return (-1);

	*invert = (args.emi_invert != 0);
	return (0);
}

/*
 * oes_read_event - Read one event
 *
 * Uses poll() for non-blocking reads instead of toggling O_NONBLOCK,
 * which is not thread-safe on a shared file descriptor.
 */
int
oes_read_event(oes_client_t *client, oes_message_t *msg, bool blocking)
{
	struct pollfd pfd;
	ssize_t n;

	if (!blocking) {
		int ret;

		pfd.fd = client->ec_fd;
		pfd.events = POLLIN;
		pfd.revents = 0;

		/* Poll with zero timeout for immediate check */
		ret = poll(&pfd, 1, 0);
		if (ret < 0)
			return (-1);	/* Preserve errno from poll() */
		if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) {
			errno = EBADF;	/* fd is dead or invalid */
			return (-1);
		}
		if (ret == 0 || !(pfd.revents & POLLIN)) {
			errno = EAGAIN;	/* No data available */
			return (-1);
		}
	}

	n = read(client->ec_fd, msg, sizeof(*msg));

	if (n < 0)
		return (-1);

	if (n != sizeof(*msg)) {
		errno = EIO;
		return (-1);
	}

	return (0);
}

/*
 * oes_respond - Respond to an AUTH event
 */
int
oes_respond(oes_client_t *client, uint64_t msg_id, oes_auth_result_t result)
{
	oes_response_t resp;
	ssize_t n;

	memset(&resp, 0, sizeof(resp));
	resp.er_id = msg_id;
	resp.er_result = result;

	n = write(client->ec_fd, &resp, sizeof(resp));
	if (n < 0)
		return (-1);

	if (n != sizeof(resp)) {
		errno = EIO;
		return (-1);
	}

	return (0);
}

/*
 * oes_dispatch - Event dispatch loop
 */
int
oes_dispatch(oes_client_t *client, oes_handler_t handler, void *context)
{
	oes_message_t msg;
	bool cont;

	for (;;) {
		if (oes_read_event(client, &msg, true) < 0)
			return (-1);

		cont = handler(client, &msg, context);
		if (!cont)
			return (0);
	}
}

/*
 * oes_get_stats - Get client statistics
 */
int
oes_get_stats(oes_client_t *client, struct oes_stats *stats)
{

	return (ioctl(client->ec_fd, OES_IOC_GET_STATS, stats));
}

/*
 * oes_event_name - Get human-readable event name
 */
const char *
oes_event_name(oes_event_type_t event)
{

	switch (event) {
	case OES_EVENT_AUTH_EXEC:	return "AUTH_EXEC";
	case OES_EVENT_AUTH_OPEN:	return "AUTH_OPEN";
	case OES_EVENT_AUTH_CREATE:	return "AUTH_CREATE";
	case OES_EVENT_AUTH_UNLINK:	return "AUTH_UNLINK";
	case OES_EVENT_AUTH_RENAME:	return "AUTH_RENAME";
	case OES_EVENT_AUTH_LINK:	return "AUTH_LINK";
	case OES_EVENT_AUTH_MOUNT:	return "AUTH_MOUNT";
	case OES_EVENT_AUTH_KLDLOAD:	return "AUTH_KLDLOAD";
	case OES_EVENT_AUTH_MMAP:	return "AUTH_MMAP";
	case OES_EVENT_AUTH_MPROTECT:	return "AUTH_MPROTECT";
	case OES_EVENT_AUTH_CHDIR:	return "AUTH_CHDIR";
	case OES_EVENT_AUTH_CHROOT:	return "AUTH_CHROOT";
	case OES_EVENT_AUTH_SETEXTATTR:	return "AUTH_SETEXTATTR";
	case OES_EVENT_AUTH_PTRACE:	return "AUTH_PTRACE";
	case OES_EVENT_AUTH_ACCESS:	return "AUTH_ACCESS";
	case OES_EVENT_AUTH_READ:	return "AUTH_READ";
	case OES_EVENT_AUTH_WRITE:	return "AUTH_WRITE";
	case OES_EVENT_AUTH_LOOKUP:	return "AUTH_LOOKUP";
	case OES_EVENT_AUTH_SETMODE:	return "AUTH_SETMODE";
	case OES_EVENT_AUTH_SETOWNER:	return "AUTH_SETOWNER";
	case OES_EVENT_AUTH_SETFLAGS:	return "AUTH_SETFLAGS";
	case OES_EVENT_AUTH_SETUTIMES:	return "AUTH_SETUTIMES";
	case OES_EVENT_AUTH_STAT:	return "AUTH_STAT";
	case OES_EVENT_AUTH_POLL:	return "AUTH_POLL";
	case OES_EVENT_AUTH_REVOKE:	return "AUTH_REVOKE";
	case OES_EVENT_AUTH_READDIR:	return "AUTH_READDIR";
	case OES_EVENT_AUTH_READLINK:	return "AUTH_READLINK";
	case OES_EVENT_AUTH_GETEXTATTR:	return "AUTH_GETEXTATTR";
	case OES_EVENT_AUTH_DELETEEXTATTR:	return "AUTH_DELETEEXTATTR";
	case OES_EVENT_AUTH_LISTEXTATTR:	return "AUTH_LISTEXTATTR";
	case OES_EVENT_AUTH_GETACL:	return "AUTH_GETACL";
	case OES_EVENT_AUTH_SETACL:	return "AUTH_SETACL";
	case OES_EVENT_AUTH_DELETEACL:	return "AUTH_DELETEACL";
	case OES_EVENT_AUTH_RELABEL:	return "AUTH_RELABEL";
	case OES_EVENT_AUTH_SWAPON:	return "AUTH_SWAPON";
	case OES_EVENT_AUTH_SWAPOFF:	return "AUTH_SWAPOFF";
	case OES_EVENT_NOTIFY_EXEC:	return "NOTIFY_EXEC";
	case OES_EVENT_NOTIFY_EXIT:	return "NOTIFY_EXIT";
	case OES_EVENT_NOTIFY_FORK:	return "NOTIFY_FORK";
	case OES_EVENT_NOTIFY_OPEN:	return "NOTIFY_OPEN";
	case OES_EVENT_NOTIFY_CREATE:	return "NOTIFY_CREATE";
	case OES_EVENT_NOTIFY_UNLINK:	return "NOTIFY_UNLINK";
	case OES_EVENT_NOTIFY_RENAME:	return "NOTIFY_RENAME";
	case OES_EVENT_NOTIFY_MOUNT:	return "NOTIFY_MOUNT";
	case OES_EVENT_NOTIFY_KLDLOAD:	return "NOTIFY_KLDLOAD";
	case OES_EVENT_NOTIFY_SIGNAL:	return "NOTIFY_SIGNAL";
	case OES_EVENT_NOTIFY_PTRACE:	return "NOTIFY_PTRACE";
	case OES_EVENT_NOTIFY_SETUID:	return "NOTIFY_SETUID";
	case OES_EVENT_NOTIFY_SETGID:	return "NOTIFY_SETGID";
	case OES_EVENT_NOTIFY_ACCESS:	return "NOTIFY_ACCESS";
	case OES_EVENT_NOTIFY_READ:	return "NOTIFY_READ";
	case OES_EVENT_NOTIFY_WRITE:	return "NOTIFY_WRITE";
	case OES_EVENT_NOTIFY_LOOKUP:	return "NOTIFY_LOOKUP";
	case OES_EVENT_NOTIFY_SETMODE:	return "NOTIFY_SETMODE";
	case OES_EVENT_NOTIFY_SETOWNER:	return "NOTIFY_SETOWNER";
	case OES_EVENT_NOTIFY_SETFLAGS:	return "NOTIFY_SETFLAGS";
	case OES_EVENT_NOTIFY_SETUTIMES:	return "NOTIFY_SETUTIMES";
	case OES_EVENT_NOTIFY_STAT:	return "NOTIFY_STAT";
	case OES_EVENT_NOTIFY_POLL:	return "NOTIFY_POLL";
	case OES_EVENT_NOTIFY_REVOKE:	return "NOTIFY_REVOKE";
	case OES_EVENT_NOTIFY_READDIR:	return "NOTIFY_READDIR";
	case OES_EVENT_NOTIFY_READLINK:	return "NOTIFY_READLINK";
	case OES_EVENT_NOTIFY_SETEXTATTR:	return "NOTIFY_SETEXTATTR";
	case OES_EVENT_NOTIFY_GETEXTATTR:	return "NOTIFY_GETEXTATTR";
	case OES_EVENT_NOTIFY_DELETEEXTATTR:	return "NOTIFY_DELETEEXTATTR";
	case OES_EVENT_NOTIFY_LISTEXTATTR:	return "NOTIFY_LISTEXTATTR";
	case OES_EVENT_NOTIFY_GETACL:	return "NOTIFY_GETACL";
	case OES_EVENT_NOTIFY_SETACL:	return "NOTIFY_SETACL";
	case OES_EVENT_NOTIFY_DELETEACL:	return "NOTIFY_DELETEACL";
	case OES_EVENT_NOTIFY_RELABEL:	return "NOTIFY_RELABEL";
	case OES_EVENT_NOTIFY_SOCKET_CONNECT:	return "NOTIFY_SOCKET_CONNECT";
	case OES_EVENT_NOTIFY_SOCKET_BIND:	return "NOTIFY_SOCKET_BIND";
	case OES_EVENT_NOTIFY_SOCKET_LISTEN:	return "NOTIFY_SOCKET_LISTEN";
	case OES_EVENT_NOTIFY_REBOOT:	return "NOTIFY_REBOOT";
	case OES_EVENT_NOTIFY_SYSCTL:	return "NOTIFY_SYSCTL";
	case OES_EVENT_NOTIFY_KENV:	return "NOTIFY_KENV";
	case OES_EVENT_NOTIFY_SWAPON:	return "NOTIFY_SWAPON";
	case OES_EVENT_NOTIFY_SWAPOFF:	return "NOTIFY_SWAPOFF";
	case OES_EVENT_NOTIFY_UNMOUNT:	return "NOTIFY_UNMOUNT";
	case OES_EVENT_NOTIFY_KLDUNLOAD:	return "NOTIFY_KLDUNLOAD";
	case OES_EVENT_NOTIFY_LINK:	return "NOTIFY_LINK";
	case OES_EVENT_NOTIFY_MMAP:	return "NOTIFY_MMAP";
	case OES_EVENT_NOTIFY_MPROTECT:	return "NOTIFY_MPROTECT";
	case OES_EVENT_NOTIFY_CHDIR:	return "NOTIFY_CHDIR";
	case OES_EVENT_NOTIFY_CHROOT:	return "NOTIFY_CHROOT";
	case OES_EVENT_NOTIFY_SOCKET_CREATE:	return "NOTIFY_SOCKET_CREATE";
	case OES_EVENT_NOTIFY_SOCKET_ACCEPT:	return "NOTIFY_SOCKET_ACCEPT";
	case OES_EVENT_NOTIFY_SOCKET_SEND:	return "NOTIFY_SOCKET_SEND";
	case OES_EVENT_NOTIFY_SOCKET_RECEIVE:	return "NOTIFY_SOCKET_RECEIVE";
	case OES_EVENT_NOTIFY_SOCKET_STAT:	return "NOTIFY_SOCKET_STAT";
	case OES_EVENT_NOTIFY_SOCKET_POLL:	return "NOTIFY_SOCKET_POLL";
	case OES_EVENT_NOTIFY_PIPE_READ:	return "NOTIFY_PIPE_READ";
	case OES_EVENT_NOTIFY_PIPE_WRITE:	return "NOTIFY_PIPE_WRITE";
	case OES_EVENT_NOTIFY_PIPE_STAT:	return "NOTIFY_PIPE_STAT";
	case OES_EVENT_NOTIFY_PIPE_POLL:	return "NOTIFY_PIPE_POLL";
	case OES_EVENT_NOTIFY_PIPE_IOCTL:	return "NOTIFY_PIPE_IOCTL";
	case OES_EVENT_NOTIFY_MOUNT_STAT:	return "NOTIFY_MOUNT_STAT";
	case OES_EVENT_NOTIFY_PRIV_CHECK:	return "NOTIFY_PRIV_CHECK";
	case OES_EVENT_NOTIFY_PROC_SCHED:	return "NOTIFY_PROC_SCHED";
	default:			return "UNKNOWN";
	}
}
