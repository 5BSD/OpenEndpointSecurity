/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 * All rights reserved.
 *
 * libesc - Userspace library for Endpoint Security Capabilities
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

#include "libesc.h"

/*
 * Client structure
 */
struct esc_client {
	int		ec_fd;		/* File descriptor */
	bool		ec_owned;	/* We own the fd (close on destroy) */
	uint32_t	ec_mode;	/* Current mode */
};

/*
 * esc_client_create - Create a new ESC client
 */
esc_client_t *
esc_client_create(void)
{
	esc_client_t *client;
	int fd;

	fd = open(ESC_DEVICE_PATH, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return (NULL);

	client = calloc(1, sizeof(*client));
	if (client == NULL) {
		close(fd);
		return (NULL);
	}

	client->ec_fd = fd;
	client->ec_owned = true;
	client->ec_mode = ESC_MODE_NOTIFY;

	return (client);
}

/*
 * esc_client_create_from_fd - Create client from existing fd
 */
esc_client_t *
esc_client_create_from_fd(int fd)
{
	esc_client_t *client;

	if (fd < 0) {
		errno = EBADF;
		return (NULL);
	}

	client = calloc(1, sizeof(*client));
	if (client == NULL)
		return (NULL);

	client->ec_fd = fd;
	client->ec_owned = false;
	client->ec_mode = ESC_MODE_NOTIFY;

	return (client);
}

/*
 * esc_client_destroy - Destroy a client
 */
void
esc_client_destroy(esc_client_t *client)
{

	if (client == NULL)
		return;

	if (client->ec_owned && client->ec_fd >= 0)
		close(client->ec_fd);

	free(client);
}

/*
 * esc_client_fd - Get the underlying file descriptor
 */
int
esc_client_fd(esc_client_t *client)
{

	return (client->ec_fd);
}

/*
 * esc_set_mode - Set client operating mode
 */
int
esc_set_mode(esc_client_t *client, uint32_t mode,
    uint32_t timeout_ms, uint32_t queue_size)
{
	struct esc_mode_args args;

	memset(&args, 0, sizeof(args));
	args.ema_mode = mode;
	args.ema_timeout_ms = timeout_ms;
	args.ema_queue_size = queue_size;

	if (ioctl(client->ec_fd, ESC_IOC_SET_MODE, &args) < 0)
		return (-1);

	client->ec_mode = mode;
	return (0);
}

/*
 * esc_get_mode - Get current client mode and configuration
 */
int
esc_get_mode(esc_client_t *client, uint32_t *mode,
    uint32_t *timeout_ms, uint32_t *queue_size)
{
	struct esc_mode_args args;

	memset(&args, 0, sizeof(args));
	if (ioctl(client->ec_fd, ESC_IOC_GET_MODE, &args) < 0)
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
 * esc_set_timeout - Set AUTH timeout independently of mode
 */
int
esc_set_timeout(esc_client_t *client, uint32_t timeout_ms)
{
	struct esc_timeout_args args;

	memset(&args, 0, sizeof(args));
	args.eta_timeout_ms = timeout_ms;

	return (ioctl(client->ec_fd, ESC_IOC_SET_TIMEOUT, &args));
}

/*
 * esc_get_timeout - Get current AUTH timeout
 */
int
esc_get_timeout(esc_client_t *client, uint32_t *timeout_ms)
{
	struct esc_timeout_args args;

	memset(&args, 0, sizeof(args));
	if (ioctl(client->ec_fd, ESC_IOC_GET_TIMEOUT, &args) < 0)
		return (-1);

	if (timeout_ms != NULL)
		*timeout_ms = args.eta_timeout_ms;

	return (0);
}

/*
 * esc_set_timeout_action - Set default action when AUTH times out
 */
int
esc_set_timeout_action(esc_client_t *client, esc_auth_result_t action)
{
	struct esc_timeout_action_args args;

	memset(&args, 0, sizeof(args));
	args.eta_action = action;

	if (ioctl(client->ec_fd, ESC_IOC_SET_TIMEOUT_ACTION, &args) < 0)
		return (-1);

	return (0);
}

/*
 * esc_get_timeout_action - Get default action when AUTH times out
 */
int
esc_get_timeout_action(esc_client_t *client, esc_auth_result_t *action)
{
	struct esc_timeout_action_args args;

	memset(&args, 0, sizeof(args));
	if (ioctl(client->ec_fd, ESC_IOC_GET_TIMEOUT_ACTION, &args) < 0)
		return (-1);

	if (action != NULL)
		*action = (esc_auth_result_t)args.eta_action;

	return (0);
}

/*
 * esc_cache_add - Add or update a decision cache entry
 */
int
esc_cache_add(esc_client_t *client, const esc_cache_entry_t *entry)
{

	return (ioctl(client->ec_fd, ESC_IOC_CACHE_ADD, entry));
}

/*
 * esc_cache_remove - Remove decision cache entries matching key
 */
int
esc_cache_remove(esc_client_t *client, const esc_cache_key_t *key)
{

	return (ioctl(client->ec_fd, ESC_IOC_CACHE_REMOVE, key));
}

/*
 * esc_cache_clear - Clear the decision cache for this client
 */
int
esc_cache_clear(esc_client_t *client)
{

	return (ioctl(client->ec_fd, ESC_IOC_CACHE_CLEAR));
}

/*
 * esc_subscribe - Subscribe to event types
 */
int
esc_subscribe(esc_client_t *client, const esc_event_type_t *events,
    size_t count, uint32_t flags)
{
	struct esc_subscribe_args args;

	memset(&args, 0, sizeof(args));
	args.esa_events = events;
	args.esa_count = count;
	args.esa_flags = flags;

	return (ioctl(client->ec_fd, ESC_IOC_SUBSCRIBE, &args));
}

/*
 * esc_subscribe_bitmap - Subscribe using bitmaps directly
 *
 * This uses the bitmap ioctl for efficient bulk subscription.
 * Bit positions correspond to (event_type & 0x0FFF).
 */
int
esc_subscribe_bitmap(esc_client_t *client, uint64_t auth_bitmap,
    uint64_t notify_bitmap, uint32_t flags)
{
	struct esc_subscribe_bitmap_args args;

	if (client == NULL) {
		errno = EINVAL;
		return (-1);
	}

	memset(&args, 0, sizeof(args));
	args.esba_auth = auth_bitmap;
	args.esba_notify = notify_bitmap;
	args.esba_flags = flags;

	return (ioctl(client->ec_fd, ESC_IOC_SUBSCRIBE_BITMAP, &args));
}

/*
 * esc_subscribe_bitmap_ex - Subscribe using 128-bit bitmaps
 *
 * Extended version supporting events with bit positions >= 64.
 */
int
esc_subscribe_bitmap_ex(esc_client_t *client, const uint64_t auth_bitmap[2],
    const uint64_t notify_bitmap[2], uint32_t flags)
{
	struct esc_subscribe_bitmap_ex_args args;

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

	return (ioctl(client->ec_fd, ESC_IOC_SUBSCRIBE_BITMAP_EX, &args));
}

/*
 * esc_subscribe_all - Subscribe to all events of a type
 *
 * Uses the extended bitmap ioctl for a single atomic operation.
 */
int
esc_subscribe_all(esc_client_t *client, bool auth, bool notify)
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

	return (esc_subscribe_bitmap_ex(client,
	    auth ? all_auth : (const uint64_t[2]){0, 0},
	    notify ? all_notify : (const uint64_t[2]){0, 0},
	    ESC_SUB_REPLACE));
}

/*
 * esc_mute_self - Mute events from the current process
 */
int
esc_mute_self(esc_client_t *client)
{
	struct esc_mute_args args;

	memset(&args, 0, sizeof(args));
	args.emu_flags = ESC_MUTE_SELF;

	return (ioctl(client->ec_fd, ESC_IOC_MUTE_PROCESS, &args));
}

/*
 * esc_mute_process - Mute events from a specific process
 */
int
esc_mute_process(esc_client_t *client, const esc_proc_token_t *token)
{
	struct esc_mute_args args;

	memset(&args, 0, sizeof(args));
	args.emu_token = *token;
	args.emu_flags = 0;

	return (ioctl(client->ec_fd, ESC_IOC_MUTE_PROCESS, &args));
}

/*
 * esc_unmute_process - Unmute a previously muted process
 */
int
esc_unmute_process(esc_client_t *client, const esc_proc_token_t *token)
{
	struct esc_mute_args args;

	memset(&args, 0, sizeof(args));
	args.emu_token = *token;

	return (ioctl(client->ec_fd, ESC_IOC_UNMUTE_PROCESS, &args));
}

/*
 * esc_mute_path - Mute events by path
 */
int
esc_mute_path(esc_client_t *client, const char *path, uint32_t type)
{
	struct esc_mute_path_args args;

	memset(&args, 0, sizeof(args));
	if (path != NULL)
		strlcpy(args.emp_path, path, sizeof(args.emp_path));
	args.emp_type = type;
	args.emp_flags = 0;

	return (ioctl(client->ec_fd, ESC_IOC_MUTE_PATH, &args));
}

/*
 * esc_unmute_path - Unmute events by path
 */
int
esc_unmute_path(esc_client_t *client, const char *path, uint32_t type)
{
	struct esc_mute_path_args args;

	memset(&args, 0, sizeof(args));
	if (path != NULL)
		strlcpy(args.emp_path, path, sizeof(args.emp_path));
	args.emp_type = type;
	args.emp_flags = 0;

	return (ioctl(client->ec_fd, ESC_IOC_UNMUTE_PATH, &args));
}

/*
 * esc_mute_target_path - Mute events by target path
 */
int
esc_mute_target_path(esc_client_t *client, const char *path, uint32_t type)
{
	struct esc_mute_path_args args;

	memset(&args, 0, sizeof(args));
	if (path != NULL)
		strlcpy(args.emp_path, path, sizeof(args.emp_path));
	args.emp_type = type;
	args.emp_flags = ESC_MUTE_PATH_FLAG_TARGET;

	return (ioctl(client->ec_fd, ESC_IOC_MUTE_PATH, &args));
}

/*
 * esc_unmute_target_path - Unmute events by target path
 */
int
esc_unmute_target_path(esc_client_t *client, const char *path, uint32_t type)
{
	struct esc_mute_path_args args;

	memset(&args, 0, sizeof(args));
	if (path != NULL)
		strlcpy(args.emp_path, path, sizeof(args.emp_path));
	args.emp_type = type;
	args.emp_flags = ESC_MUTE_PATH_FLAG_TARGET;

	return (ioctl(client->ec_fd, ESC_IOC_UNMUTE_PATH, &args));
}

/*
 * esc_set_mute_invert - Enable/disable mute inversion for a type
 */
int
esc_set_mute_invert(esc_client_t *client, uint32_t type, bool invert)
{
	struct esc_mute_invert_args args;

	memset(&args, 0, sizeof(args));
	args.emi_type = type;
	args.emi_invert = invert ? 1 : 0;

	return (ioctl(client->ec_fd, ESC_IOC_SET_MUTE_INVERT, &args));
}

/*
 * esc_get_mute_invert - Query mute inversion for a type
 */
int
esc_get_mute_invert(esc_client_t *client, uint32_t type, bool *invert)
{
	struct esc_mute_invert_args args;

	if (invert == NULL)
		return (-1);

	memset(&args, 0, sizeof(args));
	args.emi_type = type;
	if (ioctl(client->ec_fd, ESC_IOC_GET_MUTE_INVERT, &args) < 0)
		return (-1);

	*invert = (args.emi_invert != 0);
	return (0);
}

/*
 * esc_read_event - Read one event
 *
 * Uses poll() for non-blocking reads instead of toggling O_NONBLOCK,
 * which is not thread-safe on a shared file descriptor.
 */
int
esc_read_event(esc_client_t *client, esc_message_t *msg, bool blocking)
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
 * esc_respond - Respond to an AUTH event
 */
int
esc_respond(esc_client_t *client, uint64_t msg_id, esc_auth_result_t result)
{
	esc_response_t resp;
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
 * esc_dispatch - Event dispatch loop
 */
int
esc_dispatch(esc_client_t *client, esc_handler_t handler, void *context)
{
	esc_message_t msg;
	bool cont;

	for (;;) {
		if (esc_read_event(client, &msg, true) < 0)
			return (-1);

		cont = handler(client, &msg, context);
		if (!cont)
			return (0);
	}
}

/*
 * esc_get_stats - Get client statistics
 */
int
esc_get_stats(esc_client_t *client, struct esc_stats *stats)
{

	return (ioctl(client->ec_fd, ESC_IOC_GET_STATS, stats));
}

/*
 * esc_event_name - Get human-readable event name
 */
const char *
esc_event_name(esc_event_type_t event)
{

	switch (event) {
	case ESC_EVENT_AUTH_EXEC:	return "AUTH_EXEC";
	case ESC_EVENT_AUTH_OPEN:	return "AUTH_OPEN";
	case ESC_EVENT_AUTH_CREATE:	return "AUTH_CREATE";
	case ESC_EVENT_AUTH_UNLINK:	return "AUTH_UNLINK";
	case ESC_EVENT_AUTH_RENAME:	return "AUTH_RENAME";
	case ESC_EVENT_AUTH_LINK:	return "AUTH_LINK";
	case ESC_EVENT_AUTH_MOUNT:	return "AUTH_MOUNT";
	case ESC_EVENT_AUTH_KLDLOAD:	return "AUTH_KLDLOAD";
	case ESC_EVENT_AUTH_MMAP:	return "AUTH_MMAP";
	case ESC_EVENT_AUTH_MPROTECT:	return "AUTH_MPROTECT";
	case ESC_EVENT_AUTH_CHDIR:	return "AUTH_CHDIR";
	case ESC_EVENT_AUTH_CHROOT:	return "AUTH_CHROOT";
	case ESC_EVENT_AUTH_SETEXTATTR:	return "AUTH_SETEXTATTR";
	case ESC_EVENT_AUTH_PTRACE:	return "AUTH_PTRACE";
	case ESC_EVENT_AUTH_ACCESS:	return "AUTH_ACCESS";
	case ESC_EVENT_AUTH_READ:	return "AUTH_READ";
	case ESC_EVENT_AUTH_WRITE:	return "AUTH_WRITE";
	case ESC_EVENT_AUTH_LOOKUP:	return "AUTH_LOOKUP";
	case ESC_EVENT_AUTH_SETMODE:	return "AUTH_SETMODE";
	case ESC_EVENT_AUTH_SETOWNER:	return "AUTH_SETOWNER";
	case ESC_EVENT_AUTH_SETFLAGS:	return "AUTH_SETFLAGS";
	case ESC_EVENT_AUTH_SETUTIMES:	return "AUTH_SETUTIMES";
	case ESC_EVENT_AUTH_STAT:	return "AUTH_STAT";
	case ESC_EVENT_AUTH_POLL:	return "AUTH_POLL";
	case ESC_EVENT_AUTH_REVOKE:	return "AUTH_REVOKE";
	case ESC_EVENT_AUTH_READDIR:	return "AUTH_READDIR";
	case ESC_EVENT_AUTH_READLINK:	return "AUTH_READLINK";
	case ESC_EVENT_AUTH_GETEXTATTR:	return "AUTH_GETEXTATTR";
	case ESC_EVENT_AUTH_DELETEEXTATTR:	return "AUTH_DELETEEXTATTR";
	case ESC_EVENT_AUTH_LISTEXTATTR:	return "AUTH_LISTEXTATTR";
	case ESC_EVENT_AUTH_GETACL:	return "AUTH_GETACL";
	case ESC_EVENT_AUTH_SETACL:	return "AUTH_SETACL";
	case ESC_EVENT_AUTH_DELETEACL:	return "AUTH_DELETEACL";
	case ESC_EVENT_AUTH_RELABEL:	return "AUTH_RELABEL";
	case ESC_EVENT_AUTH_SWAPON:	return "AUTH_SWAPON";
	case ESC_EVENT_AUTH_SWAPOFF:	return "AUTH_SWAPOFF";
	case ESC_EVENT_NOTIFY_EXEC:	return "NOTIFY_EXEC";
	case ESC_EVENT_NOTIFY_EXIT:	return "NOTIFY_EXIT";
	case ESC_EVENT_NOTIFY_FORK:	return "NOTIFY_FORK";
	case ESC_EVENT_NOTIFY_OPEN:	return "NOTIFY_OPEN";
	case ESC_EVENT_NOTIFY_CREATE:	return "NOTIFY_CREATE";
	case ESC_EVENT_NOTIFY_UNLINK:	return "NOTIFY_UNLINK";
	case ESC_EVENT_NOTIFY_RENAME:	return "NOTIFY_RENAME";
	case ESC_EVENT_NOTIFY_MOUNT:	return "NOTIFY_MOUNT";
	case ESC_EVENT_NOTIFY_KLDLOAD:	return "NOTIFY_KLDLOAD";
	case ESC_EVENT_NOTIFY_SIGNAL:	return "NOTIFY_SIGNAL";
	case ESC_EVENT_NOTIFY_PTRACE:	return "NOTIFY_PTRACE";
	case ESC_EVENT_NOTIFY_SETUID:	return "NOTIFY_SETUID";
	case ESC_EVENT_NOTIFY_SETGID:	return "NOTIFY_SETGID";
	case ESC_EVENT_NOTIFY_ACCESS:	return "NOTIFY_ACCESS";
	case ESC_EVENT_NOTIFY_READ:	return "NOTIFY_READ";
	case ESC_EVENT_NOTIFY_WRITE:	return "NOTIFY_WRITE";
	case ESC_EVENT_NOTIFY_LOOKUP:	return "NOTIFY_LOOKUP";
	case ESC_EVENT_NOTIFY_SETMODE:	return "NOTIFY_SETMODE";
	case ESC_EVENT_NOTIFY_SETOWNER:	return "NOTIFY_SETOWNER";
	case ESC_EVENT_NOTIFY_SETFLAGS:	return "NOTIFY_SETFLAGS";
	case ESC_EVENT_NOTIFY_SETUTIMES:	return "NOTIFY_SETUTIMES";
	case ESC_EVENT_NOTIFY_STAT:	return "NOTIFY_STAT";
	case ESC_EVENT_NOTIFY_POLL:	return "NOTIFY_POLL";
	case ESC_EVENT_NOTIFY_REVOKE:	return "NOTIFY_REVOKE";
	case ESC_EVENT_NOTIFY_READDIR:	return "NOTIFY_READDIR";
	case ESC_EVENT_NOTIFY_READLINK:	return "NOTIFY_READLINK";
	case ESC_EVENT_NOTIFY_SETEXTATTR:	return "NOTIFY_SETEXTATTR";
	case ESC_EVENT_NOTIFY_GETEXTATTR:	return "NOTIFY_GETEXTATTR";
	case ESC_EVENT_NOTIFY_DELETEEXTATTR:	return "NOTIFY_DELETEEXTATTR";
	case ESC_EVENT_NOTIFY_LISTEXTATTR:	return "NOTIFY_LISTEXTATTR";
	case ESC_EVENT_NOTIFY_GETACL:	return "NOTIFY_GETACL";
	case ESC_EVENT_NOTIFY_SETACL:	return "NOTIFY_SETACL";
	case ESC_EVENT_NOTIFY_DELETEACL:	return "NOTIFY_DELETEACL";
	case ESC_EVENT_NOTIFY_RELABEL:	return "NOTIFY_RELABEL";
	case ESC_EVENT_NOTIFY_SOCKET_CONNECT:	return "NOTIFY_SOCKET_CONNECT";
	case ESC_EVENT_NOTIFY_SOCKET_BIND:	return "NOTIFY_SOCKET_BIND";
	case ESC_EVENT_NOTIFY_SOCKET_LISTEN:	return "NOTIFY_SOCKET_LISTEN";
	case ESC_EVENT_NOTIFY_REBOOT:	return "NOTIFY_REBOOT";
	case ESC_EVENT_NOTIFY_SYSCTL:	return "NOTIFY_SYSCTL";
	case ESC_EVENT_NOTIFY_KENV:	return "NOTIFY_KENV";
	case ESC_EVENT_NOTIFY_SWAPON:	return "NOTIFY_SWAPON";
	case ESC_EVENT_NOTIFY_SWAPOFF:	return "NOTIFY_SWAPOFF";
	case ESC_EVENT_NOTIFY_UNMOUNT:	return "NOTIFY_UNMOUNT";
	case ESC_EVENT_NOTIFY_KLDUNLOAD:	return "NOTIFY_KLDUNLOAD";
	case ESC_EVENT_NOTIFY_LINK:	return "NOTIFY_LINK";
	case ESC_EVENT_NOTIFY_MMAP:	return "NOTIFY_MMAP";
	case ESC_EVENT_NOTIFY_MPROTECT:	return "NOTIFY_MPROTECT";
	case ESC_EVENT_NOTIFY_CHDIR:	return "NOTIFY_CHDIR";
	case ESC_EVENT_NOTIFY_CHROOT:	return "NOTIFY_CHROOT";
	case ESC_EVENT_NOTIFY_SOCKET_CREATE:	return "NOTIFY_SOCKET_CREATE";
	case ESC_EVENT_NOTIFY_SOCKET_ACCEPT:	return "NOTIFY_SOCKET_ACCEPT";
	case ESC_EVENT_NOTIFY_SOCKET_SEND:	return "NOTIFY_SOCKET_SEND";
	case ESC_EVENT_NOTIFY_SOCKET_RECEIVE:	return "NOTIFY_SOCKET_RECEIVE";
	case ESC_EVENT_NOTIFY_SOCKET_STAT:	return "NOTIFY_SOCKET_STAT";
	case ESC_EVENT_NOTIFY_SOCKET_POLL:	return "NOTIFY_SOCKET_POLL";
	case ESC_EVENT_NOTIFY_PIPE_READ:	return "NOTIFY_PIPE_READ";
	case ESC_EVENT_NOTIFY_PIPE_WRITE:	return "NOTIFY_PIPE_WRITE";
	case ESC_EVENT_NOTIFY_PIPE_STAT:	return "NOTIFY_PIPE_STAT";
	case ESC_EVENT_NOTIFY_PIPE_POLL:	return "NOTIFY_PIPE_POLL";
	case ESC_EVENT_NOTIFY_PIPE_IOCTL:	return "NOTIFY_PIPE_IOCTL";
	case ESC_EVENT_NOTIFY_MOUNT_STAT:	return "NOTIFY_MOUNT_STAT";
	case ESC_EVENT_NOTIFY_PRIV_CHECK:	return "NOTIFY_PRIV_CHECK";
	case ESC_EVENT_NOTIFY_PROC_SCHED:	return "NOTIFY_PROC_SCHED";
	default:			return "UNKNOWN";
	}
}
