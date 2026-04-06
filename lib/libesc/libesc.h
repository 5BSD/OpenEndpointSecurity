/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 * All rights reserved.
 *
 * libesc - Userspace library for Endpoint Security Capabilities
 */

#ifndef _LIBESC_H_
#define _LIBESC_H_

#include <sys/types.h>
#include <stdbool.h>

/* Include kernel definitions */
#include <security/esc/esc.h>

__BEGIN_DECLS

/*
 * Client handle (opaque)
 */
typedef struct esc_client esc_client_t;

/*
 * Event handler callback
 *
 * Called for each event received. For AUTH events, must call
 * esc_respond() before returning (or event times out).
 *
 * Return false to stop the event loop.
 */
typedef bool (*esc_handler_t)(esc_client_t *client, const esc_message_t *msg,
    void *context);

/*
 * Client creation and destruction
 */

/*
 * esc_client_create - Create a new ESC client
 *
 * Opens /dev/esc and returns a client handle.
 * Requires appropriate privileges.
 *
 * Returns NULL on error, sets errno.
 */
esc_client_t *esc_client_create(void);

/*
 * esc_client_create_from_fd - Create client from existing fd
 *
 * Used when receiving a restricted fd from a system daemon.
 * The fd is NOT closed when client is destroyed.
 *
 * Returns NULL on error, sets errno.
 */
esc_client_t *esc_client_create_from_fd(int fd);

/*
 * esc_client_destroy - Destroy a client
 *
 * Closes the underlying fd (unless created with _from_fd).
 * Any pending AUTH events get default response.
 */
void esc_client_destroy(esc_client_t *client);

/*
 * esc_client_fd - Get the underlying file descriptor
 *
 * Useful for poll()/kevent() integration.
 */
int esc_client_fd(esc_client_t *client);

/*
 * Configuration
 */

/*
 * esc_set_mode - Set client operating mode
 *
 * mode: ESC_MODE_NOTIFY, ESC_MODE_AUTH, or ESC_MODE_PASSIVE
 * timeout_ms: AUTH timeout in milliseconds (0 = keep current)
 * queue_size: Max queued events (0 = keep current)
 *
 * Returns 0 on success, -1 on error (sets errno).
 */
int esc_set_mode(esc_client_t *client, uint32_t mode,
    uint32_t timeout_ms, uint32_t queue_size);

/*
 * esc_get_mode - Get current client mode and configuration
 *
 * mode: OUT, current operating mode (may be NULL)
 * timeout_ms: OUT, current AUTH timeout in milliseconds (may be NULL)
 * queue_size: OUT, current max queued events (may be NULL)
 *
 * Returns 0 on success, -1 on error (sets errno).
 */
int esc_get_mode(esc_client_t *client, uint32_t *mode,
    uint32_t *timeout_ms, uint32_t *queue_size);

/*
 * esc_set_timeout - Set AUTH timeout independently of mode
 *
 * timeout_ms: AUTH timeout in milliseconds (clamped to valid range)
 *
 * Unlike esc_set_mode(), this does not trigger first-mode-set logic
 * (default mutes are not applied).
 *
 * Returns 0 on success, -1 on error (sets errno).
 */
int esc_set_timeout(esc_client_t *client, uint32_t timeout_ms);

/*
 * esc_get_timeout - Get current AUTH timeout
 *
 * Returns 0 on success, -1 on error (sets errno).
 */
int esc_get_timeout(esc_client_t *client, uint32_t *timeout_ms);

/*
 * esc_set_timeout_action - Set default action when AUTH times out
 *
 * action: ESC_AUTH_ALLOW or ESC_AUTH_DENY
 */
int esc_set_timeout_action(esc_client_t *client, esc_auth_result_t action);

/*
 * esc_get_timeout_action - Get default action when AUTH times out
 */
int esc_get_timeout_action(esc_client_t *client, esc_auth_result_t *action);

/*
 * esc_cache_add - Add or update a decision cache entry
 */
int esc_cache_add(esc_client_t *client, const esc_cache_entry_t *entry);

/*
 * esc_cache_remove - Remove decision cache entries matching key
 */
int esc_cache_remove(esc_client_t *client, const esc_cache_key_t *key);

/*
 * esc_cache_clear - Clear the decision cache for this client
 */
int esc_cache_clear(esc_client_t *client);

/*
 * esc_subscribe - Subscribe to event types
 *
 * events: Array of event types to subscribe to
 * count: Number of events in array
 * flags: ESC_SUB_ADD or ESC_SUB_REPLACE
 *
 * Returns 0 on success, -1 on error.
 */
int esc_subscribe(esc_client_t *client, const esc_event_type_t *events,
    size_t count, uint32_t flags);

/*
 * esc_subscribe_bitmap - Subscribe using bitmaps directly
 *
 * Efficient bulk subscription using event bitmaps.
 * Bit positions correspond to (event_type & 0x0FFF).
 * Only supports bits 0-63. Use esc_subscribe_bitmap_ex for bits 64+.
 *
 * Returns 0 on success, -1 on error (sets errno).
 */
int esc_subscribe_bitmap(esc_client_t *client, uint64_t auth_bitmap,
    uint64_t notify_bitmap, uint32_t flags);

/*
 * esc_subscribe_bitmap_ex - Subscribe using 128-bit bitmaps
 *
 * Extended version supporting events with bit positions >= 64.
 * auth_bitmap[0] = bits 0-63, auth_bitmap[1] = bits 64-127
 * notify_bitmap[0] = bits 0-63, notify_bitmap[1] = bits 64-127
 *
 * Returns 0 on success, -1 on error (sets errno).
 */
int esc_subscribe_bitmap_ex(esc_client_t *client, const uint64_t auth_bitmap[2],
    const uint64_t notify_bitmap[2], uint32_t flags);

/*
 * esc_subscribe_all - Subscribe to all events of a type
 *
 * auth: Subscribe to all AUTH events
 * notify: Subscribe to all NOTIFY events
 */
int esc_subscribe_all(esc_client_t *client, bool auth, bool notify);

/*
 * esc_mute_self - Mute events from the current process
 *
 * Prevents recursion when this process triggers events.
 */
int esc_mute_self(esc_client_t *client);

/*
 * esc_mute_process - Mute events from a specific process
 */
int esc_mute_process(esc_client_t *client, const esc_proc_token_t *token);

/*
 * esc_unmute_process - Unmute a previously muted process
 */
int esc_unmute_process(esc_client_t *client, const esc_proc_token_t *token);

/*
 * esc_mute_path - Mute events by path
 *
 * type: ESC_MUTE_PATH_LITERAL or ESC_MUTE_PATH_PREFIX
 */
int esc_mute_path(esc_client_t *client, const char *path, uint32_t type);

/*
 * esc_unmute_path - Unmute events by path
 */
int esc_unmute_path(esc_client_t *client, const char *path, uint32_t type);

/*
 * esc_mute_target_path - Mute events by target path
 */
int esc_mute_target_path(esc_client_t *client, const char *path,
    uint32_t type);

/*
 * esc_unmute_target_path - Unmute events by target path
 */
int esc_unmute_target_path(esc_client_t *client, const char *path,
    uint32_t type);

/*
 * esc_set_mute_invert - Enable/disable mute inversion for a type
 */
int esc_set_mute_invert(esc_client_t *client, uint32_t type, bool invert);

/*
 * esc_get_mute_invert - Query mute inversion for a type
 */
int esc_get_mute_invert(esc_client_t *client, uint32_t type, bool *invert);

/*
 * Event handling
 */

/*
 * esc_read_event - Read one event (blocking or non-blocking)
 *
 * msg: Buffer to receive event
 * blocking: If true, blocks until event available
 *
 * Returns 0 on success, -1 on error.
 * EAGAIN if non-blocking and no events available.
 */
int esc_read_event(esc_client_t *client, esc_message_t *msg, bool blocking);

/*
 * esc_respond - Respond to an AUTH event
 *
 * msg_id: Message ID from esc_message_t.em_id
 * result: ESC_AUTH_ALLOW or ESC_AUTH_DENY
 *
 * Returns 0 on success, -1 on error.
 */
int esc_respond(esc_client_t *client, uint64_t msg_id,
    esc_auth_result_t result);

/*
 * esc_respond_allow - Shorthand for esc_respond(..., ESC_AUTH_ALLOW)
 */
static inline int
esc_respond_allow(esc_client_t *client, const esc_message_t *msg)
{
	return esc_respond(client, msg->em_id, ESC_AUTH_ALLOW);
}

/*
 * esc_respond_deny - Shorthand for esc_respond(..., ESC_AUTH_DENY)
 */
static inline int
esc_respond_deny(esc_client_t *client, const esc_message_t *msg)
{
	return esc_respond(client, msg->em_id, ESC_AUTH_DENY);
}

/*
 * esc_dispatch - Event dispatch loop
 *
 * Reads events and calls handler for each one.
 * Returns when handler returns false or on error.
 *
 * Returns 0 if handler stopped, -1 on error.
 */
int esc_dispatch(esc_client_t *client, esc_handler_t handler, void *context);

/*
 * Statistics
 */

/*
 * esc_get_stats - Get client statistics
 */
int esc_get_stats(esc_client_t *client, struct esc_stats *stats);

/*
 * Utility functions
 */

/*
 * esc_event_name - Get human-readable event name
 */
const char *esc_event_name(esc_event_type_t event);

/*
 * esc_is_auth_event - Check if event requires AUTH response
 */
static inline bool
esc_is_auth_event(const esc_message_t *msg)
{
	return msg->em_action == ESC_ACTION_AUTH;
}

__END_DECLS

#endif /* !_LIBESC_H_ */
