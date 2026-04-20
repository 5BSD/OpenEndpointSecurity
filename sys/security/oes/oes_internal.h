/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 * All rights reserved.
 *
 * Open Endpoint Security (OES) - Kernel Internal Header
 */

#ifndef _SECURITY_OES_INTERNAL_H_
#define _SECURITY_OES_INTERNAL_H_

#ifdef _KERNEL

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sx.h>
#include <sys/queue.h>
#include <sys/selinfo.h>
#include <sys/proc.h>
#include <sys/file.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>

#include <security/oes/oes.h>

/*
 * Forward declarations
 */
struct oes_client;
struct oes_pending;
struct oes_auth_group;
struct oes_cache_entry;

/*
 * Global state
 */
struct oes_softc {
	struct mtx		sc_mtx;		/* Protects client list */
	LIST_HEAD(, oes_client)	sc_clients;	/* All active clients */
	uint32_t		sc_nclients;	/* Number of clients */
	uint64_t		sc_next_msg_id;	/* Next message ID */
	uint64_t		sc_next_client_id; /* Next client ID */
	struct cdev		*sc_cdev;	/* Character device */
	bool			sc_active;	/* Module is active */
	uint64_t		sc_nosleep_drops; /* NOSLEEP notifies dropped */
	uint64_t		sc_alloc_failures; /* Allocation failures */
};

extern struct oes_softc oes_softc;

#define OES_LOCK()		mtx_lock(&oes_softc.sc_mtx)
#define OES_UNLOCK()		mtx_unlock(&oes_softc.sc_mtx)
#define OES_LOCK_ASSERT()	mtx_assert(&oes_softc.sc_mtx, MA_OWNED)

struct oes_mute_path_entry;
LIST_HEAD(oes_mute_path_list, oes_mute_path_entry);

/*
 * Forward declarations for UID/GID mute lists
 */
struct oes_mute_uid_entry;
struct oes_mute_gid_entry;
LIST_HEAD(oes_mute_uid_list, oes_mute_uid_entry);
LIST_HEAD(oes_mute_gid_list, oes_mute_gid_entry);

/*
 * Process mute hash table
 */
#define OES_MUTE_PROC_BUCKETS	64

struct oes_mute_entry;
LIST_HEAD(oes_mute_bucket, oes_mute_entry);

/*
 * Decision cache entry
 */
#define OES_CACHE_BUCKETS	64

struct oes_cache_entry {
	LIST_ENTRY(oes_cache_entry) ece_link;
	TAILQ_ENTRY(oes_cache_entry) ece_lru;
	oes_cache_key_t	ece_key;
	oes_auth_result_t ece_result;
	struct timespec	ece_expires;
};

LIST_HEAD(oes_cache_bucket, oes_cache_entry);
TAILQ_HEAD(oes_cache_lru, oes_cache_entry);

/*
 * Per-client state (one per open())
 *
 * Each open() creates a new client with independent subscriptions,
 * event queue, and configuration.
 */
struct oes_client {
	LIST_ENTRY(oes_client)	ec_link;	/* Link in global list */
	struct mtx		ec_mtx;		/* Protects this client */
	uint64_t		ec_id;		/* Unique client ID */
	pid_t			ec_owner_pid;	/* Owner pid (open()) */
	uint64_t		ec_owner_genid;	/* Owner generation */
	uint32_t		ec_mode;	/* OES_MODE_* */
	uint32_t		ec_timeout_ms;	/* AUTH timeout */
	uint32_t		ec_timeout_action; /* Default AUTH timeout action */
	uint64_t		ec_subscriptions[4]; /* [0,1]=AUTH (128b), [2,3]=NOTIFY (128b) */
	uint32_t		ec_flags;	/* EC_FLAG_* */
	uint32_t		ec_mute_invert;	/* OES_MUTE_INVERT_* */

	/* Event queue */
	TAILQ_HEAD(, oes_pending) ec_pending;	/* Pending events */
	TAILQ_HEAD(, oes_pending) ec_delivered;	/* Delivered AUTH events */
	uint32_t		ec_queue_count;	/* Current queue depth */
	uint32_t		ec_queue_max;	/* Max queue size */
	struct selinfo		ec_selinfo;	/* For poll/select/kqueue */

	/* Process muting (hash table by pid) */
	struct oes_mute_bucket ec_muted[OES_MUTE_PROC_BUCKETS];
	struct oes_mute_path_list ec_muted_paths;	/* Muted paths */
	struct oes_mute_path_list ec_muted_targets;	/* Muted target paths */
	uint32_t		ec_muted_proc_count;	/* Muted process count */
	uint32_t		ec_muted_path_count;	/* Muted path count */
	uint32_t		ec_muted_target_count;	/* Muted target count */

	/* Decision cache */
	struct oes_cache_bucket ec_cache[OES_CACHE_BUCKETS];
	struct oes_cache_lru	ec_cache_lru;
	uint32_t		ec_cache_entries;
	uint32_t		ec_cache_max;

	/* UID/GID muting */
	struct oes_mute_uid_list ec_muted_uids;
	struct oes_mute_gid_list ec_muted_gids;
	uint32_t		ec_muted_uid_count;
	uint32_t		ec_muted_gid_count;

	/* Statistics */
	uint64_t		ec_events_received;
	uint64_t		ec_events_dropped;
	uint64_t		ec_auth_timeouts;
	uint64_t		ec_auth_allowed;
	uint64_t		ec_auth_denied;
	uint64_t		ec_cache_hits;
	uint64_t		ec_cache_misses;
	uint64_t		ec_cache_evictions;
	uint64_t		ec_cache_expired;
};

/* Client flags */
#define EC_FLAG_CLOSING		0x0001	/* Client is closing */
#define EC_FLAG_MUTED_SELF	0x0002	/* Self-muted */
#define EC_FLAG_MODE_SET	0x0004	/* Mode has been explicitly set */

/* Mute inversion flags */
#define EC_MUTE_INVERT_PROCESS	0x0001	/* Process mute inversion */
#define EC_MUTE_INVERT_PATH	0x0002	/* Path mute inversion */
#define EC_MUTE_INVERT_TARGET	0x0004	/* Target path mute inversion */

#define EC_LOCK(ec)		mtx_lock(&(ec)->ec_mtx)
#define EC_UNLOCK(ec)		mtx_unlock(&(ec)->ec_mtx)
#define EC_LOCK_ASSERT(ec)	mtx_assert(&(ec)->ec_mtx, MA_OWNED)

/*
 * Pending event (in client queue)
 */
struct oes_pending {
	TAILQ_ENTRY(oes_pending) ep_link;	/* Link in client queue */
	oes_message_t		ep_msg;		/* The message */
	uint32_t		ep_flags;	/* EP_FLAG_* */
	int			ep_refcount;	/* Reference count */
	uint64_t		ep_client_id;	/* AUTH client ID */
	uint32_t		ep_timeout_action; /* AUTH timeout action */

	/* For AUTH events: response handling */
	struct mtx		ep_mtx;		/* Protects response state */
	struct cv		ep_cv;		/* Wait for response */
	bool			ep_responded;	/* Response received */
	oes_auth_result_t	ep_result;	/* Response value */
	uint32_t		ep_allowed_flags; /* Flags-based: allowed flags */
	uint32_t		ep_denied_flags;  /* Flags-based: denied flags */
	struct timespec		ep_deadline;	/* Absolute deadline */
	struct oes_auth_group	*ep_group;	/* AUTH arbitration group */
};

/* Pending event flags */
#define EP_FLAG_AUTH		0x0001	/* This is an AUTH event */
#define EP_FLAG_DELIVERED	0x0002	/* Delivered to userspace */
#define EP_FLAG_EXPIRED		0x0004	/* Deadline expired */

/*
 * Muted process entry
 *
 * If all em_events[] are 0, all events are muted.
 * Otherwise, only events with bits set in em_events are muted.
 * Layout: [0,1]=AUTH (128 bits), [2,3]=NOTIFY (128 bits)
 */
struct oes_mute_entry {
	LIST_ENTRY(oes_mute_entry) em_link;
	pid_t			em_pid;		/* Muted PID */
	uint64_t		em_genid;	/* Generation to detect reuse */
	uint64_t		em_events[4];	/* [0,1]=AUTH, [2,3]=NOTIFY */
};

/*
 * Muted path entry
 *
 * If all emp_events[] are 0, all events are muted.
 * Otherwise, only events with bits set in emp_events are muted.
 * Layout: [0,1]=AUTH (128 bits), [2,3]=NOTIFY (128 bits)
 */
struct oes_mute_path_entry {
	LIST_ENTRY(oes_mute_path_entry) emp_link;
	char			emp_path[MAXPATHLEN];
	size_t			emp_len;
	uint32_t		emp_type;	/* OES_MUTE_PATH_* */
	uint64_t		emp_events[4];	/* [0,1]=AUTH, [2,3]=NOTIFY */
	/* Token for matching when path resolution fails */
	uint64_t		emp_ino;	/* Inode number */
	uint64_t		emp_dev;	/* Device number */
	bool			emp_has_token;	/* Token is valid */
};

/*
 * Muted UID entry (dynamically allocated)
 */
struct oes_mute_uid_entry {
	LIST_ENTRY(oes_mute_uid_entry) emu_link;
	uid_t			emu_uid;
};

/*
 * Muted GID entry (dynamically allocated)
 */
struct oes_mute_gid_entry {
	LIST_ENTRY(oes_mute_gid_entry) emg_link;
	gid_t			emg_gid;
};

/*
 * Process mute hash helper
 */
static __inline uint32_t
oes_mute_proc_bucket(pid_t pid)
{

	return ((uint32_t)pid & (OES_MUTE_PROC_BUCKETS - 1));
}

/*
 * Subscription bitmap helpers
 *
 * AUTH events use ec_subscriptions[0,1], NOTIFY uses ec_subscriptions[2,3]
 * Each category has 128 bits (2 x 64-bit words).
 */
static __inline bool
oes_client_subscribed(struct oes_client *ec, oes_event_type_t event)
{
	int base = OES_EVENT_IS_NOTIFY(event) ? 2 : 0;
	int bit = event & 0x0FFF;
	int word = bit / 64;
	int shift = bit % 64;

	if (bit >= 128)
		return (false);
	return ((ec->ec_subscriptions[base + word] & (1ULL << shift)) != 0);
}

static __inline void
oes_client_subscribe(struct oes_client *ec, oes_event_type_t event)
{
	int base = OES_EVENT_IS_NOTIFY(event) ? 2 : 0;
	int bit = event & 0x0FFF;
	int word = bit / 64;
	int shift = bit % 64;

	if (bit < 128)
		ec->ec_subscriptions[base + word] |= (1ULL << shift);
}

static __inline void
oes_client_unsubscribe_all(struct oes_client *ec)
{
	ec->ec_subscriptions[0] = 0;
	ec->ec_subscriptions[1] = 0;
	ec->ec_subscriptions[2] = 0;
	ec->ec_subscriptions[3] = 0;
}

/*
 * Validate that an event type is a defined enum value, not just
 * a value that passes the AUTH/NOTIFY bit test and bit < 128 range.
 */
static __inline bool
oes_event_is_valid(oes_event_type_t ev)
{
	if (OES_EVENT_IS_AUTH(ev)) {
		switch (ev) {
		case OES_EVENT_AUTH_EXEC:
		case OES_EVENT_AUTH_OPEN:
		case OES_EVENT_AUTH_CREATE:
		case OES_EVENT_AUTH_UNLINK:
		case OES_EVENT_AUTH_RENAME:
		case OES_EVENT_AUTH_LINK:
		case OES_EVENT_AUTH_MOUNT:
		case OES_EVENT_AUTH_KLDLOAD:
		case OES_EVENT_AUTH_MMAP:
		case OES_EVENT_AUTH_MPROTECT:
		case OES_EVENT_AUTH_CHDIR:
		case OES_EVENT_AUTH_CHROOT:
		case OES_EVENT_AUTH_SETEXTATTR:
		case OES_EVENT_AUTH_PTRACE:
		case OES_EVENT_AUTH_ACCESS:
		case OES_EVENT_AUTH_READ:
		case OES_EVENT_AUTH_WRITE:
		case OES_EVENT_AUTH_LOOKUP:
		case OES_EVENT_AUTH_SETMODE:
		case OES_EVENT_AUTH_SETOWNER:
		case OES_EVENT_AUTH_SETFLAGS:
		case OES_EVENT_AUTH_SETUTIMES:
		case OES_EVENT_AUTH_STAT:
		case OES_EVENT_AUTH_POLL:
		case OES_EVENT_AUTH_REVOKE:
		case OES_EVENT_AUTH_READDIR:
		case OES_EVENT_AUTH_READLINK:
		case OES_EVENT_AUTH_GETEXTATTR:
		case OES_EVENT_AUTH_DELETEEXTATTR:
		case OES_EVENT_AUTH_LISTEXTATTR:
		case OES_EVENT_AUTH_GETACL:
		case OES_EVENT_AUTH_SETACL:
		case OES_EVENT_AUTH_DELETEACL:
		case OES_EVENT_AUTH_RELABEL:
		case OES_EVENT_AUTH_SWAPON:
		case OES_EVENT_AUTH_SWAPOFF:
			return (true);
		default:
			return (false);
		}
	}

	switch (ev) {
	case OES_EVENT_NOTIFY_EXEC:
	case OES_EVENT_NOTIFY_EXIT:
	case OES_EVENT_NOTIFY_FORK:
	case OES_EVENT_NOTIFY_OPEN:
	case OES_EVENT_NOTIFY_CREATE:
	case OES_EVENT_NOTIFY_UNLINK:
	case OES_EVENT_NOTIFY_RENAME:
	case OES_EVENT_NOTIFY_MOUNT:
	case OES_EVENT_NOTIFY_KLDLOAD:
	case OES_EVENT_NOTIFY_SIGNAL:
	case OES_EVENT_NOTIFY_PTRACE:
	case OES_EVENT_NOTIFY_SETUID:
	case OES_EVENT_NOTIFY_SETGID:
	case OES_EVENT_NOTIFY_ACCESS:
	case OES_EVENT_NOTIFY_READ:
	case OES_EVENT_NOTIFY_WRITE:
	case OES_EVENT_NOTIFY_LOOKUP:
	case OES_EVENT_NOTIFY_SETMODE:
	case OES_EVENT_NOTIFY_SETOWNER:
	case OES_EVENT_NOTIFY_SETFLAGS:
	case OES_EVENT_NOTIFY_SETUTIMES:
	case OES_EVENT_NOTIFY_STAT:
	case OES_EVENT_NOTIFY_POLL:
	case OES_EVENT_NOTIFY_REVOKE:
	case OES_EVENT_NOTIFY_READDIR:
	case OES_EVENT_NOTIFY_READLINK:
	case OES_EVENT_NOTIFY_GETEXTATTR:
	case OES_EVENT_NOTIFY_DELETEEXTATTR:
	case OES_EVENT_NOTIFY_LISTEXTATTR:
	case OES_EVENT_NOTIFY_GETACL:
	case OES_EVENT_NOTIFY_SETACL:
	case OES_EVENT_NOTIFY_DELETEACL:
	case OES_EVENT_NOTIFY_RELABEL:
	case OES_EVENT_NOTIFY_SETEXTATTR:
	case OES_EVENT_NOTIFY_SOCKET_CONNECT:
	case OES_EVENT_NOTIFY_SOCKET_BIND:
	case OES_EVENT_NOTIFY_SOCKET_LISTEN:
	case OES_EVENT_NOTIFY_REBOOT:
	case OES_EVENT_NOTIFY_SYSCTL:
	case OES_EVENT_NOTIFY_KENV:
	case OES_EVENT_NOTIFY_SWAPON:
	case OES_EVENT_NOTIFY_SWAPOFF:
	case OES_EVENT_NOTIFY_UNMOUNT:
	case OES_EVENT_NOTIFY_KLDUNLOAD:
	case OES_EVENT_NOTIFY_LINK:
	case OES_EVENT_NOTIFY_MMAP:
	case OES_EVENT_NOTIFY_MPROTECT:
	case OES_EVENT_NOTIFY_CHDIR:
	case OES_EVENT_NOTIFY_CHROOT:
	case OES_EVENT_NOTIFY_SOCKET_CREATE:
	case OES_EVENT_NOTIFY_SOCKET_ACCEPT:
	case OES_EVENT_NOTIFY_SOCKET_SEND:
	case OES_EVENT_NOTIFY_SOCKET_RECEIVE:
	case OES_EVENT_NOTIFY_SOCKET_STAT:
	case OES_EVENT_NOTIFY_SOCKET_POLL:
	case OES_EVENT_NOTIFY_PIPE_READ:
	case OES_EVENT_NOTIFY_PIPE_WRITE:
	case OES_EVENT_NOTIFY_PIPE_STAT:
	case OES_EVENT_NOTIFY_PIPE_POLL:
	case OES_EVENT_NOTIFY_PIPE_IOCTL:
	case OES_EVENT_NOTIFY_MOUNT_STAT:
	case OES_EVENT_NOTIFY_PRIV_CHECK:
	case OES_EVENT_NOTIFY_PROC_SCHED:
		return (true);
	default:
		return (false);
	}
}

/*
 * Valid event bitmaps.
 *
 * These define which bits correspond to real enum values.
 * Used to mask bitmap subscribe inputs, expand "mute all" correctly,
 * and validate cache keys.
 *
 * AUTH: bits 1-34 (EXEC..RELABEL), 41-42 (SWAPON, SWAPOFF)
 * NOTIFY: bits 1-4,6-9,11,13-63 (low), 64-66 (high)
 *   Gaps at bits 0, 5, 10, 12 (no NOTIFY events defined there)
 */
#define OES_VALID_AUTH_LO	0x6007FFFFFFFEULL
#define OES_VALID_AUTH_HI	0x0ULL
#define OES_VALID_NOTIFY_LO	0xFFFFFFFFFFFFEBDEULL
#define OES_VALID_NOTIFY_HI	0x7ULL

static const oes_event_type_t oes_auth_notify_map[] = {
	[OES_EVENT_AUTH_EXEC]		= OES_EVENT_NOTIFY_EXEC,
	[OES_EVENT_AUTH_OPEN]		= OES_EVENT_NOTIFY_OPEN,
	[OES_EVENT_AUTH_CREATE]		= OES_EVENT_NOTIFY_CREATE,
	[OES_EVENT_AUTH_UNLINK]		= OES_EVENT_NOTIFY_UNLINK,
	[OES_EVENT_AUTH_RENAME]		= OES_EVENT_NOTIFY_RENAME,
	[OES_EVENT_AUTH_LINK]		= OES_EVENT_NOTIFY_LINK,
	[OES_EVENT_AUTH_MOUNT]		= OES_EVENT_NOTIFY_MOUNT,
	[OES_EVENT_AUTH_KLDLOAD]	= OES_EVENT_NOTIFY_KLDLOAD,
	[OES_EVENT_AUTH_MMAP]		= OES_EVENT_NOTIFY_MMAP,
	[OES_EVENT_AUTH_MPROTECT]	= OES_EVENT_NOTIFY_MPROTECT,
	[OES_EVENT_AUTH_CHDIR]		= OES_EVENT_NOTIFY_CHDIR,
	[OES_EVENT_AUTH_CHROOT]		= OES_EVENT_NOTIFY_CHROOT,
	[OES_EVENT_AUTH_SETEXTATTR]	= OES_EVENT_NOTIFY_SETEXTATTR,
	[OES_EVENT_AUTH_PTRACE]		= OES_EVENT_NOTIFY_PTRACE,
	[OES_EVENT_AUTH_ACCESS]		= OES_EVENT_NOTIFY_ACCESS,
	[OES_EVENT_AUTH_READ]		= OES_EVENT_NOTIFY_READ,
	[OES_EVENT_AUTH_WRITE]		= OES_EVENT_NOTIFY_WRITE,
	[OES_EVENT_AUTH_LOOKUP]		= OES_EVENT_NOTIFY_LOOKUP,
	[OES_EVENT_AUTH_SETMODE]	= OES_EVENT_NOTIFY_SETMODE,
	[OES_EVENT_AUTH_SETOWNER]	= OES_EVENT_NOTIFY_SETOWNER,
	[OES_EVENT_AUTH_SETFLAGS]	= OES_EVENT_NOTIFY_SETFLAGS,
	[OES_EVENT_AUTH_SETUTIMES]	= OES_EVENT_NOTIFY_SETUTIMES,
	[OES_EVENT_AUTH_STAT]		= OES_EVENT_NOTIFY_STAT,
	[OES_EVENT_AUTH_POLL]		= OES_EVENT_NOTIFY_POLL,
	[OES_EVENT_AUTH_REVOKE]		= OES_EVENT_NOTIFY_REVOKE,
	[OES_EVENT_AUTH_READDIR]	= OES_EVENT_NOTIFY_READDIR,
	[OES_EVENT_AUTH_READLINK]	= OES_EVENT_NOTIFY_READLINK,
	[OES_EVENT_AUTH_GETEXTATTR]	= OES_EVENT_NOTIFY_GETEXTATTR,
	[OES_EVENT_AUTH_DELETEEXTATTR]	= OES_EVENT_NOTIFY_DELETEEXTATTR,
	[OES_EVENT_AUTH_LISTEXTATTR]	= OES_EVENT_NOTIFY_LISTEXTATTR,
	[OES_EVENT_AUTH_GETACL]		= OES_EVENT_NOTIFY_GETACL,
	[OES_EVENT_AUTH_SETACL]		= OES_EVENT_NOTIFY_SETACL,
	[OES_EVENT_AUTH_DELETEACL]	= OES_EVENT_NOTIFY_DELETEACL,
	[OES_EVENT_AUTH_RELABEL]	= OES_EVENT_NOTIFY_RELABEL,
	/* Swapon/Swapoff */
	[OES_EVENT_AUTH_SWAPON]		= OES_EVENT_NOTIFY_SWAPON,
	[OES_EVENT_AUTH_SWAPOFF]	= OES_EVENT_NOTIFY_SWAPOFF,
	/* Socket/pipe/mount_stat/priv/proc_sched are NOTIFY-only (no AUTH) */
};

static __inline oes_event_type_t
oes_auth_to_notify(oes_event_type_t auth_event)
{
	u_int idx = (u_int)auth_event;

	if (idx < nitems(oes_auth_notify_map))
		return (oes_auth_notify_map[idx]);
	return (0);
}

/*
 * Convert vnode type to EF_TYPE_*
 */
static __inline uint8_t
oes_vtype_to_eftype(int vt)
{
	switch (vt) {
	case VREG:	return (EF_TYPE_REG);
	case VDIR:	return (EF_TYPE_DIR);
	case VLNK:	return (EF_TYPE_LNK);
	case VCHR:	return (EF_TYPE_CHR);
	case VBLK:	return (EF_TYPE_BLK);
	case VFIFO:	return (EF_TYPE_FIFO);
	case VSOCK:	return (EF_TYPE_SOCK);
	default:	return (EF_TYPE_UNKNOWN);
	}
}

/*
 * Function prototypes - oes_dev.c
 */
int	oes_dev_init(void);
void	oes_dev_uninit(void);

/*
 * Function prototypes - oes_client.c
 */
struct oes_client *oes_client_alloc(void);
void	oes_client_free(struct oes_client *ec);
int	oes_client_subscribe_events(struct oes_client *ec,
	    oes_event_type_t *events, size_t count, uint32_t flags);
int	oes_client_subscribe_bitmap(struct oes_client *ec,
	    uint64_t auth_bitmap, uint64_t notify_bitmap, uint32_t flags);
int	oes_client_subscribe_bitmap_ex(struct oes_client *ec,
	    const uint64_t auth_bitmap[2], const uint64_t notify_bitmap[2],
	    uint32_t flags);
int	oes_client_set_mode(struct oes_client *ec, uint32_t mode,
	    uint32_t timeout_ms, uint32_t queue_size);
void	oes_client_get_mode(struct oes_client *ec, uint32_t *mode,
	    uint32_t *timeout_ms, uint32_t *queue_size);
int	oes_client_set_timeout(struct oes_client *ec, uint32_t timeout_ms);
void	oes_client_get_timeout(struct oes_client *ec, uint32_t *timeout_ms);
bool	oes_client_is_muted(struct oes_client *ec, struct proc *p,
	    oes_event_type_t event);
bool	oes_client_is_muted_by_token(struct oes_client *ec,
	    const oes_proc_token_t *token, oes_event_type_t event);
bool	oes_client_is_path_muted(struct oes_client *ec, const char *path,
	    bool target, oes_event_type_t event);
bool	oes_client_is_token_muted(struct oes_client *ec, uint64_t ino,
	    uint64_t dev, bool target, oes_event_type_t event);
int	oes_client_mute(struct oes_client *ec, oes_proc_token_t *token,
	    uint32_t flags);
int	oes_client_unmute(struct oes_client *ec, oes_proc_token_t *token);
int	oes_client_mute_path(struct oes_client *ec, const char *path,
	    uint32_t type, bool target);
int	oes_client_unmute_path(struct oes_client *ec, const char *path,
	    uint32_t type, bool target);
int	oes_client_set_mute_invert(struct oes_client *ec, uint32_t type,
	    bool invert);
int	oes_client_get_mute_invert(struct oes_client *ec, uint32_t type,
	    uint32_t *invert);
int	oes_client_set_timeout_action(struct oes_client *ec, uint32_t action);
int	oes_client_get_timeout_action(struct oes_client *ec, uint32_t *action);
void	oes_client_get_stats(struct oes_client *ec, struct oes_stats *stats);

/* Per-event-type muting */
int	oes_client_mute_events(struct oes_client *ec, oes_proc_token_t *token,
	    uint32_t flags, const oes_event_type_t *events, size_t count);
int	oes_client_unmute_events(struct oes_client *ec, oes_proc_token_t *token,
	    uint32_t flags, const oes_event_type_t *events, size_t count);
int	oes_client_mute_path_events(struct oes_client *ec, const char *path,
	    uint32_t type, bool target, const oes_event_type_t *events,
	    size_t count);
int	oes_client_unmute_path_events(struct oes_client *ec, const char *path,
	    uint32_t type, bool target, const oes_event_type_t *events,
	    size_t count);

/* Query muted lists */
int	oes_client_get_muted_processes(struct oes_client *ec,
	    struct oes_muted_process_entry *entries, size_t count,
	    size_t *actual);
int	oes_client_get_muted_paths(struct oes_client *ec,
	    struct oes_muted_path_entry *entries, size_t count,
	    size_t *actual, bool target);

/* Unmute all */
void	oes_client_unmute_all_processes(struct oes_client *ec);
void	oes_client_unmute_all_paths(struct oes_client *ec, bool target);

/* UID/GID muting */
int	oes_client_mute_uid(struct oes_client *ec, uid_t uid);
int	oes_client_unmute_uid(struct oes_client *ec, uid_t uid);
int	oes_client_mute_gid(struct oes_client *ec, gid_t gid);
int	oes_client_unmute_gid(struct oes_client *ec, gid_t gid);
void	oes_client_unmute_all_uids(struct oes_client *ec);
void	oes_client_unmute_all_gids(struct oes_client *ec);
bool	oes_client_is_uid_muted(struct oes_client *ec, uid_t uid);
bool	oes_client_is_gid_muted(struct oes_client *ec, gid_t gid);

/*
 * Function prototypes - oes_cache.c
 */
void	oes_cache_init(struct oes_client *ec);
void	oes_cache_destroy(struct oes_client *ec);
int	oes_client_cache_add(struct oes_client *ec,
	    const oes_cache_entry_t *entry);
int	oes_client_cache_remove(struct oes_client *ec,
	    const oes_cache_key_t *key);
void	oes_client_cache_clear(struct oes_client *ec);
bool	oes_client_cache_lookup(struct oes_client *ec,
	    const struct oes_pending *ep, oes_auth_result_t *result);

/*
 * Function prototypes - oes_event.c
 */
struct oes_pending *oes_pending_alloc(oes_event_type_t event, struct proc *p);
void	oes_pending_free(struct oes_pending *ep);
void	oes_pending_hold(struct oes_pending *ep);
void	oes_pending_rele(struct oes_pending *ep);
int	oes_event_enqueue(struct oes_client *ec, struct oes_pending *ep);
struct oes_pending *oes_event_dequeue(struct oes_client *ec);
int	oes_event_respond(struct oes_client *ec, uint64_t msg_id,
	    oes_auth_result_t result);
int	oes_event_respond_flags(struct oes_client *ec, uint64_t msg_id,
	    oes_auth_result_t result, uint32_t allowed_flags,
	    uint32_t denied_flags);
void	oes_event_handle_timeout(struct oes_pending *ep);
struct oes_pending *oes_pending_clone(const struct oes_pending *src);

struct oes_auth_group *oes_auth_group_alloc(void);
void	oes_auth_group_hold(struct oes_auth_group *ag);
void	oes_auth_group_rele(struct oes_auth_group *ag);
void	oes_auth_group_add_pending(struct oes_auth_group *ag);
void	oes_auth_group_cancel_pending(struct oes_auth_group *ag);
void	oes_auth_group_mark_response(struct oes_auth_group *ag,
	    oes_auth_result_t result);
int	oes_auth_group_wait(struct oes_auth_group *ag,
	    struct oes_pending **eps, size_t count);
void	oes_set_auth_deadline(struct oes_pending *ep, uint32_t timeout_ms);

/*
 * Function prototypes - oes_mac.c (MAC policy integration)
 */
int	oes_mac_init(void);
void	oes_mac_uninit(void);
uint64_t oes_proc_get_exec_id(struct proc *p);

/*
 * Helper to fill process info
 */
void	oes_fill_process(oes_process_t *ep, struct proc *p,
	    struct ucred *cred);
void	oes_fill_file(oes_file_t *ef, struct vnode *vp, struct ucred *cred);

/*
 * Sysctl variables
 */
SYSCTL_DECL(_security_oes);

extern int oes_debug;
extern int oes_default_timeout;
extern int oes_default_action;
extern int oes_default_queue_size;
extern int oes_max_clients;
extern int oes_cache_max_entries;
extern char oes_default_muted_paths[];
extern char oes_default_muted_paths_literal[];
extern int oes_default_self_mute;

/*
 * Debug macros
 */
#define OES_DEBUG(fmt, ...)	do {				\
	if (oes_debug)						\
		printf("oes: " fmt "\n", ##__VA_ARGS__);	\
} while (0)

#define OES_WARN(fmt, ...)	\
	printf("oes: WARNING: " fmt "\n", ##__VA_ARGS__)

#define OES_ERR(fmt, ...)	\
	printf("oes: ERROR: " fmt "\n", ##__VA_ARGS__)

#endif /* _KERNEL */

#endif /* !_SECURITY_OES_INTERNAL_H_ */
