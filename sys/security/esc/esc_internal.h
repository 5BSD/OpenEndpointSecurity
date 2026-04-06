/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 * All rights reserved.
 *
 * Endpoint Security Capabilities (esc) - Kernel Internal Header
 */

#ifndef _SECURITY_ESC_INTERNAL_H_
#define _SECURITY_ESC_INTERNAL_H_

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

#include <security/esc/esc.h>

/*
 * Forward declarations
 */
struct esc_client;
struct esc_pending;
struct esc_auth_group;
struct esc_cache_entry;

/*
 * Global state
 */
struct esc_softc {
	struct mtx		sc_mtx;		/* Protects client list */
	LIST_HEAD(, esc_client)	sc_clients;	/* All active clients */
	uint32_t		sc_nclients;	/* Number of clients */
	uint64_t		sc_next_msg_id;	/* Next message ID */
	uint64_t		sc_next_client_id; /* Next client ID */
	struct cdev		*sc_cdev;	/* Character device */
	bool			sc_active;	/* Module is active */
	uint64_t		sc_nosleep_drops; /* NOSLEEP notifies dropped */
	uint64_t		sc_alloc_failures; /* Allocation failures */
};

extern struct esc_softc esc_softc;

#define ESC_LOCK()		mtx_lock(&esc_softc.sc_mtx)
#define ESC_UNLOCK()		mtx_unlock(&esc_softc.sc_mtx)
#define ESC_LOCK_ASSERT()	mtx_assert(&esc_softc.sc_mtx, MA_OWNED)

struct esc_mute_path_entry;
LIST_HEAD(esc_mute_path_list, esc_mute_path_entry);

/*
 * Forward declarations for UID/GID mute lists
 */
struct esc_mute_uid_entry;
struct esc_mute_gid_entry;
LIST_HEAD(esc_mute_uid_list, esc_mute_uid_entry);
LIST_HEAD(esc_mute_gid_list, esc_mute_gid_entry);

/*
 * Process mute hash table
 */
#define ESC_MUTE_PROC_BUCKETS	64

struct esc_mute_entry;
LIST_HEAD(esc_mute_bucket, esc_mute_entry);

/*
 * Decision cache entry
 */
#define ESC_CACHE_BUCKETS	64

struct esc_cache_entry {
	LIST_ENTRY(esc_cache_entry) ece_link;
	TAILQ_ENTRY(esc_cache_entry) ece_lru;
	esc_cache_key_t	ece_key;
	esc_auth_result_t ece_result;
	struct timespec	ece_expires;
};

LIST_HEAD(esc_cache_bucket, esc_cache_entry);
TAILQ_HEAD(esc_cache_lru, esc_cache_entry);

/*
 * Per-client state (one per open())
 *
 * Each open() creates a new client with independent subscriptions,
 * event queue, and configuration.
 */
struct esc_client {
	LIST_ENTRY(esc_client)	ec_link;	/* Link in global list */
	struct mtx		ec_mtx;		/* Protects this client */
	uint64_t		ec_id;		/* Unique client ID */
	pid_t			ec_owner_pid;	/* Owner pid (open()) */
	uint64_t		ec_owner_genid;	/* Owner generation */
	uint32_t		ec_mode;	/* ESC_MODE_* */
	uint32_t		ec_timeout_ms;	/* AUTH timeout */
	uint32_t		ec_timeout_action; /* Default AUTH timeout action */
	uint64_t		ec_subscriptions[4]; /* [0,1]=AUTH (128b), [2,3]=NOTIFY (128b) */
	uint32_t		ec_flags;	/* EC_FLAG_* */
	uint32_t		ec_mute_invert;	/* ESC_MUTE_INVERT_* */

	/* Event queue */
	TAILQ_HEAD(, esc_pending) ec_pending;	/* Pending events */
	TAILQ_HEAD(, esc_pending) ec_delivered;	/* Delivered AUTH events */
	uint32_t		ec_queue_count;	/* Current queue depth */
	uint32_t		ec_queue_max;	/* Max queue size */
	struct selinfo		ec_selinfo;	/* For poll/select/kqueue */

	/* Process muting (hash table by pid) */
	struct esc_mute_bucket ec_muted[ESC_MUTE_PROC_BUCKETS];
	struct esc_mute_path_list ec_muted_paths;	/* Muted paths */
	struct esc_mute_path_list ec_muted_targets;	/* Muted target paths */
	uint32_t		ec_muted_proc_count;	/* Muted process count */
	uint32_t		ec_muted_path_count;	/* Muted path count */
	uint32_t		ec_muted_target_count;	/* Muted target count */

	/* Decision cache */
	struct esc_cache_bucket ec_cache[ESC_CACHE_BUCKETS];
	struct esc_cache_lru	ec_cache_lru;
	uint32_t		ec_cache_entries;
	uint32_t		ec_cache_max;

	/* UID/GID muting */
	struct esc_mute_uid_list ec_muted_uids;
	struct esc_mute_gid_list ec_muted_gids;
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
struct esc_pending {
	TAILQ_ENTRY(esc_pending) ep_link;	/* Link in client queue */
	esc_message_t		ep_msg;		/* The message */
	uint32_t		ep_flags;	/* EP_FLAG_* */
	int			ep_refcount;	/* Reference count */
	uint64_t		ep_client_id;	/* AUTH client ID */
	uint32_t		ep_timeout_action; /* AUTH timeout action */

	/* For AUTH events: response handling */
	struct mtx		ep_mtx;		/* Protects response state */
	struct cv		ep_cv;		/* Wait for response */
	bool			ep_responded;	/* Response received */
	esc_auth_result_t	ep_result;	/* Response value */
	uint32_t		ep_allowed_flags; /* Flags-based: allowed flags */
	uint32_t		ep_denied_flags;  /* Flags-based: denied flags */
	struct timespec		ep_deadline;	/* Absolute deadline */
	struct esc_auth_group	*ep_group;	/* AUTH arbitration group */
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
struct esc_mute_entry {
	LIST_ENTRY(esc_mute_entry) em_link;
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
struct esc_mute_path_entry {
	LIST_ENTRY(esc_mute_path_entry) emp_link;
	char			emp_path[MAXPATHLEN];
	size_t			emp_len;
	uint32_t		emp_type;	/* ESC_MUTE_PATH_* */
	uint64_t		emp_events[4];	/* [0,1]=AUTH, [2,3]=NOTIFY */
	/* Token for matching when path resolution fails */
	uint64_t		emp_ino;	/* Inode number */
	uint64_t		emp_dev;	/* Device number */
	bool			emp_has_token;	/* Token is valid */
};

/*
 * Muted UID entry (dynamically allocated)
 */
struct esc_mute_uid_entry {
	LIST_ENTRY(esc_mute_uid_entry) emu_link;
	uid_t			emu_uid;
};

/*
 * Muted GID entry (dynamically allocated)
 */
struct esc_mute_gid_entry {
	LIST_ENTRY(esc_mute_gid_entry) emg_link;
	gid_t			emg_gid;
};

/*
 * Process mute hash helper
 */
static __inline uint32_t
esc_mute_proc_bucket(pid_t pid)
{

	return ((uint32_t)pid & (ESC_MUTE_PROC_BUCKETS - 1));
}

/*
 * Subscription bitmap helpers
 *
 * AUTH events use ec_subscriptions[0,1], NOTIFY uses ec_subscriptions[2,3]
 * Each category has 128 bits (2 x 64-bit words).
 */
static __inline bool
esc_client_subscribed(struct esc_client *ec, esc_event_type_t event)
{
	int base = ESC_EVENT_IS_NOTIFY(event) ? 2 : 0;
	int bit = event & 0x0FFF;
	int word = bit / 64;
	int shift = bit % 64;

	if (bit >= 128)
		return (false);
	return ((ec->ec_subscriptions[base + word] & (1ULL << shift)) != 0);
}

static __inline void
esc_client_subscribe(struct esc_client *ec, esc_event_type_t event)
{
	int base = ESC_EVENT_IS_NOTIFY(event) ? 2 : 0;
	int bit = event & 0x0FFF;
	int word = bit / 64;
	int shift = bit % 64;

	if (bit < 128)
		ec->ec_subscriptions[base + word] |= (1ULL << shift);
}

static __inline void
esc_client_unsubscribe_all(struct esc_client *ec)
{
	ec->ec_subscriptions[0] = 0;
	ec->ec_subscriptions[1] = 0;
	ec->ec_subscriptions[2] = 0;
	ec->ec_subscriptions[3] = 0;
}

static const esc_event_type_t esc_auth_notify_map[] = {
	[ESC_EVENT_AUTH_EXEC]		= ESC_EVENT_NOTIFY_EXEC,
	[ESC_EVENT_AUTH_OPEN]		= ESC_EVENT_NOTIFY_OPEN,
	[ESC_EVENT_AUTH_CREATE]		= ESC_EVENT_NOTIFY_CREATE,
	[ESC_EVENT_AUTH_UNLINK]		= ESC_EVENT_NOTIFY_UNLINK,
	[ESC_EVENT_AUTH_RENAME]		= ESC_EVENT_NOTIFY_RENAME,
	[ESC_EVENT_AUTH_LINK]		= ESC_EVENT_NOTIFY_LINK,
	[ESC_EVENT_AUTH_MOUNT]		= ESC_EVENT_NOTIFY_MOUNT,
	[ESC_EVENT_AUTH_KLDLOAD]	= ESC_EVENT_NOTIFY_KLDLOAD,
	[ESC_EVENT_AUTH_MMAP]		= ESC_EVENT_NOTIFY_MMAP,
	[ESC_EVENT_AUTH_MPROTECT]	= ESC_EVENT_NOTIFY_MPROTECT,
	[ESC_EVENT_AUTH_CHDIR]		= ESC_EVENT_NOTIFY_CHDIR,
	[ESC_EVENT_AUTH_CHROOT]		= ESC_EVENT_NOTIFY_CHROOT,
	[ESC_EVENT_AUTH_SETEXTATTR]	= ESC_EVENT_NOTIFY_SETEXTATTR,
	[ESC_EVENT_AUTH_PTRACE]		= ESC_EVENT_NOTIFY_PTRACE,
	[ESC_EVENT_AUTH_ACCESS]		= ESC_EVENT_NOTIFY_ACCESS,
	[ESC_EVENT_AUTH_READ]		= ESC_EVENT_NOTIFY_READ,
	[ESC_EVENT_AUTH_WRITE]		= ESC_EVENT_NOTIFY_WRITE,
	[ESC_EVENT_AUTH_LOOKUP]		= ESC_EVENT_NOTIFY_LOOKUP,
	[ESC_EVENT_AUTH_SETMODE]	= ESC_EVENT_NOTIFY_SETMODE,
	[ESC_EVENT_AUTH_SETOWNER]	= ESC_EVENT_NOTIFY_SETOWNER,
	[ESC_EVENT_AUTH_SETFLAGS]	= ESC_EVENT_NOTIFY_SETFLAGS,
	[ESC_EVENT_AUTH_SETUTIMES]	= ESC_EVENT_NOTIFY_SETUTIMES,
	[ESC_EVENT_AUTH_STAT]		= ESC_EVENT_NOTIFY_STAT,
	[ESC_EVENT_AUTH_POLL]		= ESC_EVENT_NOTIFY_POLL,
	[ESC_EVENT_AUTH_REVOKE]		= ESC_EVENT_NOTIFY_REVOKE,
	[ESC_EVENT_AUTH_READDIR]	= ESC_EVENT_NOTIFY_READDIR,
	[ESC_EVENT_AUTH_READLINK]	= ESC_EVENT_NOTIFY_READLINK,
	[ESC_EVENT_AUTH_GETEXTATTR]	= ESC_EVENT_NOTIFY_GETEXTATTR,
	[ESC_EVENT_AUTH_DELETEEXTATTR]	= ESC_EVENT_NOTIFY_DELETEEXTATTR,
	[ESC_EVENT_AUTH_LISTEXTATTR]	= ESC_EVENT_NOTIFY_LISTEXTATTR,
	[ESC_EVENT_AUTH_GETACL]		= ESC_EVENT_NOTIFY_GETACL,
	[ESC_EVENT_AUTH_SETACL]		= ESC_EVENT_NOTIFY_SETACL,
	[ESC_EVENT_AUTH_DELETEACL]	= ESC_EVENT_NOTIFY_DELETEACL,
	[ESC_EVENT_AUTH_RELABEL]	= ESC_EVENT_NOTIFY_RELABEL,
	/* Swapon/Swapoff */
	[ESC_EVENT_AUTH_SWAPON]		= ESC_EVENT_NOTIFY_SWAPON,
	[ESC_EVENT_AUTH_SWAPOFF]	= ESC_EVENT_NOTIFY_SWAPOFF,
	/* Socket/pipe/mount_stat/priv/proc_sched are NOTIFY-only (no AUTH) */
};

static __inline esc_event_type_t
esc_auth_to_notify(esc_event_type_t auth_event)
{
	u_int idx = (u_int)auth_event;

	if (idx < nitems(esc_auth_notify_map))
		return (esc_auth_notify_map[idx]);
	return (0);
}

/*
 * Convert vnode type to EF_TYPE_*
 */
static __inline uint8_t
esc_vtype_to_eftype(int vt)
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
 * Function prototypes - esc_dev.c
 */
int	esc_dev_init(void);
void	esc_dev_uninit(void);

/*
 * Function prototypes - esc_client.c
 */
struct esc_client *esc_client_alloc(void);
void	esc_client_free(struct esc_client *ec);
int	esc_client_subscribe_events(struct esc_client *ec,
	    esc_event_type_t *events, size_t count, uint32_t flags);
int	esc_client_subscribe_bitmap(struct esc_client *ec,
	    uint64_t auth_bitmap, uint64_t notify_bitmap, uint32_t flags);
int	esc_client_subscribe_bitmap_ex(struct esc_client *ec,
	    const uint64_t auth_bitmap[2], const uint64_t notify_bitmap[2],
	    uint32_t flags);
int	esc_client_set_mode(struct esc_client *ec, uint32_t mode,
	    uint32_t timeout_ms, uint32_t queue_size);
void	esc_client_get_mode(struct esc_client *ec, uint32_t *mode,
	    uint32_t *timeout_ms, uint32_t *queue_size);
int	esc_client_set_timeout(struct esc_client *ec, uint32_t timeout_ms);
void	esc_client_get_timeout(struct esc_client *ec, uint32_t *timeout_ms);
bool	esc_client_is_muted(struct esc_client *ec, struct proc *p,
	    esc_event_type_t event);
bool	esc_client_is_muted_by_token(struct esc_client *ec,
	    const esc_proc_token_t *token, esc_event_type_t event);
bool	esc_client_is_path_muted(struct esc_client *ec, const char *path,
	    bool target, esc_event_type_t event);
bool	esc_client_is_token_muted(struct esc_client *ec, uint64_t ino,
	    uint64_t dev, bool target, esc_event_type_t event);
int	esc_client_mute(struct esc_client *ec, esc_proc_token_t *token,
	    uint32_t flags);
int	esc_client_unmute(struct esc_client *ec, esc_proc_token_t *token);
int	esc_client_mute_path(struct esc_client *ec, const char *path,
	    uint32_t type, bool target);
int	esc_client_unmute_path(struct esc_client *ec, const char *path,
	    uint32_t type, bool target);
int	esc_client_set_mute_invert(struct esc_client *ec, uint32_t type,
	    bool invert);
int	esc_client_get_mute_invert(struct esc_client *ec, uint32_t type,
	    uint32_t *invert);
int	esc_client_set_timeout_action(struct esc_client *ec, uint32_t action);
int	esc_client_get_timeout_action(struct esc_client *ec, uint32_t *action);
void	esc_client_get_stats(struct esc_client *ec, struct esc_stats *stats);

/* Per-event-type muting */
int	esc_client_mute_events(struct esc_client *ec, esc_proc_token_t *token,
	    uint32_t flags, const esc_event_type_t *events, size_t count);
int	esc_client_unmute_events(struct esc_client *ec, esc_proc_token_t *token,
	    uint32_t flags, const esc_event_type_t *events, size_t count);
int	esc_client_mute_path_events(struct esc_client *ec, const char *path,
	    uint32_t type, bool target, const esc_event_type_t *events,
	    size_t count);
int	esc_client_unmute_path_events(struct esc_client *ec, const char *path,
	    uint32_t type, bool target, const esc_event_type_t *events,
	    size_t count);

/* Query muted lists */
int	esc_client_get_muted_processes(struct esc_client *ec,
	    struct esc_muted_process_entry *entries, size_t count,
	    size_t *actual);
int	esc_client_get_muted_paths(struct esc_client *ec,
	    struct esc_muted_path_entry *entries, size_t count,
	    size_t *actual, bool target);

/* Unmute all */
void	esc_client_unmute_all_processes(struct esc_client *ec);
void	esc_client_unmute_all_paths(struct esc_client *ec, bool target);

/* UID/GID muting */
int	esc_client_mute_uid(struct esc_client *ec, uid_t uid);
int	esc_client_unmute_uid(struct esc_client *ec, uid_t uid);
int	esc_client_mute_gid(struct esc_client *ec, gid_t gid);
int	esc_client_unmute_gid(struct esc_client *ec, gid_t gid);
void	esc_client_unmute_all_uids(struct esc_client *ec);
void	esc_client_unmute_all_gids(struct esc_client *ec);
bool	esc_client_is_uid_muted(struct esc_client *ec, uid_t uid);
bool	esc_client_is_gid_muted(struct esc_client *ec, gid_t gid);

/*
 * Function prototypes - esc_cache.c
 */
void	esc_cache_init(struct esc_client *ec);
void	esc_cache_destroy(struct esc_client *ec);
int	esc_client_cache_add(struct esc_client *ec,
	    const esc_cache_entry_t *entry);
int	esc_client_cache_remove(struct esc_client *ec,
	    const esc_cache_key_t *key);
void	esc_client_cache_clear(struct esc_client *ec);
bool	esc_client_cache_lookup(struct esc_client *ec,
	    const struct esc_pending *ep, esc_auth_result_t *result);

/*
 * Function prototypes - esc_event.c
 */
struct esc_pending *esc_pending_alloc(esc_event_type_t event, struct proc *p);
void	esc_pending_free(struct esc_pending *ep);
void	esc_pending_hold(struct esc_pending *ep);
void	esc_pending_rele(struct esc_pending *ep);
int	esc_event_enqueue(struct esc_client *ec, struct esc_pending *ep);
struct esc_pending *esc_event_dequeue(struct esc_client *ec);
int	esc_event_respond(struct esc_client *ec, uint64_t msg_id,
	    esc_auth_result_t result);
int	esc_event_respond_flags(struct esc_client *ec, uint64_t msg_id,
	    esc_auth_result_t result, uint32_t allowed_flags,
	    uint32_t denied_flags);
void	esc_event_handle_timeout(struct esc_pending *ep);
struct esc_pending *esc_pending_clone(const struct esc_pending *src);

struct esc_auth_group *esc_auth_group_alloc(void);
void	esc_auth_group_hold(struct esc_auth_group *ag);
void	esc_auth_group_rele(struct esc_auth_group *ag);
void	esc_auth_group_add_pending(struct esc_auth_group *ag);
void	esc_auth_group_cancel_pending(struct esc_auth_group *ag);
void	esc_auth_group_mark_response(struct esc_auth_group *ag,
	    esc_auth_result_t result);
int	esc_auth_group_wait(struct esc_auth_group *ag,
	    struct esc_pending **eps, size_t count);
void	esc_set_auth_deadline(struct esc_pending *ep, uint32_t timeout_ms);

/*
 * Function prototypes - esc_mac.c (MAC policy integration)
 */
int	esc_mac_init(void);
void	esc_mac_uninit(void);
uint64_t esc_proc_get_exec_id(struct proc *p);

/*
 * Helper to fill process info
 */
void	esc_fill_process(esc_process_t *ep, struct proc *p,
	    struct ucred *cred);
void	esc_fill_file(esc_file_t *ef, struct vnode *vp, struct ucred *cred);

/*
 * Sysctl variables
 */
SYSCTL_DECL(_security_esc);

extern int esc_debug;
extern int esc_default_timeout;
extern int esc_default_action;
extern int esc_default_queue_size;
extern int esc_max_clients;
extern int esc_cache_max_entries;
extern char esc_default_muted_paths[];
extern char esc_default_muted_paths_literal[];
extern int esc_default_self_mute;

/*
 * Debug macros
 */
#define ESC_DEBUG(fmt, ...)	do {				\
	if (esc_debug)						\
		printf("esc: " fmt "\n", ##__VA_ARGS__);	\
} while (0)

#define ESC_WARN(fmt, ...)	\
	printf("esc: WARNING: " fmt "\n", ##__VA_ARGS__)

#define ESC_ERR(fmt, ...)	\
	printf("esc: ERROR: " fmt "\n", ##__VA_ARGS__)

#endif /* _KERNEL */

#endif /* !_SECURITY_ESC_INTERNAL_H_ */
