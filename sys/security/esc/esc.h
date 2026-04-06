/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 * All rights reserved.
 *
 * Endpoint Security Capabilities (esc) - Public Header
 *
 * This header defines the userspace API for the esc(4) framework.
 * The framework provides capability-based security event monitoring
 * and authorization, inspired by Apple's Endpoint Security but
 * designed around FreeBSD's Capsicum model.
 */

#ifndef _SYS_ESC_H_
#define _SYS_ESC_H_

#include <sys/types.h>
#include <sys/ioccom.h>
#include <sys/param.h>
#include <sys/dirent.h>
#include <sys/extattr.h>

/*
 * API Version - increment on breaking changes
 */
#define ESC_API_VERSION		1

/*
 * Event Types
 *
 * AUTH events (0x0001-0x0FFF): Sleepable hooks that can block for response.
 * NOTIFY events (0x1001-0x1FFF): Informational, never block.
 */
typedef enum {
	/* AUTH events - require response, can block operations */
	ESC_EVENT_AUTH_EXEC		= 0x0001,
	ESC_EVENT_AUTH_OPEN		= 0x0002,
	ESC_EVENT_AUTH_CREATE		= 0x0003,
	ESC_EVENT_AUTH_UNLINK		= 0x0004,
	ESC_EVENT_AUTH_RENAME		= 0x0005,
	ESC_EVENT_AUTH_LINK		= 0x0006,
	ESC_EVENT_AUTH_MOUNT		= 0x0007,
	ESC_EVENT_AUTH_KLDLOAD		= 0x0008,
	ESC_EVENT_AUTH_MMAP		= 0x0009,
	ESC_EVENT_AUTH_MPROTECT		= 0x000A,
	ESC_EVENT_AUTH_CHDIR		= 0x000B,
	ESC_EVENT_AUTH_CHROOT		= 0x000C,
	ESC_EVENT_AUTH_SETEXTATTR	= 0x000D,
	ESC_EVENT_AUTH_PTRACE		= 0x000E,
	ESC_EVENT_AUTH_ACCESS		= 0x000F,
	ESC_EVENT_AUTH_READ		= 0x0010,
	ESC_EVENT_AUTH_WRITE		= 0x0011,
	ESC_EVENT_AUTH_LOOKUP		= 0x0012,
	ESC_EVENT_AUTH_SETMODE		= 0x0013,
	ESC_EVENT_AUTH_SETOWNER		= 0x0014,
	ESC_EVENT_AUTH_SETFLAGS		= 0x0015,
	ESC_EVENT_AUTH_SETUTIMES	= 0x0016,
	ESC_EVENT_AUTH_STAT		= 0x0017,
	ESC_EVENT_AUTH_POLL		= 0x0018,
	ESC_EVENT_AUTH_REVOKE		= 0x0019,
	ESC_EVENT_AUTH_READDIR		= 0x001A,
	ESC_EVENT_AUTH_READLINK		= 0x001B,
	ESC_EVENT_AUTH_GETEXTATTR	= 0x001C,
	ESC_EVENT_AUTH_DELETEEXTATTR	= 0x001D,
	ESC_EVENT_AUTH_LISTEXTATTR	= 0x001E,
	ESC_EVENT_AUTH_GETACL		= 0x001F,
	ESC_EVENT_AUTH_SETACL		= 0x0020,
	ESC_EVENT_AUTH_DELETEACL	= 0x0021,
	ESC_EVENT_AUTH_RELABEL		= 0x0022,
	/* 0x0023-0x0028 reserved (removed: NOSLEEP hooks are NOTIFY-only) */
	ESC_EVENT_AUTH_SWAPON		= 0x0029,
	ESC_EVENT_AUTH_SWAPOFF		= 0x002A,
	/* 0x002B-0x0038 reserved (socket/pipe/mount_stat/priv/sched are NOTIFY-only) */

	/* NOTIFY events - informational only */
	ESC_EVENT_NOTIFY_EXEC		= 0x1001,
	ESC_EVENT_NOTIFY_EXIT		= 0x1002,
	ESC_EVENT_NOTIFY_FORK		= 0x1003,
	ESC_EVENT_NOTIFY_OPEN		= 0x1004,
	ESC_EVENT_NOTIFY_CREATE		= 0x1006,
	ESC_EVENT_NOTIFY_UNLINK		= 0x1007,
	ESC_EVENT_NOTIFY_RENAME		= 0x1008,
	ESC_EVENT_NOTIFY_MOUNT		= 0x1009,
	ESC_EVENT_NOTIFY_KLDLOAD	= 0x100B,
	ESC_EVENT_NOTIFY_SIGNAL		= 0x100D,
	ESC_EVENT_NOTIFY_PTRACE		= 0x100E,
	ESC_EVENT_NOTIFY_SETUID		= 0x100F,
	ESC_EVENT_NOTIFY_SETGID		= 0x1010,
	ESC_EVENT_NOTIFY_ACCESS		= 0x1011,
	ESC_EVENT_NOTIFY_READ		= 0x1012,
	ESC_EVENT_NOTIFY_WRITE		= 0x1013,
	ESC_EVENT_NOTIFY_LOOKUP		= 0x1014,
	ESC_EVENT_NOTIFY_SETMODE	= 0x1015,
	ESC_EVENT_NOTIFY_SETOWNER	= 0x1016,
	ESC_EVENT_NOTIFY_SETFLAGS	= 0x1017,
	ESC_EVENT_NOTIFY_SETUTIMES	= 0x1018,
	ESC_EVENT_NOTIFY_STAT		= 0x1019,
	ESC_EVENT_NOTIFY_POLL		= 0x101A,
	ESC_EVENT_NOTIFY_REVOKE		= 0x101B,
	ESC_EVENT_NOTIFY_READDIR	= 0x101C,
	ESC_EVENT_NOTIFY_READLINK	= 0x101D,
	ESC_EVENT_NOTIFY_GETEXTATTR	= 0x101E,
	ESC_EVENT_NOTIFY_DELETEEXTATTR	= 0x101F,
	ESC_EVENT_NOTIFY_LISTEXTATTR	= 0x1020,
	ESC_EVENT_NOTIFY_GETACL		= 0x1021,
	ESC_EVENT_NOTIFY_SETACL		= 0x1022,
	ESC_EVENT_NOTIFY_DELETEACL	= 0x1023,
	ESC_EVENT_NOTIFY_RELABEL	= 0x1024,
	ESC_EVENT_NOTIFY_SETEXTATTR	= 0x1025,
	ESC_EVENT_NOTIFY_SOCKET_CONNECT	= 0x1026,
	ESC_EVENT_NOTIFY_SOCKET_BIND	= 0x1027,
	ESC_EVENT_NOTIFY_SOCKET_LISTEN	= 0x1028,
	ESC_EVENT_NOTIFY_REBOOT		= 0x1029,
	ESC_EVENT_NOTIFY_SYSCTL		= 0x102A,
	ESC_EVENT_NOTIFY_KENV		= 0x102B,
	ESC_EVENT_NOTIFY_SWAPON		= 0x102C,
	ESC_EVENT_NOTIFY_SWAPOFF	= 0x102D,
	ESC_EVENT_NOTIFY_UNMOUNT	= 0x102E,
	ESC_EVENT_NOTIFY_KLDUNLOAD	= 0x102F,
	ESC_EVENT_NOTIFY_LINK		= 0x1030,
	ESC_EVENT_NOTIFY_MMAP		= 0x1031,
	ESC_EVENT_NOTIFY_MPROTECT	= 0x1032,
	ESC_EVENT_NOTIFY_CHDIR		= 0x1033,
	ESC_EVENT_NOTIFY_CHROOT		= 0x1034,
	ESC_EVENT_NOTIFY_SOCKET_CREATE	= 0x1035,
	ESC_EVENT_NOTIFY_SOCKET_ACCEPT	= 0x1036,
	ESC_EVENT_NOTIFY_SOCKET_SEND	= 0x1037,
	ESC_EVENT_NOTIFY_SOCKET_RECEIVE	= 0x1038,
	ESC_EVENT_NOTIFY_SOCKET_STAT	= 0x1039,
	ESC_EVENT_NOTIFY_SOCKET_POLL	= 0x103A,
	ESC_EVENT_NOTIFY_PIPE_READ	= 0x103B,
	ESC_EVENT_NOTIFY_PIPE_WRITE	= 0x103C,
	ESC_EVENT_NOTIFY_PIPE_STAT	= 0x103D,
	ESC_EVENT_NOTIFY_PIPE_POLL	= 0x103E,
	ESC_EVENT_NOTIFY_PIPE_IOCTL	= 0x103F,
	ESC_EVENT_NOTIFY_MOUNT_STAT	= 0x1040,
	ESC_EVENT_NOTIFY_PRIV_CHECK	= 0x1041,
	ESC_EVENT_NOTIFY_PROC_SCHED	= 0x1042,
} esc_event_type_t;

#define ESC_EVENT_IS_AUTH(e)	(((e) & 0x1000) == 0)
#define ESC_EVENT_IS_NOTIFY(e)	(((e) & 0x1000) != 0)

/*
 * Events NOT implementable due to FreeBSD limitations:
 *
 * - NOTIFY_CLOSE: No mpo_vnode_check_close hook or eventhandler exists.
 *   File close tracking would require kernel modifications.
 *
 * - AUTH_TRUNCATE/NOTIFY_TRUNCATE: No mpo_vnode_check_truncate hook.
 *   truncate(2)/ftruncate(2) are not intercepted by MAC setattr hooks.
 *
 * - AUTH_UNMOUNT: No mpo_mount_check_umount MAC hook for authorization.
 *   NOTIFY_UNMOUNT is available via vfs_unmounted eventhandler.
 *
 * - AUTH_KLDUNLOAD: No mpo_kld_check_unload MAC hook for authorization.
 *   NOTIFY_KLDUNLOAD is available via kld_unload eventhandler.
 *
 * Future work: Propose new MAC hooks to FreeBSD for AUTH operations.
 */

/*
 * Action type - does event require a response?
 */
typedef enum {
	ESC_ACTION_AUTH		= 0,	/* Requires response */
	ESC_ACTION_NOTIFY	= 1,	/* Informational only */
} esc_action_t;

/*
 * AUTH response values
 */
typedef enum {
	ESC_AUTH_ALLOW	= 0,
	ESC_AUTH_DENY	= 1,
} esc_auth_result_t;

/*
 * Client operating modes
 */
#define ESC_MODE_NOTIFY		0x0000	/* Notify-only, never blocks kernel */
#define ESC_MODE_AUTH		0x0001	/* Can respond to AUTH events */
#define ESC_MODE_PASSIVE	0x0002	/* Receive AUTH as NOTIFY (no block) */

/*
 * Process token - unique process identity
 *
 * Contains pid plus generation counter to detect pid reuse.
 * Used with ESC_IOC_MUTE_PROCESS to identify processes.
 */
typedef struct {
	uint64_t	ept_id;		/* Process ID (pid) */
	uint64_t	ept_genid;	/* Generation (detects pid reuse) */
} esc_proc_token_t;

/*
 * File token - unique file identity
 *
 * Contains inode plus device/generation info.
 */
typedef struct {
	uint64_t	eft_id;		/* Inode number */
	uint64_t	eft_dev;	/* Device ID */
} esc_file_token_t;

/*
 * Process information
 *
 * Analogous to Apple's es_process_t. Contains snapshot of process
 * state at time of event.
 */
typedef struct {
	esc_proc_token_t ep_token;	/* Token for muting/identity */
	uint64_t	ep_exec_id;	/* Execution ID: same on fork, new on exec */
	pid_t		ep_pid;		/* Process ID */
	pid_t		ep_ppid;	/* Parent PID */
	char		ep_pcomm[MAXCOMLEN + 1]; /* Parent command name */
	pid_t		ep_pgid;	/* Process group ID */
	pid_t		ep_sid;		/* Session ID */
	uid_t		ep_uid;		/* Effective UID */
	uid_t		ep_ruid;	/* Real UID */
	uid_t		ep_suid;	/* Saved UID */
	gid_t		ep_gid;		/* Effective GID */
	gid_t		ep_rgid;	/* Real GID */
	gid_t		ep_sgid;	/* Saved GID */
	int		ep_jid;		/* Jail ID (0 if not jailed) */
	uint32_t	ep_flags;	/* EP_FLAG_* below */

	/* ABI/Binary type - detect Linux vs FreeBSD binaries */
	uint8_t		ep_abi;		/* EP_ABI_FREEBSD, EP_ABI_LINUX, etc. */
	uint8_t		ep_pad[3];

	/* Timing */
	int64_t		ep_start_sec;	/* Process start time (seconds) */
	int64_t		ep_start_usec;	/* Process start time (microseconds) */

	/* Supplementary groups */
	uint16_t	ep_ngroups;	/* Number of supplementary groups */
	gid_t		ep_groups[16];	/* First 16 supplementary groups */

	/* Audit info */
	uid_t		ep_auid;	/* Audit user ID */
	uint32_t	ep_asid;	/* Audit session ID */

	/* Paths and names */
	char		ep_comm[MAXCOMLEN + 1];	/* Command name */
	char		ep_path[MAXPATHLEN];	/* Executable path */
	char		ep_cwd[MAXPATHLEN];	/* Current working directory */
	char		ep_tty[32];	/* Controlling TTY name */
	char		ep_login[MAXLOGNAME];	/* Login name */
	char		ep_jailname[MAXHOSTNAMELEN]; /* Jail name if jailed */
} esc_process_t;

/* Process flags */
#define EP_FLAG_SETUID		0x0001	/* Running setuid */
#define EP_FLAG_SETGID		0x0002	/* Running setgid */
#define EP_FLAG_JAILED		0x0004	/* In a jail */
#define EP_FLAG_CAPMODE		0x0008	/* In capability mode */
#define EP_FLAG_LINUX		0x0200	/* Linux binary (via Linuxulator) */
#define EP_FLAG_TRACED		0x0010	/* Being ptraced */
#define EP_FLAG_SYSTEM		0x0020	/* System process */
#define EP_FLAG_WEXIT		0x0040	/* Process is exiting */
#define EP_FLAG_EXEC		0x0080	/* Process did exec */
#define EP_FLAG_CONTROLT	0x0100	/* Has controlling terminal */

/* ABI types for ep_abi (matches SV_ABI_* from sys/sysent.h) */
#define EP_ABI_FREEBSD		9	/* Native FreeBSD binary */
#define EP_ABI_LINUX		3	/* Linux binary (Linuxulator) */
#define EP_ABI_UNDEF		255	/* Unknown/undefined */

/*
 * File information
 */
typedef struct {
	esc_file_token_t ef_token;	/* Token for fd retrieval */
	uint64_t	ef_ino;		/* Inode number */
	uint64_t	ef_dev;		/* Device ID */
	uint64_t	ef_size;	/* File size in bytes */
	uint64_t	ef_blocks;	/* Blocks allocated */
	mode_t		ef_mode;	/* File mode */
	uid_t		ef_uid;		/* Owner UID */
	gid_t		ef_gid;		/* Owner GID */
	uint32_t	ef_flags;	/* File flags (chflags) */
	uint32_t	ef_nlink;	/* Link count */
	uint8_t		ef_type;	/* File type: EF_TYPE_* below */
	uint8_t		ef_pad[3];

	/* Timestamps (seconds since epoch) */
	int64_t		ef_atime;	/* Access time */
	int64_t		ef_mtime;	/* Modification time */
	int64_t		ef_ctime;	/* Change time */
	int64_t		ef_birthtime;	/* Creation time */

	/* Filesystem info */
	char		ef_fstype[16];	/* Filesystem type (ufs, zfs, etc.) */
	char		ef_path[MAXPATHLEN];
} esc_file_t;

/* File types */
#define EF_TYPE_UNKNOWN		0
#define EF_TYPE_REG		1	/* Regular file */
#define EF_TYPE_DIR		2	/* Directory */
#define EF_TYPE_LNK		3	/* Symbolic link */
#define EF_TYPE_CHR		4	/* Character device */
#define EF_TYPE_BLK		5	/* Block device */
#define EF_TYPE_FIFO		6	/* Named pipe */
#define EF_TYPE_SOCK		7	/* Socket */

/*
 * Event-specific data structures
 */

/* Maximum size for embedded exec arguments */
#define ESC_EXEC_ARGS_MAX	4096

/* ESC_EVENT_*_EXEC */
typedef struct {
	esc_process_t	target;		/* Process with new executable path */
	esc_file_t	executable;	/* Executable being run */
	uint32_t	argc;		/* Argument count */
	uint32_t	envc;		/* Environment count */
	uint32_t	argv_len;	/* Length of argv data in args[] */
	uint32_t	envp_len;	/* Length of envp data in args[] */
	uint32_t	flags;		/* EE_FLAG_* */
	uint32_t	reserved;
	char		args[ESC_EXEC_ARGS_MAX]; /* NUL-separated: argv then envp */
} esc_event_exec_t;

/* Exec event flags */
#define EE_FLAG_ARGV_TRUNCATED	0x0001	/* argv was truncated */
#define EE_FLAG_ENVP_TRUNCATED	0x0002	/* envp was truncated */

/* ESC_EVENT_*_OPEN */
typedef struct {
	esc_file_t	file;		/* File being opened */
	int		flags;		/* Open flags (O_RDONLY, etc.) */
	mode_t		mode;		/* Reserved (creation mode unavailable from MAC hook) */
} esc_event_open_t;

/* ESC_EVENT_*_ACCESS */
typedef struct {
	esc_file_t	file;		/* File being checked */
	int		accmode;	/* VREAD/VWRITE/VEXEC */
} esc_event_access_t;

/* ESC_EVENT_*_READ / ESC_EVENT_*_WRITE */
typedef struct {
	esc_file_t	file;		/* File being read/written */
} esc_event_rw_t;

/* Generic file event */
typedef struct {
	esc_file_t	file;		/* File */
} esc_event_file_t;

/* ESC_EVENT_*_READDIR */
typedef struct {
	esc_file_t	dir;		/* Directory being read */
} esc_event_readdir_t;

/* ESC_EVENT_*_LOOKUP */
typedef struct {
	esc_file_t	dir;		/* Directory being searched */
	char		name[MAXNAMLEN + 1]; /* Lookup name */
} esc_event_lookup_t;

/* ESC_EVENT_*_CREATE */
typedef struct {
	esc_file_t	dir;		/* Parent directory */
	esc_file_t	file;		/* New file/dir being created */
	mode_t		mode;		/* Creation mode */
} esc_event_create_t;

/* ESC_EVENT_*_UNLINK */
typedef struct {
	esc_file_t	dir;		/* Parent directory */
	esc_file_t	file;		/* File being removed */
} esc_event_unlink_t;

/* ESC_EVENT_*_RENAME */
typedef struct {
	esc_file_t	src_dir;	/* Source directory */
	esc_file_t	src_file;	/* Source file */
	esc_file_t	dst_dir;	/* Destination directory */
	char		dst_name[MAXNAMLEN + 1]; /* New name */
} esc_event_rename_t;

/* ESC_EVENT_*_LINK */
typedef struct {
	esc_file_t	target;		/* Target of the new link */
	esc_file_t	dir;		/* Directory containing link */
	char		name[MAXNAMLEN + 1]; /* Link name */
} esc_event_link_t;

/* ESC_EVENT_NOTIFY_FORK */
typedef struct {
	esc_process_t	child;		/* Newly created child */
} esc_event_fork_t;

/* ESC_EVENT_NOTIFY_EXIT */
typedef struct {
	int		status;		/* Exit status (wait-style) */
} esc_event_exit_t;

/* ESC_EVENT_*_MOUNT */
typedef struct {
	esc_file_t	mountpoint;	/* Mount point */
	char		fstype[16];	/* Filesystem type */
	char		source[MAXPATHLEN]; /* Source device/path */
	uint64_t	flags;		/* Mount flags */
} esc_event_mount_t;

/* ESC_EVENT_*_KLDLOAD */
typedef struct {
	esc_file_t	file;		/* Module file */
	char		name[64];	/* Module name */
} esc_event_kldload_t;

/* ESC_EVENT_*_MMAP */
typedef struct {
	esc_file_t	file;		/* File being mapped (if any) */
	uint64_t	addr;		/* Reserved (addr unavailable from MAC hook) */
	size_t		len;		/* Reserved (len unavailable from MAC hook) */
	int		prot;		/* Protection flags */
	int		flags;		/* Mmap flags */
} esc_event_mmap_t;

/* ESC_EVENT_*_SETMODE */
typedef struct {
	esc_file_t	file;		/* File being changed */
	mode_t		mode;		/* New mode */
} esc_event_setmode_t;

/* ESC_EVENT_*_SETOWNER */
typedef struct {
	esc_file_t	file;		/* File being changed */
	uid_t		uid;		/* New owner uid */
	gid_t		gid;		/* New owner gid */
} esc_event_setowner_t;

/* ESC_EVENT_*_SETFLAGS */
typedef struct {
	esc_file_t	file;		/* File being changed */
	u_long		flags;		/* New file flags */
} esc_event_setflags_t;

/* ESC_EVENT_*_SETUTIMES */
typedef struct {
	esc_file_t	file;		/* File being changed */
	struct timespec	atime;		/* New access time */
	struct timespec	mtime;		/* New modification time */
} esc_event_setutimes_t;

/* ESC_EVENT_*_MPROTECT */
typedef struct {
	esc_file_t	file;		/* File backing mapping (if any) */
	int		prot;		/* Protection flags */
} esc_event_mprotect_t;

/* ESC_EVENT_*_CHDIR */
typedef struct {
	esc_file_t	dir;		/* New working directory */
} esc_event_chdir_t;

/* ESC_EVENT_*_CHROOT */
typedef struct {
	esc_file_t	dir;		/* New root directory */
} esc_event_chroot_t;

/* ESC_EVENT_*_SETEXTATTR */
typedef struct {
	esc_file_t	file;		/* Target file */
	int		attrnamespace;	/* EXTATTR_NAMESPACE_* */
	char		name[EXTATTR_MAXNAMELEN + 1]; /* Attr name */
} esc_event_setextattr_t;

/* ESC_EVENT_*_{GET,DELETE,LIST}EXTATTR */
typedef struct {
	esc_file_t	file;		/* Target file */
	int		attrnamespace;	/* EXTATTR_NAMESPACE_* */
	char		name[EXTATTR_MAXNAMELEN + 1]; /* Attr name (if any) */
} esc_event_extattr_t;

/* ESC_EVENT_*_{GET,SET,DELETE}ACL */
typedef struct {
	esc_file_t	file;		/* Target file */
	int		type;		/* ACL_TYPE_* */
} esc_event_acl_t;

/* ESC_EVENT_NOTIFY_SIGNAL */
typedef struct {
	esc_process_t	target;		/* Target process */
	int		signum;		/* Signal number */
} esc_event_signal_t;

/* ESC_EVENT_*_PTRACE */
typedef struct {
	esc_process_t	target;		/* Target process */
	int		request;	/* Reserved (request type unavailable from MAC hook) */
} esc_event_ptrace_t;

/* ESC_EVENT_NOTIFY_SETUID */
typedef struct {
	uid_t		uid;		/* New UID */
} esc_event_setuid_t;

/* ESC_EVENT_NOTIFY_SETGID */
typedef struct {
	gid_t		gid;		/* New GID */
} esc_event_setgid_t;

/* Socket address (for socket events) */
typedef struct {
	uint8_t		esa_family;	/* AF_INET, AF_INET6, AF_UNIX, etc. */
	uint8_t		esa_pad[3];
	uint16_t	esa_port;	/* Port (network byte order, AF_INET/6) */
	uint16_t	esa_pad2;
	union {
		uint32_t	v4;		/* IPv4 address */
		uint8_t		v6[16];		/* IPv6 address */
		char		path[104];	/* Unix socket path */
	} esa_addr;
} esc_sockaddr_t;

/* Socket information */
typedef struct {
	int		es_domain;	/* AF_INET, AF_INET6, AF_UNIX */
	int		es_type;	/* SOCK_STREAM, SOCK_DGRAM, etc. */
	int		es_protocol;	/* Protocol number */
	int		es_pad;
} esc_socket_t;

/* ESC_EVENT_*_SOCKET_CONNECT / ESC_EVENT_*_SOCKET_BIND */
typedef struct {
	esc_socket_t	socket;		/* Socket info */
	esc_sockaddr_t	address;	/* Remote/local address */
} esc_event_socket_addr_t;

/* ESC_EVENT_*_SOCKET_LISTEN */
typedef struct {
	esc_socket_t	socket;		/* Socket info */
} esc_event_socket_t;

/* ESC_EVENT_*_REBOOT */
typedef struct {
	int		howto;		/* Reboot flags (RB_HALT, etc.) */
} esc_event_reboot_t;

/* ESC_EVENT_*_SYSCTL */
typedef struct {
	char		name[256];	/* Sysctl name (dot-separated) */
	int		op;		/* Operation: 0=read, 1=write */
} esc_event_sysctl_t;

/*
 * Kenv (kernel environment) event
 */
typedef struct {
	char		name[128];	/* Environment variable name */
	int		op;		/* Operation: 0=get, 1=set, 2=unset */
} esc_event_kenv_t;

/*
 * Swapon event
 */
typedef struct {
	esc_file_t	file;		/* Swap device/file */
} esc_event_swapon_t;

/*
 * Swapoff event
 */
typedef struct {
	esc_file_t	file;		/* Swap device/file */
} esc_event_swapoff_t;

/*
 * Socket create event
 */
typedef struct {
	int		domain;		/* AF_INET, AF_INET6, AF_UNIX, etc. */
	int		type;		/* SOCK_STREAM, SOCK_DGRAM, etc. */
	int		protocol;	/* Protocol number */
	int		pad;
} esc_event_socket_create_t;

/*
 * Pipe event (read/write/stat/poll/ioctl)
 */
typedef struct {
	uint64_t	pipe_id;	/* Unique pipe identifier */
	unsigned long	ioctl_cmd;	/* For ioctl events */
} esc_event_pipe_t;

/*
 * Mount stat event
 */
typedef struct {
	char		fstype[16];	/* Filesystem type */
	char		fspath[MAXPATHLEN]; /* Mount point */
} esc_event_mount_stat_t;

/*
 * Privilege check event
 */
typedef struct {
	int		priv;		/* Privilege number (PRIV_*) */
} esc_event_priv_t;

/*
 * Process scheduling event
 */
typedef struct {
	esc_process_t	target;		/* Target process */
} esc_event_proc_sched_t;

/*
 * Main message structure
 *
 * Clients read these from the esc fd. Size is fixed for ABI stability.
 */
typedef struct {
	uint32_t	em_version;	/* ESC_MESSAGE_VERSION */
	uint32_t	em_reserved;	/* Alignment padding */
	uint64_t	em_id;		/* Unique message ID (for response) */
	esc_event_type_t em_event;	/* Event type */
	esc_action_t	em_action;	/* AUTH or NOTIFY */
	struct timespec	em_time;	/* Event timestamp (CLOCK_MONOTONIC) */
	struct timespec	em_deadline;	/* AUTH deadline (CLOCK_MONOTONIC) */
	esc_process_t	em_process;	/* Process that triggered event */

	union {
		esc_event_exec_t	exec;
		esc_event_open_t	open;
		esc_event_access_t	access;
		esc_event_rw_t		rw;
		esc_event_file_t	stat;
		esc_event_file_t	poll;
		esc_event_file_t	revoke;
		esc_event_readdir_t	readdir;
		esc_event_file_t	readlink;
		esc_event_extattr_t	getextattr;
		esc_event_extattr_t	deleteextattr;
		esc_event_extattr_t	listextattr;
		esc_event_acl_t	getacl;
		esc_event_acl_t	setacl;
		esc_event_acl_t	deleteacl;
		esc_event_file_t	relabel;
		esc_event_lookup_t	lookup;
		esc_event_create_t	create;
		esc_event_unlink_t	unlink;
		esc_event_rename_t	rename;
		esc_event_link_t	link;
		esc_event_fork_t	fork;
		esc_event_exit_t	exit;
		esc_event_mount_t	mount;
		esc_event_kldload_t	kldload;
		esc_event_mmap_t	mmap;
		esc_event_setmode_t	setmode;
		esc_event_setowner_t	setowner;
		esc_event_setflags_t	setflags;
		esc_event_setutimes_t	setutimes;
		esc_event_mprotect_t	mprotect;
		esc_event_chdir_t	chdir;
		esc_event_chroot_t	chroot;
		esc_event_setextattr_t	setextattr;
		esc_event_signal_t	signal;
		esc_event_ptrace_t	ptrace;
		esc_event_setuid_t	setuid;
		esc_event_setgid_t	setgid;
		esc_event_socket_addr_t	socket_connect;
		esc_event_socket_addr_t	socket_bind;
		esc_event_socket_t	socket_listen;
		esc_event_reboot_t	reboot;
		esc_event_sysctl_t	sysctl;
		esc_event_kenv_t	kenv;
		esc_event_swapon_t	swapon;
		esc_event_swapoff_t	swapoff;
		esc_event_mount_t	unmount;
		esc_event_kldload_t	kldunload;
		esc_event_socket_create_t socket_create;
		esc_event_socket_t	socket_accept;
		esc_event_socket_t	socket_send;
		esc_event_socket_t	socket_receive;
		esc_event_socket_t	socket_stat;
		esc_event_socket_t	socket_poll;
		esc_event_pipe_t	pipe;
		esc_event_mount_stat_t	mount_stat;
		esc_event_priv_t	priv;
		esc_event_proc_sched_t	proc_sched;
		uint8_t			_reserved[128]; /* Future expansion */
	} em_event_data;
} esc_message_t;

#define ESC_MESSAGE_VERSION	1

/*
 * Response structure
 *
 * Clients write these to respond to AUTH events.
 */
typedef struct {
	uint64_t	er_id;		/* Message ID being responded to */
	esc_auth_result_t er_result;	/* ALLOW or DENY */
	uint32_t	er_flags;	/* Reserved, must be 0 */
} esc_response_t;

/*
 * Flags-based response for partial authorization (AUTH_OPEN, AUTH_MMAP).
 * No downgrade: operations are fully allowed or fully denied.
 */
typedef struct {
	uint64_t	erf_id;		/* Message ID being responded to */
	esc_auth_result_t erf_result;	/* ALLOW (with flags) or DENY */
	uint32_t	erf_reserved;	/* Padding */
	uint32_t	erf_allowed_flags; /* Flags to allow (event-specific) */
	uint32_t	erf_denied_flags;  /* Flags explicitly denied */
} esc_response_flags_t;

/*
 * IOCTL definitions
 */

/* Subscribe to event types */
struct esc_subscribe_args {
	const esc_event_type_t *esa_events;	/* Array of event types */
	size_t		esa_count;	/* Number of events */
	uint32_t	esa_flags;	/* ESC_SUB_* flags */
};
#define ESC_SUB_ADD		0x0000	/* Add to existing subscriptions */
#define ESC_SUB_REPLACE		0x0001	/* Replace all subscriptions */

#define ESC_IOC_SUBSCRIBE	_IOW('E', 1, struct esc_subscribe_args)

/* Subscribe using bitmap (no event count limit) */
struct esc_subscribe_bitmap_args {
	uint64_t	esba_auth;	/* AUTH event bitmap (bit = event & 0x0FFF) */
	uint64_t	esba_notify;	/* NOTIFY event bitmap (bit = event & 0x0FFF) */
	uint32_t	esba_flags;	/* ESC_SUB_* flags */
	uint32_t	esba_reserved;
};

#define ESC_IOC_SUBSCRIBE_BITMAP	_IOW('E', 34, struct esc_subscribe_bitmap_args)

/* Subscribe using extended bitmap (supports bits 64+) */
struct esc_subscribe_bitmap_ex_args {
	uint64_t	esba_auth[2];	/* AUTH event bitmap (128 bits) */
	uint64_t	esba_notify[2];	/* NOTIFY event bitmap (128 bits) */
	uint32_t	esba_flags;	/* ESC_SUB_* flags */
	uint32_t	esba_reserved;
};

#define ESC_IOC_SUBSCRIBE_BITMAP_EX	_IOW('E', 35, struct esc_subscribe_bitmap_ex_args)

/* Set client mode and parameters */
struct esc_mode_args {
	uint32_t	ema_mode;	/* ESC_MODE_* */
	uint32_t	ema_timeout_ms;	/* AUTH timeout (0 = default) */
	uint32_t	ema_queue_size;	/* Max queued events (0 = default) */
	uint32_t	ema_flags;	/* Reserved */
};

#define ESC_IOC_SET_MODE	_IOW('E', 2, struct esc_mode_args)
#define ESC_IOC_GET_MODE	_IOR('E', 31, struct esc_mode_args)

/*
 * Set/get AUTH timeout independently of mode
 *
 * Allows changing timeout without re-triggering mode-set logic.
 */
struct esc_timeout_args {
	uint32_t	eta_timeout_ms;	/* AUTH timeout in milliseconds */
};

#define ESC_IOC_SET_TIMEOUT	_IOW('E', 32, struct esc_timeout_args)
#define ESC_IOC_GET_TIMEOUT	_IOR('E', 33, struct esc_timeout_args)

/* Mute events from a process */
struct esc_mute_args {
	esc_proc_token_t emu_token;	/* Process to mute (ignored if SELF) */
	uint32_t	emu_flags;	/* ESC_MUTE_* flags */
};
#define ESC_MUTE_SELF		0x0001	/* Mute calling process */

#define ESC_IOC_MUTE_PROCESS	_IOW('E', 3, struct esc_mute_args)
#define ESC_IOC_UNMUTE_PROCESS	_IOW('E', 4, struct esc_mute_args)

/*
 * Mute events by path
 */
struct esc_mute_path_args {
	char		emp_path[MAXPATHLEN]; /* Path to mute */
	uint32_t	emp_type;	/* ESC_MUTE_PATH_* */
	uint32_t	emp_flags;	/* ESC_MUTE_PATH_FLAG_* */
};

#define ESC_MUTE_PATH_LITERAL	0x0001	/* Exact match */
#define ESC_MUTE_PATH_PREFIX	0x0002	/* Prefix match */

#define ESC_MUTE_PATH_FLAG_TARGET	0x0001	/* Target path list */

#define ESC_IOC_MUTE_PATH	_IOW('E', 9, struct esc_mute_path_args)
#define ESC_IOC_UNMUTE_PATH	_IOW('E', 10, struct esc_mute_path_args)

/*
 * Mute inversion
 */
typedef enum {
	ESC_MUTE_INVERT_PROCESS		= 1,
	ESC_MUTE_INVERT_PATH		= 2,
	ESC_MUTE_INVERT_TARGET_PATH	= 3,
} esc_mute_invert_type_t;

struct esc_mute_invert_args {
	uint32_t	emi_type;	/* ESC_MUTE_INVERT_* */
	uint32_t	emi_invert;	/* 0 = normal, 1 = inverted */
};

#define ESC_IOC_SET_MUTE_INVERT	_IOW('E', 7, struct esc_mute_invert_args)
#define ESC_IOC_GET_MUTE_INVERT	_IOWR('E', 8, struct esc_mute_invert_args)

/*
 * Per-event-type muting
 *
 * Mute specific event types for a process or path, rather than all events.
 * Similar to Apple ES es_mute_process_events() and es_mute_path_events().
 */
#define ESC_MAX_MUTE_EVENTS	64	/* Max events per mute call */

struct esc_mute_process_events_args {
	esc_proc_token_t empe_token;		/* Process to mute */
	uint32_t	empe_flags;		/* ESC_MUTE_SELF, etc. */
	uint32_t	empe_count;		/* Number of events */
	esc_event_type_t empe_events[ESC_MAX_MUTE_EVENTS]; /* Events to mute */
};

struct esc_mute_path_events_args {
	char		empae_path[MAXPATHLEN];	/* Path to mute */
	uint32_t	empae_type;		/* ESC_MUTE_PATH_* */
	uint32_t	empae_flags;		/* ESC_MUTE_PATH_FLAG_* */
	uint32_t	empae_count;		/* Number of events */
	esc_event_type_t empae_events[ESC_MAX_MUTE_EVENTS]; /* Events to mute */
};

#define ESC_IOC_MUTE_PROCESS_EVENTS	_IOW('E', 16, struct esc_mute_process_events_args)
#define ESC_IOC_UNMUTE_PROCESS_EVENTS	_IOW('E', 17, struct esc_mute_process_events_args)
#define ESC_IOC_MUTE_PATH_EVENTS	_IOW('E', 18, struct esc_mute_path_events_args)
#define ESC_IOC_UNMUTE_PATH_EVENTS	_IOW('E', 19, struct esc_mute_path_events_args)

/*
 * Query muted processes/paths
 *
 * Retrieve list of currently muted processes or paths.
 * Similar to Apple ES es_muted_processes_events() and es_muted_paths_events().
 */
#define ESC_MAX_MUTED_ENTRIES	256	/* Max entries returned per call */

struct esc_muted_process_entry {
	esc_proc_token_t emp_token;		/* Muted process */
	uint32_t	emp_event_count;	/* 0 = all events muted */
	esc_event_type_t emp_events[ESC_MAX_MUTE_EVENTS]; /* Specific events */
};

struct esc_muted_path_entry {
	char		emp_path[MAXPATHLEN];	/* Muted path */
	uint32_t	emp_type;		/* ESC_MUTE_PATH_* */
	uint32_t	emp_flags;		/* ESC_MUTE_PATH_FLAG_* */
	uint32_t	emp_event_count;	/* 0 = all events muted */
	esc_event_type_t emp_events[ESC_MAX_MUTE_EVENTS]; /* Specific events */
};

struct esc_get_muted_processes_args {
	struct esc_muted_process_entry *egmp_entries; /* OUT: array */
	size_t		egmp_count;		/* IN: array size */
	size_t		egmp_actual;		/* OUT: actual count */
};

struct esc_get_muted_paths_args {
	struct esc_muted_path_entry *egmpa_entries; /* OUT: array */
	size_t		egmpa_count;		/* IN: array size */
	size_t		egmpa_actual;		/* OUT: actual count */
	uint32_t	egmpa_flags;		/* ESC_MUTE_PATH_FLAG_TARGET */
};

#define ESC_IOC_GET_MUTED_PROCESSES	_IOWR('E', 20, struct esc_get_muted_processes_args)
#define ESC_IOC_GET_MUTED_PATHS		_IOWR('E', 21, struct esc_get_muted_paths_args)

/*
 * Unmute all
 *
 * Clear all muted processes or paths in one operation.
 * Similar to Apple ES es_unmute_all_paths() (and added for processes).
 */
#define ESC_IOC_UNMUTE_ALL_PROCESSES	_IO('E', 22)
#define ESC_IOC_UNMUTE_ALL_PATHS	_IO('E', 23)
#define ESC_IOC_UNMUTE_ALL_TARGET_PATHS	_IO('E', 24)

/*
 * UID/GID muting
 *
 * Mute events from processes running as specific UIDs or GIDs.
 * Uses effective UID/GID for matching.
 */
#define ESC_MUTE_PROC_MAX	1024	/* Max muted processes per client */
#define ESC_MUTE_PATH_MAX	256	/* Max muted paths per client */
#define ESC_MUTE_UID_MAX	64	/* Max muted UIDs per client */
#define ESC_MUTE_GID_MAX	64	/* Max muted GIDs per client */

struct esc_mute_uid_args {
	uid_t		emu_uid;	/* UID to mute */
};

struct esc_mute_gid_args {
	gid_t		emg_gid;	/* GID to mute */
};

#define ESC_IOC_MUTE_UID	_IOW('E', 25, struct esc_mute_uid_args)
#define ESC_IOC_UNMUTE_UID	_IOW('E', 26, struct esc_mute_uid_args)
#define ESC_IOC_MUTE_GID	_IOW('E', 27, struct esc_mute_gid_args)
#define ESC_IOC_UNMUTE_GID	_IOW('E', 28, struct esc_mute_gid_args)
#define ESC_IOC_UNMUTE_ALL_UIDS	_IO('E', 29)
#define ESC_IOC_UNMUTE_ALL_GIDS	_IO('E', 30)

/*
 * Default AUTH timeout action
 */
struct esc_timeout_action_args {
	uint32_t	eta_action;	/* ESC_AUTH_ALLOW or ESC_AUTH_DENY */
};

#define ESC_IOC_SET_TIMEOUT_ACTION	_IOW('E', 11, struct esc_timeout_action_args)
#define ESC_IOC_GET_TIMEOUT_ACTION	_IOWR('E', 12, struct esc_timeout_action_args)

/*
 * Decision cache
 *
 * Cache AUTH decisions using a key of event + tokens.
 */
#define ESC_CACHE_KEY_PROCESS	0x0001
#define ESC_CACHE_KEY_FILE	0x0002
#define ESC_CACHE_KEY_TARGET	0x0004

#define ESC_CACHE_EVENT_ANY	0	/* Wildcard for remove */

typedef struct {
	esc_event_type_t eck_event;	/* ESC_EVENT_AUTH_* or ANY */
	uint32_t	eck_flags;	/* ESC_CACHE_KEY_* */
	esc_proc_token_t eck_process;
	esc_file_token_t eck_file;
	esc_file_token_t eck_target;
} esc_cache_key_t;

typedef struct {
	esc_cache_key_t	ece_key;	/* Cache key */
	esc_auth_result_t ece_result;	/* ALLOW or DENY */
	uint32_t	ece_ttl_ms;	/* Time-to-live in ms */
} esc_cache_entry_t;

#define ESC_IOC_CACHE_ADD	_IOW('E', 13, esc_cache_entry_t)
#define ESC_IOC_CACHE_REMOVE	_IOW('E', 14, esc_cache_key_t)
#define ESC_IOC_CACHE_CLEAR	_IO('E', 15)

/* Get client statistics and configuration */
struct esc_stats {
	/* Counters */
	uint64_t	es_events_received;	/* Total events received */
	uint64_t	es_events_dropped;	/* Events dropped (queue full) */
	uint64_t	es_auth_timeouts;	/* AUTH timeouts */
	uint64_t	es_auth_allowed;	/* AUTH events allowed */
	uint64_t	es_auth_denied;		/* AUTH events denied */
	uint64_t	es_cache_hits;		/* Cache hits */
	uint64_t	es_cache_misses;	/* Cache misses */
	uint64_t	es_cache_evictions;	/* Cache evictions */
	uint64_t	es_cache_expired;	/* Cache expired removals */

	/* Cache state */
	uint32_t	es_cache_entries;	/* Current cache entries */
	uint32_t	es_cache_max;		/* Max cache entries */

	/* Queue state */
	uint32_t	es_queue_current;	/* Current queue depth */
	uint32_t	es_queue_max;		/* Max queue size */

	/* Current configuration */
	uint32_t	es_mode;		/* ESC_MODE_* */
	uint32_t	es_timeout_ms;		/* AUTH timeout in ms */
	uint32_t	es_timeout_action;	/* ESC_AUTH_ALLOW or DENY */
	uint32_t	es_reserved;		/* Padding for alignment */
};

#define ESC_IOC_GET_STATS	_IOR('E', 6, struct esc_stats)

/* Capsicum ioctl permission sets for cap_ioctls_limit() */

/* Ioctl arrays for common permission sets */
#ifndef _KERNEL
#define ESC_IOCTLS_THIRD_PARTY_INIT \
	{ ESC_IOC_SUBSCRIBE, ESC_IOC_SUBSCRIBE_BITMAP, \
	  ESC_IOC_GET_MODE, ESC_IOC_GET_TIMEOUT, \
	  ESC_IOC_MUTE_PROCESS, ESC_IOC_UNMUTE_PROCESS, \
	  ESC_IOC_MUTE_PATH, ESC_IOC_UNMUTE_PATH, ESC_IOC_SET_MUTE_INVERT, \
	  ESC_IOC_GET_MUTE_INVERT, ESC_IOC_SET_TIMEOUT_ACTION, \
	  ESC_IOC_GET_TIMEOUT_ACTION, ESC_IOC_GET_STATS, \
	  ESC_IOC_MUTE_PROCESS_EVENTS, ESC_IOC_UNMUTE_PROCESS_EVENTS, \
	  ESC_IOC_MUTE_PATH_EVENTS, ESC_IOC_UNMUTE_PATH_EVENTS, \
	  ESC_IOC_GET_MUTED_PROCESSES, ESC_IOC_GET_MUTED_PATHS, \
	  ESC_IOC_UNMUTE_ALL_PROCESSES, ESC_IOC_UNMUTE_ALL_PATHS, \
	  ESC_IOC_UNMUTE_ALL_TARGET_PATHS, \
	  ESC_IOC_MUTE_UID, ESC_IOC_UNMUTE_UID, ESC_IOC_MUTE_GID, \
	  ESC_IOC_UNMUTE_GID, ESC_IOC_UNMUTE_ALL_UIDS, ESC_IOC_UNMUTE_ALL_GIDS }

#define ESC_IOCTLS_ALL_INIT \
	{ ESC_IOC_SUBSCRIBE, ESC_IOC_SUBSCRIBE_BITMAP, \
	  ESC_IOC_SET_MODE, ESC_IOC_GET_MODE, \
	  ESC_IOC_SET_TIMEOUT, ESC_IOC_GET_TIMEOUT, \
	  ESC_IOC_MUTE_PROCESS, ESC_IOC_UNMUTE_PROCESS, \
	  ESC_IOC_MUTE_PATH, ESC_IOC_UNMUTE_PATH, \
	  ESC_IOC_SET_MUTE_INVERT, ESC_IOC_GET_MUTE_INVERT, \
	  ESC_IOC_SET_TIMEOUT_ACTION, ESC_IOC_GET_TIMEOUT_ACTION, \
	  ESC_IOC_CACHE_ADD, ESC_IOC_CACHE_REMOVE, ESC_IOC_CACHE_CLEAR, \
	  ESC_IOC_GET_STATS, \
	  ESC_IOC_MUTE_PROCESS_EVENTS, ESC_IOC_UNMUTE_PROCESS_EVENTS, \
	  ESC_IOC_MUTE_PATH_EVENTS, ESC_IOC_UNMUTE_PATH_EVENTS, \
	  ESC_IOC_GET_MUTED_PROCESSES, ESC_IOC_GET_MUTED_PATHS, \
	  ESC_IOC_UNMUTE_ALL_PROCESSES, ESC_IOC_UNMUTE_ALL_PATHS, \
	  ESC_IOC_UNMUTE_ALL_TARGET_PATHS, \
	  ESC_IOC_MUTE_UID, ESC_IOC_UNMUTE_UID, ESC_IOC_MUTE_GID, \
	  ESC_IOC_UNMUTE_GID, ESC_IOC_UNMUTE_ALL_UIDS, ESC_IOC_UNMUTE_ALL_GIDS }
#endif

/*
 * Default values
 */
#define ESC_DEFAULT_TIMEOUT_MS	30000	/* 30 seconds */
#define ESC_DEFAULT_QUEUE_SIZE	1024	/* Events per client */
#define ESC_MIN_TIMEOUT_MS	1000	/* 1 second minimum */
#define ESC_MAX_TIMEOUT_MS	300000	/* 5 minutes maximum */
#define ESC_MAX_CACHE_TTL_MS	3600000	/* 1 hour maximum */

/*
 * Device path
 */
#define ESC_DEVICE_PATH		"/dev/esc"

#endif /* !_SYS_ESC_H_ */
