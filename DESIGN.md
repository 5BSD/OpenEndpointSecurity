# Endpoint Security Capabilities (esc)

## Overview

A capability-based security event monitoring and authorization framework for
FreeBSD, inspired by Apple's Endpoint Security but designed around FreeBSD's
Capsicum capability model.

**Primary use case**: Provide a safe, stable API for third-party security
vendors to build EDR/AV/endpoint security software on FreeBSD.

## Scope / Non-Goals

- Identity uses process tokens plus an execution ID (random 64-bit, stable
  across fork, changes on exec).
- No code signing or entitlement model is in scope for esc.
- No entitlement gating; access control is via Capsicum ioctls and open
  privileges only.

## Prior Art

- **Apple Endpoint Security**: Mach-message based, entitlement-gated, userspace
  daemon receives events from kernel via XPC. AUTH events block until response
  or deadline. See [objective-see.org](https://objective-see.org/blog/blog_0x47.html)

- **NetBSD kauth**: Scope-based listener model, designed to allow userspace
  dispatch (requires callers hold no locks). See [kauth(9)](https://man.netbsd.org/kauth.9)

- **FreeBSD MAC Framework**: Extensible kernel access control with sleepable
  and non-sleepable hooks. Our implementation will use this as the hook source.

## Design Philosophy

### Third-Party Vendor Safety

The esc framework is designed for third-party consumption. A buggy or
malicious third-party client must not be able to:

- Crash the kernel
- Hang the system indefinitely
- Access events they're not authorized for
- Interfere with other clients

**Safety guarantees:**

| Risk | Mitigation |
|------|------------|
| Slow/hung client | Timeout expires, default policy applied |
| Client crashes | Kernel wakes up waiters, applies default |
| Malformed responses | Validate before processing |
| Queue exhaustion | Per-client queue limits |
| fd exhaustion | No automatic fd creation; clients opt in via explicit APIs |
| Recursive events | Self-mute required/automatic |
| Unauthorized access | Capsicum ioctl limits restrict operations |

### Capability-Based Access Control

Since esc is a loadable kernel module, we use Capsicum's ioctl limiting
(`cap_ioctls_limit()`) instead of adding new capability rights bits.
This enables delegation without requiring kernel changes:

```
System Administrator / Init System
        │
        ▼
    open("/dev/esc")  ←── Full privileges (all ioctls)
        │
        │ dup() + cap_ioctls_limit() to create safe subset
        ▼
    Third-party EDR  ←── Limited capability
        │
        │ Can: subscribe, read events, mute processes
        │ Cannot: ESC_IOC_SET_MODE (no AUTH mode, can't change timeout)
```

**Ioctl Permission Sets:**

| Set | Ioctls | Use Case |
|-----|--------|----------|
| THIRD_PARTY | SUBSCRIBE, GET_MODE, GET_TIMEOUT, MUTE/UNMUTE, MUTE_PATH/UNMUTE_PATH, MUTE_INVERT, TIMEOUT_ACTION, GET_STATS | NOTIFY-only EDR clients (can query, not set mode) |
| ALL | All ioctls including SET_MODE, SET_TIMEOUT, CACHE_* | Trusted system daemons |

Example creating restricted handle for third-party:
```c
int vendor_fd = dup(esc_fd);
cap_ioctl_t allowed[] = ESC_IOCTLS_THIRD_PARTY_INIT;
cap_ioctls_limit(vendor_fd, allowed, nitems(allowed));
cap_rights_limit(vendor_fd, &(cap_rights_t)CAP_RIGHTS_INITIALIZER(
    CAP_READ, CAP_WRITE, CAP_EVENT, CAP_IOCTL));
/* Pass vendor_fd to sandboxed third-party process */
```

## Requirements

### Core Requirements

1. **Capability-based interface**: Multiple `open()` calls to `/dev/esc` create
   independent client handles, each a capability that can be passed to sandboxed
   processes

2. **Configurable timeout**: Per-client configurable AUTH event deadline

3. **Passive mode**: Clients can operate in notify-only mode (no blocking)

4. **Pollable events**: Clients can `poll()`/`kevent()` for incoming events

5. **Rich event data**: Process info, file paths, credentials - similar to
   Apple's `es_process_t` and `es_message_t`

6. **Process muting**: Ability to mute and invert muting for processes to
   prevent recursion and implement allowlist behavior

### Design Goals

- Work within FreeBSD's existing frameworks (MAC, Capsicum)
- Minimize kernel complexity - keep policy in userspace
- Support multiple concurrent clients with independent subscriptions
- Graceful degradation when no clients or clients unresponsive
- CAPENABLED - usable from within capability mode
- **Safe for third-party use**

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           Userspace                                  │
│                                                                      │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐   │
│  │  System Daemon   │  │  Third-party EDR │  │  Audit Logger    │   │
│  │  (AUTH mode)     │  │  (NOTIFY mode)   │  │  (NOTIFY mode)   │   │
│  │  Full privileges │  │  Limited rights  │  │  Limited rights  │   │
│  └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘   │
│           │                     │                     │              │
│           │ fd from open()      │ fd passed/limited   │              │
│           ▼                     ▼                     ▼              │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                     libesc (userspace library)                │   │
│  │  - esc_client_create()    - esc_subscribe()                   │   │
│  │  - esc_respond()          - esc_set_mute_invert()             │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                              ioctl/read/poll
                                    │
┌─────────────────────────────────────────────────────────────────────┐
│                            Kernel                                    │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    /dev/esc (character device)                │   │
│  │                                                               │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │   │
│  │  │  Client 0   │  │  Client 1   │  │  Client 2   │           │   │
│  │  │  AUTH mode  │  │  NOTIFY     │  │  NOTIFY     │           │   │
│  │  │  timeout=5s │  │  (3rd party)│  │  (3rd party)│           │   │
│  │  │  subs: EXEC │  │  subs: ALL  │  │  subs: EXEC │           │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘           │   │
│  │                                                               │   │
│  │  Event Queue (per-client)                                     │   │
│  │  Response handling                                            │   │
│  │  Procdesc creation on demand                                  │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                              │                                       │
│                         MAC hooks                                    │
│                              │                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    mac_esc.ko (MAC policy module)             │   │
│  │                                                               │   │
│  │  mpo_vnode_check_exec()    → ESC_EVENT_EXEC                   │   │
│  │  mpo_vnode_check_open()    → ESC_EVENT_OPEN                   │   │
│  │  mpo_vnode_check_unlink()  → ESC_EVENT_UNLINK                 │   │
│  │  mpo_kld_check_load()      → ESC_EVENT_KLDLOAD                │   │
│  │  mpo_mount_check_mount()   → ESC_EVENT_MOUNT                  │   │
│  │  ...                                                          │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

## Data Structures

### Event Types

```c
typedef enum {
    /* AUTH events (sleepable hooks - can block for response) */
    ESC_EVENT_AUTH_EXEC         = 0x0001,
    ESC_EVENT_AUTH_OPEN         = 0x0002,
    ESC_EVENT_AUTH_CREATE       = 0x0003,
    ESC_EVENT_AUTH_UNLINK       = 0x0004,
    ESC_EVENT_AUTH_RENAME       = 0x0005,
    ESC_EVENT_AUTH_LINK         = 0x0006,
    ESC_EVENT_AUTH_MOUNT        = 0x0007,
    ESC_EVENT_AUTH_KLDLOAD      = 0x0008,
    ESC_EVENT_AUTH_MMAP         = 0x0009,
    ESC_EVENT_AUTH_MPROTECT     = 0x000A,
    ESC_EVENT_AUTH_CHDIR        = 0x000B,
    ESC_EVENT_AUTH_CHROOT       = 0x000C,
    ESC_EVENT_AUTH_SETEXTATTR   = 0x000D,
    ESC_EVENT_AUTH_PTRACE       = 0x000E,
    ESC_EVENT_AUTH_ACCESS       = 0x000F,
    ESC_EVENT_AUTH_READ         = 0x0010,
    ESC_EVENT_AUTH_WRITE        = 0x0011,
    ESC_EVENT_AUTH_LOOKUP       = 0x0012,
    ESC_EVENT_AUTH_SETMODE      = 0x0013,
    ESC_EVENT_AUTH_SETOWNER     = 0x0014,
    ESC_EVENT_AUTH_SETFLAGS     = 0x0015,
    ESC_EVENT_AUTH_SETUTIMES    = 0x0016,
    ESC_EVENT_AUTH_STAT         = 0x0017,
    ESC_EVENT_AUTH_POLL         = 0x0018,
    ESC_EVENT_AUTH_REVOKE       = 0x0019,
    ESC_EVENT_AUTH_READDIR      = 0x001A,
    ESC_EVENT_AUTH_READLINK     = 0x001B,
    ESC_EVENT_AUTH_GETEXTATTR   = 0x001C,
    ESC_EVENT_AUTH_DELETEEXTATTR= 0x001D,
    ESC_EVENT_AUTH_LISTEXTATTR  = 0x001E,
    ESC_EVENT_AUTH_GETACL       = 0x001F,
    ESC_EVENT_AUTH_SETACL       = 0x0020,
    ESC_EVENT_AUTH_DELETEACL    = 0x0021,
    ESC_EVENT_AUTH_RELABEL      = 0x0022,

    /* NOTIFY events (may include non-sleepable hooks) */
    ESC_EVENT_NOTIFY_EXEC       = 0x1001,
    ESC_EVENT_NOTIFY_EXIT       = 0x1002,
    ESC_EVENT_NOTIFY_FORK       = 0x1003,
    ESC_EVENT_NOTIFY_OPEN       = 0x1004,
    ESC_EVENT_NOTIFY_CREATE     = 0x1006,
    ESC_EVENT_NOTIFY_UNLINK     = 0x1007,
    ESC_EVENT_NOTIFY_RENAME     = 0x1008,
    ESC_EVENT_NOTIFY_MOUNT      = 0x1009,
    ESC_EVENT_NOTIFY_KLDLOAD    = 0x100B,
    ESC_EVENT_NOTIFY_SIGNAL     = 0x100D,
    ESC_EVENT_NOTIFY_PTRACE     = 0x100E,
    ESC_EVENT_NOTIFY_SETUID     = 0x100F,
    ESC_EVENT_NOTIFY_SETGID     = 0x1010,
    ESC_EVENT_NOTIFY_ACCESS     = 0x1011,
    ESC_EVENT_NOTIFY_READ       = 0x1012,
    ESC_EVENT_NOTIFY_WRITE      = 0x1013,
    ESC_EVENT_NOTIFY_LOOKUP     = 0x1014,
    ESC_EVENT_NOTIFY_SETMODE    = 0x1015,
    ESC_EVENT_NOTIFY_SETOWNER   = 0x1016,
    ESC_EVENT_NOTIFY_SETFLAGS   = 0x1017,
    ESC_EVENT_NOTIFY_SETUTIMES  = 0x1018,
    ESC_EVENT_NOTIFY_STAT       = 0x1019,
    ESC_EVENT_NOTIFY_POLL       = 0x101A,
    ESC_EVENT_NOTIFY_REVOKE     = 0x101B,
    ESC_EVENT_NOTIFY_READDIR    = 0x101C,
    ESC_EVENT_NOTIFY_READLINK   = 0x101D,
    ESC_EVENT_NOTIFY_GETEXTATTR = 0x101E,
    ESC_EVENT_NOTIFY_DELETEEXTATTR = 0x101F,
    ESC_EVENT_NOTIFY_LISTEXTATTR = 0x1020,
    ESC_EVENT_NOTIFY_GETACL     = 0x1021,
    ESC_EVENT_NOTIFY_SETACL     = 0x1022,
    ESC_EVENT_NOTIFY_DELETEACL  = 0x1023,
    ESC_EVENT_NOTIFY_RELABEL    = 0x1024,
    ESC_EVENT_NOTIFY_SETEXTATTR = 0x1025,
} esc_event_type_t;

#define ESC_EVENT_IS_AUTH(e)    (((e) & 0x1000) == 0)
#define ESC_EVENT_IS_NOTIFY(e)  (((e) & 0x1000) != 0)
```

**Sleepability rules (MAC hook constraints):**

- **AUTH-capable (sleepable)**: `mpo_vnode_check_*` (exec/open/access/read/write/lookup/create/unlink/rename/link/chdir/chroot/mmap/mprotect/setextattr/getextattr/deleteextattr/listextattr/setmode/setowner/setflags/setutimes/stat/poll/readdir/readlink/revoke/getacl/setacl/deleteacl/relabel), `mpo_mount_check_mount`, and `mpo_kld_check_load` use `MAC_POLICY_CHECK`, so AUTH mode can block safely.
- **NOTIFY-only (non-sleepable)**: `mpo_proc_check_debug` (ptrace), `mpo_proc_check_signal`, and `mpo_cred_check_setuid/setgid` use `MAC_POLICY_CHECK_NOSLEEP`, so they must never block. These are delivered only as NOTIFY events even though `ESC_EVENT_AUTH_PTRACE` is defined for API completeness.
- **Process NOTIFY events**: `process_fork` and `process_exit` are delivered via eventhandlers (non-sleepable) and always NOTIFY.

### Process Information

```c
/*
 * Process token - stable identity for muting and correlation.
 */
typedef struct {
    uint64_t    ept_id;         /* Unique token ID */
    uint64_t    ept_genid;      /* Generation (detects pid reuse) */
} esc_proc_token_t;

/*
 * Process information - analogous to Apple's es_process_t
 */
typedef struct {
    esc_proc_token_t ep_token;      /* Token for muting/correlation */
    uint64_t        ep_exec_id;     /* Execution ID (random per exec) */
    pid_t           ep_pid;         /* Process ID */
    pid_t           ep_ppid;        /* Parent PID */
    pid_t           ep_pgid;        /* Process group ID */
    pid_t           ep_sid;         /* Session ID */
    uid_t           ep_uid;         /* Effective UID */
    uid_t           ep_ruid;        /* Real UID */
    gid_t           ep_gid;         /* Effective GID */
    gid_t           ep_rgid;        /* Real GID */
    int             ep_jid;         /* Jail ID (0 if not jailed) */
    uint32_t        ep_flags;       /* EP_* flags below */
    char            ep_comm[MAXCOMLEN+1];   /* Command name */
    char            ep_path[MAXPATHLEN];    /* Executable path */
    /* Future: MAC label and other metadata (no code signing/entitlements). */
} esc_process_t;

#define EP_FLAG_SETUID      0x0001  /* Running setuid */
#define EP_FLAG_SETGID      0x0002  /* Running setgid */
#define EP_FLAG_JAILED      0x0004  /* In a jail */
#define EP_FLAG_CAPMODE     0x0008  /* In capability mode */
```

### File Information

```c
/*
 * File token - stable identity for correlation.
 */
typedef struct {
    uint64_t    eft_id;
    uint64_t    eft_dev;
} esc_file_token_t;

/*
 * File information
 */
typedef struct {
    esc_file_token_t ef_token;      /* Token for correlation */
    uint64_t        ef_ino;         /* Inode number */
    uint64_t        ef_dev;         /* Device */
    mode_t          ef_mode;        /* File mode */
    uid_t           ef_uid;         /* Owner UID */
    gid_t           ef_gid;         /* Owner GID */
    uint32_t        ef_flags;       /* File flags */
    char            ef_path[MAXPATHLEN];
} esc_file_t;
```

### Message Structure

```c
/*
 * Action type - does this require a response?
 */
typedef enum {
    ESC_ACTION_AUTH,        /* Requires response before proceeding */
    ESC_ACTION_NOTIFY,      /* Informational only */
} esc_action_t;

/*
 * AUTH response values
 */
typedef enum {
    ESC_AUTH_ALLOW  = 0,
    ESC_AUTH_DENY   = 1,
} esc_auth_result_t;

/*
 * Event-specific data unions (selected examples)
 */
typedef struct {
    esc_process_t   target;         /* New process after exec */
    esc_file_t      executable;     /* Executable being run */
    /* args/env available via separate ioctl if needed */
} esc_event_exec_t;

typedef struct {
    esc_file_t      file;           /* File being opened */
    int             flags;          /* Open flags (O_RDONLY, etc.) */
} esc_event_open_t;

typedef struct {
    esc_process_t   child;          /* Newly forked child */
} esc_event_fork_t;

typedef struct {
    int             status;         /* Exit status */
} esc_event_exit_t;

typedef struct {
    esc_file_t      source;         /* Source file */
    esc_file_t      dest;           /* Destination */
} esc_event_rename_t;

/*
 * Main message structure - what clients read
 */
typedef struct {
    uint32_t            em_version;     /* Structure version */
    uint64_t            em_id;          /* Unique message ID (for response) */
    esc_event_type_t    em_event;       /* Event type */
    esc_action_t        em_action;      /* AUTH or NOTIFY */
    struct timespec     em_time;        /* Event timestamp */
    struct timespec     em_deadline;    /* AUTH deadline (0 = no deadline) */
    esc_process_t       em_process;     /* Process that triggered event */

    union {
        esc_event_exec_t    exec;
        esc_event_open_t    open;
        esc_event_fork_t    fork;
        esc_event_exit_t    exit;
        esc_event_rename_t  rename;
        /* ... other event types ... */
        uint8_t             raw[512];   /* Future expansion */
    } em_event_data;
} esc_message_t;

#define ESC_MESSAGE_VERSION 1
```

### Response Structure

```c
/*
 * Response from client to kernel for AUTH events
 */
typedef struct {
    uint64_t            er_id;      /* Message ID being responded to */
    esc_auth_result_t   er_result;  /* ALLOW or DENY */
    uint32_t            er_flags;   /* Reserved */
} esc_response_t;
```

## Capability Rights

The key differentiator from Apple's model: Capsicum ioctl limiting controls access.

Since esc is a loadable kernel module, we use `cap_ioctls_limit()` rather than
adding new capability rights bits (which would require kernel changes).

```c
/*
 * Ioctl permission sets for esc(4)
 *
 * Control which ioctls a client can use via cap_ioctls_limit().
 * The system daemon opens /dev/esc with all ioctls, then creates
 * restricted handles for third-party vendors.
 */

/* Third-party monitoring without AUTH mode (can query but not set mode/timeout) */
#define ESC_IOCTLS_THIRD_PARTY_INIT \
    { ESC_IOC_SUBSCRIBE, ESC_IOC_GET_MODE, ESC_IOC_GET_TIMEOUT, \
      ESC_IOC_MUTE_PROCESS, ESC_IOC_UNMUTE_PROCESS, \
      ESC_IOC_MUTE_PATH, ESC_IOC_UNMUTE_PATH, ESC_IOC_SET_MUTE_INVERT, \
      ESC_IOC_GET_MUTE_INVERT, ESC_IOC_SET_TIMEOUT_ACTION, \
      ESC_IOC_GET_TIMEOUT_ACTION, ESC_IOC_GET_STATS, ... }

/* Full access (trusted system daemons only) */
#define ESC_IOCTLS_ALL_INIT \
    { ESC_IOC_SUBSCRIBE, ESC_IOC_SET_MODE, ESC_IOC_GET_MODE, \
      ESC_IOC_SET_TIMEOUT, ESC_IOC_GET_TIMEOUT, \
      ESC_IOC_MUTE_PROCESS, ESC_IOC_UNMUTE_PROCESS, \
      ESC_IOC_MUTE_PATH, ESC_IOC_UNMUTE_PATH, \
      ESC_IOC_SET_MUTE_INVERT, ESC_IOC_GET_MUTE_INVERT, \
      ESC_IOC_SET_TIMEOUT_ACTION, ESC_IOC_GET_TIMEOUT_ACTION, \
      ESC_IOC_CACHE_ADD, ESC_IOC_CACHE_REMOVE, ESC_IOC_CACHE_CLEAR, \
      ESC_IOC_GET_STATS, ... }
```

### Third-Party Client Setup

```c
/*
 * System daemon creates limited handle for third-party vendor
 */
int create_vendor_handle(void) {
    int fd = open("/dev/esc", O_RDWR);
    if (fd < 0)
        return -1;

    /* Duplicate so we keep our full-access copy */
    int vendor_fd = dup(fd);
    if (vendor_fd < 0)
        return -1;

    /* Limit which ioctls can be used */
    cap_ioctl_t allowed[] = ESC_IOCTLS_THIRD_PARTY_INIT;
    if (cap_ioctls_limit(vendor_fd, allowed, nitems(allowed)) < 0) {
        close(vendor_fd);
        return -1;
    }

    /* Also limit to basic fd operations */
    cap_rights_t rights;
    cap_rights_init(&rights, CAP_READ, CAP_WRITE, CAP_EVENT, CAP_IOCTL);
    if (cap_rights_limit(vendor_fd, &rights) < 0) {
        close(vendor_fd);
        return -1;
    }

    return vendor_fd;  /* Safe to pass to third-party code */
}
```

### What Third Parties Cannot Do

Without `ESC_IOC_SET_MODE`:
- Enter AUTH mode (can only receive NOTIFY events or AUTH-as-NOTIFY in PASSIVE mode)
- Change timeout or queue size settings
- This prevents third parties from being able to block system operations

The kernel checks ioctl permissions automatically via Capsicum. No additional
checks needed in esc_ioctl() - unauthorized ioctls return ENOTCAPABLE.

## Device Interface

### Opening /dev/esc

Each `open()` creates an independent client instance (capability). The fd can be:
- Passed to sandboxed child processes
- Used with `cap_rights_limit()` to restrict operations
- Duplicated to create multiple handles to same client

```c
int fd = open("/dev/esc", O_RDWR);
// fd is now a capability to a new ESC client
```

### IOCTLs

Access to ioctls is controlled via `cap_ioctls_limit()`. If an ioctl is not
in the allowed set, the kernel returns ENOTCAPABLE automatically.

```c
/*
 * ESC_IOC_SUBSCRIBE - Subscribe to event types
 */
struct esc_subscribe_args {
    const esc_event_type_t    *events;    /* Array of event types */
    size_t              count;      /* Number of events */
    uint32_t            flags;      /* ESC_SUB_* flags */
};
#define ESC_SUB_ADD     0x0000      /* Add to existing subscriptions */
#define ESC_SUB_REPLACE 0x0001      /* Replace existing subscriptions */

#define ESC_IOC_SUBSCRIBE   _IOW('E', 1, struct esc_subscribe_args)

/*
 * ESC_IOC_SET_MODE - Set client mode
 * Restricted to trusted clients - not in ESC_IOCTLS_THIRD_PARTY set.
 */
struct esc_mode_args {
    uint32_t    mode;               /* ESC_MODE_* */
    uint32_t    timeout_ms;         /* AUTH timeout (0 = keep current) */
    uint32_t    queue_size;         /* Max queued events (0 = keep current) */
};
#define ESC_MODE_NOTIFY     0x0000  /* Notify-only, never block kernel */
#define ESC_MODE_AUTH       0x0001  /* Can respond to AUTH events */
#define ESC_MODE_PASSIVE    0x0002  /* Never block, even for AUTH */

#define ESC_IOC_SET_MODE    _IOW('E', 2, struct esc_mode_args)

/*
 * ESC_IOC_GET_MODE - Query current mode and configuration
 * Available to third-party clients (read-only).
 */
#define ESC_IOC_GET_MODE    _IOR('E', 31, struct esc_mode_args)

/*
 * ESC_IOC_SET_TIMEOUT / GET_TIMEOUT - Set/get AUTH timeout independently
 * SET_TIMEOUT is restricted to trusted clients.
 * GET_TIMEOUT is available to third-party clients.
 * Unlike SET_MODE, SET_TIMEOUT does not trigger first-mode-set logic.
 */
struct esc_timeout_args {
    uint32_t    timeout_ms;         /* AUTH timeout in ms */
};
#define ESC_IOC_SET_TIMEOUT _IOW('E', 32, struct esc_timeout_args)
#define ESC_IOC_GET_TIMEOUT _IOR('E', 33, struct esc_timeout_args)

/*
 * ESC_IOC_MUTE_PROCESS - Mute events from a process
 *
 * Like Apple's es_mute_process - stop receiving events from this process.
 * Useful to avoid recursion when the security daemon triggers events.
 */
struct esc_mute_args {
    esc_proc_token_t    token;      /* Process to mute */
    uint32_t            flags;      /* ESC_MUTE_* */
};
#define ESC_MUTE_ALL        0x0000  /* Mute all events from process */
#define ESC_MUTE_SELF       0x0001  /* Mute current process */

#define ESC_IOC_MUTE_PROCESS    _IOW('E', 3, struct esc_mute_args)

/*
 * ESC_IOC_UNMUTE_PROCESS - Unmute a previously muted process
 */
#define ESC_IOC_UNMUTE_PROCESS  _IOW('E', 4, struct esc_mute_args)

/*
 * ESC_IOC_MUTE_PATH - Mute events by path
 *
 * Literal or prefix matching; can target primary path or target path.
 */
struct esc_mute_path_args {
    char        path[MAXPATHLEN];
    uint32_t    type;      /* ESC_MUTE_PATH_* */
    uint32_t    flags;     /* ESC_MUTE_PATH_FLAG_* */
};
#define ESC_MUTE_PATH_LITERAL       0x0001
#define ESC_MUTE_PATH_PREFIX        0x0002
#define ESC_MUTE_PATH_FLAG_TARGET   0x0001
#define ESC_IOC_MUTE_PATH       _IOW('E', 9, struct esc_mute_path_args)
#define ESC_IOC_UNMUTE_PATH     _IOW('E', 10, struct esc_mute_path_args)

/* Note: path muting only applies when an event provides a path field. */

/*
 * ESC_IOC_SET_MUTE_INVERT - Invert muting logic
 *
 * When enabled, the mute list becomes an allowlist. Only entries in the
 * mute list generate events for this client.
 */
struct esc_mute_invert_args {
    uint32_t    type;       /* ESC_MUTE_INVERT_* */
    uint32_t    invert;     /* 0 = normal, 1 = inverted */
};
#define ESC_MUTE_INVERT_PROCESS     0x0001
#define ESC_MUTE_INVERT_PATH        0x0002
#define ESC_MUTE_INVERT_TARGET_PATH 0x0003
#define ESC_IOC_SET_MUTE_INVERT _IOW('E', 7, struct esc_mute_invert_args)

/*
 * ESC_IOC_GET_MUTE_INVERT - Get current muting inversion flags
 */
#define ESC_IOC_GET_MUTE_INVERT _IOR('E', 8, struct esc_mute_invert_args)

/*
 * ESC_IOC_SET_TIMEOUT_ACTION - Default action on AUTH timeout
 */
struct esc_timeout_action_args {
    uint32_t    action;     /* ESC_AUTH_ALLOW or ESC_AUTH_DENY */
};
#define ESC_IOC_SET_TIMEOUT_ACTION _IOW('E', 11, struct esc_timeout_action_args)

/*
 * ESC_IOC_GET_TIMEOUT_ACTION - Get default action on AUTH timeout
 */
#define ESC_IOC_GET_TIMEOUT_ACTION _IOWR('E', 12, struct esc_timeout_action_args)

/*
 * ESC_IOC_CACHE_ADD - Add/update a decision cache entry
 * ESC_IOC_CACHE_REMOVE - Remove cache entries matching key
 * ESC_IOC_CACHE_CLEAR - Clear all cache entries for client
 */
#define ESC_CACHE_KEY_PROCESS    0x0001
#define ESC_CACHE_KEY_FILE       0x0002
#define ESC_CACHE_KEY_TARGET     0x0004
#define ESC_CACHE_EVENT_ANY      0

typedef struct {
    esc_event_type_t eck_event;    /* ESC_EVENT_AUTH_* or ANY */
    uint32_t    eck_flags;         /* ESC_CACHE_KEY_* */
    esc_proc_token_t eck_process;
    esc_file_token_t eck_file;
    esc_file_token_t eck_target;
} esc_cache_key_t;

typedef struct {
    esc_cache_key_t ece_key;
    esc_auth_result_t ece_result;  /* ALLOW or DENY */
    uint32_t    ece_ttl_ms;        /* Time-to-live in ms */
} esc_cache_entry_t;

#define ESC_IOC_CACHE_ADD    _IOW('E', 13, esc_cache_entry_t)
#define ESC_IOC_CACHE_REMOVE _IOW('E', 14, esc_cache_key_t)
#define ESC_IOC_CACHE_CLEAR  _IO('E', 15)

/* NOTE: ESC_IOC_GET_ARGS is not currently implemented.
 * Future work: deferred fetch of exec argv/envp by message ID. */

/*
 * ESC_IOC_GET_STATS - Retrieve per-client stats
 */
#define ESC_IOC_GET_STATS       _IOR('E', 6, struct esc_stats)
```

### Reading Events

```c
/* read() returns one esc_message_t structure per call */
esc_message_t msg;
ssize_t n = read(fd, &msg, sizeof(msg));
if (n == sizeof(msg)) {
    handle_event(&msg);
}
```

### Responding to AUTH Events

```c
/* write() sends responses */
esc_response_t resp = {
    .er_id = msg.em_id,
    .er_result = ESC_AUTH_ALLOW,
};
write(fd, &resp, sizeof(resp));
```

### Polling

```c
/* poll()/kevent() work normally */
/* Requires: CAP_EVENT (standard Capsicum right) */
struct pollfd pfd = { .fd = fd, .events = POLLIN };
poll(&pfd, 1, -1);

/* Or with kqueue */
struct kevent ev;
EV_SET(&ev, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
kevent(kq, &ev, 1, NULL, 0, NULL);
```

## Kernel Implementation

### Module Structure

```
sys/security/esc/
├── esc.h           # Public header (also installed to /usr/include)
├── esc_internal.h  # Internal definitions
├── esc_dev.c       # Character device implementation
├── esc_client.c    # Per-client state management
├── esc_event.c     # Event generation and dispatch
├── esc_mac.c       # MAC policy hooks
└── Makefile
```

### Client State (per open())

```c
struct esc_client {
    struct mtx          ec_mtx;         /* Protects this structure */
    uint32_t            ec_mode;        /* AUTH/NOTIFY/PASSIVE */
    uint32_t            ec_timeout_ms;  /* AUTH timeout */
    uint64_t            ec_subscriptions; /* Bitmask of subscribed events */
    TAILQ_HEAD(, esc_pending) ec_pending; /* Pending events */
    struct selinfo      ec_selinfo;     /* For poll/select */
    uint32_t            ec_queue_size;  /* Max queue depth */
    uint32_t            ec_queue_count; /* Current queue depth */
    LIST_HEAD(, esc_mute_entry) ec_muted; /* Muted processes */
    uint32_t            ec_mute_invert; /* Muting inversion flags */
    /* Capability rights (cached from file) */
    cap_rights_t        ec_rights;
};
```

### Event Flow (AUTH)

```
1. MAC hook fires (e.g., mpo_vnode_check_exec)
2. esc_event_generate() called with event data
3. For each subscribed AUTH-mode client:
   a. Create pending event structure
   b. Add to client's queue
   c. wakeup() poll waiters
   d. msleep() with timeout waiting for response
4. Collect responses (or apply defaults on timeout)
5. Return combined decision to MAC framework
```

### Event Flow (NOTIFY)

```
1. MAC hook fires (or we hook process exit, etc.)
2. esc_event_generate() called with event data
3. For each subscribed client (any mode):
   a. Create event structure
   b. Add to client's queue (drop if full)
   c. wakeup() poll waiters
4. Return immediately (no blocking)
```

## Userspace Library (libesc)

```c
/* High-level API */
typedef struct esc_client esc_client_t;

/* Create client (opens /dev/esc) */
esc_client_t *esc_client_create(void);
esc_client_t *esc_client_create_from_fd(int fd);
void esc_client_destroy(esc_client_t *client);

/* Get underlying fd for poll/kevent */
int esc_client_fd(esc_client_t *client);

/* Subscribe to events */
int esc_subscribe(esc_client_t *client,
                  esc_event_type_t *events, size_t count,
                  uint32_t flags);

/* Set client mode */
int esc_set_mode(esc_client_t *client, uint32_t mode,
                 uint32_t timeout_ms, uint32_t queue_size);

/* Get current mode and configuration */
int esc_get_mode(esc_client_t *client, uint32_t *mode,
                 uint32_t *timeout_ms, uint32_t *queue_size);

/* Set/get AUTH timeout independently (does not trigger first-mode-set logic) */
int esc_set_timeout(esc_client_t *client, uint32_t timeout_ms);
int esc_get_timeout(esc_client_t *client, uint32_t *timeout_ms);

/* Read next event (blocking or non-blocking based on fd flags) */
int esc_read_event(esc_client_t *client, esc_message_t *msg);

/* Respond to AUTH event */
int esc_respond(esc_client_t *client, uint64_t msg_id,
                esc_auth_result_t result);

/* Mute process */
int esc_mute_process(esc_client_t *client, esc_proc_token_t token);
int esc_mute_self(esc_client_t *client);
int esc_unmute_process(esc_client_t *client, esc_proc_token_t token);
int esc_mute_path(esc_client_t *client, const char *path, uint32_t type);
int esc_unmute_path(esc_client_t *client, const char *path, uint32_t type);
int esc_mute_target_path(esc_client_t *client, const char *path, uint32_t type);
int esc_unmute_target_path(esc_client_t *client, const char *path, uint32_t type);
int esc_set_mute_invert(esc_client_t *client, uint32_t type, bool invert);
int esc_get_mute_invert(esc_client_t *client, uint32_t type, bool *invert);

/* Utility: Extract info from process */
pid_t esc_process_pid(const esc_process_t *proc);
const char *esc_process_path(const esc_process_t *proc);
```

## Security Considerations

### Privilege Requirements

- Opening `/dev/esc` requires `PRIV_DRIVER` (may add `PRIV_ESC_CLIENT` later)
- AUTH mode controlled via `cap_ioctls_limit()` - deny `ESC_IOC_SET_MODE`
- Muting inversion is per-client; use it carefully when delegating fds

### Third-Party Sandboxing Example

```c
/*
 * Third-party EDR that receives a limited esc handle
 * Cannot enter AUTH mode, cannot change timeouts
 */
int vendor_main(int esc_fd) {  /* fd passed from system daemon */
    /* Subscribe to events we care about */
    esc_event_type_t events[] = {
        ESC_EVENT_NOTIFY_EXEC,
        ESC_EVENT_NOTIFY_FORK,
        ESC_EVENT_NOTIFY_EXIT
    };
    struct esc_subscribe_args sub = { events, 3, 0 };
    ioctl(esc_fd, ESC_IOC_SUBSCRIBE, &sub);

    /* Mute ourselves to prevent recursion */
    ioctl(esc_fd, ESC_IOC_MUTE_PROCESS,
          &(struct esc_mute_args){ .flags = ESC_MUTE_SELF });

    /* We CAN enter capability mode for additional sandboxing */
    cap_enter();

    /* Process events */
    while (1) {
        esc_message_t msg;
        if (read(esc_fd, &msg, sizeof(msg)) == sizeof(msg)) {
            /* Log, analyze, send to cloud, etc. */
            process_event(&msg);

        }
    }
}
```

### Preventing Deadlocks

1. **Self-muting**: Clients should mute themselves to prevent recursion
2. **Timeout enforcement**: Kernel enforces deadlines, applies default on timeout
3. **Queue limits**: Events dropped if client queue full (configurable)
4. **No lock dependencies**: AUTH events only in sleepable hooks

## Implementation Plan

### Phase 1: Core Infrastructure
- [ ] Character device skeleton (`esc_dev.c`)
- [ ] Client state management (`esc_client.c`)
- [ ] Basic read/write/poll implementation
- [ ] Event queue management
- [ ] Capsicum rights checking

### Phase 2: MAC Integration
- [ ] MAC policy module (`mac_esc.c`)
- [ ] Hook sleepable VFS operations (exec, open, create, unlink)
- [ ] AUTH event blocking with timeout
- [ ] NOTIFY event generation

### Phase 3: Capsicum Integration
- [ ] Ioctl permission sets (ESC_IOCTLS_THIRD_PARTY, ESC_IOCTLS_ALL)
- [ ] CAPENABLED for device (uses cap_ioctls_limit for ioctl restrictions)

### Phase 4: Process Events
- [ ] Hook fork/exit (NOTIFY only - non-sleepable)
- [ ] Process muting
- [ ] Self-mute support
- [ ] Muting inversion
- [ ] Path/target path muting

### Phase 5: Userspace Library
- [ ] libesc implementation
- [ ] Example security daemon
- [ ] Example third-party client
- [ ] Test suite

### Phase 6: Documentation & Polish
- [ ] Man pages: esc(4), libesc(3), esc_client_create(3)
- [ ] Integration tests
- [ ] Performance tuning
- [ ] Security audit

## Future Work / TODOs

- [ ] Expand event catalog beyond current vnode/process coverage (network,
      IPC, device, audit, etc.)
- [ ] Multi-client AUTH delivery and arbitration (fan-out, priority, combine
      decisions)
- [ ] Fuller suppression/mute semantics (process tree, file tokens, per-event
      filters, path globbing, global/namespace mutes)

## Open Questions

1. **Event versioning**: How to handle structure changes across versions?
   - Option A: Version field + variable-length events
   - Option B: Stable ABI with reserved fields
   - **Recommendation**: Option B for third-party stability

2. **Multiple AUTH clients**: If multiple clients subscribe to same AUTH event,
   how to combine responses?
   - Option A: First responder wins
   - Option B: All must agree (AND)
   - Option C: Any can deny (OR of denials)
   - **Implemented**: deliver to all AUTH clients, wait for all responses or
     timeouts, and deny if any client denies (timeouts apply per-client default)

3. **Audit integration**: Should events also go to audit trail?
   - Could integrate with existing audit(4) for compliance

4. **Jail isolation**: Should clients in jails only see events from their jail?
   - **Recommendation**: Yes, enforce jail boundaries by default

## References

- [Apple Endpoint Security](https://developer.apple.com/documentation/endpointsecurity)
- [Writing a Process Monitor](https://objective-see.org/blog/blog_0x47.html)
- [NetBSD kauth(9)](https://man.netbsd.org/kauth.9)
- [FreeBSD MAC Framework](https://docs.freebsd.org/en/books/arch-handbook/mac/)
- [FreeBSD Capsicum](https://man.freebsd.org/capsicum)
