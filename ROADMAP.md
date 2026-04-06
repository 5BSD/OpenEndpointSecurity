# OES Roadmap - Future Features

This document tracks potential features for OES (Endpoint Security Capabilities).

## Legend

- **Type**: AUTH (can block), NOTIFY (informational), or BOTH
- **Difficulty**: Easy (existing hooks), Medium (eventhandler work), Hard (kernel patch needed)
- **Priority**: P0 (critical), P1 (high), P2 (medium), P3 (nice-to-have)

---

## 0. CRITICAL: MAC Framework Sleep Semantics

The MAC framework uses two different macros:
- `MAC_POLICY_CHECK` - **CAN SLEEP** - suitable for AUTH (blocking)
- `MAC_POLICY_CHECK_NOSLEEP` - **CANNOT SLEEP** - NOTIFY only!

### NOSLEEP Hooks (NOTIFY-only, RESOLVED):

The following MAC hooks use MAC_POLICY_CHECK_NOSLEEP and cannot block.
They are now **NOTIFY-only** in the implementation:

| Event | MAC Hook | Status |
|-------|----------|--------|
| NOTIFY_SOCKET_CONNECT | socket_check_connect | ✓ NOTIFY-only |
| NOTIFY_SOCKET_BIND | socket_check_bind | ✓ NOTIFY-only |
| NOTIFY_SOCKET_LISTEN | socket_check_listen | ✓ NOTIFY-only |
| NOTIFY_REBOOT | system_check_reboot | ✓ NOTIFY-only |
| NOTIFY_SYSCTL | system_check_sysctl | ✓ NOTIFY-only |
| NOTIFY_KENV | kenv_check_* | ✓ NOTIFY-only |

Note: AUTH_PTRACE uses proc_check_debug which IS sleepable (MAC_POLICY_CHECK).
Note: AUTH_MOUNT uses vnode hooks, not system hooks - it works correctly.

### AUTH Events That CAN Block (sleepable hooks):

All vnode operations use `MAC_POLICY_CHECK` (sleepable):
- AUTH_EXEC, AUTH_OPEN, AUTH_CREATE, AUTH_UNLINK, AUTH_RENAME
- AUTH_LINK, AUTH_MMAP, AUTH_MPROTECT, AUTH_CHDIR, AUTH_CHROOT
- AUTH_SETEXTATTR, AUTH_ACCESS, AUTH_READ, AUTH_WRITE, AUTH_LOOKUP
- AUTH_SETMODE, AUTH_SETOWNER, AUTH_SETFLAGS, AUTH_SETUTIMES
- AUTH_STAT, AUTH_POLL, AUTH_REVOKE, AUTH_READDIR, AUTH_READLINK
- AUTH_GETEXTATTR, AUTH_DELETEEXTATTR, AUTH_LISTEXTATTR
- AUTH_GETACL, AUTH_SETACL, AUTH_DELETEACL, AUTH_RELABEL

System operations that CAN sleep:
- AUTH_KLDLOAD (kld_check_load)
- AUTH_SWAPON (system_check_swapon)
- AUTH_SWAPOFF (system_check_swapoff)

### NOTIFY-Only Events (no AUTH hook exists):

| Event | Reason |
|-------|--------|
| NOTIFY_UNMOUNT | Uses eventhandler, no MAC hook |
| NOTIFY_KLDUNLOAD | Uses eventhandler, no MAC hook |
| NOTIFY_EXIT | Uses eventhandler |
| NOTIFY_FORK | Uses eventhandler |
| NOTIFY_SIGNAL | Would need proc_check_signal but it's NOSLEEP |
| NOTIFY_SETUID/SETGID | cred_check_* are NOSLEEP |

---

## 0.1 Current OES Implementation Reference

### Eventhandlers (NOTIFY only - inherently non-blocking):

| Event | Eventhandler | Notes |
|-------|--------------|-------|
| NOTIFY_FORK | `process_fork` | Post-fork notification |
| NOTIFY_EXIT | `process_exit` | Post-exit notification |
| NOTIFY_UNMOUNT | `vfs_unmounted` | Post-unmount notification |
| NOTIFY_KLDUNLOAD | `kld_unload` | Post-unload notification |

### MAC Hooks - Sleepable (AUTH works):

| Event | MAC Hook | Can Block |
|-------|----------|-----------|
| AUTH_EXEC | mpo_vnode_check_exec | YES |
| AUTH_OPEN | mpo_vnode_check_open | YES |
| AUTH_CREATE | mpo_vnode_check_create | YES |
| AUTH_UNLINK | mpo_vnode_check_unlink | YES |
| AUTH_RENAME | mpo_vnode_check_rename_from/to | YES |
| AUTH_LINK | mpo_vnode_check_link | YES |
| AUTH_MMAP | mpo_vnode_check_mmap | YES |
| AUTH_MPROTECT | mpo_vnode_check_mprotect | YES |
| AUTH_CHDIR | mpo_vnode_check_chdir | YES |
| AUTH_CHROOT | mpo_vnode_check_chroot | YES |
| AUTH_ACCESS | mpo_vnode_check_access | YES |
| AUTH_READ | mpo_vnode_check_read | YES |
| AUTH_WRITE | mpo_vnode_check_write | YES |
| AUTH_LOOKUP | mpo_vnode_check_lookup | YES |
| AUTH_STAT | mpo_vnode_check_stat | YES |
| AUTH_POLL | mpo_vnode_check_poll | YES |
| AUTH_REVOKE | mpo_vnode_check_revoke | YES |
| AUTH_READDIR | mpo_vnode_check_readdir | YES |
| AUTH_READLINK | mpo_vnode_check_readlink | YES |
| AUTH_SETMODE | mpo_vnode_check_setmode | YES |
| AUTH_SETOWNER | mpo_vnode_check_setowner | YES |
| AUTH_SETFLAGS | mpo_vnode_check_setflags | YES |
| AUTH_SETUTIMES | mpo_vnode_check_setutimes | YES |
| AUTH_SETEXTATTR | mpo_vnode_check_setextattr | YES |
| AUTH_GETEXTATTR | mpo_vnode_check_getextattr | YES |
| AUTH_DELETEEXTATTR | mpo_vnode_check_deleteextattr | YES |
| AUTH_LISTEXTATTR | mpo_vnode_check_listextattr | YES |
| AUTH_GETACL | mpo_vnode_check_getacl | YES |
| AUTH_SETACL | mpo_vnode_check_setacl | YES |
| AUTH_DELETEACL | mpo_vnode_check_deleteacl | YES |
| AUTH_RELABEL | mpo_vnode_check_relabel | YES |
| AUTH_KLDLOAD | mpo_kld_check_load | YES |
| AUTH_SWAPON | mpo_system_check_swapon | YES |
| AUTH_SWAPOFF | mpo_system_check_swapoff | YES |

### MAC Hooks - NOSLEEP (Now NOTIFY-only):

| Event | MAC Hook | Status |
|-------|----------|--------|
| NOTIFY_SOCKET_CONNECT | mpo_socket_check_connect | ✓ NOTIFY-only (resolved) |
| NOTIFY_SOCKET_BIND | mpo_socket_check_bind | ✓ NOTIFY-only (resolved) |
| NOTIFY_SOCKET_LISTEN | mpo_socket_check_listen | ✓ NOTIFY-only (resolved) |
| NOTIFY_REBOOT | mpo_system_check_reboot | ✓ NOTIFY-only (resolved) |
| NOTIFY_SYSCTL | mpo_system_check_sysctl | ✓ NOTIFY-only (resolved) |
| NOTIFY_KENV | mpo_kenv_check_* | ✓ NOTIFY-only (resolved) |
| AUTH_PTRACE | mpo_proc_check_debug | Sleepable (MAC_POLICY_CHECK) |
| NOTIFY_SIGNAL | mpo_proc_check_signal | NOTIFY-only by design |
| NOTIFY_SETUID | mpo_cred_check_setuid | NOTIFY-only by design |
| NOTIFY_SETGID | mpo_cred_check_setgid | NOTIFY-only by design |

### NOTIFY-only Events (no AUTH variant):

| Event | Why |
|-------|-----|
| NOTIFY_UNMOUNT | Uses eventhandler, not MAC hook |
| NOTIFY_KLDUNLOAD | Uses eventhandler, not MAC hook |
| NOTIFY_EXIT | Process termination notification |
| NOTIFY_FORK | Process creation notification |

---

## 1. Missing Events (Require Kernel Patches)

These events cannot be implemented without adding new MAC hooks or eventhandlers to FreeBSD.

| Event | Type | Difficulty | Priority | Notes |
|-------|------|------------|----------|-------|
| CLOSE | NOTIFY | Hard | P0 | No `mpo_vnode_check_close` hook. Critical for file integrity monitoring. Would need to add MAC hook to `vn_close()` or use eventhandler. |
| TRUNCATE | BOTH | Hard | P2 | No `mpo_vnode_check_truncate`. truncate(2)/ftruncate(2) bypass setattr hooks. |
| FCNTL | BOTH | Hard | P1 | No `mpo_vnode_check_fcntl`. Important for lock monitoring (F_SETLK, F_GETLK). |
| DUP/DUP2 | NOTIFY | Hard | P3 | No hook for fd duplication. Less critical. |
| IOCTL | BOTH | Hard | P2 | No generic `mpo_vnode_check_ioctl`. Could monitor device control. |

### Proposed Kernel Patches

```
1. sys/kern/vfs_vnops.c - Add eventhandler for vn_close()
   EVENTHANDLER_INVOKE(vfs_closed, vp, td);

2. sys/kern/vfs_syscalls.c - Add MAC hook for truncate
   mac_vnode_check_truncate(cred, vp, length);

3. sys/kern/kern_descrip.c - Add MAC hook for fcntl
   mac_vnode_check_fcntl(cred, fp, cmd, arg);
```

---

## 2. FreeBSD-Specific Opportunities

These are unique to FreeBSD and would differentiate OES from Apple ES.

### 2.1 Jail Events

| Event | Type | Difficulty | Priority | Implementation |
|-------|------|------------|----------|----------------|
| JAIL_CREATE | NOTIFY | Medium | P1 | Use `prison_created` eventhandler (if exists) or add one |
| JAIL_DESTROY | NOTIFY | Medium | P1 | Use `prison_destroyed` eventhandler |
| JAIL_ATTACH | BOTH | Medium | P1 | MAC hook: `mpo_cred_check_jail` exists? Or use `jail_attach` eventhandler |

**Event Data Structure:**
```c
typedef struct {
    int         jid;              /* Jail ID */
    char        name[MAXHOSTNAMELEN];  /* Jail name */
    char        path[MAXPATHLEN]; /* Jail root path */
    char        hostname[MAXHOSTNAMELEN];
    uint32_t    flags;            /* Jail flags */
} oes_event_jail_t;
```

### 2.2 Capsicum Events

| Event | Type | Difficulty | Priority | Implementation |
|-------|------|------------|----------|----------------|
| CAPSICUM_ENTER | NOTIFY | Medium | P1 | Hook `cap_enter()` - eventhandler or MAC |
| CAPSICUM_RIGHTS_LIMIT | NOTIFY | Medium | P2 | Hook `cap_rights_limit()` |
| CAPSICUM_IOCTLS_LIMIT | NOTIFY | Medium | P3 | Hook `cap_ioctls_limit()` |
| CAPSICUM_FCNTLS_LIMIT | NOTIFY | Medium | P3 | Hook `cap_fcntls_limit()` |

**Event Data Structure:**
```c
typedef struct {
    int         fd;               /* File descriptor (if applicable) */
    uint64_t    rights[2];        /* CAP_RIGHTS_VERSION_00 */
    uint32_t    fcntls;           /* Allowed fcntl commands */
    uint32_t    nioctls;          /* Number of allowed ioctls */
} oes_event_capsicum_t;
```

### 2.3 Process Control Events

| Event | Type | Difficulty | Priority | Implementation |
|-------|------|------------|----------|----------------|
| PROCCTL | BOTH | Medium | P2 | MAC hook for procctl(2) operations |
| RFORK | NOTIFY | Easy | P2 | Extend existing fork hook to capture rfork flags |
| KTRACE | BOTH | Medium | P2 | Hook ktrace(2) - security sensitive |
| WAIT | NOTIFY | Easy | P3 | Process wait events |

**Procctl operations of interest:**
- PROC_SPROTECT - process protection
- PROC_TRACE_CTL - trace control
- PROC_TRAPCAP - Capsicum violation trapping
- PROC_ASLR_CTL - ASLR control

### 2.4 Audit Events

| Event | Type | Difficulty | Priority | Implementation |
|-------|------|------------|----------|----------------|
| AUDIT_SUBMIT | NOTIFY | Medium | P3 | Hook audit record submission |
| AUDIT_PIPE_OPEN | NOTIFY | Easy | P3 | Hook /dev/auditpipe open |

---

## 3. Deep Integrations

### 3.1 ZFS Integration

| Event | Type | Difficulty | Priority | Implementation |
|-------|------|------------|----------|----------------|
| ZFS_SNAPSHOT_CREATE | NOTIFY | Medium | P2 | ZFS eventhandler or ioctl hook |
| ZFS_SNAPSHOT_DESTROY | NOTIFY | Medium | P2 | ZFS eventhandler |
| ZFS_CLONE | NOTIFY | Medium | P3 | ZFS clone operations |
| ZFS_SEND | NOTIFY | Hard | P3 | ZFS send stream start |
| ZFS_RECEIVE | BOTH | Hard | P2 | ZFS receive - security sensitive |
| ZFS_KEY_LOAD | NOTIFY | Medium | P2 | Encryption key load |
| ZFS_KEY_UNLOAD | NOTIFY | Medium | P2 | Encryption key unload |
| ZFS_MOUNT | NOTIFY | Easy | P3 | Already have MOUNT, but ZFS-specific data |

**Event Data Structure:**
```c
typedef struct {
    char        pool[256];        /* Pool name */
    char        dataset[1024];    /* Dataset path */
    char        snapshot[256];    /* Snapshot name (if applicable) */
    uint64_t    guid;             /* Dataset GUID */
    uint32_t    op;               /* Operation type */
} oes_event_zfs_t;
```

### 3.2 GEOM Integration

| Event | Type | Difficulty | Priority | Implementation |
|-------|------|------------|----------|----------------|
| GEOM_ELI_ATTACH | NOTIFY | Medium | P2 | Disk encryption attach |
| GEOM_ELI_DETACH | NOTIFY | Medium | P2 | Disk encryption detach |
| GEOM_CREATE | NOTIFY | Hard | P3 | GEOM provider creation |
| GEOM_DESTROY | NOTIFY | Hard | P3 | GEOM provider destruction |

### 3.3 Networking Deep Integration

| Event | Type | Difficulty | Priority | Implementation |
|-------|------|------------|----------|----------------|
| PF_RULE_ADD | NOTIFY | Medium | P2 | Firewall rule changes |
| PF_RULE_REMOVE | NOTIFY | Medium | P2 | Firewall rule removal |
| IPFW_RULE_ADD | NOTIFY | Medium | P2 | IPFW rule changes |
| ROUTE_ADD | NOTIFY | Easy | P3 | Routing table changes |
| ROUTE_DELETE | NOTIFY | Easy | P3 | Routing table changes |
| IF_UP/IF_DOWN | NOTIFY | Easy | P3 | Interface state changes |

### 3.4 bhyve Integration (Future)

| Event | Type | Difficulty | Priority | Implementation |
|-------|------|------------|----------|----------------|
| VM_CREATE | NOTIFY | Hard | P3 | bhyve VM creation |
| VM_DESTROY | NOTIFY | Hard | P3 | bhyve VM destruction |
| VM_RUN | NOTIFY | Hard | P3 | bhyve VM start |

---

## 4. API Gaps

### 4.1 Bulk Operations

| Feature | Priority | Notes |
|---------|----------|-------|
| Batch subscribe | P2 | Subscribe to multiple events atomically |
| Batch mute | P2 | Mute multiple processes/paths atomically |
| Batch response | P1 | Respond to multiple AUTH events at once |

**Proposed IOCTLs:**
```c
struct oes_batch_response {
    uint32_t        ebr_count;
    oes_response_t  *ebr_responses;
};
#define OES_IOC_BATCH_RESPOND  _IOW('E', 40, struct oes_batch_response)
```

### 4.2 Event Notification Improvements

| Feature | Priority | Notes |
|---------|----------|-------|
| kqueue integration | P1 | EVFILT_READ already works, add EVFILT_USER for signals |
| Event sequence numbers | P2 | For ordering and gap detection |
| Transaction IDs | P2 | Correlate related events |

**Proposed:**
```c
/* Add to oes_message_t */
uint64_t    em_seq;        /* Sequence number */
uint64_t    em_txn_id;     /* Transaction ID (optional) */
```

### 4.3 File Descriptor Access

| Feature | Priority | Notes |
|---------|----------|-------|
| Get backing fd | P2 | Get fd for file in event (for content inspection) |
| fd passing | P3 | Pass fd to client via SCM_RIGHTS |

**Proposed:**
```c
struct oes_getfd_args {
    uint64_t    egf_msg_id;    /* Message ID */
    int         egf_which;     /* 0=file, 1=target, 2=dir */
    int         egf_fd;        /* OUT: file descriptor */
};
#define OES_IOC_GET_FD  _IOWR('E', 41, struct oes_getfd_args)
```

### 4.4 Enhanced Caching

| Feature | Priority | Notes |
|---------|----------|-------|
| Cache stats per event type | P3 | Better observability |
| Negative cache | P2 | Explicit "don't cache" responses |
| Cache invalidation hooks | P2 | Invalidate on file change |

### 4.5 Client Management

| Feature | Priority | Notes |
|---------|----------|-------|
| Client identification | P2 | Name/tag for debugging |
| Priority levels | P2 | High-priority clients get events first |
| Graceful degradation | P1 | Configurable behavior when client dies |

**Proposed:**
```c
struct oes_client_info {
    char        eci_name[64];      /* Client name */
    uint32_t    eci_priority;      /* 0=normal, 1=high */
    uint32_t    eci_flags;         /* ECI_FLAG_* */
};
#define OES_IOC_SET_CLIENT_INFO  _IOW('E', 42, struct oes_client_info)
```

---

## 5. Implementation Priority

### Phase 1 - Critical (P0)
1. CLOSE event (requires kernel patch proposal)

### Phase 2 - High Priority (P1)
1. Jail events (JAIL_CREATE, JAIL_DESTROY, JAIL_ATTACH)
2. Capsicum CAPSICUM_ENTER event
3. FCNTL event (requires kernel patch)
4. Batch response API
5. kqueue improvements

### Phase 3 - Medium Priority (P2)
1. ZFS events (snapshot, key load/unload)
2. GEOM ELI events
3. Procctl events
4. Event sequence numbers
5. Get backing fd API
6. TRUNCATE event

### Phase 4 - Nice to Have (P3)
1. DUP events
2. Full ZFS integration
3. bhyve integration
4. Advanced networking events
5. Audit integration

---

## 6. Kernel Patch Proposals

### 6.1 CLOSE Event (P0)

**File:** `sys/kern/vfs_vnops.c`

```c
/* In vn_close() before VOP_CLOSE */
#ifdef MAC
    /* Notify MAC framework of close */
    mac_vnode_notify_close(cred, vp, fp, fflag);
#endif
```

**New MAC hook:**
```c
/* sys/security/mac/mac_framework.h */
void mac_vnode_notify_close(struct ucred *cred, struct vnode *vp,
    struct file *fp, int fflag);
```

### 6.2 FCNTL Event (P1)

**File:** `sys/kern/kern_descrip.c`

```c
/* In kern_fcntl() before operation */
#ifdef MAC
    if (fp->f_type == DTYPE_VNODE) {
        error = mac_vnode_check_fcntl(td->td_ucred, fp, cmd, arg);
        if (error)
            return (error);
    }
#endif
```

### 6.3 Jail Events (P1)

**File:** `sys/kern/kern_jail.c`

Add eventhandlers:
```c
EVENTHANDLER_DECLARE(prison_create, void (*)(struct prison *));
EVENTHANDLER_DECLARE(prison_destroy, void (*)(struct prison *));
```

---

## 7. Testing Requirements

Each new feature needs:
1. Unit test in `tests/`
2. Integration test demonstrating real-world use
3. Stress test for resource exhaustion
4. Documentation update

---

## 8. Compatibility Notes

- New events should be additive (don't break existing subscriptions)
- New struct fields should be appended (ABI stability)
- Use reserved space in existing structures when possible
- Version bump `OES_API_VERSION` for breaking changes only
