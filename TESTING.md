# ESC (Endpoint Security Capabilities) Test Plan

## Overview

ESC is a capability-based security event monitoring framework for FreeBSD,
inspired by Apple's Endpoint Security. It provides a safe API for third-party
security vendors to build EDR/AV software.

## Architecture Summary

```
┌─────────────────────────────────────────────────────────────┐
│                      Kernel Space                           │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │  MAC hooks  │───▶│  esc_event  │───▶│  /dev/esc   │     │
│  │ (esc_mac.c) │    │             │    │ (esc_dev.c) │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
│                                              │              │
└──────────────────────────────────────────────│──────────────┘
                                               │
                    ┌──────────────────────────┼──────────────┐
                    │          Userspace       │              │
                    │                          ▼              │
                    │  ┌─────────────────────────────────┐   │
                    │  │           escd                   │   │
                    │  │   (owns /dev/esc, AUTH mode)     │   │
                    │  └───────────────┬─────────────────┘   │
                    │                  │ Unix socket         │
                    │                  │ (SCM_RIGHTS)        │
                    │                  ▼                     │
                    │  ┌─────────────────────────────────┐   │
                    │  │       vendor_client              │   │
                    │  │  (restricted fd, NOTIFY only)    │   │
                    │  └─────────────────────────────────┘   │
                    └─────────────────────────────────────────┘
```

## Key Design Decisions

1. **Loadable kernel module** - No kernel source changes required
2. **Capsicum ioctl limiting** - Uses `cap_ioctls_limit()` not new CAP_* rights
3. **Third-party restriction** - Cannot enter AUTH mode (no ESC_IOC_SET_MODE)
4. **exec_id tracking** - 64-bit random ID, same on fork, new on exec

## File Locations

```
/home/koryheard/Projects/esc/
├── sys/security/esc/          # Kernel module
│   ├── esc.h                  # Public API header
│   ├── esc_internal.h         # Kernel internal header
│   ├── esc_dev.c              # Character device
│   ├── esc_client.c           # Client management
│   ├── esc_event.c            # Event handling
│   ├── esc_mac.c              # MAC policy hooks
│   └── Makefile
├── lib/libesc/                # Userspace library
│   ├── libesc.h
│   ├── libesc.c
│   └── Makefile
├── tests/                     # Unit tests
│   ├── test_mute.c
│   ├── test_passive_mode.c
│   ├── test_path_mute.c
│   ├── test_process_events.c
│   ├── test_vnode_events.c
│   └── test_decision_cache.c
└── examples/                  # Example programs
    ├── escd.c                 # System daemon
    ├── vendor_client.c        # Third-party example
    └── Makefile
```

---

## Phase 1: Build Verification

### 1.1 Build Kernel Module

```sh
cd /home/koryheard/Projects/esc/sys/security/esc
make clean && make
```

**Expected**: Compiles without errors, produces `esc.ko`

**Common issues**:
- Missing includes
- Undefined symbols (check esc_internal.h prototypes)
- MAC framework API changes

### 1.2 Build Userspace Library

```sh
cd /home/koryheard/Projects/esc/lib/libesc
make clean && make
```

**Expected**: Produces `libesc.so.1` and `libesc.a`

### 1.3 Build Example Programs

```sh
cd /home/koryheard/Projects/esc/examples
make clean && make
```

**Expected**: Produces `escd` and `vendor_client` binaries

### 1.4 Build and Run Unit Tests

```sh
cd /home/koryheard/Projects/esc
./run_tests.sh
```

**Expected**: Builds and runs `tests/test_process_events`,
`tests/test_vnode_events`, `tests/test_mute`, `tests/test_passive_mode`,
`tests/test_path_mute`, `tests/test_auth_timeout`,
`tests/test_multi_client_notify`, `tests/test_multi_client_auth`, and
`tests/test_decision_cache`
without failures

---

## Phase 2: Basic Device Functionality

### 2.1 Load Module

```sh
kldload ./esc.ko
```

**Expected**:
- Module loads successfully
- `kldstat | grep esc` shows module loaded
- `/dev/esc` appears
- `dmesg` shows: "esc: Endpoint Security Capabilities device created"

### 2.2 Device Permissions

```sh
ls -la /dev/esc
```

**Expected**: `crw------- 1 root wheel ... /dev/esc`

### 2.3 Privileged Access

```sh
# As root
cat /dev/esc  # Should block waiting for events (Ctrl+C to exit)
```

**Expected**: Blocks (no error)

### 2.4 Unprivileged Access

```sh
# As regular user
cat /dev/esc
```

**Expected**: "Permission denied" (EACCES or EPERM)

### 2.5 Sysctl Interface

```sh
sysctl security.esc
```

**Expected**:
```
security.esc.debug: 0
security.esc.default_timeout: 30000
security.esc.default_queue_size: 1024
security.esc.max_clients: 64
```

---

## Phase 3: Event Delivery (NOTIFY)

### 3.1 Basic NOTIFY Event

Create test program `test_notify.c`:
```c
#include <libesc.h>
#include <stdio.h>
#include <signal.h>

static volatile int running = 1;

static void sighandler(int sig) { running = 0; }

static bool handler(esc_client_t *c, const esc_message_t *m, void *ctx) {
    printf("[%s] pid=%d comm=%s\n",
        esc_event_name(m->em_event),
        m->em_process.ep_pid,
        m->em_process.ep_comm);
    return running;
}

int main() {
    signal(SIGINT, sighandler);

    esc_client_t *client = esc_client_create();
    if (!client) { perror("create"); return 1; }

    if (esc_subscribe_all(client, false, true) < 0)
        { perror("subscribe"); return 1; }

    if (esc_mute_self(client) < 0)
        { perror("mute"); return 1; }

    printf("Listening for NOTIFY events...\n");
    esc_dispatch(client, handler, NULL);

    esc_client_destroy(client);
    return 0;
}
```

**Test**:
```sh
./test_notify &
sleep 1
ls /tmp
kill %1
```

**Expected**: See NOTIFY_EXEC, NOTIFY_OPEN events for `ls`

### 3.2 exec_id Behavior

**Test**: Fork without exec
```sh
# In test program, print ep_exec_id
# Fork a child, compare exec_id
```

**Expected**: Parent and child have same exec_id

**Test**: Fork with exec
```sh
# Fork and exec /bin/true
# Compare exec_id before and after
```

**Expected**: After exec, exec_id is different

### 3.3 Process Info Accuracy

**Test**: Verify event data matches actual process

**Check**:
- ep_pid matches actual PID
- ep_ppid matches actual parent
- ep_uid/ep_gid match credentials
- ep_comm matches command name
- ep_jid correct for jailed processes

---

## Phase 4: AUTH Mode

### 4.1 Set AUTH Mode

```c
esc_client_t *client = esc_client_create();
int rc = esc_set_mode(client, ESC_MODE_AUTH, 5000, 0);  // 5s timeout
printf("set_mode returned: %d\n", rc);
```

**Expected**: Returns 0 (success)

### 4.2 AUTH Event Blocks

**Test**:
1. Subscribe to AUTH_EXEC
2. In another terminal, run `sleep 1`
3. Observe the sleep command blocks

**Expected**: `sleep` doesn't start until response or timeout

### 4.3 AUTH Allow

```c
if (esc_is_auth_event(msg)) {
    esc_respond_allow(client, msg);
}
```

**Expected**: Blocked operation proceeds normally

### 4.4 AUTH Deny

```c
if (esc_is_auth_event(msg)) {
    esc_respond_deny(client, msg);
}
```

**Expected**:
- Operation fails with EPERM
- e.g., exec returns "Operation not permitted"

### 4.5 AUTH Timeout

**Test**: Subscribe to AUTH but don't respond

**Expected**:
- After timeout (default 30s), operation proceeds
- `ec_auth_timeouts` stat increments

---

## Phase 5: Third-Party Restriction

### 5.1 Start escd

```sh
./escd -d  # Debug mode
```

**Expected**:
- "started, listening on /var/run/escd.sock"
- Socket file created

### 5.2 Connect vendor_client

```sh
./vendor_client
```

**Expected**:
```
Connecting to escd at /var/run/escd.sock...
Received restricted fd N
Attempting to set AUTH mode (should fail)...
  Failed as expected: Not capable
Subscribing to NOTIFY events...
Listening for events...
```

### 5.3 Verify Restriction

In vendor_client, attempt:
```c
int rc = esc_set_mode(client, ESC_MODE_AUTH, 0, 0);
```

**Expected**: Returns -1, errno == ENOTCAPABLE

### 5.4 NOTIFY Still Works

**Test**: While vendor_client running, exec commands

**Expected**: vendor_client receives NOTIFY events

### 5.5 Cannot Respond to AUTH

If vendor_client somehow receives AUTH events (via PASSIVE mode),
attempting to respond should fail.

**Expected**: `esc_respond()` returns ENOTCAPABLE

---

## Phase 6: Stress and Edge Cases

### 6.1 Rapid Events

```sh
for i in $(seq 1 1000); do /bin/true; done
```

**Expected**:
- No events dropped (check es_events_dropped stat)
- No kernel panics
- Client keeps up

### 6.2 Client Exit During AUTH

**Test**:
1. Start AUTH client
2. Trigger AUTH event
3. Kill client before responding

**Expected**:
- Pending AUTH times out
- Operation eventually proceeds
- No kernel hang or panic

### 6.3 Module Unload

```sh
# With clients connected
kldunload esc
```

**Expected**:
- Clients receive POLLHUP or read returns error
- Module unloads cleanly
- No kernel panic

### 6.4 Multiple AUTH Clients

**Test**: Two clients both in AUTH mode, same event type

**Expected**:
- Only one receives the AUTH event
- First to respond wins
- Or: clear policy (e.g., first registered)

### 6.5 Queue Full

**Test**:
1. Set small queue size (e.g., 10)
2. Generate many events without reading

**Expected**:
- es_events_dropped increments
- No crash
- New events still queue when space available

### 6.6 Muting and Inversion

**Test**:
1. Start NOTIFY client and mute a child process
2. Confirm events from that child are suppressed
3. Enable mute inversion and confirm only the muted process generates events
4. Mute a literal path and confirm matching exec events are suppressed
5. Enable path inversion and confirm allowlist behavior
6. Mute a target path and confirm link/rename targets are suppressed

**Expected**:
- Muted process events suppressed before inversion
- Inversion flips to allowlist behavior
- Path and target path muting behave as expected

---

## Phase 7: Security Verification

### 7.1 Privilege Escalation

**Test**: Unprivileged process tries to:
- Open /dev/esc directly
- Use received fd to set AUTH mode
- Manipulate events

**Expected**: All fail with appropriate errors

### 7.2 Information Leakage

**Test**: Check event data for sensitive info leakage

**Verify**:
- No kernel pointers exposed
- No uninitialized memory
- Paths correctly bounded

### 7.3 Resource Exhaustion

**Test**:
- Open max_clients + 1 connections
- Create many mute entries
- Very long running AUTH

**Expected**:
- Proper EAGAIN/ENOMEM errors
- System remains stable

---

## Debugging Tips

### Enable Debug Output

```sh
sysctl security.esc.debug=1
```

### Check Module Messages

```sh
dmesg | grep esc
```

### Trace ioctls

```sh
ktrace -i ./test_program
kdump | grep ioctl
```

### Check Client Stats

```c
struct esc_stats stats;
esc_get_stats(client, &stats);
printf("received=%lu dropped=%lu timeouts=%lu\n",
    stats.es_events_received,
    stats.es_events_dropped,
    stats.es_auth_timeouts);
```

---

## Known Limitations / TODOs

1. **PASSIVE mode coverage** - limited to exec-only conversion
2. **AUTH coverage** - Expand AUTH-mode tests beyond exec/open

---

## Success Criteria

- [ ] All Phase 1-5 tests pass
- [ ] No kernel panics under any test
- [ ] Third-party clients cannot escalate privileges
- [ ] AUTH timeout works correctly
- [ ] Module loads/unloads cleanly
- [ ] exec_id behaves correctly (same on fork, new on exec)
