# Open Endpoint Security (OES) - Requirements

## Stakeholder Requirements

These are the core requirements gathered from the stakeholder:

## Out of Scope

- Code signing and entitlement metadata.
- Entitlement gating (access control is via Capsicum ioctls and open
  privileges only).

### REQ-001: Capability-Based Interface
**Priority**: Must Have
**Description**: Multiple `open()` calls to the virtual device create multiple
independent handles (capabilities). Each handle can be passed to sandboxed
processes and restricted using Capsicum rights.

**Acceptance Criteria**:
- [ ] Each `open("/dev/oes")` creates a new independent client
- [ ] Client fd can be passed across fork/exec
- [ ] Client fd can be restricted with `cap_rights_limit()`
- [ ] Device is CAPENABLED (works in capability mode after open)

**Design Reference**: DESIGN.md § Device Interface, § Capability Rights

---

### REQ-002: Configurable Timeout
**Priority**: Must Have
**Description**: The timeout for AUTH events must be configurable per-client.

**Acceptance Criteria**:
- [ ] `OES_IOC_SET_MODE` ioctl accepts timeout value
- [ ] Timeout applies to all AUTH events for that client
- [ ] Default timeout is reasonable (5-30 seconds)
- [ ] Timeout=0 means use system default

**Design Reference**: DESIGN.md § IOCTLs (OES_IOC_SET_MODE)

---

### REQ-003: Passive Mode
**Priority**: Must Have
**Description**: Ability to operate in passive/notify-only mode where the
client receives events but never blocks kernel operations.

**Acceptance Criteria**:
- [ ] `OES_MODE_NOTIFY` mode receives only NOTIFY events
- [ ] `OES_MODE_PASSIVE` mode receives AUTH events as NOTIFY (no blocking)
- [ ] Passive mode client cannot accidentally block system operations

**Design Reference**: DESIGN.md § IOCTLs (OES_IOC_SET_MODE), § Event Flow

---

### REQ-004: Pollable Events
**Priority**: Must Have
**Description**: Clients must be able to poll/select/kevent on their handle
to wait for incoming events.

**Acceptance Criteria**:
- [ ] `poll()` returns POLLIN when events are available
- [ ] `select()` marks fd readable when events available
- [ ] `kevent()` with EVFILT_READ works
- [ ] Non-blocking `read()` returns EAGAIN when no events

**Design Reference**: DESIGN.md § Device Interface (Polling)

---

### REQ-005: Rich Event Data
**Priority**: Must Have
**Description**: Events must include detailed information about subjects
(processes) and objects (files, etc.) similar to Apple's Endpoint Security.

**Acceptance Criteria**:
- [ ] Process info includes: pid, ppid, pgid, sid, uid, gid, path, comm
- [ ] File info includes: path, ino, dev, mode, owner
- [ ] Event info includes: timestamp, event type, action type
- [ ] Exec events include target process and executable info

**Design Reference**: DESIGN.md § Data Structures

---

### REQ-006: Muting and Inversion
**Priority**: Must Have
**Description**: Clients must be able to mute processes and optionally invert
muting so the mute list becomes an allowlist.

**Acceptance Criteria**:
- [ ] `OES_IOC_MUTE_PROCESS` mutes events from a process token
- [ ] `OES_MUTE_SELF` mutes the calling process
- [ ] `OES_IOC_UNMUTE_PROCESS` restores events for the process
- [ ] `OES_IOC_MUTE_PATH` mutes events by path (literal/prefix)
- [ ] `OES_IOC_UNMUTE_PATH` removes path mutes
- [ ] `OES_MUTE_PATH_FLAG_TARGET` applies to target paths (rename/link)
- [ ] `OES_IOC_SET_MUTE_INVERT` flips muting to allowlist behavior
- [ ] `OES_IOC_GET_MUTE_INVERT` reports current inversion state

**Design Reference**: DESIGN.md § IOCTLs (Muting)

---

## Derived Requirements

These requirements are derived from the stakeholder requirements and design:

### REQ-D01: Multiple Client Support
**Derived From**: REQ-001
**Description**: The kernel must support multiple concurrent clients with
independent subscriptions and state.

**Acceptance Criteria**:
- [ ] Each open() creates independent client state
- [ ] Clients have independent subscription sets
- [ ] Clients have independent event queues
- [ ] Closing one client doesn't affect others

---

### REQ-D02: Event Subscription
**Derived From**: REQ-003, REQ-005
**Description**: Clients must be able to subscribe to specific event types.

**Acceptance Criteria**:
- [ ] `OES_IOC_SUBSCRIBE` ioctl to select event types
- [ ] Can subscribe to AUTH events only if in AUTH mode
- [ ] Can add to or replace subscriptions
- [ ] Unsubscribed events are not delivered

---

### REQ-D03: AUTH Event Response
**Derived From**: REQ-002
**Description**: Clients in AUTH mode must be able to respond to AUTH events
with ALLOW or DENY.

**Acceptance Criteria**:
- [ ] `write()` with `oes_response_t` sends response
- [ ] Response includes message ID for correlation
- [ ] Late responses (after timeout) are ignored
- [ ] Invalid message ID returns error

---

### REQ-D04: Process Muting
**Derived From**: REQ-001, REQ-006
**Description**: Clients must be able to mute events from specific processes
to prevent recursion when the security daemon triggers events.

**Acceptance Criteria**:
- [ ] `OES_IOC_MUTE_PROCESS` silences events from token's process
- [ ] `OES_MUTE_SELF` silences events from calling process
- [ ] Muted processes don't generate events for that client
- [ ] Can unmute previously muted processes
- [ ] Mute inversion makes the mute list act as an allowlist

---

### REQ-D05: Queue Management
**Derived From**: REQ-004, REQ-002
**Description**: Per-client event queues must be bounded and configurable.

**Acceptance Criteria**:
- [ ] Queue has configurable maximum size
- [ ] Events dropped when queue full (with notification)
- [ ] Default queue size is reasonable for typical use
- [ ] Queue cleared on client close

---

### REQ-D07: Privilege Control
**Derived From**: REQ-001, REQ-003
**Description**: Appropriate privileges required for different operations.

**Acceptance Criteria**:
- [ ] Opening `/dev/oes` requires specific privilege
- [ ] AUTH mode requires elevated privilege
- [ ] Capsicum rights restrict operations after open

---

## Non-Functional Requirements

### REQ-NF01: Performance
**Description**: Event processing should not significantly impact system
performance.

**Acceptance Criteria**:
- [ ] NOTIFY events add < 1μs latency per event
- [ ] AUTH events with responsive client add < 10μs latency
- [ ] System remains responsive with unresponsive AUTH client (timeout works)
- [ ] Event delivery scales linearly with client count

---

### REQ-NF02: Reliability
**Description**: The framework must handle error conditions gracefully.

**Acceptance Criteria**:
- [ ] Client crash doesn't block system operations
- [ ] Kernel module unload cleans up all state
- [ ] Memory leaks must not occur under any scenario
- [ ] No kernel panics from malformed input

---

### REQ-NF03: Compatibility
**Description**: Must integrate with existing FreeBSD frameworks.

**Acceptance Criteria**:
- [ ] Uses standard MAC framework hooks
- [ ] Uses standard Capsicum rights model
- [ ] Uses standard cdev interfaces

---

## Future Requirements / TODOs

- [ ] Expand event catalog beyond current vnode/process coverage (network,
      IPC, device, audit, etc.)
- [ ] Define multi-client AUTH delivery and arbitration semantics
- [ ] Fuller suppression/mute semantics (process tree, file tokens, per-event
      filters, path globbing, global/namespace mutes)

## Traceability Matrix

| Requirement | Design Section | Test Case |
|-------------|----------------|-----------|
| REQ-001 | Device Interface | TC-001-* |
| REQ-002 | IOCTLs | TC-002-* |
| REQ-003 | IOCTLs, Event Flow | TC-003-* |
| REQ-004 | Device Interface | TC-004-* |
| REQ-005 | Data Structures | TC-005-* |
| REQ-006 | IOCTLs (Muting) | TC-D04-* |
| REQ-D01 | Architecture | TC-D01-* |
| REQ-D02 | IOCTLs | TC-D02-* |
| REQ-D03 | Device Interface | TC-D03-* |
| REQ-D04 | IOCTLs | TC-D04-* |
| REQ-D05 | Client State | TC-D05-* |
| REQ-D07 | Security | TC-D07-* |

## Test Cases (Outline)

### TC-001: Capability-Based Interface
- TC-001-01: Multiple opens create independent clients
- TC-001-02: Client fd works across fork
- TC-001-03: cap_rights_limit restricts operations
- TC-001-04: Device works in capability mode

### TC-002: Configurable Timeout
- TC-002-01: Custom timeout via ioctl
- TC-002-02: Timeout=0 uses default
- TC-002-03: Timeout expires, default action taken

### TC-003: Passive Mode
- TC-003-01: NOTIFY mode receives NOTIFY events only
- TC-003-02: PASSIVE mode receives AUTH as NOTIFY
- TC-003-03: PASSIVE client doesn't block operations

### TC-004: Pollable Events
- TC-004-01: poll() returns POLLIN on event
- TC-004-02: select() marks fd readable
- TC-004-03: kevent() works with EVFILT_READ
- TC-004-04: Non-blocking read returns EAGAIN

### TC-005: Rich Event Data
- TC-005-01: Exec event contains process info
- TC-005-02: Open event contains file info
- TC-005-03: All expected fields populated

### TC-D04: Process Muting
- TC-D04-01: Muted process stops events for that client
- TC-D04-02: OES_MUTE_SELF suppresses self events
- TC-D04-03: Unmute restores events
- TC-D04-04: Mute inversion allowlists muted process
- TC-D04-05: Path muting suppresses matching events
- TC-D04-06: Target path muting suppresses matching target paths
- TC-D04-07: Path inversion allowlists muted paths

## Glossary

| Term | Definition |
|------|------------|
| AUTH event | Event requiring authorization response before operation proceeds |
| NOTIFY event | Informational event that doesn't block operations |
| Client | An open handle to /dev/oes |
| Token | Lightweight handle that identifies a process or file |
| Muting | Suppressing events from a specific process |
| Mute inversion | Muting logic where the mute list becomes an allowlist |
| Path muting | Suppressing events that match a path (literal or prefix) |
| Target path muting | Suppressing events based on the destination path |
