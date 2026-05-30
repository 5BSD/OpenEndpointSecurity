# Production Readiness

OES can run in monitoring mode by default. Prevention deployments should opt in
to stricter AUTH behavior and treat message flags as part of the policy input.

## AUTH Policy

By default, AUTH operations fail open when no AUTH client is consulted, and
allocation failure follows `security.oes.default_action`. This is compatible
with monitoring-first deployments.

For prevention deployments, set:

```sh
sysctl security.oes.auth_fail_closed=1
sysctl security.oes.require_auth_clients=1
```

`auth_fail_closed=1` denies AUTH operations when OES cannot allocate or deliver
required authorization state. `require_auth_clients=1` denies AUTH operations
when no AUTH-mode client is consulted.

## Path Fidelity

File paths are best-effort in MAC hooks. Some hooks enter with VFS locks held,
so OES avoids `vn_fullpath()` in those contexts to prevent deadlock. For
namei-backed operations, OES may also report the requested pathname from
`componentname.cn_pnbuf`; those file objects set
`OES_FILE_META_PATH_REQUESTED` because the string is useful context but is not
canonical identity and may be relative, contain symlinks, or race with later
namespace changes.

When an event cannot include a reliable object path, `em_flags` includes
`OES_MSG_FLAG_PATH_UNAVAILABLE`. File and process objects also carry
`ef_meta_flags` and `ep_meta_flags` so consumers can tell which object in a
multi-object message lacked a stable path.

Consumers must not treat an empty path as a successful path match. Use file
tokens (`ef_token`) for identity-sensitive decisions when available. Treat
`OES_MSG_FLAG_PATH_UNAVAILABLE` as a higher-risk signal and treat
`OES_FILE_META_PATH_REQUESTED` as request context rather than stable identity.

## Notify-Only Events

NOSLEEP hooks cannot block. Socket, pipe, reboot, sysctl, kenv, privilege,
fork/exit, and similar events are delivered as NOTIFY only and may be dropped
under lock or allocation pressure. Watch `es_nosleep_drops` and
`es_alloc_failures` in `OES_IOC_GET_STATS`.

## ABI Drift

Event subscription masks are centralized as `OES_*_EVENT_MASK_*` in
`sys/security/oes/oes.h`. `tests/test_event_abi` verifies that the masks match
the public enum list.
