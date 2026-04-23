# OES Production Readiness

This document is the minimum operational checklist for running Open Endpoint
Security as an enforcement component rather than a development prototype.

## Current Status

The tree is close enough to validate operationally, but it is not yet
production-ready.

Open items before release:

- Fix the outstanding correctness issues in AUTH fanout, muting semantics,
  event validation, and process group reporting.
- Add focused regression coverage for those fixes.
- ~~Example-program link failure against `liboes`.~~ (Resolved)
- Run the full root-only validation and sustained stress pass on a real loaded
  `oes.ko` instance.

## Production Policy

### AUTH Memory Pressure

Production policy for AUTH enforcement is:

- Sleepable AUTH dispatch must not silently degrade to allow because an
  internal fanout allocation failed.
- Any allocation required to consult AUTH clients in a sleepable hook should be
  treated as mandatory infrastructure, not best-effort telemetry.
- That means AUTH per-client pending clones, arbitration state, and similar
  sleepable-path structures should use sleepable allocation semantics.
- If an AUTH event cannot be represented before client consultation at all, the
  system behavior must be explicit and operator-chosen, never accidental.

Operationally:

- Enforcement deployments should set `security.oes.default_action=1`
  (`OES_AUTH_DENY`).
- Monitor-only or fail-open deployments should set
  `security.oes.default_action=0` (`OES_AUTH_ALLOW`) deliberately, not by
  default inheritance.
- Timeout policy and allocation-failure policy should match. A deployment that
  expects prevention should not run with timeout allow.

### Timeout Policy

Recommended production defaults:

- Prevention / enforcement: `default_action=DENY`, bounded timeout, explicit
  client-specific queue sizing.
- Observation / EDR-only: `default_action=ALLOW`, NOTIFY or PASSIVE mode unless
  AUTH is strictly required.

Timeout guidance:

- Start with `security.oes.default_timeout=5000` for prevention workloads.
- Use shorter timeouts only after measuring client latency under load.
- Do not leave timeout behavior implicit; set it in deployment config and
  document the rationale.

### Mode Discipline

- `oesd` or the privileged owner should be the only AUTH-capable control point.
- Third-party or delegated clients should receive restricted fds and remain in
  NOTIFY/PASSIVE usage patterns.
- Self-muting and default muting should be configured explicitly per role,
  especially for daemons that generate high event volume.

## Release Gates

A production candidate should pass all of the following:

- `make -C sys/security/oes`
- `make -C lib/liboes`
- `make -C tests`
- `make -C examples`
- `./run_tests.sh` as root on a FreeBSD host with a loadable `oes.ko`
- Sustained stress sequence below without hangs, panics, or policy surprises

If `make -C examples` fails, do not ship the tree as a release candidate. The
examples are part of the operational surface.

## Root-Run Stress Validation

This is the minimum sustained run to execute on a real FreeBSD test host as
root.

### 1. Load and baseline

```sh
cd /path/to/OpenEndpointSecurity
./run_tests.sh
sysctl security.oes
ls -l /dev/oes
```

Capture:

- loaded module version/build
- `security.oes.*` sysctl values
- whether `/dev/oes` permissions match the intended deployment model

### 2. Sustained multi-client stress

```sh
cd /path/to/OpenEndpointSecurity/tests

jot 10 | while read i; do
  echo "== test_multi_client_auth run $i =="
  ./test_multi_client_auth || exit 1
done

jot 10 | while read i; do
  echo "== test_multi_client_notify run $i =="
  ./test_multi_client_notify || exit 1
done

jot 10 | while read i; do
  echo "== test_stress run $i =="
  ./test_stress || exit 1
done

jot 5 | while read i; do
  echo "== test_memory_pressure run $i =="
  ./test_memory_pressure || exit 1
done
```

Watch for:

- unexpected AUTH allows/denies
- queue starvation or permanent backlog
- client cleanup failures after rapid open/close
- kernel warnings, KASSERTs, lock-order reversals, or panics
- steadily increasing dropped events or auth timeouts

### 3. Enforcement-specific checks

Run at least once with prevention posture:

```sh
sysctl security.oes.default_action=1
sysctl security.oes.default_timeout=5000
```

Then rerun:

```sh
./test_auth_timeout
./test_auth_responses
./test_flags_response
./test_memory_pressure
```

Goal:

- confirm timeout behavior matches deployment intent
- confirm memory pressure does not silently relax authorization
- confirm partial-authorization events behave deterministically

### 4. Post-run inspection

Capture after the stress run:

```sh
sysctl security.oes
kldstat | grep oes
dmesg | tail -200
```

Production sign-off should include the before/after sysctl state and the
relevant `dmesg` slice.

## Operational Defaults

Suggested starting values for enforcement:

```sh
sysctl security.oes.default_action=1
sysctl security.oes.default_timeout=5000
sysctl security.oes.default_queue_size=4096
sysctl security.oes.default_self_mute=1
```

Suggested starting values for observation-only deployments:

```sh
sysctl security.oes.default_action=0
sysctl security.oes.default_timeout=5000
sysctl security.oes.default_queue_size=4096
sysctl security.oes.default_self_mute=1
```

Queue size should be tuned from measured event rate, not left at a tiny default
in high-volume systems.

## Logging and Telemetry

Before production, ensure operators can answer:

- how many events were dropped
- how many AUTH events timed out
- whether any AUTH path failed open
- whether client queues are saturating
- whether memory pressure is causing dispatch skips

Today, some of this is observable through stats and debug logging, but release
readiness should include stable counters for all policy-relevant failure modes.

## Non-Root Validation Performed From This Shell

The following was validated in the current environment without root:

- `make -C lib/liboes clean all` succeeded
- `make -C tests clean all` succeeded
- `make -C examples clean all` succeeded

The root-only stress run in this document still needs to be executed by a user
with permission to load the module and access `/dev/oes`.
