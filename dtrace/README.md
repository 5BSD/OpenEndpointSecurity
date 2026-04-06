DTrace workflows for OES

Each script asserts a specific OES kernel workflow using fbt probes.
Run as root. Most scripts are driven by a subject command via -c and
exit after TIMEOUT seconds (default 20).

Usage examples:

- Load/unload:
  dtrace -s dtrace/00-load-unload.d -c 'kldload ./sys/security/oes/oes.ko; kldunload oes'

- Open/close + subscribe:
  dtrace -s dtrace/01-open-close.d -c './test_oes -h'
  dtrace -s dtrace/02-ioctl-subscribe-mode.d -c './test_oes -n'

- Auth/notify dispatch (use a workload that triggers vnode events):
  dtrace -s dtrace/04-auth-dispatch.d -c './tests/test_vnode_events'
  dtrace -s dtrace/05-notify-dispatch.d -c './tests/test_vnode_events'

- Cache/mute:
  dtrace -s dtrace/07-cache.d -c './tests/test_decision_cache'
  dtrace -s dtrace/08-mute.d -c './tests/test_mute'

- Rename/fork/exit:
  dtrace -s dtrace/09-rename.d -c './tests/test_vnode_events'
  dtrace -s dtrace/11-fork-exit.d -c './tests/test_process_events'

- Exec args:
  dtrace -s dtrace/10-exec-args.d -c './test_oes -a'

Override timeout:
  dtrace -D TIMEOUT=60 -s dtrace/04-auth-dispatch.d -c './tests/test_vnode_events'

Notes:
- These scripts validate function sequencing and presence, not user-visible output.
- Scripts ending in "coverage" (14/15) print which hooks ran without strict asserts.
