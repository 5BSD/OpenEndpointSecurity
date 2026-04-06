# ESC Test Suite Makefile
#
# Build and run tests for the ESC kernel module

CC?=		cc
CFLAGS=		-Wall -Wextra -I../sys
TESTS=		test_mute \
		test_path_mute \
		test_decision_cache \
		test_auth_timeout \
		test_multi_client_auth \
		test_multi_client_notify \
		test_passive_mode \
		test_process_events \
		test_vnode_events \
		test_per_event_muting \
		test_query_muted \
		test_unmute_all \
		test_flags_response \
		test_unmount_event \
		test_kldunload_event \
		test_fd_handling \
		test_error_conditions \
		test_stress \
		test_edge_cases \
		test_socket_events \
		test_mute_inversion \
		test_default_muting \
		test_timeout_deadlines \
		test_bad_ioctls \
		test_auth_responses \
		test_event_delivery \
		test_memory_pressure \
		test_uid_gid_mute \
		test_exec_args \
		test_process_info \
		test_mode_timeout_api \
		test_hook_coverage \
		test_signal_events \
		test_extattr_acl_events \
		test_mmap_mprotect_events \
		test_chdir_chroot_events

.PHONY: all clean run

all: $(TESTS)

%: %.c
	$(CC) $(CFLAGS) -o $@ $<

# Tests that require pthread
test_stress: test_stress.c
	$(CC) $(CFLAGS) -lpthread -o $@ $<

test_auth_responses: test_auth_responses.c
	$(CC) $(CFLAGS) -lpthread -o $@ $<

# Tests that require libacl
test_extattr_acl_events: test_extattr_acl_events.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TESTS)

# Run all tests (requires root and loaded esc module)
run: all
	@echo "=== Running ESC Test Suite ==="
	@echo "Note: Tests require root and loaded esc module"
	@echo ""
	@for t in $(TESTS); do \
		echo "--- Running $$t ---"; \
		./$$t || echo "FAILED: $$t"; \
		echo ""; \
	done
	@echo "=== Test Suite Complete ==="
