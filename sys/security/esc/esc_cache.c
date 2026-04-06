/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 * All rights reserved.
 *
 * Endpoint Security Capabilities (esc) - Decision Cache
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/time.h>
#include <sys/sdt.h>

#include <security/esc/esc.h>
#include <security/esc/esc_internal.h>

MALLOC_DECLARE(M_ESC);

/* DTrace probes defined in esc_event.c */
SDT_PROBE_DECLARE(esc, , , cache__hit);
SDT_PROBE_DECLARE(esc, , , cache__miss);

static __inline bool
esc_cache_proc_equal(const esc_proc_token_t *a, const esc_proc_token_t *b)
{

	return (a->ept_id == b->ept_id && a->ept_genid == b->ept_genid);
}

static __inline bool
esc_cache_file_equal(const esc_file_token_t *a, const esc_file_token_t *b)
{

	return (a->eft_id == b->eft_id && a->eft_dev == b->eft_dev);
}

static __inline bool
esc_cache_file_valid(const esc_file_token_t *tok)
{

	return (tok->eft_id != 0 || tok->eft_dev != 0);
}

static uint32_t
esc_cache_bucket(esc_event_type_t event)
{

	return ((uint32_t)event & (ESC_CACHE_BUCKETS - 1));
}

static void
esc_cache_make_deadline(struct timespec *deadline, uint32_t ttl_ms)
{
	struct timespec now;
	struct timespec ts;

	nanouptime(&now);
	ts.tv_sec = ttl_ms / 1000;
	ts.tv_nsec = (ttl_ms % 1000) * 1000000;
	timespecadd(&now, &ts, deadline);
}

static bool
esc_cache_key_equal(const esc_cache_key_t *a, const esc_cache_key_t *b)
{

	if (a->eck_event != b->eck_event)
		return (false);
	if (a->eck_flags != b->eck_flags)
		return (false);
	if ((a->eck_flags & ESC_CACHE_KEY_PROCESS) &&
	    !esc_cache_proc_equal(&a->eck_process, &b->eck_process))
		return (false);
	if ((a->eck_flags & ESC_CACHE_KEY_FILE) &&
	    !esc_cache_file_equal(&a->eck_file, &b->eck_file))
		return (false);
	if ((a->eck_flags & ESC_CACHE_KEY_TARGET) &&
	    !esc_cache_file_equal(&a->eck_target, &b->eck_target))
		return (false);
	return (true);
}

static bool
esc_cache_key_match_lookup(const esc_cache_key_t *entry,
    const esc_cache_key_t *lookup)
{

	if (entry->eck_event != lookup->eck_event)
		return (false);
	/* Require exact flag match to prevent decision bleed across operations */
	if (entry->eck_flags != lookup->eck_flags)
		return (false);
	if ((entry->eck_flags & ESC_CACHE_KEY_PROCESS) &&
	    !esc_cache_proc_equal(&entry->eck_process, &lookup->eck_process))
		return (false);
	if ((entry->eck_flags & ESC_CACHE_KEY_FILE) &&
	    !esc_cache_file_equal(&entry->eck_file, &lookup->eck_file))
		return (false);
	if ((entry->eck_flags & ESC_CACHE_KEY_TARGET) &&
	    !esc_cache_file_equal(&entry->eck_target, &lookup->eck_target))
		return (false);
	return (true);
}

static bool
esc_cache_key_match_remove(const esc_cache_key_t *entry,
    const esc_cache_key_t *remove)
{

	if (remove->eck_event != ESC_CACHE_EVENT_ANY &&
	    entry->eck_event != remove->eck_event)
		return (false);
	if ((remove->eck_flags & ESC_CACHE_KEY_PROCESS) != 0) {
		if ((entry->eck_flags & ESC_CACHE_KEY_PROCESS) == 0)
			return (false);
		if (!esc_cache_proc_equal(&entry->eck_process,
		    &remove->eck_process))
			return (false);
	}
	if ((remove->eck_flags & ESC_CACHE_KEY_FILE) != 0) {
		if ((entry->eck_flags & ESC_CACHE_KEY_FILE) == 0)
			return (false);
		if (!esc_cache_file_equal(&entry->eck_file, &remove->eck_file))
			return (false);
	}
	if ((remove->eck_flags & ESC_CACHE_KEY_TARGET) != 0) {
		if ((entry->eck_flags & ESC_CACHE_KEY_TARGET) == 0)
			return (false);
		if (!esc_cache_file_equal(&entry->eck_target,
		    &remove->eck_target))
			return (false);
	}
	return (true);
}

static bool
esc_cache_key_from_pending(const struct esc_pending *ep,
    esc_cache_key_t *key)
{
	const esc_message_t *msg;
	esc_file_token_t file = { 0 };
	esc_file_token_t target = { 0 };

	msg = &ep->ep_msg;
	if (!ESC_EVENT_IS_AUTH(msg->em_event))
		return (false);

	bzero(key, sizeof(*key));
	key->eck_event = msg->em_event;
	key->eck_flags = ESC_CACHE_KEY_PROCESS;
	key->eck_process = msg->em_process.ep_token;

	switch (msg->em_event) {
	case ESC_EVENT_AUTH_EXEC:
		file = msg->em_event_data.exec.executable.ef_token;
		break;
	case ESC_EVENT_AUTH_OPEN:
		file = msg->em_event_data.open.file.ef_token;
		break;
	case ESC_EVENT_AUTH_ACCESS:
		file = msg->em_event_data.access.file.ef_token;
		break;
	case ESC_EVENT_AUTH_READ:
	case ESC_EVENT_AUTH_WRITE:
		file = msg->em_event_data.rw.file.ef_token;
		break;
	case ESC_EVENT_AUTH_STAT:
		file = msg->em_event_data.stat.file.ef_token;
		break;
	case ESC_EVENT_AUTH_POLL:
		file = msg->em_event_data.poll.file.ef_token;
		break;
	case ESC_EVENT_AUTH_REVOKE:
		file = msg->em_event_data.revoke.file.ef_token;
		break;
	case ESC_EVENT_AUTH_READDIR:
		file = msg->em_event_data.readdir.dir.ef_token;
		break;
	case ESC_EVENT_AUTH_READLINK:
		file = msg->em_event_data.readlink.file.ef_token;
		break;
	case ESC_EVENT_AUTH_LOOKUP:
		file = msg->em_event_data.lookup.dir.ef_token;
		break;
	case ESC_EVENT_AUTH_CREATE:
		/* Can't cache CREATE - file doesn't exist, key would collapse */
		return (false);
	case ESC_EVENT_AUTH_UNLINK:
		file = msg->em_event_data.unlink.file.ef_token;
		target = msg->em_event_data.unlink.dir.ef_token;
		break;
	case ESC_EVENT_AUTH_RENAME:
		file = msg->em_event_data.rename.src_file.ef_token;
		target = msg->em_event_data.rename.dst_dir.ef_token;
		break;
	case ESC_EVENT_AUTH_LINK:
		file = msg->em_event_data.link.target.ef_token;
		target = msg->em_event_data.link.dir.ef_token;
		break;
	case ESC_EVENT_AUTH_MOUNT:
		file = msg->em_event_data.mount.mountpoint.ef_token;
		break;
	case ESC_EVENT_AUTH_KLDLOAD:
		file = msg->em_event_data.kldload.file.ef_token;
		break;
	case ESC_EVENT_AUTH_MMAP:
		file = msg->em_event_data.mmap.file.ef_token;
		break;
	case ESC_EVENT_AUTH_MPROTECT:
		file = msg->em_event_data.mprotect.file.ef_token;
		break;
	case ESC_EVENT_AUTH_CHDIR:
		file = msg->em_event_data.chdir.dir.ef_token;
		break;
	case ESC_EVENT_AUTH_CHROOT:
		file = msg->em_event_data.chroot.dir.ef_token;
		break;
	case ESC_EVENT_AUTH_SETEXTATTR:
		file = msg->em_event_data.setextattr.file.ef_token;
		break;
	case ESC_EVENT_AUTH_GETEXTATTR:
		file = msg->em_event_data.getextattr.file.ef_token;
		break;
	case ESC_EVENT_AUTH_DELETEEXTATTR:
		file = msg->em_event_data.deleteextattr.file.ef_token;
		break;
	case ESC_EVENT_AUTH_LISTEXTATTR:
		file = msg->em_event_data.listextattr.file.ef_token;
		break;
	case ESC_EVENT_AUTH_GETACL:
		file = msg->em_event_data.getacl.file.ef_token;
		break;
	case ESC_EVENT_AUTH_SETACL:
		file = msg->em_event_data.setacl.file.ef_token;
		break;
	case ESC_EVENT_AUTH_DELETEACL:
		file = msg->em_event_data.deleteacl.file.ef_token;
		break;
	case ESC_EVENT_AUTH_RELABEL:
		file = msg->em_event_data.relabel.file.ef_token;
		break;
	case ESC_EVENT_AUTH_SETMODE:
		file = msg->em_event_data.setmode.file.ef_token;
		break;
	case ESC_EVENT_AUTH_SETOWNER:
		file = msg->em_event_data.setowner.file.ef_token;
		break;
	case ESC_EVENT_AUTH_SETFLAGS:
		file = msg->em_event_data.setflags.file.ef_token;
		break;
	case ESC_EVENT_AUTH_SETUTIMES:
		file = msg->em_event_data.setutimes.file.ef_token;
		break;
	case ESC_EVENT_AUTH_SWAPON:
		file = msg->em_event_data.swapon.file.ef_token;
		break;
	case ESC_EVENT_AUTH_SWAPOFF:
		file = msg->em_event_data.swapoff.file.ef_token;
		break;
	case ESC_EVENT_AUTH_PTRACE:
		/* Target is a process, not a file - can't cache */
		return (false);
	default:
		break;
	}

	if (esc_cache_file_valid(&file)) {
		key->eck_flags |= ESC_CACHE_KEY_FILE;
		key->eck_file = file;
	}
	if (esc_cache_file_valid(&target)) {
		key->eck_flags |= ESC_CACHE_KEY_TARGET;
		key->eck_target = target;
	}

	return (true);
}

static void
esc_cache_remove_entry_locked(struct esc_client *ec,
    struct esc_cache_entry *entry, bool expired, bool eviction)
{

	EC_LOCK_ASSERT(ec);
	LIST_REMOVE(entry, ece_link);
	TAILQ_REMOVE(&ec->ec_cache_lru, entry, ece_lru);
	if (ec->ec_cache_entries > 0)
		ec->ec_cache_entries--;
	if (expired)
		ec->ec_cache_expired++;
	else if (eviction)
		ec->ec_cache_evictions++;
	free(entry, M_ESC);
}

static void
esc_cache_clear_locked(struct esc_client *ec)
{
	struct esc_cache_entry *entry, *tmp;

	EC_LOCK_ASSERT(ec);
	TAILQ_FOREACH_SAFE(entry, &ec->ec_cache_lru, ece_lru, tmp)
		esc_cache_remove_entry_locked(ec, entry, false, false);
}

static bool
esc_cache_flags_valid(uint32_t flags)
{

	/* Require at least PROCESS key to prevent overly broad cache entries */
	if ((flags & ESC_CACHE_KEY_PROCESS) == 0)
		return (false);
	return ((flags & ~(ESC_CACHE_KEY_PROCESS | ESC_CACHE_KEY_FILE |
	    ESC_CACHE_KEY_TARGET)) == 0);
}

void
esc_cache_init(struct esc_client *ec)
{
	int i;

	for (i = 0; i < ESC_CACHE_BUCKETS; i++)
		LIST_INIT(&ec->ec_cache[i]);
	TAILQ_INIT(&ec->ec_cache_lru);
	ec->ec_cache_entries = 0;
	ec->ec_cache_max = esc_cache_max_entries;
}

void
esc_cache_destroy(struct esc_client *ec)
{

	EC_LOCK_ASSERT(ec);
	esc_cache_clear_locked(ec);
}

int
esc_client_cache_add(struct esc_client *ec, const esc_cache_entry_t *entry)
{
	struct esc_cache_entry *cur;
	struct esc_cache_entry *victim;
	struct esc_cache_entry *new_entry;
	struct timespec expires;
	uint32_t idx;

	if (entry == NULL)
		return (EINVAL);
	if (entry->ece_key.eck_event == ESC_CACHE_EVENT_ANY)
		return (EINVAL);
	if (!ESC_EVENT_IS_AUTH(entry->ece_key.eck_event))
		return (EINVAL);
	/* AUTH_PTRACE targets processes, not files - can't cache */
	if (entry->ece_key.eck_event == ESC_EVENT_AUTH_PTRACE)
		return (EINVAL);
	if (!esc_cache_flags_valid(entry->ece_key.eck_flags))
		return (EINVAL);
	if (entry->ece_result != ESC_AUTH_ALLOW &&
	    entry->ece_result != ESC_AUTH_DENY)
		return (EINVAL);
	if (entry->ece_ttl_ms == 0 ||
	    entry->ece_ttl_ms > ESC_MAX_CACHE_TTL_MS)
		return (EINVAL);

	esc_cache_make_deadline(&expires, entry->ece_ttl_ms);
	new_entry = malloc(sizeof(*new_entry), M_ESC, M_WAITOK | M_ZERO);
	new_entry->ece_key = entry->ece_key;
	new_entry->ece_result = entry->ece_result;
	new_entry->ece_expires = expires;

	EC_LOCK(ec);
	if (ec->ec_cache_max == 0) {
		EC_UNLOCK(ec);
		free(new_entry, M_ESC);
		return (ENOSPC);
	}

	idx = esc_cache_bucket(entry->ece_key.eck_event);
	LIST_FOREACH(cur, &ec->ec_cache[idx], ece_link) {
		if (esc_cache_key_equal(&cur->ece_key, &entry->ece_key)) {
			cur->ece_result = entry->ece_result;
			cur->ece_expires = expires;
			TAILQ_REMOVE(&ec->ec_cache_lru, cur, ece_lru);
			TAILQ_INSERT_HEAD(&ec->ec_cache_lru, cur, ece_lru);
			EC_UNLOCK(ec);
			free(new_entry, M_ESC);
			return (0);
		}
	}

	LIST_INSERT_HEAD(&ec->ec_cache[idx], new_entry, ece_link);
	TAILQ_INSERT_HEAD(&ec->ec_cache_lru, new_entry, ece_lru);
	ec->ec_cache_entries++;

	while (ec->ec_cache_entries > ec->ec_cache_max) {
		victim = TAILQ_LAST(&ec->ec_cache_lru, esc_cache_lru);
		if (victim == NULL)
			break;
		esc_cache_remove_entry_locked(ec, victim, false, true);
	}

	EC_UNLOCK(ec);
	return (0);
}

int
esc_client_cache_remove(struct esc_client *ec, const esc_cache_key_t *key)
{
	struct esc_cache_entry *cur, *tmp;
	uint32_t idx;
	uint32_t removed = 0;
	uint32_t flags;

	if (key == NULL)
		return (EINVAL);
	if (key->eck_event != ESC_CACHE_EVENT_ANY &&
	    !ESC_EVENT_IS_AUTH(key->eck_event))
		return (EINVAL);
	flags = key->eck_flags;
	if (!esc_cache_flags_valid(flags))
		return (EINVAL);

	EC_LOCK(ec);
	if (key->eck_event == ESC_CACHE_EVENT_ANY) {
		for (idx = 0; idx < ESC_CACHE_BUCKETS; idx++) {
			LIST_FOREACH_SAFE(cur, &ec->ec_cache[idx], ece_link,
			    tmp) {
				if (!esc_cache_key_match_remove(&cur->ece_key,
				    key))
					continue;
				esc_cache_remove_entry_locked(ec, cur, false,
				    false);
				removed++;
			}
		}
	} else {
		idx = esc_cache_bucket(key->eck_event);
		LIST_FOREACH_SAFE(cur, &ec->ec_cache[idx], ece_link, tmp) {
			if (!esc_cache_key_match_remove(&cur->ece_key, key))
				continue;
			esc_cache_remove_entry_locked(ec, cur, false, false);
			removed++;
		}
	}
	EC_UNLOCK(ec);

	return (removed > 0 ? 0 : ESRCH);
}

void
esc_client_cache_clear(struct esc_client *ec)
{

	EC_LOCK(ec);
	esc_cache_clear_locked(ec);
	EC_UNLOCK(ec);
}

bool
esc_client_cache_lookup(struct esc_client *ec, const struct esc_pending *ep,
    esc_auth_result_t *result)
{
	struct esc_cache_entry *cur, *tmp;
	esc_cache_key_t lookup;
	struct timespec now;
	uint32_t idx;

	EC_LOCK_ASSERT(ec);

	if (ec->ec_cache_max == 0 || ec->ec_cache_entries == 0)
		return (false);
	if (!esc_cache_key_from_pending(ep, &lookup))
		return (false);

	nanouptime(&now);
	idx = esc_cache_bucket(lookup.eck_event);

	LIST_FOREACH_SAFE(cur, &ec->ec_cache[idx], ece_link, tmp) {
		if (timespeccmp(&now, &cur->ece_expires, >=)) {
			esc_cache_remove_entry_locked(ec, cur, true, false);
			continue;
		}
		if (!esc_cache_key_match_lookup(&cur->ece_key, &lookup))
			continue;
		TAILQ_REMOVE(&ec->ec_cache_lru, cur, ece_lru);
		TAILQ_INSERT_HEAD(&ec->ec_cache_lru, cur, ece_lru);
		ec->ec_cache_hits++;
		SDT_PROBE3(esc, , , cache__hit,
		    ep->ep_msg.em_event,
		    ep->ep_msg.em_process.ep_pid,
		    cur->ece_result);
		if (result != NULL)
			*result = cur->ece_result;
		return (true);
	}

	ec->ec_cache_misses++;
	SDT_PROBE2(esc, , , cache__miss,
	    ep->ep_msg.em_event,
	    ep->ep_msg.em_process.ep_pid);
	return (false);
}
