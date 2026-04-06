/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 * All rights reserved.
 *
 * Endpoint Security Capabilities (esc) - Event Generation and Dispatch
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/condvar.h>
#include <sys/selinfo.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <sys/sdt.h>
#include <machine/atomic.h>

#include <security/esc/esc.h>
#include <security/esc/esc_internal.h>

MALLOC_DECLARE(M_ESC);

/*
 * DTrace SDT provider for ESC
 *
 * Probes:
 *   esc:::auth-allow(event, pid, path)     - AUTH event allowed
 *   esc:::auth-deny(event, pid, path)      - AUTH event denied
 *   esc:::auth-timeout(event, pid, action) - AUTH event timed out
 *   esc:::event-enqueue(event, pid, client_id) - Event queued for client
 *   esc:::event-drop(event, pid, client_id) - Event dropped (queue full)
 *   esc:::cache-hit(event, pid, result)    - Decision cache hit
 *   esc:::cache-miss(event, pid)           - Decision cache miss
 *
 * Example usage:
 *   dtrace -n 'esc:::auth-deny { printf("%s pid=%d", execname, arg1); }'
 */
SDT_PROVIDER_DEFINE(esc);

SDT_PROBE_DEFINE3(esc, , , auth__allow,
    "esc_event_type_t",		/* event type */
    "pid_t",			/* process ID */
    "const char *");		/* path (if applicable) */

SDT_PROBE_DEFINE3(esc, , , auth__deny,
    "esc_event_type_t",		/* event type */
    "pid_t",			/* process ID */
    "const char *");		/* path (if applicable) */

SDT_PROBE_DEFINE3(esc, , , auth__timeout,
    "esc_event_type_t",		/* event type */
    "pid_t",			/* process ID */
    "esc_auth_result_t");	/* default action taken */

SDT_PROBE_DEFINE3(esc, , , event__enqueue,
    "esc_event_type_t",		/* event type */
    "pid_t",			/* process ID */
    "uint64_t");		/* client ID */

SDT_PROBE_DEFINE3(esc, , , event__drop,
    "esc_event_type_t",		/* event type */
    "pid_t",			/* process ID */
    "uint64_t");		/* client ID */

SDT_PROBE_DEFINE3(esc, , , cache__hit,
    "esc_event_type_t",		/* event type */
    "pid_t",			/* process ID */
    "esc_auth_result_t");	/* cached result */

SDT_PROBE_DEFINE2(esc, , , cache__miss,
    "esc_event_type_t",		/* event type */
    "pid_t");			/* process ID */

struct esc_auth_group {
	struct mtx	ag_mtx;
	struct cv	ag_cv;
	uint32_t	ag_pending;
	bool		ag_denied;
	int		ag_refcount;
};

struct esc_auth_group *
esc_auth_group_alloc(void)
{
	struct esc_auth_group *ag;

	ag = malloc(sizeof(*ag), M_ESC, M_NOWAIT | M_ZERO);
	if (ag == NULL)
		return (NULL);

	mtx_init(&ag->ag_mtx, "esc_auth_group", NULL, MTX_DEF);
	cv_init(&ag->ag_cv, "esc_auth_group");
	ag->ag_refcount = 1;

	return (ag);
}

void
esc_auth_group_hold(struct esc_auth_group *ag)
{

	if (ag == NULL)
		return;
	atomic_add_int(&ag->ag_refcount, 1);
}

void
esc_auth_group_rele(struct esc_auth_group *ag)
{

	if (ag == NULL)
		return;
	if (atomic_fetchadd_int(&ag->ag_refcount, -1) == 1) {
		cv_destroy(&ag->ag_cv);
		mtx_destroy(&ag->ag_mtx);
		free(ag, M_ESC);
	}
}

void
esc_auth_group_add_pending(struct esc_auth_group *ag)
{

	mtx_lock(&ag->ag_mtx);
	ag->ag_pending++;
	mtx_unlock(&ag->ag_mtx);
}

void
esc_auth_group_cancel_pending(struct esc_auth_group *ag)
{

	mtx_lock(&ag->ag_mtx);
	if (ag->ag_pending > 0)
		ag->ag_pending--;
	cv_broadcast(&ag->ag_cv);
	mtx_unlock(&ag->ag_mtx);
}

void
esc_auth_group_mark_response(struct esc_auth_group *ag,
    esc_auth_result_t result)
{

	mtx_lock(&ag->ag_mtx);
	if (ag->ag_pending > 0)
		ag->ag_pending--;
	if (result == ESC_AUTH_DENY)
		ag->ag_denied = true;
	cv_broadcast(&ag->ag_cv);
	mtx_unlock(&ag->ag_mtx);
}

static void
esc_auth_group_update_timeouts(struct esc_auth_group *ag,
    struct esc_pending **eps, size_t count)
{
	struct timespec now;
	size_t i;

	nanouptime(&now);

	for (i = 0; i < count; i++) {
		struct esc_pending *ep = eps[i];
		esc_auth_result_t action;
		bool responded;

		if (ep == NULL)
			continue;

		mtx_lock(&ep->ep_mtx);
		responded = ep->ep_responded;
		action = ep->ep_timeout_action;
		if (!responded &&
		    timespeccmp(&now, &ep->ep_deadline, >=)) {
			ep->ep_responded = true;
			ep->ep_result = action;
			ep->ep_flags |= EP_FLAG_EXPIRED;
			mtx_unlock(&ep->ep_mtx);

			SDT_PROBE3(esc, , , auth__timeout,
			    ep->ep_msg.em_event,
			    ep->ep_msg.em_process.ep_pid,
			    action);

			esc_auth_group_mark_response(ag, action);
			esc_event_handle_timeout(ep);
			continue;
		}
		mtx_unlock(&ep->ep_mtx);
	}
}

int
esc_auth_group_wait(struct esc_auth_group *ag, struct esc_pending **eps,
    size_t count)
{
	struct timespec next_deadline;
	bool have_deadline;
	size_t i;
	bool denied = false;

	for (;;) {
		esc_auth_group_update_timeouts(ag, eps, count);

		mtx_lock(&ag->ag_mtx);
		if (ag->ag_pending == 0) {
			denied = ag->ag_denied;
			mtx_unlock(&ag->ag_mtx);
			break;
		}
		mtx_unlock(&ag->ag_mtx);

		have_deadline = false;
		for (i = 0; i < count; i++) {
			struct esc_pending *ep = eps[i];
			bool responded;

			if (ep == NULL)
				continue;

			mtx_lock(&ep->ep_mtx);
			responded = ep->ep_responded;
			if (!responded) {
				if (!have_deadline ||
				    timespeccmp(&ep->ep_deadline,
				    &next_deadline, <)) {
					next_deadline = ep->ep_deadline;
					have_deadline = true;
				}
			}
			mtx_unlock(&ep->ep_mtx);
		}

		if (!have_deadline)
			continue;

		mtx_lock(&ag->ag_mtx);
		if (ag->ag_pending == 0) {
			denied = ag->ag_denied;
			mtx_unlock(&ag->ag_mtx);
			break;
		}
		cv_timedwait_sbt(&ag->ag_cv, &ag->ag_mtx,
		    tstosbt(next_deadline), SBT_1MS, C_ABSOLUTE);
		mtx_unlock(&ag->ag_mtx);
	}

	return (denied ? EACCES : 0);
}

void
esc_set_auth_deadline(struct esc_pending *ep, uint32_t timeout_ms)
{
	struct timespec ts;
	struct timespec deadline;

	if (timeout_ms == 0)
		timeout_ms = ESC_DEFAULT_TIMEOUT_MS;

	nanouptime(&deadline);
	ts.tv_sec = timeout_ms / 1000;
	ts.tv_nsec = (timeout_ms % 1000) * 1000000;
	timespecadd(&deadline, &ts, &deadline);

	ep->ep_deadline = deadline;
	ep->ep_msg.em_deadline = deadline;
}

struct esc_pending *
esc_pending_alloc(esc_event_type_t event, struct proc *p)
{
	struct esc_pending *ep;

	ep = malloc(sizeof(*ep), M_ESC, M_NOWAIT | M_ZERO);
	if (ep == NULL)
		return (NULL);

	ep->ep_refcount = 1;
	ep->ep_msg.em_version = ESC_MESSAGE_VERSION;

	/* Assign unique message ID */
	ep->ep_msg.em_id = atomic_fetchadd_64(&esc_softc.sc_next_msg_id, 1);

	ep->ep_msg.em_event = event;

	if (ESC_EVENT_IS_AUTH(event)) {
		ep->ep_msg.em_action = ESC_ACTION_AUTH;
		ep->ep_flags |= EP_FLAG_AUTH;
		mtx_init(&ep->ep_mtx, "esc_pending", NULL, MTX_DEF);
		cv_init(&ep->ep_cv, "esc_auth");
		ep->ep_responded = false;
		ep->ep_result = ESC_AUTH_ALLOW;
	} else {
		ep->ep_msg.em_action = ESC_ACTION_NOTIFY;
	}

	ep->ep_group = NULL;
	nanouptime(&ep->ep_msg.em_time);

	if (p != NULL) {
		PROC_LOCK(p);
		esc_fill_process(&ep->ep_msg.em_process, p, NULL);
		PROC_UNLOCK(p);
	}

	return (ep);
}

struct esc_pending *
esc_pending_clone(const struct esc_pending *src)
{
	struct esc_pending *ep;

	if (src == NULL)
		return (NULL);

	ep = malloc(sizeof(*ep), M_ESC, M_NOWAIT | M_ZERO);
	if (ep == NULL)
		return (NULL);

	ep->ep_refcount = 1;
	ep->ep_flags = src->ep_flags & EP_FLAG_AUTH;
	ep->ep_msg = src->ep_msg;
	ep->ep_msg.em_deadline = (struct timespec){ 0 };
	ep->ep_deadline = (struct timespec){ 0 };
	ep->ep_group = NULL;

	if (ep->ep_flags & EP_FLAG_AUTH) {
		mtx_init(&ep->ep_mtx, "esc_pending", NULL, MTX_DEF);
		cv_init(&ep->ep_cv, "esc_auth");
		ep->ep_responded = false;
		ep->ep_result = ESC_AUTH_ALLOW;
	}

	return (ep);
}

void
esc_pending_free(struct esc_pending *ep)
{

	if (ep->ep_flags & EP_FLAG_AUTH) {
		cv_destroy(&ep->ep_cv);
		mtx_destroy(&ep->ep_mtx);
	}

	if (ep->ep_group != NULL)
		esc_auth_group_rele(ep->ep_group);

	free(ep, M_ESC);
}

void
esc_pending_hold(struct esc_pending *ep)
{

	atomic_add_int(&ep->ep_refcount, 1);
}

void
esc_pending_rele(struct esc_pending *ep)
{

	if (atomic_fetchadd_int(&ep->ep_refcount, -1) == 1)
		esc_pending_free(ep);
}

int
esc_event_enqueue(struct esc_client *ec, struct esc_pending *ep)
{

	EC_LOCK_ASSERT(ec);

	if (ec->ec_queue_count >= ec->ec_queue_max) {
		ec->ec_events_dropped++;
		SDT_PROBE3(esc, , , event__drop,
		    ep->ep_msg.em_event,
		    ep->ep_msg.em_process.ep_pid,
		    ec->ec_id);
		return (ENOSPC);
	}

	esc_pending_hold(ep);
	TAILQ_INSERT_TAIL(&ec->ec_pending, ep, ep_link);
	ec->ec_queue_count++;
	ec->ec_events_received++;

	SDT_PROBE3(esc, , , event__enqueue,
	    ep->ep_msg.em_event,
	    ep->ep_msg.em_process.ep_pid,
	    ec->ec_id);

	selwakeup(&ec->ec_selinfo);
	KNOTE_LOCKED(&ec->ec_selinfo.si_note, 0);
	wakeup(&ec->ec_pending);

	return (0);
}

struct esc_pending *
esc_event_dequeue(struct esc_client *ec)
{
	struct esc_pending *ep;

	EC_LOCK_ASSERT(ec);

	ep = TAILQ_FIRST(&ec->ec_pending);
	if (ep != NULL) {
		TAILQ_REMOVE(&ec->ec_pending, ep, ep_link);
		ec->ec_queue_count--;
		ep->ep_flags |= EP_FLAG_DELIVERED;
		/* Reference transferred to caller */
	}

	return (ep);
}

/*
 * Internal helper: Respond to an AUTH event
 *
 * If has_flags is true, allowed_flags and denied_flags are stored
 * for flags-based partial authorization.
 */
static int
esc_event_respond_internal(struct esc_client *ec, uint64_t msg_id,
    esc_auth_result_t result, uint32_t allowed_flags, uint32_t denied_flags,
    bool has_flags)
{
	struct esc_pending *ep;
	int error = ESRCH;
	bool in_delivered = false;

	EC_LOCK(ec);

	/* Find the pending event by message ID */
	TAILQ_FOREACH(ep, &ec->ec_pending, ep_link) {
		if (ep->ep_msg.em_id == msg_id)
			break;
	}

	/* Also check delivered queue */
	if (ep == NULL) {
		TAILQ_FOREACH(ep, &ec->ec_delivered, ep_link) {
			if (ep->ep_msg.em_id == msg_id) {
				in_delivered = true;
				break;
			}
		}
	}

	if (ep != NULL && (ep->ep_flags & EP_FLAG_AUTH)) {
		mtx_lock(&ep->ep_mtx);

		if (!ep->ep_responded) {
			ep->ep_responded = true;
			ep->ep_result = result;
			if (has_flags) {
				ep->ep_allowed_flags = allowed_flags;
				ep->ep_denied_flags = denied_flags;
			}

			/* Update stats and fire DTrace probes */
			if (result == ESC_AUTH_ALLOW) {
				ec->ec_auth_allowed++;
				SDT_PROBE3(esc, , , auth__allow,
				    ep->ep_msg.em_event,
				    ep->ep_msg.em_process.ep_pid,
				    ep->ep_msg.em_process.ep_path);
			} else {
				ec->ec_auth_denied++;
				SDT_PROBE3(esc, , , auth__deny,
				    ep->ep_msg.em_event,
				    ep->ep_msg.em_process.ep_pid,
				    ep->ep_msg.em_process.ep_path);
			}

			if (ep->ep_group != NULL)
				esc_auth_group_mark_response(ep->ep_group,
				    result);

			cv_broadcast(&ep->ep_cv);
			error = 0;
		} else {
			/* Already responded (timeout or duplicate) */
			error = EALREADY;
		}

		mtx_unlock(&ep->ep_mtx);

		/* Remove from delivered queue and release */
		if (in_delivered && error == 0) {
			TAILQ_REMOVE(&ec->ec_delivered, ep, ep_link);
			esc_pending_rele(ep);
		}
	}

	EC_UNLOCK(ec);

	return (error);
}

int
esc_event_respond(struct esc_client *ec, uint64_t msg_id,
    esc_auth_result_t result)
{

	return (esc_event_respond_internal(ec, msg_id, result, 0, 0, false));
}

/*
 * Respond with flags for partial authorization (e.g., AUTH_OPEN).
 */
int
esc_event_respond_flags(struct esc_client *ec, uint64_t msg_id,
    esc_auth_result_t result, uint32_t allowed_flags, uint32_t denied_flags)
{

	return (esc_event_respond_internal(ec, msg_id, result, allowed_flags,
	    denied_flags, true));
}

void
esc_event_handle_timeout(struct esc_pending *ep)
{
	struct esc_client *ec;
	bool need_rele = false;

	if (ep == NULL || ep->ep_client_id == 0)
		return;

	ESC_LOCK();
	LIST_FOREACH(ec, &esc_softc.sc_clients, ec_link) {
		if (ec->ec_id != ep->ep_client_id)
			continue;

		EC_LOCK(ec);
		ec->ec_auth_timeouts++;

		if (ep->ep_flags & EP_FLAG_DELIVERED) {
			/* Remove from delivered queue */
			struct esc_pending *cur;

			TAILQ_FOREACH(cur, &ec->ec_delivered, ep_link) {
				if (cur == ep) {
					TAILQ_REMOVE(&ec->ec_delivered, ep,
					    ep_link);
					need_rele = true;
					break;
				}
			}
		} else {
			/* Remove from pending queue */
			struct esc_pending *cur;

			TAILQ_FOREACH(cur, &ec->ec_pending, ep_link) {
				if (cur == ep) {
					TAILQ_REMOVE(&ec->ec_pending, ep,
					    ep_link);
					ec->ec_queue_count--;
					need_rele = true;
					break;
				}
			}
		}
		EC_UNLOCK(ec);
		break;
	}
	ESC_UNLOCK();

	if (need_rele)
		esc_pending_rele(ep);
}

