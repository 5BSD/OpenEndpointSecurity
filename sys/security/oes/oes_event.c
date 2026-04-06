/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 * All rights reserved.
 *
 * Open Endpoint Security (OES) - Event Generation and Dispatch
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

#include <security/oes/oes.h>
#include <security/oes/oes_internal.h>

MALLOC_DECLARE(M_ESC);

/*
 * DTrace SDT provider for OES
 *
 * Probes:
 *   oes:::auth-allow(event, pid, path)     - AUTH event allowed
 *   oes:::auth-deny(event, pid, path)      - AUTH event denied
 *   oes:::auth-timeout(event, pid, action) - AUTH event timed out
 *   oes:::event-enqueue(event, pid, client_id) - Event queued for client
 *   oes:::event-drop(event, pid, client_id) - Event dropped (queue full)
 *   oes:::cache-hit(event, pid, result)    - Decision cache hit
 *   oes:::cache-miss(event, pid)           - Decision cache miss
 *
 * Example usage:
 *   dtrace -n 'oes:::auth-deny { printf("%s pid=%d", execname, arg1); }'
 */
SDT_PROVIDER_DEFINE(oes);

SDT_PROBE_DEFINE3(oes, , , auth__allow,
    "oes_event_type_t",		/* event type */
    "pid_t",			/* process ID */
    "const char *");		/* path (if applicable) */

SDT_PROBE_DEFINE3(oes, , , auth__deny,
    "oes_event_type_t",		/* event type */
    "pid_t",			/* process ID */
    "const char *");		/* path (if applicable) */

SDT_PROBE_DEFINE3(oes, , , auth__timeout,
    "oes_event_type_t",		/* event type */
    "pid_t",			/* process ID */
    "oes_auth_result_t");	/* default action taken */

SDT_PROBE_DEFINE3(oes, , , event__enqueue,
    "oes_event_type_t",		/* event type */
    "pid_t",			/* process ID */
    "uint64_t");		/* client ID */

SDT_PROBE_DEFINE3(oes, , , event__drop,
    "oes_event_type_t",		/* event type */
    "pid_t",			/* process ID */
    "uint64_t");		/* client ID */

SDT_PROBE_DEFINE3(oes, , , cache__hit,
    "oes_event_type_t",		/* event type */
    "pid_t",			/* process ID */
    "oes_auth_result_t");	/* cached result */

SDT_PROBE_DEFINE2(oes, , , cache__miss,
    "oes_event_type_t",		/* event type */
    "pid_t");			/* process ID */

struct oes_auth_group {
	struct mtx	ag_mtx;
	struct cv	ag_cv;
	uint32_t	ag_pending;
	bool		ag_denied;
	int		ag_refcount;
};

struct oes_auth_group *
oes_auth_group_alloc(void)
{
	struct oes_auth_group *ag;

	ag = malloc(sizeof(*ag), M_ESC, M_NOWAIT | M_ZERO);
	if (ag == NULL)
		return (NULL);

	mtx_init(&ag->ag_mtx, "oes_auth_group", NULL, MTX_DEF);
	cv_init(&ag->ag_cv, "oes_auth_group");
	ag->ag_refcount = 1;

	return (ag);
}

void
oes_auth_group_hold(struct oes_auth_group *ag)
{

	if (ag == NULL)
		return;
	atomic_add_int(&ag->ag_refcount, 1);
}

void
oes_auth_group_rele(struct oes_auth_group *ag)
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
oes_auth_group_add_pending(struct oes_auth_group *ag)
{

	mtx_lock(&ag->ag_mtx);
	ag->ag_pending++;
	mtx_unlock(&ag->ag_mtx);
}

void
oes_auth_group_cancel_pending(struct oes_auth_group *ag)
{

	mtx_lock(&ag->ag_mtx);
	if (ag->ag_pending > 0)
		ag->ag_pending--;
	cv_broadcast(&ag->ag_cv);
	mtx_unlock(&ag->ag_mtx);
}

void
oes_auth_group_mark_response(struct oes_auth_group *ag,
    oes_auth_result_t result)
{

	mtx_lock(&ag->ag_mtx);
	if (ag->ag_pending > 0)
		ag->ag_pending--;
	if (result == OES_AUTH_DENY)
		ag->ag_denied = true;
	cv_broadcast(&ag->ag_cv);
	mtx_unlock(&ag->ag_mtx);
}

static void
oes_auth_group_update_timeouts(struct oes_auth_group *ag,
    struct oes_pending **eps, size_t count)
{
	struct timespec now;
	size_t i;

	nanouptime(&now);

	for (i = 0; i < count; i++) {
		struct oes_pending *ep = eps[i];
		oes_auth_result_t action;
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

			SDT_PROBE3(oes, , , auth__timeout,
			    ep->ep_msg.em_event,
			    ep->ep_msg.em_process.ep_pid,
			    action);

			oes_auth_group_mark_response(ag, action);
			oes_event_handle_timeout(ep);
			continue;
		}
		mtx_unlock(&ep->ep_mtx);
	}
}

int
oes_auth_group_wait(struct oes_auth_group *ag, struct oes_pending **eps,
    size_t count)
{
	struct timespec next_deadline;
	bool have_deadline;
	size_t i;
	bool denied = false;

	for (;;) {
		oes_auth_group_update_timeouts(ag, eps, count);

		mtx_lock(&ag->ag_mtx);
		if (ag->ag_pending == 0) {
			denied = ag->ag_denied;
			mtx_unlock(&ag->ag_mtx);
			break;
		}
		mtx_unlock(&ag->ag_mtx);

		have_deadline = false;
		for (i = 0; i < count; i++) {
			struct oes_pending *ep = eps[i];
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
oes_set_auth_deadline(struct oes_pending *ep, uint32_t timeout_ms)
{
	struct timespec ts;
	struct timespec deadline;

	if (timeout_ms == 0)
		timeout_ms = OES_DEFAULT_TIMEOUT_MS;

	nanouptime(&deadline);
	ts.tv_sec = timeout_ms / 1000;
	ts.tv_nsec = (timeout_ms % 1000) * 1000000;
	timespecadd(&deadline, &ts, &deadline);

	ep->ep_deadline = deadline;
	ep->ep_msg.em_deadline = deadline;
}

struct oes_pending *
oes_pending_alloc(oes_event_type_t event, struct proc *p)
{
	struct oes_pending *ep;

	ep = malloc(sizeof(*ep), M_ESC, M_NOWAIT | M_ZERO);
	if (ep == NULL)
		return (NULL);

	ep->ep_refcount = 1;
	ep->ep_msg.em_version = OES_MESSAGE_VERSION;

	/* Assign unique message ID */
	ep->ep_msg.em_id = atomic_fetchadd_64(&oes_softc.sc_next_msg_id, 1);

	ep->ep_msg.em_event = event;

	if (OES_EVENT_IS_AUTH(event)) {
		ep->ep_msg.em_action = OES_ACTION_AUTH;
		ep->ep_flags |= EP_FLAG_AUTH;
		mtx_init(&ep->ep_mtx, "oes_pending", NULL, MTX_DEF);
		cv_init(&ep->ep_cv, "oes_auth");
		ep->ep_responded = false;
		ep->ep_result = OES_AUTH_ALLOW;
	} else {
		ep->ep_msg.em_action = OES_ACTION_NOTIFY;
	}

	ep->ep_group = NULL;
	nanouptime(&ep->ep_msg.em_time);

	if (p != NULL) {
		PROC_LOCK(p);
		oes_fill_process(&ep->ep_msg.em_process, p, NULL);
		PROC_UNLOCK(p);
	}

	return (ep);
}

struct oes_pending *
oes_pending_clone(const struct oes_pending *src)
{
	struct oes_pending *ep;

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
		mtx_init(&ep->ep_mtx, "oes_pending", NULL, MTX_DEF);
		cv_init(&ep->ep_cv, "oes_auth");
		ep->ep_responded = false;
		ep->ep_result = OES_AUTH_ALLOW;
	}

	return (ep);
}

void
oes_pending_free(struct oes_pending *ep)
{

	if (ep->ep_flags & EP_FLAG_AUTH) {
		cv_destroy(&ep->ep_cv);
		mtx_destroy(&ep->ep_mtx);
	}

	if (ep->ep_group != NULL)
		oes_auth_group_rele(ep->ep_group);

	free(ep, M_ESC);
}

void
oes_pending_hold(struct oes_pending *ep)
{

	atomic_add_int(&ep->ep_refcount, 1);
}

void
oes_pending_rele(struct oes_pending *ep)
{

	if (atomic_fetchadd_int(&ep->ep_refcount, -1) == 1)
		oes_pending_free(ep);
}

int
oes_event_enqueue(struct oes_client *ec, struct oes_pending *ep)
{

	EC_LOCK_ASSERT(ec);

	if (ec->ec_queue_count >= ec->ec_queue_max) {
		ec->ec_events_dropped++;
		SDT_PROBE3(oes, , , event__drop,
		    ep->ep_msg.em_event,
		    ep->ep_msg.em_process.ep_pid,
		    ec->ec_id);
		return (ENOSPC);
	}

	oes_pending_hold(ep);
	TAILQ_INSERT_TAIL(&ec->ec_pending, ep, ep_link);
	ec->ec_queue_count++;
	ec->ec_events_received++;

	SDT_PROBE3(oes, , , event__enqueue,
	    ep->ep_msg.em_event,
	    ep->ep_msg.em_process.ep_pid,
	    ec->ec_id);

	selwakeup(&ec->ec_selinfo);
	KNOTE_LOCKED(&ec->ec_selinfo.si_note, 0);
	wakeup(&ec->ec_pending);

	return (0);
}

struct oes_pending *
oes_event_dequeue(struct oes_client *ec)
{
	struct oes_pending *ep;

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
oes_event_respond_internal(struct oes_client *ec, uint64_t msg_id,
    oes_auth_result_t result, uint32_t allowed_flags, uint32_t denied_flags,
    bool has_flags)
{
	struct oes_pending *ep;
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
			if (result == OES_AUTH_ALLOW) {
				ec->ec_auth_allowed++;
				SDT_PROBE3(oes, , , auth__allow,
				    ep->ep_msg.em_event,
				    ep->ep_msg.em_process.ep_pid,
				    ep->ep_msg.em_process.ep_path);
			} else {
				ec->ec_auth_denied++;
				SDT_PROBE3(oes, , , auth__deny,
				    ep->ep_msg.em_event,
				    ep->ep_msg.em_process.ep_pid,
				    ep->ep_msg.em_process.ep_path);
			}

			if (ep->ep_group != NULL)
				oes_auth_group_mark_response(ep->ep_group,
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
			oes_pending_rele(ep);
		}
	}

	EC_UNLOCK(ec);

	return (error);
}

int
oes_event_respond(struct oes_client *ec, uint64_t msg_id,
    oes_auth_result_t result)
{

	return (oes_event_respond_internal(ec, msg_id, result, 0, 0, false));
}

/*
 * Respond with flags for partial authorization (e.g., AUTH_OPEN).
 */
int
oes_event_respond_flags(struct oes_client *ec, uint64_t msg_id,
    oes_auth_result_t result, uint32_t allowed_flags, uint32_t denied_flags)
{

	return (oes_event_respond_internal(ec, msg_id, result, allowed_flags,
	    denied_flags, true));
}

void
oes_event_handle_timeout(struct oes_pending *ep)
{
	struct oes_client *ec;
	bool need_rele = false;

	if (ep == NULL || ep->ep_client_id == 0)
		return;

	OES_LOCK();
	LIST_FOREACH(ec, &oes_softc.sc_clients, ec_link) {
		if (ec->ec_id != ep->ep_client_id)
			continue;

		EC_LOCK(ec);
		ec->ec_auth_timeouts++;

		if (ep->ep_flags & EP_FLAG_DELIVERED) {
			/* Remove from delivered queue */
			struct oes_pending *cur;

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
			struct oes_pending *cur;

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
	OES_UNLOCK();

	if (need_rele)
		oes_pending_rele(ep);
}

