/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 * All rights reserved.
 *
 * Endpoint Security Capabilities (esc) - Character Device
 *
 * This file implements /dev/esc, the userspace interface to the
 * endpoint security framework.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/fcntl.h>
#include <sys/filio.h>
#include <sys/resourcevar.h>
#include <sys/poll.h>
#include <sys/selinfo.h>
#include <sys/capsicum.h>
#include <sys/priv.h>
#include <sys/sysctl.h>

#include <security/esc/esc.h>
#include <security/esc/esc_internal.h>

MALLOC_DEFINE(M_ESC, "esc", "Endpoint Security Capabilities");

/*
 * Global state
 */
struct esc_softc esc_softc;

/*
 * Sysctl variables
 */
SYSCTL_NODE(_security, OID_AUTO, esc, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "Endpoint Security Capabilities");

int esc_debug = 0;
SYSCTL_INT(_security_esc, OID_AUTO, debug, CTLFLAG_RW,
    &esc_debug, 0, "Enable debug output");

int esc_default_timeout = ESC_DEFAULT_TIMEOUT_MS;
SYSCTL_INT(_security_esc, OID_AUTO, default_timeout, CTLFLAG_RW,
    &esc_default_timeout, 0, "Default AUTH timeout in milliseconds");

int esc_default_action = ESC_AUTH_ALLOW;
SYSCTL_INT(_security_esc, OID_AUTO, default_action, CTLFLAG_RW,
    &esc_default_action, 0, "Default AUTH timeout action (0=allow, 1=deny)");

int esc_default_queue_size = ESC_DEFAULT_QUEUE_SIZE;
SYSCTL_INT(_security_esc, OID_AUTO, default_queue_size, CTLFLAG_RW,
    &esc_default_queue_size, 0, "Default event queue size per client");

int esc_max_clients = 64;
SYSCTL_INT(_security_esc, OID_AUTO, max_clients, CTLFLAG_RW,
    &esc_max_clients, 0, "Maximum number of concurrent clients");

int esc_cache_max_entries = 1024;
SYSCTL_INT(_security_esc, OID_AUTO, cache_max_entries, CTLFLAG_RW,
    &esc_cache_max_entries, 0, "Maximum decision cache entries per client");

/*
 * Default muting configuration
 *
 * These sysctls define paths that are automatically muted for new clients.
 * Paths are colon-separated (e.g., "/var/log:/tmp:/dev").
 * Applied when client calls ESC_IOC_SET_MODE.
 */
char esc_default_muted_paths[1024] = "";
SYSCTL_STRING(_security_esc, OID_AUTO, default_muted_paths, CTLFLAG_RW,
    esc_default_muted_paths, sizeof(esc_default_muted_paths),
    "Colon-separated paths to mute by default (prefix match)");

char esc_default_muted_paths_literal[1024] = "";
SYSCTL_STRING(_security_esc, OID_AUTO, default_muted_paths_literal, CTLFLAG_RW,
    esc_default_muted_paths_literal, sizeof(esc_default_muted_paths_literal),
    "Colon-separated paths to mute by default (literal match)");

int esc_default_self_mute = 1;
SYSCTL_INT(_security_esc, OID_AUTO, default_self_mute, CTLFLAG_RW,
    &esc_default_self_mute, 0, "Automatically self-mute new clients (1=yes)");

/*
 * Device operations
 */
static d_open_t		esc_open;
static d_close_t	esc_close;
static d_read_t		esc_read;
static d_write_t	esc_write;
static d_ioctl_t	esc_ioctl;
static d_poll_t		esc_poll;
static d_kqfilter_t	esc_kqfilter;

static int	esc_ioctl_subscribe(struct esc_client *ec,
		    struct esc_subscribe_args *args);
static int	esc_ioctl_subscribe_bitmap(struct esc_client *ec,
		    struct esc_subscribe_bitmap_args *args);
static int	esc_ioctl_subscribe_bitmap_ex(struct esc_client *ec,
		    struct esc_subscribe_bitmap_ex_args *args);
static int	esc_ioctl_set_mode(struct esc_client *ec,
		    struct esc_mode_args *args);
static int	esc_ioctl_get_mode(struct esc_client *ec,
		    struct esc_mode_args *args);
static int	esc_ioctl_set_timeout(struct esc_client *ec,
		    struct esc_timeout_args *args);
static int	esc_ioctl_get_timeout(struct esc_client *ec,
		    struct esc_timeout_args *args);
static int	esc_ioctl_mute_process(struct esc_client *ec,
		    struct esc_mute_args *args);
static int	esc_ioctl_unmute_process(struct esc_client *ec,
		    struct esc_mute_args *args);
static int	esc_ioctl_mute_path(struct esc_client *ec,
		    struct esc_mute_path_args *args);
static int	esc_ioctl_unmute_path(struct esc_client *ec,
		    struct esc_mute_path_args *args);
static int	esc_ioctl_set_mute_invert(struct esc_client *ec,
		    struct esc_mute_invert_args *args);
static int	esc_ioctl_get_mute_invert(struct esc_client *ec,
		    struct esc_mute_invert_args *args);
static int	esc_ioctl_set_timeout_action(struct esc_client *ec,
		    struct esc_timeout_action_args *args);
static int	esc_ioctl_get_timeout_action(struct esc_client *ec,
		    struct esc_timeout_action_args *args);
static int	esc_ioctl_cache_add(struct esc_client *ec,
		    esc_cache_entry_t *entry);
static int	esc_ioctl_cache_remove(struct esc_client *ec,
		    esc_cache_key_t *key);
static int	esc_ioctl_cache_clear(struct esc_client *ec);
static int	esc_ioctl_get_stats(struct esc_client *ec,
		    struct esc_stats *stats);
static int	esc_ioctl_mute_process_events(struct esc_client *ec,
		    struct esc_mute_process_events_args *args);
static int	esc_ioctl_unmute_process_events(struct esc_client *ec,
		    struct esc_mute_process_events_args *args);
static int	esc_ioctl_mute_path_events(struct esc_client *ec,
		    struct esc_mute_path_events_args *args);
static int	esc_ioctl_unmute_path_events(struct esc_client *ec,
		    struct esc_mute_path_events_args *args);
static int	esc_ioctl_get_muted_processes(struct esc_client *ec,
		    struct esc_get_muted_processes_args *args);
static int	esc_ioctl_get_muted_paths(struct esc_client *ec,
		    struct esc_get_muted_paths_args *args);
static int	esc_ioctl_unmute_all_processes(struct esc_client *ec);
static int	esc_ioctl_unmute_all_paths(struct esc_client *ec, bool target);

/* Forward declaration for cdevpriv dtor */
void	esc_client_dtor(void *data);

static struct cdevsw esc_cdevsw = {
	.d_version =	D_VERSION,
	.d_open =	esc_open,
	.d_close =	esc_close,
	.d_read =	esc_read,
	.d_write =	esc_write,
	.d_ioctl =	esc_ioctl,
	.d_poll =	esc_poll,
	.d_kqfilter =	esc_kqfilter,
	.d_name =	"esc",
};

/*
 * Kqueue filter operations
 */
static void	esc_kqdetach(struct knote *kn);
static int	esc_kqread(struct knote *kn, long hint);

static struct filterops esc_rfiltops = {
	.f_isfd =	1,
	.f_detach =	esc_kqdetach,
	.f_event =	esc_kqread,
};

/*
 * esc_open - Create new client on each open()
 *
 * Each open() creates an independent client with its own subscriptions,
 * event queue, and configuration.
 */
static int
esc_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
	struct esc_client *ec;
	int error;

	(void)dev;
	(void)oflags;
	(void)devtype;

	/* Check privilege to open the device */
	error = priv_check(td, PRIV_DRIVER);
	if (error)
		return (error);

	/* Reject opens during module unload */
	ESC_LOCK();
	if (!esc_softc.sc_active) {
		ESC_UNLOCK();
		return (ENXIO);
	}

	/* Enforce max clients */
	if (esc_softc.sc_nclients >= esc_max_clients) {
		ESC_UNLOCK();
		return (EAGAIN);
	}
	esc_softc.sc_nclients++;
	ESC_UNLOCK();

	/* Allocate client state */
	ec = esc_client_alloc();
	if (ec == NULL) {
		ESC_LOCK();
		esc_softc.sc_nclients--;
		ESC_UNLOCK();
		return (ENOMEM);
	}

	ESC_LOCK();
	ec->ec_id = esc_softc.sc_next_client_id++;
	ESC_UNLOCK();

	/* Record owner identity for self-mute */
	PROC_LOCK(td->td_proc);
	ec->ec_owner_pid = td->td_proc->p_pid;
	if (td->td_proc->p_stats != NULL) {
		/* Must match esc_proc_genid() formula: sec*1000000 + usec */
		ec->ec_owner_genid =
		    (uint64_t)td->td_proc->p_stats->p_start.tv_sec * 1000000ULL +
		    (uint64_t)td->td_proc->p_stats->p_start.tv_usec;
	}
	PROC_UNLOCK(td->td_proc);

	/* Store client in cdevpriv for later retrieval */
	error = devfs_set_cdevpriv(ec, esc_client_dtor);
	if (error) {
		esc_client_free(ec);
		ESC_LOCK();
		esc_softc.sc_nclients--;
		ESC_UNLOCK();
		return (error);
	}

	/* Add to global client list */
	ESC_LOCK();
	LIST_INSERT_HEAD(&esc_softc.sc_clients, ec, ec_link);
	ESC_UNLOCK();

	ESC_DEBUG("client %p opened by pid %d", ec, td->td_proc->p_pid);

	return (0);
}

/*
 * esc_client_dtor - Called when file descriptor is closed
 */
void
esc_client_dtor(void *data)
{
	struct esc_client *ec = data;

	if (ec == NULL)
		return;

	ESC_DEBUG("client %p closing", ec);

	/* Mark as closing to reject new events */
	EC_LOCK(ec);
	ec->ec_flags |= EC_FLAG_CLOSING;
	EC_UNLOCK(ec);

	/* Remove from global list */
	ESC_LOCK();
	LIST_REMOVE(ec, ec_link);
	esc_softc.sc_nclients--;
	ESC_UNLOCK();

	/* Wake any waiters and clean up */
	esc_client_free(ec);
}

/*
 * esc_close - Close handler (actual cleanup in dtor)
 */
static int
esc_close(struct cdev *dev, int fflag, int devtype, struct thread *td)
{
	/* Cleanup happens in esc_client_dtor via devfs_clear_cdevpriv */
	return (0);
}

/*
 * esc_read - Read events from client queue
 *
 * Returns one esc_message_t per read. Blocks if queue is empty
 * (unless O_NONBLOCK).
 */
static int
esc_read(struct cdev *dev, struct uio *uio, int ioflag)
{
	struct esc_client *ec;
	struct esc_pending *ep;
	int error;

	error = devfs_get_cdevpriv((void **)&ec);
	if (error)
		return (error);

	/* Must read exactly one message */
	if (uio->uio_resid < sizeof(esc_message_t))
		return (EINVAL);

	EC_LOCK(ec);

	/* Wait for events if queue is empty */
	while (TAILQ_EMPTY(&ec->ec_pending)) {
		if (ec->ec_flags & EC_FLAG_CLOSING) {
			EC_UNLOCK(ec);
			return (ENXIO);
		}
		if (ioflag & O_NONBLOCK) {
			EC_UNLOCK(ec);
			return (EAGAIN);
		}
		error = msleep(&ec->ec_pending, &ec->ec_mtx, PCATCH,
		    "escrd", 0);
		if (error) {
			EC_UNLOCK(ec);
			return (error);
		}
	}

	/* Dequeue events, skipping expired AUTH events */
	for (;;) {
		ep = esc_event_dequeue(ec);
		KASSERT(ep != NULL, ("esc_read: dequeue returned NULL"));

		if (ESC_EVENT_IS_AUTH(ep->ep_msg.em_event) &&
		    (ep->ep_flags & EP_FLAG_EXPIRED)) {
			/* Skip expired AUTH event, release it */
			EC_UNLOCK(ec);
			esc_pending_rele(ep);
			EC_LOCK(ec);

			/* Check if more events available */
			if (TAILQ_EMPTY(&ec->ec_pending)) {
				if (ec->ec_flags & EC_FLAG_CLOSING) {
					EC_UNLOCK(ec);
					return (ENXIO);
				}
				if (ioflag & O_NONBLOCK) {
					EC_UNLOCK(ec);
					return (EAGAIN);
				}
				error = msleep(&ec->ec_pending, &ec->ec_mtx,
				    PCATCH, "escrd", 0);
				if (error) {
					EC_UNLOCK(ec);
					return (error);
				}
			}
			continue;
		}
		break;
	}

	/*
	 * Add AUTH events to delivered queue for response flow.
	 * NOTIFY events are released immediately after read.
	 */
	if (ESC_EVENT_IS_AUTH(ep->ep_msg.em_event)) {
		TAILQ_INSERT_TAIL(&ec->ec_delivered, ep, ep_link);
	}

	EC_UNLOCK(ec);

	/* Copy message to userspace */
	error = uiomove(&ep->ep_msg, sizeof(esc_message_t), uio);

	/*
	 * Handle copyout failure for AUTH events.
	 * If the event was added to the delivered queue but userspace
	 * never received it, we must requeue it for retry.
	 */
	if (error != 0 && ESC_EVENT_IS_AUTH(ep->ep_msg.em_event)) {
		EC_LOCK(ec);
		TAILQ_REMOVE(&ec->ec_delivered, ep, ep_link);
		ep->ep_flags &= ~EP_FLAG_DELIVERED;
		TAILQ_INSERT_HEAD(&ec->ec_pending, ep, ep_link);
		ec->ec_queue_count++;
		/* Wake up poll/select/kqueue waiters and sleepers */
		selwakeup(&ec->ec_selinfo);
		KNOTE_LOCKED(&ec->ec_selinfo.si_note, 0);
		wakeup(&ec->ec_pending);
		EC_UNLOCK(ec);
		return (error);
	}

	/* Release NOTIFY events (AUTH events stay in delivered queue) */
	if (!ESC_EVENT_IS_AUTH(ep->ep_msg.em_event)) {
		esc_pending_rele(ep);
	}

	return (error);
}

/*
 * esc_write - Write AUTH responses
 *
 * Clients write responses to AUTH events. Two formats are supported:
 * - esc_response_t: Basic allow/deny response
 * - esc_response_flags_t: Response with flags for partial authorization
 *
 * The write size determines which format is used.
 */
static int
esc_write(struct cdev *dev, struct uio *uio, int ioflag)
{
	struct esc_client *ec;
	int error;

	error = devfs_get_cdevpriv((void **)&ec);
	if (error)
		return (error);

	if (uio->uio_resid == sizeof(esc_response_t)) {
		/* Basic response */
		esc_response_t resp;

		error = uiomove(&resp, sizeof(resp), uio);
		if (error)
			return (error);

		/* Validate response */
		if (resp.er_result != ESC_AUTH_ALLOW &&
		    resp.er_result != ESC_AUTH_DENY)
			return (EINVAL);

		error = esc_event_respond(ec, resp.er_id, resp.er_result);

	} else if (uio->uio_resid == sizeof(esc_response_flags_t)) {
		/* Flags-based response */
		esc_response_flags_t resp;

		error = uiomove(&resp, sizeof(resp), uio);
		if (error)
			return (error);

		/* Validate response */
		if (resp.erf_result != ESC_AUTH_ALLOW &&
		    resp.erf_result != ESC_AUTH_DENY)
			return (EINVAL);

		error = esc_event_respond_flags(ec, resp.erf_id,
		    resp.erf_result, resp.erf_allowed_flags,
		    resp.erf_denied_flags);

	} else {
		/* Invalid size */
		return (EINVAL);
	}

	return (error);
}

static int
esc_ioctl_subscribe(struct esc_client *ec, struct esc_subscribe_args *args)
{
	esc_event_type_t *events;
	size_t count;
	int error;

	if (args == NULL)
		return (EINVAL);

	count = args->esa_count;
	if (count == 0 || count > 64)
		return (EINVAL);

	events = malloc(count * sizeof(*events), M_ESC, M_WAITOK);
	error = copyin(args->esa_events, events, count * sizeof(*events));
	if (error) {
		free(events, M_ESC);
		return (error);
	}

	error = esc_client_subscribe_events(ec, events, count, args->esa_flags);
	free(events, M_ESC);
	return (error);
}

static int
esc_ioctl_subscribe_bitmap(struct esc_client *ec,
    struct esc_subscribe_bitmap_args *args)
{
	if (args == NULL)
		return (EINVAL);

	return (esc_client_subscribe_bitmap(ec, args->esba_auth,
	    args->esba_notify, args->esba_flags));
}

static int
esc_ioctl_subscribe_bitmap_ex(struct esc_client *ec,
    struct esc_subscribe_bitmap_ex_args *args)
{
	if (args == NULL)
		return (EINVAL);

	return (esc_client_subscribe_bitmap_ex(ec, args->esba_auth,
	    args->esba_notify, args->esba_flags));
}

static int
esc_ioctl_set_mode(struct esc_client *ec, struct esc_mode_args *args)
{

	if (args == NULL)
		return (EINVAL);

	/*
	 * Access to this ioctl is controlled via cap_ioctls_limit().
	 * Third-party clients won't have this ioctl in their allowed set.
	 */
	return (esc_client_set_mode(ec, args->ema_mode,
	    args->ema_timeout_ms, args->ema_queue_size));
}

static int
esc_ioctl_get_mode(struct esc_client *ec, struct esc_mode_args *args)
{

	if (args == NULL)
		return (EINVAL);

	esc_client_get_mode(ec, &args->ema_mode, &args->ema_timeout_ms,
	    &args->ema_queue_size);
	args->ema_flags = 0;
	return (0);
}

static int
esc_ioctl_set_timeout(struct esc_client *ec, struct esc_timeout_args *args)
{

	if (args == NULL)
		return (EINVAL);

	return (esc_client_set_timeout(ec, args->eta_timeout_ms));
}

static int
esc_ioctl_get_timeout(struct esc_client *ec, struct esc_timeout_args *args)
{

	if (args == NULL)
		return (EINVAL);

	esc_client_get_timeout(ec, &args->eta_timeout_ms);
	return (0);
}

static int
esc_ioctl_mute_process(struct esc_client *ec, struct esc_mute_args *args)
{

	if (args == NULL)
		return (EINVAL);

	return (esc_client_mute(ec, &args->emu_token, args->emu_flags));
}

static int
esc_ioctl_unmute_process(struct esc_client *ec, struct esc_mute_args *args)
{
	struct esc_mute_entry *em, *em_tmp;
	pid_t mypid;

	if (args == NULL)
		return (EINVAL);

	/* Self-unmute: clear the self-mute flag AND remove list entry */
	if (args->emu_flags & ESC_MUTE_SELF) {
		/*
		 * Use ec_owner_pid, not curproc->p_pid, because the fd may
		 * have been passed to another process.  Self-mute is about
		 * the original opener, not the current caller.
		 */
		EC_LOCK(ec);
		mypid = ec->ec_owner_pid;
		ec->ec_flags &= ~EC_FLAG_MUTED_SELF;

		/* Also remove the list entry for self */
		LIST_FOREACH_SAFE(em, &ec->ec_muted[esc_mute_proc_bucket(mypid)],
		    em_link, em_tmp) {
			if (em->em_pid == mypid) {
				LIST_REMOVE(em, em_link);
				free(em, M_ESC);
				ec->ec_muted_proc_count--;
				break;
			}
		}

		EC_UNLOCK(ec);
		return (0);
	}

	return (esc_client_unmute(ec, &args->emu_token));
}

static int
esc_ioctl_mute_path(struct esc_client *ec, struct esc_mute_path_args *args)
{
	bool target;

	if (args == NULL)
		return (EINVAL);

	target = (args->emp_flags & ESC_MUTE_PATH_FLAG_TARGET) != 0;
	return (esc_client_mute_path(ec, args->emp_path, args->emp_type,
	    target));
}

static int
esc_ioctl_unmute_path(struct esc_client *ec, struct esc_mute_path_args *args)
{
	bool target;

	if (args == NULL)
		return (EINVAL);

	target = (args->emp_flags & ESC_MUTE_PATH_FLAG_TARGET) != 0;
	return (esc_client_unmute_path(ec, args->emp_path, args->emp_type,
	    target));
}

static int
esc_ioctl_set_mute_invert(struct esc_client *ec,
    struct esc_mute_invert_args *args)
{

	if (args == NULL)
		return (EINVAL);

	return (esc_client_set_mute_invert(ec, args->emi_type,
	    args->emi_invert != 0));
}

static int
esc_ioctl_get_mute_invert(struct esc_client *ec,
    struct esc_mute_invert_args *args)
{

	if (args == NULL)
		return (EINVAL);

	return (esc_client_get_mute_invert(ec, args->emi_type,
	    &args->emi_invert));
}

static int
esc_ioctl_set_timeout_action(struct esc_client *ec,
    struct esc_timeout_action_args *args)
{

	if (args == NULL)
		return (EINVAL);

	return (esc_client_set_timeout_action(ec, args->eta_action));
}

static int
esc_ioctl_get_timeout_action(struct esc_client *ec,
    struct esc_timeout_action_args *args)
{

	if (args == NULL)
		return (EINVAL);

	return (esc_client_get_timeout_action(ec, &args->eta_action));
}

static int
esc_ioctl_cache_add(struct esc_client *ec, esc_cache_entry_t *entry)
{

	if (entry == NULL)
		return (EINVAL);

	return (esc_client_cache_add(ec, entry));
}

static int
esc_ioctl_cache_remove(struct esc_client *ec, esc_cache_key_t *key)
{

	if (key == NULL)
		return (EINVAL);

	return (esc_client_cache_remove(ec, key));
}

static int
esc_ioctl_cache_clear(struct esc_client *ec)
{

	esc_client_cache_clear(ec);
	return (0);
}

static int
esc_ioctl_get_stats(struct esc_client *ec, struct esc_stats *stats)
{

	esc_client_get_stats(ec, stats);
	return (0);
}

static int
esc_ioctl_mute_process_events(struct esc_client *ec,
    struct esc_mute_process_events_args *args)
{

	if (args == NULL)
		return (EINVAL);

	if (args->empe_count > ESC_MAX_MUTE_EVENTS)
		return (EINVAL);

	return (esc_client_mute_events(ec, &args->empe_token, args->empe_flags,
	    args->empe_events, args->empe_count));
}

static int
esc_ioctl_unmute_process_events(struct esc_client *ec,
    struct esc_mute_process_events_args *args)
{

	if (args == NULL)
		return (EINVAL);

	if (args->empe_count > ESC_MAX_MUTE_EVENTS)
		return (EINVAL);

	return (esc_client_unmute_events(ec, &args->empe_token, args->empe_flags,
	    args->empe_events, args->empe_count));
}

static int
esc_ioctl_mute_path_events(struct esc_client *ec,
    struct esc_mute_path_events_args *args)
{
	bool target;

	if (args == NULL)
		return (EINVAL);

	if (args->empae_count > ESC_MAX_MUTE_EVENTS)
		return (EINVAL);

	target = (args->empae_flags & ESC_MUTE_PATH_FLAG_TARGET) != 0;
	return (esc_client_mute_path_events(ec, args->empae_path,
	    args->empae_type, target, args->empae_events, args->empae_count));
}

static int
esc_ioctl_unmute_path_events(struct esc_client *ec,
    struct esc_mute_path_events_args *args)
{
	bool target;

	if (args == NULL)
		return (EINVAL);

	if (args->empae_count > ESC_MAX_MUTE_EVENTS)
		return (EINVAL);

	target = (args->empae_flags & ESC_MUTE_PATH_FLAG_TARGET) != 0;
	return (esc_client_unmute_path_events(ec, args->empae_path,
	    args->empae_type, target, args->empae_events, args->empae_count));
}

static int
esc_ioctl_get_muted_processes(struct esc_client *ec,
    struct esc_get_muted_processes_args *args)
{
	struct esc_muted_process_entry *kbuf = NULL;
	size_t count, actual;
	int error;

	if (args == NULL)
		return (EINVAL);

	count = args->egmp_count;
	if (count > ESC_MAX_MUTED_ENTRIES)
		count = ESC_MAX_MUTED_ENTRIES;

	/* Allocate kernel buffer for results */
	if (count > 0 && args->egmp_entries != NULL)
		kbuf = malloc(count * sizeof(*kbuf), M_ESC, M_WAITOK | M_ZERO);

	/* Fill kernel buffer */
	error = esc_client_get_muted_processes(ec, kbuf, count, &actual);
	if (error != 0) {
		if (kbuf != NULL)
			free(kbuf, M_ESC);
		return (error);
	}

	/* Copy results to userspace */
	if (kbuf != NULL && actual > 0) {
		size_t tocopy = (actual < count) ? actual : count;
		error = copyout(kbuf, args->egmp_entries,
		    tocopy * sizeof(*kbuf));
	}

	if (kbuf != NULL)
		free(kbuf, M_ESC);

	args->egmp_actual = actual;
	return (error);
}

static int
esc_ioctl_get_muted_paths(struct esc_client *ec,
    struct esc_get_muted_paths_args *args)
{
	struct esc_muted_path_entry *kbuf = NULL;
	size_t count, actual;
	bool target;
	int error;

	if (args == NULL)
		return (EINVAL);

	target = (args->egmpa_flags & ESC_MUTE_PATH_FLAG_TARGET) != 0;
	count = args->egmpa_count;
	if (count > ESC_MAX_MUTED_ENTRIES)
		count = ESC_MAX_MUTED_ENTRIES;

	/* Allocate kernel buffer for results */
	if (count > 0 && args->egmpa_entries != NULL)
		kbuf = malloc(count * sizeof(*kbuf), M_ESC, M_WAITOK | M_ZERO);

	/* Fill kernel buffer */
	error = esc_client_get_muted_paths(ec, kbuf, count, &actual, target);
	if (error != 0) {
		if (kbuf != NULL)
			free(kbuf, M_ESC);
		return (error);
	}

	/* Copy results to userspace */
	if (kbuf != NULL && actual > 0) {
		size_t tocopy = (actual < count) ? actual : count;
		error = copyout(kbuf, args->egmpa_entries,
		    tocopy * sizeof(*kbuf));
	}

	if (kbuf != NULL)
		free(kbuf, M_ESC);

	args->egmpa_actual = actual;
	return (error);
}

static int
esc_ioctl_unmute_all_processes(struct esc_client *ec)
{

	esc_client_unmute_all_processes(ec);
	return (0);
}

static int
esc_ioctl_unmute_all_paths(struct esc_client *ec, bool target)
{

	esc_client_unmute_all_paths(ec, target);
	return (0);
}

/*
 * esc_ioctl - Handle control operations
 */
static int
esc_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag,
    struct thread *td)
{
	struct esc_client *ec;
	int error;

	error = devfs_get_cdevpriv((void **)&ec);
	if (error)
		return (error);

	switch (cmd) {
	case ESC_IOC_SUBSCRIBE: {
		return (esc_ioctl_subscribe(ec,
		    (struct esc_subscribe_args *)data));
	}

	case ESC_IOC_SUBSCRIBE_BITMAP: {
		return (esc_ioctl_subscribe_bitmap(ec,
		    (struct esc_subscribe_bitmap_args *)data));
	}

	case ESC_IOC_SUBSCRIBE_BITMAP_EX: {
		return (esc_ioctl_subscribe_bitmap_ex(ec,
		    (struct esc_subscribe_bitmap_ex_args *)data));
	}

	case ESC_IOC_SET_MODE: {
		return (esc_ioctl_set_mode(ec, (struct esc_mode_args *)data));
	}

	case ESC_IOC_GET_MODE: {
		return (esc_ioctl_get_mode(ec, (struct esc_mode_args *)data));
	}

	case ESC_IOC_SET_TIMEOUT: {
		return (esc_ioctl_set_timeout(ec,
		    (struct esc_timeout_args *)data));
	}

	case ESC_IOC_GET_TIMEOUT: {
		return (esc_ioctl_get_timeout(ec,
		    (struct esc_timeout_args *)data));
	}

	case ESC_IOC_MUTE_PROCESS: {
		return (esc_ioctl_mute_process(ec, (struct esc_mute_args *)data));
	}

	case ESC_IOC_UNMUTE_PROCESS: {
		return (esc_ioctl_unmute_process(ec, (struct esc_mute_args *)data));
	}

	case ESC_IOC_MUTE_PATH: {
		return (esc_ioctl_mute_path(ec,
		    (struct esc_mute_path_args *)data));
	}

	case ESC_IOC_UNMUTE_PATH: {
		return (esc_ioctl_unmute_path(ec,
		    (struct esc_mute_path_args *)data));
	}

	case ESC_IOC_SET_MUTE_INVERT: {
		return (esc_ioctl_set_mute_invert(ec,
		    (struct esc_mute_invert_args *)data));
	}

	case ESC_IOC_GET_MUTE_INVERT: {
		return (esc_ioctl_get_mute_invert(ec,
		    (struct esc_mute_invert_args *)data));
	}

	case ESC_IOC_SET_TIMEOUT_ACTION: {
		return (esc_ioctl_set_timeout_action(ec,
		    (struct esc_timeout_action_args *)data));
	}

	case ESC_IOC_GET_TIMEOUT_ACTION: {
		return (esc_ioctl_get_timeout_action(ec,
		    (struct esc_timeout_action_args *)data));
	}

	case ESC_IOC_CACHE_ADD: {
		return (esc_ioctl_cache_add(ec, (esc_cache_entry_t *)data));
	}

	case ESC_IOC_CACHE_REMOVE: {
		return (esc_ioctl_cache_remove(ec, (esc_cache_key_t *)data));
	}

	case ESC_IOC_CACHE_CLEAR:
		return (esc_ioctl_cache_clear(ec));

	case ESC_IOC_GET_STATS: {
		return (esc_ioctl_get_stats(ec, (struct esc_stats *)data));
	}

	case ESC_IOC_MUTE_PROCESS_EVENTS: {
		return (esc_ioctl_mute_process_events(ec,
		    (struct esc_mute_process_events_args *)data));
	}

	case ESC_IOC_UNMUTE_PROCESS_EVENTS: {
		return (esc_ioctl_unmute_process_events(ec,
		    (struct esc_mute_process_events_args *)data));
	}

	case ESC_IOC_MUTE_PATH_EVENTS: {
		return (esc_ioctl_mute_path_events(ec,
		    (struct esc_mute_path_events_args *)data));
	}

	case ESC_IOC_UNMUTE_PATH_EVENTS: {
		return (esc_ioctl_unmute_path_events(ec,
		    (struct esc_mute_path_events_args *)data));
	}

	case ESC_IOC_GET_MUTED_PROCESSES: {
		return (esc_ioctl_get_muted_processes(ec,
		    (struct esc_get_muted_processes_args *)data));
	}

	case ESC_IOC_GET_MUTED_PATHS: {
		return (esc_ioctl_get_muted_paths(ec,
		    (struct esc_get_muted_paths_args *)data));
	}

	case ESC_IOC_UNMUTE_ALL_PROCESSES:
		return (esc_ioctl_unmute_all_processes(ec));

	case ESC_IOC_UNMUTE_ALL_PATHS:
		return (esc_ioctl_unmute_all_paths(ec, false));

	case ESC_IOC_UNMUTE_ALL_TARGET_PATHS:
		return (esc_ioctl_unmute_all_paths(ec, true));

	case ESC_IOC_MUTE_UID: {
		struct esc_mute_uid_args *args =
		    (struct esc_mute_uid_args *)data;
		return (esc_client_mute_uid(ec, args->emu_uid));
	}

	case ESC_IOC_UNMUTE_UID: {
		struct esc_mute_uid_args *args =
		    (struct esc_mute_uid_args *)data;
		return (esc_client_unmute_uid(ec, args->emu_uid));
	}

	case ESC_IOC_MUTE_GID: {
		struct esc_mute_gid_args *args =
		    (struct esc_mute_gid_args *)data;
		return (esc_client_mute_gid(ec, args->emg_gid));
	}

	case ESC_IOC_UNMUTE_GID: {
		struct esc_mute_gid_args *args =
		    (struct esc_mute_gid_args *)data;
		return (esc_client_unmute_gid(ec, args->emg_gid));
	}

	case ESC_IOC_UNMUTE_ALL_UIDS:
		esc_client_unmute_all_uids(ec);
		return (0);

	case ESC_IOC_UNMUTE_ALL_GIDS:
		esc_client_unmute_all_gids(ec);
		return (0);

	case FIONBIO:
	case FIOASYNC:
		/* Handled by upper layers */
		return (0);

	case FIONREAD: {
		int *nread = (int *)data;

		EC_LOCK(ec);
		*nread = ec->ec_queue_count * sizeof(esc_message_t);
		EC_UNLOCK(ec);
		return (0);
	}

	default:
		return (ENOTTY);
	}
}

/*
 * esc_poll - Poll for events
 */
static int
esc_poll(struct cdev *dev, int events, struct thread *td)
{
	struct esc_client *ec;
	int revents = 0;
	int error;

	error = devfs_get_cdevpriv((void **)&ec);
	if (error)
		return (POLLNVAL);

	EC_LOCK(ec);

	if (events & (POLLIN | POLLRDNORM)) {
		if (!TAILQ_EMPTY(&ec->ec_pending))
			revents |= events & (POLLIN | POLLRDNORM);
		else
			selrecord(td, &ec->ec_selinfo);
	}

	/* Always writable (responses don't block) */
	if (events & (POLLOUT | POLLWRNORM))
		revents |= events & (POLLOUT | POLLWRNORM);

	if (ec->ec_flags & EC_FLAG_CLOSING)
		revents |= POLLHUP;

	EC_UNLOCK(ec);

	return (revents);
}

/*
 * esc_kqfilter - Kqueue filter attachment
 */
static int
esc_kqfilter(struct cdev *dev, struct knote *kn)
{
	struct esc_client *ec;
	int error;

	error = devfs_get_cdevpriv((void **)&ec);
	if (error)
		return (error);

	switch (kn->kn_filter) {
	case EVFILT_READ:
		kn->kn_fop = &esc_rfiltops;
		kn->kn_hook = ec;
		EC_LOCK(ec);
		knlist_add(&ec->ec_selinfo.si_note, kn, 1);
		EC_UNLOCK(ec);
		return (0);

	default:
		return (EINVAL);
	}
}

static void
esc_kqdetach(struct knote *kn)
{
	struct esc_client *ec = kn->kn_hook;

	EC_LOCK(ec);
	knlist_remove(&ec->ec_selinfo.si_note, kn, 1);
	EC_UNLOCK(ec);
}

static int
esc_kqread(struct knote *kn, long hint)
{
	struct esc_client *ec = kn->kn_hook;
	int ready;

	EC_LOCK(ec);
	kn->kn_data = ec->ec_queue_count * sizeof(esc_message_t);
	ready = !TAILQ_EMPTY(&ec->ec_pending);
	EC_UNLOCK(ec);

	return (ready);
}

/*
 * Device initialization
 */
int
esc_dev_init(void)
{
	bzero(&esc_softc, sizeof(esc_softc));

	mtx_init(&esc_softc.sc_mtx, "esc", NULL, MTX_DEF);
	LIST_INIT(&esc_softc.sc_clients);
	esc_softc.sc_next_msg_id = 1;
	esc_softc.sc_next_client_id = 1;

	esc_softc.sc_cdev = make_dev(&esc_cdevsw, 0, UID_ROOT, GID_WHEEL,
	    0600, "esc");
	if (esc_softc.sc_cdev == NULL) {
		mtx_destroy(&esc_softc.sc_mtx);
		return (ENXIO);
	}

	esc_softc.sc_active = true;

	printf("esc: Endpoint Security Capabilities device created\n");

	return (0);
}

void
esc_dev_uninit(void)
{
	struct esc_client *ec, *ec_tmp;
	int wait_count = 0;

	if (!esc_softc.sc_active)
		return;

	esc_softc.sc_active = false;

	/* Wake all clients and mark them as closing */
	ESC_LOCK();
	LIST_FOREACH_SAFE(ec, &esc_softc.sc_clients, ec_link, ec_tmp) {
		EC_LOCK(ec);
		ec->ec_flags |= EC_FLAG_CLOSING;
		/* Wake all waiters: msleep, poll/select, and kqueue */
		wakeup(&ec->ec_pending);
		selwakeup(&ec->ec_selinfo);
		KNOTE_LOCKED(&ec->ec_selinfo.si_note, 0);
		EC_UNLOCK(ec);
	}

	/*
	 * Wait for clients to drain. Clients are removed from the list
	 * in esc_client_dtor when their fd is closed. We must wait before
	 * destroying the cdev or mutex to avoid use-after-free.
	 */
	while (esc_softc.sc_nclients > 0 && wait_count < 50) {
		ESC_UNLOCK();
		pause("escdrn", hz / 10);  /* 100ms */
		wait_count++;
		ESC_LOCK();
	}

	if (esc_softc.sc_nclients > 0) {
		printf("esc: warning: %u clients still open after 5s\n",
		    esc_softc.sc_nclients);
	}
	ESC_UNLOCK();

	if (esc_softc.sc_cdev != NULL) {
		destroy_dev(esc_softc.sc_cdev);
		esc_softc.sc_cdev = NULL;
	}

	printf("esc: device destroyed\n");

	mtx_destroy(&esc_softc.sc_mtx);
}

/*
 * Module event handler
 */
static int
esc_modevent(module_t mod, int type, void *data)
{
	int error = 0;

	switch (type) {
	case MOD_LOAD:
		error = esc_dev_init();
		if (error != 0)
			break;
		error = esc_mac_init();
		if (error != 0) {
			esc_dev_uninit();
			break;
		}
		break;

	case MOD_UNLOAD:
		esc_mac_uninit();
		esc_dev_uninit();
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

static moduledata_t esc_mod = {
	"esc",
	esc_modevent,
	NULL
};

DECLARE_MODULE(esc, esc_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
MODULE_VERSION(esc, 1);
MODULE_DEPEND(esc, kernel_mac_support, 6, 6, 6);
