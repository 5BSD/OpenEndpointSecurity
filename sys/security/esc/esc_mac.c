/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 * All rights reserved.
 *
 * Endpoint Security Capabilities (esc) - MAC Policy Integration
 *
 * This file hooks into the FreeBSD MAC framework to generate
 * security events for subscribed clients.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/imgact.h>
#include <sys/sysctl.h>
#include <sys/random.h>
#include <sys/fcntl.h>
#include <sys/eventhandler.h>
#include <sys/acl.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/domain.h>
#include <sys/sdt.h>
#include <sys/pipe.h>
#include <sys/priv.h>
#include <netinet/in.h>
#include <sys/un.h>

#include <security/mac/mac_policy.h>
#include <security/audit/audit.h>

#include <security/esc/esc.h>
#include <security/esc/esc_internal.h>

/* DTrace probes defined in esc_event.c */
SDT_PROBE_DECLARE(esc, , , auth__allow);
SDT_PROBE_DECLARE(esc, , , auth__deny);

MALLOC_DECLARE(M_ESC);

/*
 * Per-credential label: stores the execution ID
 *
 * The exec_id is a 64-bit random value that:
 * - Stays the same across fork() (inherited by child via cred_copy_label)
 * - Changes on exec() (new random value in vnode_execve_transition)
 *
 * This allows tracking process lineage and detecting when
 * the actual executable code changes.
 */
struct esc_cred_label {
	uint64_t	ecl_exec_id;	/* Execution ID */
};

static int esc_slot;		/* MAC label slot for our data */
static bool esc_mac_registered;	/* Track if MAC policy is registered */
static eventhandler_tag esc_proc_fork_tag;
static eventhandler_tag esc_proc_exit_tag;
static eventhandler_tag esc_vfs_mounted_tag;
static eventhandler_tag esc_vfs_unmounted_tag;
static eventhandler_tag esc_kld_unload_tag;
static struct mtx esc_rename_mtx;

struct esc_rename_ctx {
	LIST_ENTRY(esc_rename_ctx) er_link;
	lwpid_t			er_tid;
	pid_t			er_pid;
	time_t			er_time;	/* creation time for gc */
	esc_file_t		er_src_dir;
	esc_file_t		er_src_file;
	char			er_src_name[MAXNAMLEN + 1];
};

/* Entries older than this (in seconds) are garbage collected */
#define ESC_RENAME_CACHE_MAX_AGE	60

static LIST_HEAD(, esc_rename_ctx) esc_rename_list =
    LIST_HEAD_INITIALIZER(esc_rename_list);

#define SLOT(l)	((struct esc_cred_label *)mac_label_get((l), esc_slot))
#define SLOT_SET(l, v) mac_label_set((l), esc_slot, (uintptr_t)(v))

/* Forward declarations for socket helpers */
static void esc_fill_sockaddr(esc_sockaddr_t *esa, const struct sockaddr *sa);
static void esc_fill_socket_info(esc_socket_t *es, struct socket *so);

static __inline uint64_t
esc_generate_exec_id(void)
{
	uint64_t id;

	arc4random_buf(&id, sizeof(id));
	return (id);
}

uint64_t
esc_proc_get_exec_id(struct proc *p)
{
	struct ucred *cred;
	struct esc_cred_label *ecl;

	PROC_LOCK_ASSERT(p, MA_OWNED);

	cred = p->p_ucred;
	if (cred->cr_label == NULL)
		return (0);

	ecl = SLOT(cred->cr_label);
	if (ecl == NULL)
		return (0);

	return (ecl->ecl_exec_id);
}

/* MAC hook: allocate label for new credential */
static void
esc_mac_cred_init_label(struct label *label)
{
	struct esc_cred_label *ecl;

	if (!esc_mac_registered) {
		SLOT_SET(label, NULL);
		return;
	}

	ecl = malloc(sizeof(*ecl), M_ESC, M_NOWAIT | M_ZERO);
	if (ecl != NULL)
		ecl->ecl_exec_id = esc_generate_exec_id();
	SLOT_SET(label, ecl);
}

/* MAC hook: free label from credential */
static void
esc_mac_cred_destroy_label(struct label *label)
{
	struct esc_cred_label *ecl;

	ecl = SLOT(label);
	if (ecl != NULL) {
		free(ecl, M_ESC);
		SLOT_SET(label, NULL);
	}
}

/* MAC hook: copy label (preserves exec_id across fork) */
static void
esc_mac_cred_copy_label(struct label *src, struct label *dst)
{
	struct esc_cred_label *src_ecl, *dst_ecl;

	src_ecl = SLOT(src);
	dst_ecl = SLOT(dst);

	if (src_ecl != NULL && dst_ecl != NULL)
		dst_ecl->ecl_exec_id = src_ecl->ecl_exec_id;
}

/* MAC hook: generate new exec_id after exec */
static void
esc_mac_vnode_execve_transition(struct ucred *old, struct ucred *new,
    struct vnode *vp, struct label *vplabel, struct label *interpvplabel,
    struct image_params *imgp, struct label *execlabel)
{
	struct esc_cred_label *ecl;
	struct label *label;

	label = new->cr_label;
	if (label == NULL)
		return;

	ecl = SLOT(label);
	if (ecl != NULL) {
		ecl->ecl_exec_id = esc_generate_exec_id();
		ESC_DEBUG("exec: new exec_id %llu for pid %d",
		    (unsigned long long)ecl->ecl_exec_id, curproc->p_pid);
	}
}

struct esc_vnode_event_info {
	struct ucred		*cred;
	struct vnode		*vp;
	struct vnode		*dvp;
	struct componentname	*cnp;
	struct vattr		*vap;
	struct proc		*target_proc;
	struct esc_rename_ctx	*rename_ctx;
	struct socket		*socket;
	struct sockaddr		*sockaddr;
	accmode_t		accmode;
	int			prot;
	int			mmap_flags;
	int			attrnamespace;
	const char		*attrname;
	acl_type_t		acl_type;
	int			signum;
	uid_t			uid;
	gid_t			gid;
	mode_t			mode;
	uid_t			owner_uid;
	gid_t			owner_gid;
	u_long			fflags;
	struct timespec		atime;
	struct timespec		mtime;
	int			reboot_howto;
	const char		*sysctl_name;
	int			sysctl_op;
	const char		*kenv_name;
	int			kenv_op;
	int			socket_domain;
	int			socket_type;
	int			socket_protocol;
	struct pipepair		*pipepair;
	unsigned long		ioctl_cmd;
	struct mount		*mp;
	int			priv;
	bool			nosleep;	/* Use non-blocking delivery */
};

#define ESC_VNODE_INFO_INIT(_cred) \
	((struct esc_vnode_event_info){ .cred = (_cred) })


static void
esc_copy_component(char *dst, size_t dstlen, const struct componentname *cnp)
{
	size_t len;

	if (dstlen == 0) {
		return;
	}
	dst[0] = '\0';

	if (cnp == NULL || cnp->cn_nameptr == NULL || cnp->cn_namelen == 0)
		return;

	len = cnp->cn_namelen;
	if (len >= dstlen)
		len = dstlen - 1;

	memcpy(dst, cnp->cn_nameptr, len);
	dst[len] = '\0';
}

static void
esc_build_path(char *dst, size_t dstlen, const char *dir, const char *name)
{
	size_t dlen;

	if (dstlen == 0)
		return;

	dst[0] = '\0';
	if (dir == NULL || dir[0] == '\0') {
		if (name != NULL)
			strlcpy(dst, name, dstlen);
		return;
	}
	if (name == NULL || name[0] == '\0') {
		strlcpy(dst, dir, dstlen);
		return;
	}

	dlen = strlen(dir);
	if (dir[dlen - 1] == '/')
		snprintf(dst, dstlen, "%s%s", dir, name);
	else
		snprintf(dst, dstlen, "%s/%s", dir, name);
}

static struct esc_pending *
esc_pending_alloc_notify_from_template(const struct esc_pending *src,
    esc_event_type_t notify_event, struct proc *p, struct ucred *cred)
{
	struct esc_pending *ep;

	ep = esc_pending_alloc(notify_event, p);
	if (ep == NULL)
		return (NULL);

	ep->ep_msg.em_time = src->ep_msg.em_time;
	ep->ep_msg.em_action = ESC_ACTION_NOTIFY;
	bcopy(&src->ep_msg.em_event_data, &ep->ep_msg.em_event_data,
	    sizeof(src->ep_msg.em_event_data));

	return (ep);
}

/* Forward declaration for per-event path muting */
static bool esc_event_is_path_muted(struct esc_client *ec,
    const struct esc_pending *ep, esc_event_type_t mute_event);

static int
esc_dispatch_event(struct esc_pending *ep, struct proc *p, struct ucred *cred,
    esc_event_type_t notify_event)
{
	struct esc_client *ec;
	struct esc_pending *ep_client;
	struct esc_pending *ep_notify;
	struct esc_auth_group *ag = NULL;
	struct esc_pending **auth_eps = NULL;
	size_t auth_count = 0;
	size_t auth_max = 0;
	bool is_auth;
	bool cached_denied = false;
	int error = 0;
	esc_event_type_t event;

	event = ep->ep_msg.em_event;
	is_auth = ESC_EVENT_IS_AUTH(event);


	if (is_auth) {
		/* All AUTH events can sleep (NOSLEEP hooks are NOTIFY-only) */
		for (;;) {
			size_t need;

			ESC_LOCK();
			need = esc_softc.sc_nclients;
			if (need <= auth_max)
				break;
			ESC_UNLOCK();

			if (auth_eps != NULL)
				free(auth_eps, M_ESC);
			auth_eps = malloc(sizeof(*auth_eps) * need,
			    M_ESC, M_WAITOK | M_ZERO);
			auth_max = need;
		}
	} else {
		ESC_LOCK();
	}

	LIST_FOREACH(ec, &esc_softc.sc_clients, ec_link) {
		esc_event_type_t mute_event;

		EC_LOCK(ec);

		if (ec->ec_flags & EC_FLAG_CLOSING) {
			EC_UNLOCK(ec);
			continue;
		}

		/* NOTIFY clients mute by NOTIFY event type, others by AUTH */
		mute_event = (is_auth && ec->ec_mode == ESC_MODE_NOTIFY &&
		    notify_event != 0) ? notify_event : event;

		if (esc_client_is_muted(ec, p, mute_event)) {
			EC_UNLOCK(ec);
			continue;
		}
		if (esc_event_is_path_muted(ec, ep, mute_event)) {
			EC_UNLOCK(ec);
			continue;
		}

		/* Check UID/GID muting */
		if (cred != NULL) {
			if (esc_client_is_uid_muted(ec, cred->cr_uid) ||
			    esc_client_is_gid_muted(ec, cred->cr_gid)) {
				EC_UNLOCK(ec);
				continue;
			}
		}

		if (is_auth) {
			if (ec->ec_mode == ESC_MODE_AUTH) {
				uint32_t timeout = ec->ec_timeout_ms;
				uint32_t action = ec->ec_timeout_action;
				esc_auth_result_t cache_result;

				if (!esc_client_subscribed(ec, event)) {
					EC_UNLOCK(ec);
					continue;
				}

				if (esc_client_cache_lookup(ec, ep,
				    &cache_result)) {
					if (cache_result == ESC_AUTH_DENY)
						cached_denied = true;
					if (cache_result == ESC_AUTH_ALLOW)
						ec->ec_auth_allowed++;
					else
						ec->ec_auth_denied++;
					EC_UNLOCK(ec);
					continue;
				}

				ep_client = esc_pending_clone(ep);
				if (ep_client == NULL) {
					ec->ec_events_dropped++;
					EC_UNLOCK(ec);
					continue;
				}

				if (ag == NULL) {
					ag = esc_auth_group_alloc();
					if (ag == NULL) {
						ec->ec_events_dropped++;
						esc_pending_rele(ep_client);
						EC_UNLOCK(ec);
						continue;
					}
				}

				if (timeout == 0)
					timeout = ESC_DEFAULT_TIMEOUT_MS;
				if (action != ESC_AUTH_ALLOW &&
				    action != ESC_AUTH_DENY)
					action = ESC_AUTH_ALLOW;

				ep_client->ep_client_id = ec->ec_id;
				ep_client->ep_timeout_action = action;
				esc_set_auth_deadline(ep_client, timeout);

				esc_auth_group_hold(ag);
				ep_client->ep_group = ag;
				esc_auth_group_add_pending(ag);

				if (esc_event_enqueue(ec, ep_client) == 0) {
					if (auth_eps != NULL &&
					    auth_count < auth_max)
						auth_eps[auth_count++] = ep_client;
				} else {
					esc_auth_group_cancel_pending(ag);
					esc_pending_rele(ep_client);
				}
				EC_UNLOCK(ec);
				continue;
			}

			if (ec->ec_mode == ESC_MODE_PASSIVE &&
			    notify_event != 0 &&
			    esc_client_subscribed(ec, event)) {
				ep_notify = esc_pending_alloc_notify_from_template(
				    ep, notify_event, p, cred);
				if (ep_notify != NULL) {
					esc_event_enqueue(ec, ep_notify);
					esc_pending_rele(ep_notify);
				}
				EC_UNLOCK(ec);
				continue;
			}

			if (ec->ec_mode == ESC_MODE_NOTIFY &&
			    notify_event != 0 &&
			    esc_client_subscribed(ec, notify_event)) {
				ep_notify = esc_pending_alloc_notify_from_template(
				    ep, notify_event, p, cred);
				if (ep_notify != NULL) {
					esc_event_enqueue(ec, ep_notify);
					esc_pending_rele(ep_notify);
				}
				EC_UNLOCK(ec);
				continue;
			}
			EC_UNLOCK(ec);
			continue;
		}

		if (!esc_client_subscribed(ec, event)) {
			EC_UNLOCK(ec);
			continue;
		}

		ep_client = esc_pending_clone(ep);
		if (ep_client != NULL) {
			esc_event_enqueue(ec, ep_client);
			esc_pending_rele(ep_client);
		} else {
			ec->ec_events_dropped++;
		}
		EC_UNLOCK(ec);
	}

	ESC_UNLOCK();

	/*
	 * Wait for AUTH responses. All AUTH events can sleep
	 * (NOSLEEP hooks are NOTIFY-only now).
	 */
	if (is_auth && auth_count > 0 && ag != NULL)
		error = esc_auth_group_wait(ag, auth_eps, auth_count);
	if (is_auth && cached_denied)
		error = EACCES;

	/*
	 * Check flags-based responses for events that support partial
	 * authorization (OPEN, MMAP, MPROTECT). If a client allowed with
	 * restricted flags, deny if the requested flags exceed what's allowed.
	 */
	if (error == 0 && is_auth && auth_count > 0) {
		uint32_t requested_flags = 0;
		size_t i;

		/* Get requested flags based on event type */
		switch (event) {
		case ESC_EVENT_AUTH_OPEN:
			requested_flags = ep->ep_msg.em_event_data.open.flags;
			break;
		case ESC_EVENT_AUTH_MMAP:
			requested_flags = ep->ep_msg.em_event_data.mmap.prot;
			break;
		case ESC_EVENT_AUTH_MPROTECT:
			requested_flags = ep->ep_msg.em_event_data.mprotect.prot;
			break;
		default:
			break;
		}

		/* Check each client's flags-based response */
		for (i = 0; i < auth_count && error == 0; i++) {
			struct esc_pending *ep_auth = auth_eps[i];
			uint32_t allowed, denied;

			if (ep_auth == NULL)
				continue;

			mtx_lock(&ep_auth->ep_mtx);
			allowed = ep_auth->ep_allowed_flags;
			denied = ep_auth->ep_denied_flags;
			mtx_unlock(&ep_auth->ep_mtx);

			/*
			 * If client set denied_flags and requested has any
			 * of those flags, deny the operation.
			 */
			if (denied != 0 && (requested_flags & denied) != 0) {
				error = EACCES;
				break;
			}

			/*
			 * If client set allowed_flags (partial allow) and
			 * requested has flags not in allowed set, deny.
			 */
			if (allowed != 0 &&
			    (requested_flags & ~allowed) != 0) {
				error = EACCES;
				break;
			}
		}
	}

	/*
	 * Record ESC denials in audit records when audit is active.
	 * This adds context to the syscall's audit record indicating
	 * that ESC denied the operation.
	 */
	if (error == EACCES) {
		AUDIT_ARG_TEXT("ESC: authorization denied");
		SDT_PROBE3(esc, , , auth__deny,
		    ep->ep_msg.em_event,
		    ep->ep_msg.em_process.ep_pid,
		    ep->ep_msg.em_process.ep_path);
	}

	if (auth_eps != NULL) {
		size_t i;

		for (i = 0; i < auth_count; i++)
			esc_pending_rele(auth_eps[i]);
		free(auth_eps, M_ESC);
	}

	if (ag != NULL)
		esc_auth_group_rele(ag);

	return (error);
}

static void
esc_rename_cache_init(void)
{
	mtx_init(&esc_rename_mtx, "esc_rename", NULL, MTX_DEF);
	LIST_INIT(&esc_rename_list);
}

static void
esc_rename_cache_destroy(void)
{
	struct esc_rename_ctx *ctx, *tmp;

	mtx_lock(&esc_rename_mtx);
	LIST_FOREACH_SAFE(ctx, &esc_rename_list, er_link, tmp) {
		LIST_REMOVE(ctx, er_link);
		free(ctx, M_ESC);
	}
	mtx_unlock(&esc_rename_mtx);
	mtx_destroy(&esc_rename_mtx);
}

static void
esc_rename_cache_store(struct thread *td,
    const struct esc_vnode_event_info *info)
{
	struct esc_rename_ctx *ctx, *cur, *tmp;
	time_t now;
	bool found_self = false;

	if (info == NULL)
		return;

	ctx = malloc(sizeof(*ctx), M_ESC, M_NOWAIT | M_ZERO);
	if (ctx == NULL)
		return;

	now = time_second;
	ctx->er_tid = td->td_tid;
	ctx->er_pid = td->td_proc->p_pid;
	ctx->er_time = now;
	if (info->dvp != NULL)
		esc_fill_file(&ctx->er_src_dir, info->dvp, info->cred);
	if (info->vp != NULL)
		esc_fill_file(&ctx->er_src_file, info->vp, info->cred);
	esc_copy_component(ctx->er_src_name, sizeof(ctx->er_src_name),
	    info->cnp);
	if (ctx->er_src_dir.ef_path[0] != '\0' &&
	    ctx->er_src_name[0] != '\0') {
		esc_build_path(ctx->er_src_file.ef_path,
		    sizeof(ctx->er_src_file.ef_path),
		    ctx->er_src_dir.ef_path,
		    ctx->er_src_name);
	}

	mtx_lock(&esc_rename_mtx);
	LIST_FOREACH_SAFE(cur, &esc_rename_list, er_link, tmp) {
		/* Replace existing entry for this tid/pid */
		if (!found_self &&
		    cur->er_tid == td->td_tid &&
		    cur->er_pid == td->td_proc->p_pid) {
			LIST_REMOVE(cur, er_link);
			free(cur, M_ESC);
			found_self = true;
			continue;
		}
		/* Garbage collect stale entries (failed/aborted renames) */
		if (now - cur->er_time > ESC_RENAME_CACHE_MAX_AGE) {
			LIST_REMOVE(cur, er_link);
			free(cur, M_ESC);
		}
	}
	LIST_INSERT_HEAD(&esc_rename_list, ctx, er_link);
	mtx_unlock(&esc_rename_mtx);
}

static struct esc_rename_ctx *
esc_rename_cache_take(struct thread *td)
{
	struct esc_rename_ctx *ctx;


	mtx_lock(&esc_rename_mtx);
	LIST_FOREACH(ctx, &esc_rename_list, er_link) {
		if (ctx->er_tid == td->td_tid &&
		    ctx->er_pid == td->td_proc->p_pid) {
			LIST_REMOVE(ctx, er_link);
			mtx_unlock(&esc_rename_mtx);
			return (ctx);
		}
	}
	mtx_unlock(&esc_rename_mtx);

	return (NULL);
}

static void
esc_rename_cache_purge_pid(pid_t pid)
{
	struct esc_rename_ctx *ctx, *tmp;

	if (pid <= 0)
		return;

	mtx_lock(&esc_rename_mtx);
	LIST_FOREACH_SAFE(ctx, &esc_rename_list, er_link, tmp) {
		if (ctx->er_pid != pid)
			continue;
		LIST_REMOVE(ctx, er_link);
		free(ctx, M_ESC);
	}
	mtx_unlock(&esc_rename_mtx);
}

static void
esc_fill_file_from_vap(esc_file_t *ef, struct vattr *vap)
{
	bzero(ef, sizeof(*ef));
	if (vap == NULL)
		return;

	ef->ef_type = esc_vtype_to_eftype(vap->va_type);
	ef->ef_mode = vap->va_mode;
	ef->ef_uid = vap->va_uid;
	ef->ef_gid = vap->va_gid;
}

static const char *
esc_event_primary_path(const struct esc_pending *ep)
{
	const esc_message_t *msg = &ep->ep_msg;

	switch (msg->em_event) {
	case ESC_EVENT_AUTH_EXEC:
	case ESC_EVENT_NOTIFY_EXEC:
		return (msg->em_event_data.exec.executable.ef_path);
	case ESC_EVENT_AUTH_OPEN:
	case ESC_EVENT_NOTIFY_OPEN:
		return (msg->em_event_data.open.file.ef_path);
	case ESC_EVENT_AUTH_ACCESS:
	case ESC_EVENT_NOTIFY_ACCESS:
		return (msg->em_event_data.access.file.ef_path);
	case ESC_EVENT_AUTH_READ:
	case ESC_EVENT_NOTIFY_READ:
	case ESC_EVENT_AUTH_WRITE:
	case ESC_EVENT_NOTIFY_WRITE:
		return (msg->em_event_data.rw.file.ef_path);
	case ESC_EVENT_AUTH_STAT:
	case ESC_EVENT_NOTIFY_STAT:
		return (msg->em_event_data.stat.file.ef_path);
	case ESC_EVENT_AUTH_POLL:
	case ESC_EVENT_NOTIFY_POLL:
		return (msg->em_event_data.poll.file.ef_path);
	case ESC_EVENT_AUTH_REVOKE:
	case ESC_EVENT_NOTIFY_REVOKE:
		return (msg->em_event_data.revoke.file.ef_path);
	case ESC_EVENT_AUTH_READLINK:
	case ESC_EVENT_NOTIFY_READLINK:
		return (msg->em_event_data.readlink.file.ef_path);
	case ESC_EVENT_AUTH_READDIR:
	case ESC_EVENT_NOTIFY_READDIR:
		return (msg->em_event_data.readdir.dir.ef_path);
	case ESC_EVENT_AUTH_LOOKUP:
	case ESC_EVENT_NOTIFY_LOOKUP:
		if (msg->em_event_data.lookup.name[0] != '\0')
			return (msg->em_event_data.lookup.name);
		return (msg->em_event_data.lookup.dir.ef_path);
	case ESC_EVENT_AUTH_CREATE:
	case ESC_EVENT_NOTIFY_CREATE:
		if (msg->em_event_data.create.file.ef_path[0] != '\0')
			return (msg->em_event_data.create.file.ef_path);
		return (msg->em_event_data.create.dir.ef_path);
	case ESC_EVENT_AUTH_UNLINK:
	case ESC_EVENT_NOTIFY_UNLINK:
		if (msg->em_event_data.unlink.file.ef_path[0] != '\0')
			return (msg->em_event_data.unlink.file.ef_path);
		return (msg->em_event_data.unlink.dir.ef_path);
	case ESC_EVENT_AUTH_RENAME:
	case ESC_EVENT_NOTIFY_RENAME:
		if (msg->em_event_data.rename.src_file.ef_path[0] != '\0')
			return (msg->em_event_data.rename.src_file.ef_path);
		return (msg->em_event_data.rename.src_dir.ef_path);
	case ESC_EVENT_AUTH_LINK:
	case ESC_EVENT_NOTIFY_LINK:
		return (msg->em_event_data.link.target.ef_path);
	case ESC_EVENT_AUTH_KLDLOAD:
	case ESC_EVENT_NOTIFY_KLDLOAD:
		return (msg->em_event_data.kldload.file.ef_path);
	case ESC_EVENT_AUTH_MMAP:
	case ESC_EVENT_NOTIFY_MMAP:
		return (msg->em_event_data.mmap.file.ef_path);
	case ESC_EVENT_AUTH_MPROTECT:
	case ESC_EVENT_NOTIFY_MPROTECT:
		return (msg->em_event_data.mprotect.file.ef_path);
	case ESC_EVENT_AUTH_SETMODE:
	case ESC_EVENT_NOTIFY_SETMODE:
		return (msg->em_event_data.setmode.file.ef_path);
	case ESC_EVENT_AUTH_SETOWNER:
	case ESC_EVENT_NOTIFY_SETOWNER:
		return (msg->em_event_data.setowner.file.ef_path);
	case ESC_EVENT_AUTH_SETFLAGS:
	case ESC_EVENT_NOTIFY_SETFLAGS:
		return (msg->em_event_data.setflags.file.ef_path);
	case ESC_EVENT_AUTH_SETUTIMES:
	case ESC_EVENT_NOTIFY_SETUTIMES:
		return (msg->em_event_data.setutimes.file.ef_path);
	case ESC_EVENT_AUTH_CHDIR:
	case ESC_EVENT_NOTIFY_CHDIR:
		return (msg->em_event_data.chdir.dir.ef_path);
	case ESC_EVENT_AUTH_CHROOT:
	case ESC_EVENT_NOTIFY_CHROOT:
		return (msg->em_event_data.chroot.dir.ef_path);
	case ESC_EVENT_AUTH_SETEXTATTR:
	case ESC_EVENT_NOTIFY_SETEXTATTR:
		return (msg->em_event_data.setextattr.file.ef_path);
	case ESC_EVENT_AUTH_GETEXTATTR:
	case ESC_EVENT_NOTIFY_GETEXTATTR:
		return (msg->em_event_data.getextattr.file.ef_path);
	case ESC_EVENT_AUTH_DELETEEXTATTR:
	case ESC_EVENT_NOTIFY_DELETEEXTATTR:
		return (msg->em_event_data.deleteextattr.file.ef_path);
	case ESC_EVENT_AUTH_LISTEXTATTR:
	case ESC_EVENT_NOTIFY_LISTEXTATTR:
		return (msg->em_event_data.listextattr.file.ef_path);
	case ESC_EVENT_AUTH_GETACL:
	case ESC_EVENT_NOTIFY_GETACL:
		return (msg->em_event_data.getacl.file.ef_path);
	case ESC_EVENT_AUTH_SETACL:
	case ESC_EVENT_NOTIFY_SETACL:
		return (msg->em_event_data.setacl.file.ef_path);
	case ESC_EVENT_AUTH_DELETEACL:
	case ESC_EVENT_NOTIFY_DELETEACL:
		return (msg->em_event_data.deleteacl.file.ef_path);
	case ESC_EVENT_AUTH_RELABEL:
	case ESC_EVENT_NOTIFY_RELABEL:
		return (msg->em_event_data.relabel.file.ef_path);
	case ESC_EVENT_AUTH_MOUNT:
	case ESC_EVENT_NOTIFY_MOUNT:
		return (msg->em_event_data.mount.mountpoint.ef_path);
	case ESC_EVENT_NOTIFY_UNMOUNT:
		return (msg->em_event_data.unmount.mountpoint.ef_path);
	case ESC_EVENT_AUTH_SWAPON:
	case ESC_EVENT_NOTIFY_SWAPON:
		return (msg->em_event_data.swapon.file.ef_path);
	case ESC_EVENT_AUTH_SWAPOFF:
	case ESC_EVENT_NOTIFY_SWAPOFF:
		return (msg->em_event_data.swapoff.file.ef_path);
	case ESC_EVENT_NOTIFY_MOUNT_STAT:
		return (msg->em_event_data.mount_stat.fspath);
	default:
		return (NULL);
	}
}

/*
 * Return pointer to the primary file structure for an event.
 * Used for token-based path muting when path resolution fails.
 */
static const esc_file_t *
esc_event_primary_file(const struct esc_pending *ep)
{
	const esc_message_t *msg = &ep->ep_msg;

	switch (msg->em_event) {
	case ESC_EVENT_AUTH_EXEC:
	case ESC_EVENT_NOTIFY_EXEC:
		return (&msg->em_event_data.exec.executable);
	case ESC_EVENT_AUTH_OPEN:
	case ESC_EVENT_NOTIFY_OPEN:
		return (&msg->em_event_data.open.file);
	case ESC_EVENT_AUTH_ACCESS:
	case ESC_EVENT_NOTIFY_ACCESS:
		return (&msg->em_event_data.access.file);
	case ESC_EVENT_AUTH_READ:
	case ESC_EVENT_NOTIFY_READ:
	case ESC_EVENT_AUTH_WRITE:
	case ESC_EVENT_NOTIFY_WRITE:
		return (&msg->em_event_data.rw.file);
	case ESC_EVENT_AUTH_STAT:
	case ESC_EVENT_NOTIFY_STAT:
		return (&msg->em_event_data.stat.file);
	case ESC_EVENT_AUTH_POLL:
	case ESC_EVENT_NOTIFY_POLL:
		return (&msg->em_event_data.poll.file);
	case ESC_EVENT_AUTH_REVOKE:
	case ESC_EVENT_NOTIFY_REVOKE:
		return (&msg->em_event_data.revoke.file);
	case ESC_EVENT_AUTH_READLINK:
	case ESC_EVENT_NOTIFY_READLINK:
		return (&msg->em_event_data.readlink.file);
	case ESC_EVENT_AUTH_READDIR:
	case ESC_EVENT_NOTIFY_READDIR:
		return (&msg->em_event_data.readdir.dir);
	case ESC_EVENT_AUTH_SETMODE:
	case ESC_EVENT_NOTIFY_SETMODE:
		return (&msg->em_event_data.setmode.file);
	case ESC_EVENT_AUTH_SETOWNER:
	case ESC_EVENT_NOTIFY_SETOWNER:
		return (&msg->em_event_data.setowner.file);
	case ESC_EVENT_AUTH_SETFLAGS:
	case ESC_EVENT_NOTIFY_SETFLAGS:
		return (&msg->em_event_data.setflags.file);
	case ESC_EVENT_AUTH_SETUTIMES:
	case ESC_EVENT_NOTIFY_SETUTIMES:
		return (&msg->em_event_data.setutimes.file);
	case ESC_EVENT_AUTH_CHDIR:
	case ESC_EVENT_NOTIFY_CHDIR:
		return (&msg->em_event_data.chdir.dir);
	case ESC_EVENT_AUTH_CHROOT:
	case ESC_EVENT_NOTIFY_CHROOT:
		return (&msg->em_event_data.chroot.dir);
	case ESC_EVENT_AUTH_SETEXTATTR:
	case ESC_EVENT_NOTIFY_SETEXTATTR:
		return (&msg->em_event_data.setextattr.file);
	case ESC_EVENT_AUTH_GETEXTATTR:
	case ESC_EVENT_NOTIFY_GETEXTATTR:
		return (&msg->em_event_data.getextattr.file);
	case ESC_EVENT_AUTH_DELETEEXTATTR:
	case ESC_EVENT_NOTIFY_DELETEEXTATTR:
		return (&msg->em_event_data.deleteextattr.file);
	case ESC_EVENT_AUTH_LISTEXTATTR:
	case ESC_EVENT_NOTIFY_LISTEXTATTR:
		return (&msg->em_event_data.listextattr.file);
	case ESC_EVENT_AUTH_GETACL:
	case ESC_EVENT_NOTIFY_GETACL:
		return (&msg->em_event_data.getacl.file);
	case ESC_EVENT_AUTH_SETACL:
	case ESC_EVENT_NOTIFY_SETACL:
		return (&msg->em_event_data.setacl.file);
	case ESC_EVENT_AUTH_DELETEACL:
	case ESC_EVENT_NOTIFY_DELETEACL:
		return (&msg->em_event_data.deleteacl.file);
	case ESC_EVENT_AUTH_RELABEL:
	case ESC_EVENT_NOTIFY_RELABEL:
		return (&msg->em_event_data.relabel.file);
	case ESC_EVENT_AUTH_MMAP:
	case ESC_EVENT_NOTIFY_MMAP:
		return (&msg->em_event_data.mmap.file);
	case ESC_EVENT_AUTH_MPROTECT:
	case ESC_EVENT_NOTIFY_MPROTECT:
		return (&msg->em_event_data.mprotect.file);
	case ESC_EVENT_AUTH_KLDLOAD:
	case ESC_EVENT_NOTIFY_KLDLOAD:
		return (&msg->em_event_data.kldload.file);
	case ESC_EVENT_AUTH_MOUNT:
	case ESC_EVENT_NOTIFY_MOUNT:
		return (&msg->em_event_data.mount.mountpoint);
	case ESC_EVENT_NOTIFY_UNMOUNT:
		return (&msg->em_event_data.unmount.mountpoint);
	case ESC_EVENT_AUTH_SWAPON:
	case ESC_EVENT_NOTIFY_SWAPON:
		return (&msg->em_event_data.swapon.file);
	case ESC_EVENT_AUTH_SWAPOFF:
	case ESC_EVENT_NOTIFY_SWAPOFF:
		return (&msg->em_event_data.swapoff.file);
	default:
		return (NULL);
	}
}

static const char *
esc_event_target_path(const struct esc_pending *ep)
{
	const esc_message_t *msg = &ep->ep_msg;

	switch (msg->em_event) {
	case ESC_EVENT_AUTH_RENAME:
	case ESC_EVENT_NOTIFY_RENAME:
		return (msg->em_event_data.rename.dst_name);
	case ESC_EVENT_AUTH_LINK:
	case ESC_EVENT_NOTIFY_LINK:
		return (msg->em_event_data.link.name);
	default:
		return (NULL);
	}
}

static bool
esc_event_path_muted_join(struct esc_client *ec, const char *dir,
    const char *name, bool target, bool require_basename, esc_event_type_t event)
{
	char fullpath[MAXPATHLEN];

	if (dir == NULL || name == NULL)
		return (false);
	if (dir[0] == '\0' || name[0] == '\0')
		return (false);
	if (require_basename && strchr(name, '/') != NULL)
		return (false);

	esc_build_path(fullpath, sizeof(fullpath), dir, name);
	return (esc_client_is_path_muted(ec, fullpath, target, event));
}

/*
 * Check if an event's path is muted.
 *
 * mute_event specifies the event type to use for per-event path muting.
 * This allows NOTIFY mode clients to check NOTIFY event types even when
 * the pending event contains an AUTH event type.  If mute_event is 0,
 * the event type from the pending structure is used.
 */
static bool
esc_event_is_path_muted(struct esc_client *ec, const struct esc_pending *ep,
    esc_event_type_t mute_event)
{
	const esc_message_t *msg;
	const esc_file_t *file;
	const char *path;
	const char *target_path;
	esc_event_type_t event;

	EC_LOCK_ASSERT(ec);

	msg = &ep->ep_msg;
	event = (mute_event != 0) ? mute_event : msg->em_event;
	path = esc_event_primary_path(ep);
	file = esc_event_primary_file(ep);

	if (event == ESC_EVENT_AUTH_EXEC) {
		if (path != NULL && path[0] != '\0' &&
		    esc_client_is_path_muted(ec, path, false, event))
			return (true);
	} else if (event != ESC_EVENT_AUTH_LOOKUP &&
	    event != ESC_EVENT_NOTIFY_LOOKUP) {
		if (path != NULL && path[0] != '\0' &&
		    esc_client_is_path_muted(ec, path, false, event))
			return (true);
		/*
		 * Token-based fallback: if path is empty (e.g., vnode locked
		 * during MAC hook), try matching by inode/device.
		 */
		if ((path == NULL || path[0] == '\0') && file != NULL &&
		    esc_client_is_token_muted(ec, file->ef_ino, file->ef_dev,
		    false, event))
			return (true);
	}

	/*
	 * Event-specific path mute checks.  LOOKUP events need special
	 * handling because esc_event_primary_path returns just the component
	 * name, not the full path.  We must join dir+name to check properly.
	 */
	switch (event) {
	case ESC_EVENT_AUTH_LOOKUP:
	case ESC_EVENT_NOTIFY_LOOKUP:
		if (esc_event_path_muted_join(ec,
		    msg->em_event_data.lookup.dir.ef_path,
		    msg->em_event_data.lookup.name, false, false, event))
			return (true);
		break;
	case ESC_EVENT_AUTH_CREATE:
	case ESC_EVENT_NOTIFY_CREATE:
		if (esc_event_path_muted_join(ec,
		    msg->em_event_data.create.dir.ef_path,
		    msg->em_event_data.create.file.ef_path, false, true, event))
			return (true);
		break;
	case ESC_EVENT_AUTH_UNLINK:
	case ESC_EVENT_NOTIFY_UNLINK:
		if (esc_event_path_muted_join(ec,
		    msg->em_event_data.unlink.dir.ef_path,
		    msg->em_event_data.unlink.file.ef_path, false, true, event))
			return (true);
		break;
	case ESC_EVENT_AUTH_RENAME:
	case ESC_EVENT_NOTIFY_RENAME:
		if (esc_event_path_muted_join(ec,
		    msg->em_event_data.rename.src_dir.ef_path,
		    msg->em_event_data.rename.src_file.ef_path, false, true, event))
			return (true);
		break;
	default:
		break;
	}

	/*
	 * Target path mute check.  For RENAME and LINK events,
	 * esc_event_target_path returns just the basename (dst_name or
	 * link.name), not a full path.  Use join-based checking for those.
	 */
	switch (event) {
	case ESC_EVENT_AUTH_RENAME:
	case ESC_EVENT_NOTIFY_RENAME:
		if (esc_event_path_muted_join(ec,
		    msg->em_event_data.rename.dst_dir.ef_path,
		    msg->em_event_data.rename.dst_name, true, false, event))
			return (true);
		break;
	case ESC_EVENT_AUTH_LINK:
	case ESC_EVENT_NOTIFY_LINK:
		/* Check full path first (dir + name) */
		if (esc_event_path_muted_join(ec,
		    msg->em_event_data.link.dir.ef_path,
		    msg->em_event_data.link.name, true, false, event))
			return (true);
		/* Also check just the link name (basename) for convenience */
		if (msg->em_event_data.link.name[0] != '\0' &&
		    esc_client_is_path_muted(ec, msg->em_event_data.link.name,
		    true, event))
			return (true);
		break;
	default:
		/* Other events: target_path is a full path, check directly */
		target_path = esc_event_target_path(ep);
		if (target_path != NULL && target_path[0] != '\0' &&
		    esc_client_is_path_muted(ec, target_path, true, event))
			return (true);
		break;
	}

	return (false);
}

static int
esc_accmode_to_open_flags(accmode_t accmode)
{
	int flags = 0;

	if ((accmode & (VREAD | VWRITE)) == (VREAD | VWRITE))
		flags = O_RDWR;
	else if (accmode & VWRITE)
		flags = O_WRONLY;
	else if (accmode & VREAD)
		flags = O_RDONLY;

	if (accmode & VEXEC)
		flags |= O_EXEC;

	return (flags);
}

/*
 * Clone an esc_pending for per-client delivery in NOSLEEP context.
 * Uses M_NOWAIT so may return NULL on allocation failure.
 */
static struct esc_pending *
esc_pending_clone_nosleep(const struct esc_pending *src)
{
	struct esc_pending *ep;

	ep = malloc(sizeof(*ep), M_ESC, M_NOWAIT | M_ZERO);
	if (ep == NULL)
		return (NULL);

	/* Copy the entire structure */
	bcopy(src, ep, sizeof(*ep));

	/* Reset per-instance fields */
	ep->ep_refcount = 1;
	ep->ep_flags = 0;
	/* ep_link will be set by TAILQ_INSERT */

	return (ep);
}

static void
esc_deliver_notify_nosleep(struct esc_pending *ep, struct proc *p)
{
	struct esc_client *ec;
	struct esc_pending *ep_clone;

	if (!mtx_trylock(&esc_softc.sc_mtx)) {
		atomic_add_64(&esc_softc.sc_nosleep_drops, 1);
		return;
	}

	LIST_FOREACH(ec, &esc_softc.sc_clients, ec_link) {
		if (!mtx_trylock(&ec->ec_mtx)) {
			/* Can't check subscription without lock, count as drop */
			atomic_add_64(&esc_softc.sc_nosleep_drops, 1);
			continue;
		}
		if (ec->ec_flags & EC_FLAG_CLOSING) {
			EC_UNLOCK(ec);
			continue;
		}
		if (!esc_client_subscribed(ec, ep->ep_msg.em_event)) {
			EC_UNLOCK(ec);
			continue;
		}
		/*
		 * Use token-based mute check - NOSLEEP-safe.
		 * The token was captured when the event was created,
		 * so we don't need PROC_LOCK here.
		 */
		if (esc_client_is_muted_by_token(ec,
		    &ep->ep_msg.em_process.ep_token, ep->ep_msg.em_event)) {
			EC_UNLOCK(ec);
			continue;
		}
		if (esc_event_is_path_muted(ec, ep, 0)) {
			EC_UNLOCK(ec);
			continue;
		}
		/* Check UID/GID muting using process info from message */
		if (esc_client_is_uid_muted(ec, ep->ep_msg.em_process.ep_uid) ||
		    esc_client_is_gid_muted(ec, ep->ep_msg.em_process.ep_gid)) {
			EC_UNLOCK(ec);
			continue;
		}

		ep_clone = esc_pending_clone_nosleep(ep);
		if (ep_clone == NULL) {
			atomic_add_64(&esc_softc.sc_nosleep_drops, 1);
			EC_UNLOCK(ec);
			continue;
		}

		if (esc_event_enqueue(ec, ep_clone) != 0)
			esc_pending_free(ep_clone);
		else
			esc_pending_rele(ep_clone);
		EC_UNLOCK(ec);
	}

	ESC_UNLOCK();
}

static void
esc_proc_event_fork(void *arg __unused, struct proc *p1,
    struct proc *p2, int flags __unused)
{
	struct esc_pending *ep;

	if (!esc_softc.sc_active)
		return;

	ep = esc_pending_alloc(ESC_EVENT_NOTIFY_FORK, p1);
	if (ep == NULL)
		return;

	PROC_LOCK(p2);
	esc_fill_process(&ep->ep_msg.em_event_data.fork.child, p2, p2->p_ucred);
	PROC_UNLOCK(p2);

	esc_deliver_notify_nosleep(ep, p1);
	esc_pending_rele(ep);
}

static void
esc_proc_event_exit(void *arg __unused, struct proc *p)
{
	struct esc_pending *ep;
	int xexit;

	if (!esc_softc.sc_active)
		return;

	esc_rename_cache_purge_pid(p->p_pid);

	PROC_LOCK(p);
	xexit = p->p_xexit;
	PROC_UNLOCK(p);

	ep = esc_pending_alloc(ESC_EVENT_NOTIFY_EXIT, p);
	if (ep == NULL)
		return;

	ep->ep_msg.em_event_data.exit.status = xexit;

	esc_deliver_notify_nosleep(ep, p);
	esc_pending_rele(ep);
}

/*
 * Eventhandler: vfs_mounted - called when a filesystem is mounted
 */
static void
esc_vfs_event_mounted(void *arg __unused, struct mount *mp,
    struct vnode *vp, struct thread *td)
{
	struct esc_pending *ep;
	struct ucred *cred;
	struct proc *p;
	struct statfs *sp;

	if (!esc_softc.sc_active)
		return;

	p = td->td_proc;
	PROC_LOCK(p);
	cred = crhold(p->p_ucred);
	PROC_UNLOCK(p);

	ep = esc_pending_alloc(ESC_EVENT_NOTIFY_MOUNT, p);
	if (ep == NULL) {
		crfree(cred);
		return;
	}

	/* Fill mount event data from mount structure */
	sp = &mp->mnt_stat;
	if (vp != NULL)
		esc_fill_file(&ep->ep_msg.em_event_data.mount.mountpoint,
		    vp, cred);
	/* Fallback: use f_mntonname if vnode path resolution failed */
	if (ep->ep_msg.em_event_data.mount.mountpoint.ef_path[0] == '\0')
		strlcpy(ep->ep_msg.em_event_data.mount.mountpoint.ef_path,
		    sp->f_mntonname,
		    sizeof(ep->ep_msg.em_event_data.mount.mountpoint.ef_path));
	strlcpy(ep->ep_msg.em_event_data.mount.fstype, sp->f_fstypename,
	    sizeof(ep->ep_msg.em_event_data.mount.fstype));
	strlcpy(ep->ep_msg.em_event_data.mount.source, sp->f_mntfromname,
	    sizeof(ep->ep_msg.em_event_data.mount.source));
	ep->ep_msg.em_event_data.mount.flags = mp->mnt_flag;

	esc_deliver_notify_nosleep(ep, p);
	esc_pending_rele(ep);
	crfree(cred);
}

/*
 * Eventhandler: vfs_unmounted - called when a filesystem is unmounted
 */
static void
esc_vfs_event_unmounted(void *arg __unused, struct mount *mp,
    struct thread *td)
{
	struct esc_pending *ep;
	struct ucred *cred;
	struct proc *p;
	struct statfs *sp;

	if (!esc_softc.sc_active)
		return;

	p = td->td_proc;
	PROC_LOCK(p);
	cred = crhold(p->p_ucred);
	PROC_UNLOCK(p);

	ep = esc_pending_alloc(ESC_EVENT_NOTIFY_UNMOUNT, p);
	if (ep == NULL) {
		crfree(cred);
		return;
	}

	/* Fill unmount event data from mount structure */
	sp = &mp->mnt_stat;
	esc_fill_file(&ep->ep_msg.em_event_data.unmount.mountpoint,
	    mp->mnt_vnodecovered, cred);
	/* Fallback: use f_mntonname if vnode path resolution failed */
	if (ep->ep_msg.em_event_data.unmount.mountpoint.ef_path[0] == '\0')
		strlcpy(ep->ep_msg.em_event_data.unmount.mountpoint.ef_path,
		    sp->f_mntonname,
		    sizeof(ep->ep_msg.em_event_data.unmount.mountpoint.ef_path));
	strlcpy(ep->ep_msg.em_event_data.unmount.fstype, sp->f_fstypename,
	    sizeof(ep->ep_msg.em_event_data.unmount.fstype));
	strlcpy(ep->ep_msg.em_event_data.unmount.source, sp->f_mntfromname,
	    sizeof(ep->ep_msg.em_event_data.unmount.source));
	ep->ep_msg.em_event_data.unmount.flags = mp->mnt_flag;

	esc_deliver_notify_nosleep(ep, p);
	esc_pending_rele(ep);
	crfree(cred);
}

/*
 * Eventhandler: kld_unload - called when a kernel module is unloaded
 */
static void
esc_kld_event_unload(void *arg __unused, const char *name, caddr_t addr __unused,
    size_t size __unused)
{
	struct esc_pending *ep;
	struct ucred *cred;
	struct proc *p;

	if (!esc_softc.sc_active)
		return;

	p = curthread->td_proc;

	PROC_LOCK(p);
	cred = crhold(p->p_ucred);
	PROC_UNLOCK(p);

	ep = esc_pending_alloc(ESC_EVENT_NOTIFY_KLDUNLOAD, p);
	if (ep == NULL) {
		crfree(cred);
		return;
	}

	/* Fill kldunload event data - no file vnode available at unload time */
	memset(&ep->ep_msg.em_event_data.kldunload.file, 0,
	    sizeof(ep->ep_msg.em_event_data.kldunload.file));
	if (name != NULL)
		strlcpy(ep->ep_msg.em_event_data.kldunload.name, name,
		    sizeof(ep->ep_msg.em_event_data.kldunload.name));

	esc_deliver_notify_nosleep(ep, p);
	esc_pending_rele(ep);
	crfree(cred);
}

static void
esc_fill_event_file(esc_file_t *file, struct vnode *vp, struct ucred *cred)
{

	if (vp != NULL)
		esc_fill_file(file, vp, cred);
}

static void
esc_event_join_component(char *dst, size_t dstlen, const char *dir)
{
	char fullpath[MAXPATHLEN];

	if (dst == NULL || dir == NULL)
		return;
	if (dst[0] == '\0' || dir[0] == '\0')
		return;

	esc_build_path(fullpath, sizeof(fullpath), dir, dst);
	strlcpy(dst, fullpath, dstlen);
}

static void
esc_fill_event_open(struct esc_pending *ep, struct vnode *vp,
    accmode_t accmode, struct ucred *cred)
{

	esc_fill_event_file(&ep->ep_msg.em_event_data.open.file, vp, cred);
	ep->ep_msg.em_event_data.open.flags =
	    esc_accmode_to_open_flags(accmode);
}

static void
esc_fill_event_access(struct esc_pending *ep, struct vnode *vp,
    accmode_t accmode, struct ucred *cred)
{

	esc_fill_event_file(&ep->ep_msg.em_event_data.access.file, vp, cred);
	ep->ep_msg.em_event_data.access.accmode = accmode;
}

static void
esc_fill_event_rw(struct esc_pending *ep, struct vnode *vp, struct ucred *cred)
{

	esc_fill_event_file(&ep->ep_msg.em_event_data.rw.file, vp, cred);
}

static void
esc_fill_event_stat(struct esc_pending *ep, struct vnode *vp,
    struct ucred *cred)
{

	esc_fill_event_file(&ep->ep_msg.em_event_data.stat.file, vp, cred);
}

static void
esc_fill_event_poll(struct esc_pending *ep, struct vnode *vp,
    struct ucred *cred)
{

	esc_fill_event_file(&ep->ep_msg.em_event_data.poll.file, vp, cred);
}

static void
esc_fill_event_revoke(struct esc_pending *ep, struct vnode *vp,
    struct ucred *cred)
{

	esc_fill_event_file(&ep->ep_msg.em_event_data.revoke.file, vp, cred);
}

static void
esc_fill_event_readlink(struct esc_pending *ep, struct vnode *vp,
    struct ucred *cred)
{

	esc_fill_event_file(&ep->ep_msg.em_event_data.readlink.file, vp, cred);
}

static void
esc_fill_event_readdir(struct esc_pending *ep, struct vnode *dvp,
    struct ucred *cred)
{

	esc_fill_event_file(&ep->ep_msg.em_event_data.readdir.dir, dvp, cred);
}

static void
esc_fill_event_lookup(struct esc_pending *ep, struct vnode *dvp,
    struct componentname *cnp, struct ucred *cred)
{

	esc_fill_event_file(&ep->ep_msg.em_event_data.lookup.dir, dvp, cred);
	esc_copy_component(ep->ep_msg.em_event_data.lookup.name,
	    sizeof(ep->ep_msg.em_event_data.lookup.name), cnp);
}

static void
esc_fill_event_create(struct esc_pending *ep, struct vnode *dvp,
    struct vattr *vap, struct componentname *cnp, struct ucred *cred)
{

	esc_fill_event_file(&ep->ep_msg.em_event_data.create.dir, dvp, cred);
	esc_fill_file_from_vap(&ep->ep_msg.em_event_data.create.file, vap);
	esc_copy_component(ep->ep_msg.em_event_data.create.file.ef_path,
	    sizeof(ep->ep_msg.em_event_data.create.file.ef_path), cnp);
	esc_event_join_component(ep->ep_msg.em_event_data.create.file.ef_path,
	    sizeof(ep->ep_msg.em_event_data.create.file.ef_path),
	    ep->ep_msg.em_event_data.create.dir.ef_path);
	if (vap != NULL)
		ep->ep_msg.em_event_data.create.mode = vap->va_mode;
}

static void
esc_fill_event_unlink(struct esc_pending *ep, struct vnode *dvp,
    struct vnode *vp, struct componentname *cnp, struct ucred *cred)
{

	esc_fill_event_file(&ep->ep_msg.em_event_data.unlink.dir, dvp, cred);
	esc_fill_event_file(&ep->ep_msg.em_event_data.unlink.file, vp, cred);
	esc_copy_component(ep->ep_msg.em_event_data.unlink.file.ef_path,
	    sizeof(ep->ep_msg.em_event_data.unlink.file.ef_path), cnp);
	esc_event_join_component(ep->ep_msg.em_event_data.unlink.file.ef_path,
	    sizeof(ep->ep_msg.em_event_data.unlink.file.ef_path),
	    ep->ep_msg.em_event_data.unlink.dir.ef_path);
}

static void
esc_fill_event_rename(struct esc_pending *ep,
    const struct esc_rename_ctx *rename_ctx, struct vnode *dvp,
    struct componentname *cnp, struct ucred *cred)
{

	if (rename_ctx != NULL) {
		ep->ep_msg.em_event_data.rename.src_dir =
		    rename_ctx->er_src_dir;
		ep->ep_msg.em_event_data.rename.src_file =
		    rename_ctx->er_src_file;
	}
	esc_fill_event_file(&ep->ep_msg.em_event_data.rename.dst_dir, dvp, cred);
	esc_copy_component(ep->ep_msg.em_event_data.rename.dst_name,
	    sizeof(ep->ep_msg.em_event_data.rename.dst_name), cnp);
}

static void
esc_fill_event_link(struct esc_pending *ep, struct vnode *vp,
    struct vnode *dvp, struct componentname *cnp, struct ucred *cred)
{

	esc_fill_event_file(&ep->ep_msg.em_event_data.link.target, vp, cred);
	esc_fill_event_file(&ep->ep_msg.em_event_data.link.dir, dvp, cred);
	esc_copy_component(ep->ep_msg.em_event_data.link.name,
	    sizeof(ep->ep_msg.em_event_data.link.name), cnp);
}

static void
esc_fill_event_kldload(struct esc_pending *ep, struct vnode *vp,
    struct ucred *cred)
{

	esc_fill_event_file(&ep->ep_msg.em_event_data.kldload.file, vp, cred);
}

static void
esc_fill_event_mmap(struct esc_pending *ep, struct vnode *vp, int prot,
    int mmap_flags, struct ucred *cred)
{

	esc_fill_event_file(&ep->ep_msg.em_event_data.mmap.file, vp, cred);
	ep->ep_msg.em_event_data.mmap.prot = prot;
	ep->ep_msg.em_event_data.mmap.flags = mmap_flags;
}

static void
esc_fill_event_mprotect(struct esc_pending *ep, struct vnode *vp, int prot,
    struct ucred *cred)
{

	esc_fill_event_file(&ep->ep_msg.em_event_data.mprotect.file, vp, cred);
	ep->ep_msg.em_event_data.mprotect.prot = prot;
}

static void
esc_fill_event_setmode(struct esc_pending *ep, struct vnode *vp, mode_t mode,
    struct ucred *cred)
{

	esc_fill_event_file(&ep->ep_msg.em_event_data.setmode.file, vp, cred);
	ep->ep_msg.em_event_data.setmode.mode = mode;
}

static void
esc_fill_event_setowner(struct esc_pending *ep, struct vnode *vp, uid_t uid,
    gid_t gid, struct ucred *cred)
{

	esc_fill_event_file(&ep->ep_msg.em_event_data.setowner.file, vp, cred);
	ep->ep_msg.em_event_data.setowner.uid = uid;
	ep->ep_msg.em_event_data.setowner.gid = gid;
}

static void
esc_fill_event_setflags(struct esc_pending *ep, struct vnode *vp,
    u_long flags, struct ucred *cred)
{

	esc_fill_event_file(&ep->ep_msg.em_event_data.setflags.file, vp, cred);
	ep->ep_msg.em_event_data.setflags.flags = flags;
}

static void
esc_fill_event_setutimes(struct esc_pending *ep, struct vnode *vp,
    struct timespec atime, struct timespec mtime, struct ucred *cred)
{

	esc_fill_event_file(&ep->ep_msg.em_event_data.setutimes.file, vp, cred);
	ep->ep_msg.em_event_data.setutimes.atime = atime;
	ep->ep_msg.em_event_data.setutimes.mtime = mtime;
}

static void
esc_fill_event_chdir(struct esc_pending *ep, struct vnode *dvp,
    struct ucred *cred)
{

	esc_fill_event_file(&ep->ep_msg.em_event_data.chdir.dir, dvp, cred);
}

static void
esc_fill_event_chroot(struct esc_pending *ep, struct vnode *dvp,
    struct ucred *cred)
{

	esc_fill_event_file(&ep->ep_msg.em_event_data.chroot.dir, dvp, cred);
}

static void
esc_fill_event_setextattr(struct esc_pending *ep, struct vnode *vp,
    int attrnamespace, const char *attrname, struct ucred *cred)
{

	esc_fill_event_file(&ep->ep_msg.em_event_data.setextattr.file, vp, cred);
	ep->ep_msg.em_event_data.setextattr.attrnamespace = attrnamespace;
	if (attrname != NULL) {
		strlcpy(ep->ep_msg.em_event_data.setextattr.name, attrname,
		    sizeof(ep->ep_msg.em_event_data.setextattr.name));
	}
}

static void
esc_fill_event_getextattr(struct esc_pending *ep, struct vnode *vp,
    int attrnamespace, const char *attrname, struct ucred *cred)
{

	esc_fill_event_file(&ep->ep_msg.em_event_data.getextattr.file, vp, cred);
	ep->ep_msg.em_event_data.getextattr.attrnamespace = attrnamespace;
	if (attrname != NULL) {
		strlcpy(ep->ep_msg.em_event_data.getextattr.name, attrname,
		    sizeof(ep->ep_msg.em_event_data.getextattr.name));
	}
}

static void
esc_fill_event_deleteextattr(struct esc_pending *ep, struct vnode *vp,
    int attrnamespace, const char *attrname, struct ucred *cred)
{

	esc_fill_event_file(&ep->ep_msg.em_event_data.deleteextattr.file, vp, cred);
	ep->ep_msg.em_event_data.deleteextattr.attrnamespace = attrnamespace;
	if (attrname != NULL) {
		strlcpy(ep->ep_msg.em_event_data.deleteextattr.name, attrname,
		    sizeof(ep->ep_msg.em_event_data.deleteextattr.name));
	}
}

static void
esc_fill_event_listextattr(struct esc_pending *ep, struct vnode *vp,
    int attrnamespace, struct ucred *cred)
{

	esc_fill_event_file(&ep->ep_msg.em_event_data.listextattr.file, vp, cred);
	ep->ep_msg.em_event_data.listextattr.attrnamespace = attrnamespace;
	ep->ep_msg.em_event_data.listextattr.name[0] = '\0';
}

static void
esc_fill_event_acl(esc_event_acl_t *acl, struct vnode *vp, acl_type_t type,
    struct ucred *cred)
{

	esc_fill_event_file(&acl->file, vp, cred);
	acl->type = (int)type;
}

static void
esc_fill_event_getacl(struct esc_pending *ep, struct vnode *vp,
    acl_type_t type, struct ucred *cred)
{

	esc_fill_event_acl(&ep->ep_msg.em_event_data.getacl, vp, type, cred);
}

static void
esc_fill_event_setacl(struct esc_pending *ep, struct vnode *vp,
    acl_type_t type, struct ucred *cred)
{

	esc_fill_event_acl(&ep->ep_msg.em_event_data.setacl, vp, type, cred);
}

static void
esc_fill_event_deleteacl(struct esc_pending *ep, struct vnode *vp,
    acl_type_t type, struct ucred *cred)
{

	esc_fill_event_acl(&ep->ep_msg.em_event_data.deleteacl, vp, type, cred);
}

static void
esc_fill_event_relabel(struct esc_pending *ep, struct vnode *vp,
    struct ucred *cred)
{

	esc_fill_event_file(&ep->ep_msg.em_event_data.relabel.file, vp, cred);
}

static void
esc_fill_event_signal(struct esc_pending *ep, struct proc *target_proc,
    int signum)
{

	if (target_proc != NULL) {
		PROC_LOCK(target_proc);
		esc_fill_process(&ep->ep_msg.em_event_data.signal.target,
		    target_proc, NULL);
		PROC_UNLOCK(target_proc);
	}
	ep->ep_msg.em_event_data.signal.signum = signum;
}

static void
esc_fill_event_setuid(struct esc_pending *ep, uid_t uid)
{

	ep->ep_msg.em_event_data.setuid.uid = uid;
}

static void
esc_fill_event_setgid(struct esc_pending *ep, gid_t gid)
{

	ep->ep_msg.em_event_data.setgid.gid = gid;
}

/*
 * Helper: Generate an event and optionally wait for AUTH response.
 * NOSLEEP hooks (info.nosleep=true) use cache-only authorization.
 */
static int
esc_generate_vnode_event(esc_event_type_t event,
    const struct esc_vnode_event_info *info)
{
	struct proc *p = curthread->td_proc;
	struct esc_pending *ep;
	esc_event_type_t notify_event;
	int error = 0;
	struct ucred *cred = info->cred;
	struct vnode *vp = info->vp;
	struct vnode *dvp = info->dvp;
	struct componentname *cnp = info->cnp;
	struct vattr *vap = info->vap;
	struct proc *target_proc = info->target_proc;
	struct esc_rename_ctx *rename_ctx = info->rename_ctx;
	accmode_t accmode = info->accmode;
	int prot = info->prot;
	int mmap_flags = info->mmap_flags;
	int attrnamespace = info->attrnamespace;
	const char *attrname = info->attrname;
	acl_type_t acl_type = info->acl_type;
	int signum = info->signum;
	uid_t uid = info->uid;
	gid_t gid = info->gid;
	mode_t mode = info->mode;
	uid_t owner_uid = info->owner_uid;
	gid_t owner_gid = info->owner_gid;
	u_long fflags = info->fflags;
	struct timespec atime = info->atime;
	struct timespec mtime = info->mtime;
	struct socket *so = info->socket;
	struct sockaddr *sa = info->sockaddr;
	int reboot_howto = info->reboot_howto;
	const char *sysctl_name = info->sysctl_name;
	int sysctl_op = info->sysctl_op;
	const char *kenv_name = info->kenv_name;
	int kenv_op = info->kenv_op;

	if (!esc_softc.sc_active || p == NULL)
		return (0);

	notify_event = ESC_EVENT_IS_AUTH(event) ? esc_auth_to_notify(event) : event;

	/* Allocate pending event */
	ep = esc_pending_alloc(event, p);
	if (ep == NULL) {
		atomic_add_64(&esc_softc.sc_alloc_failures, 1);
		if (ESC_EVENT_IS_AUTH(event))
			return (esc_default_action == ESC_AUTH_DENY ? EACCES : 0);
		return (0);
	}

	/*
	 * Fill event-specific data based on event type.
	 */
	{
		switch (event) {
		case ESC_EVENT_AUTH_OPEN:
		case ESC_EVENT_NOTIFY_OPEN:
			esc_fill_event_open(ep, vp, accmode, cred);
			break;
		case ESC_EVENT_AUTH_ACCESS:
		case ESC_EVENT_NOTIFY_ACCESS:
			esc_fill_event_access(ep, vp, accmode, cred);
			break;
		case ESC_EVENT_AUTH_READ:
		case ESC_EVENT_NOTIFY_READ:
		case ESC_EVENT_AUTH_WRITE:
		case ESC_EVENT_NOTIFY_WRITE:
			esc_fill_event_rw(ep, vp, cred);
			break;
		case ESC_EVENT_AUTH_STAT:
		case ESC_EVENT_NOTIFY_STAT:
			esc_fill_event_stat(ep, vp, cred);
			break;
		case ESC_EVENT_AUTH_POLL:
		case ESC_EVENT_NOTIFY_POLL:
			esc_fill_event_poll(ep, vp, cred);
			break;
		case ESC_EVENT_AUTH_REVOKE:
		case ESC_EVENT_NOTIFY_REVOKE:
			esc_fill_event_revoke(ep, vp, cred);
			break;
		case ESC_EVENT_AUTH_READLINK:
		case ESC_EVENT_NOTIFY_READLINK:
			esc_fill_event_readlink(ep, vp, cred);
			break;
		case ESC_EVENT_AUTH_READDIR:
		case ESC_EVENT_NOTIFY_READDIR:
			esc_fill_event_readdir(ep, dvp, cred);
			break;
		case ESC_EVENT_AUTH_LOOKUP:
		case ESC_EVENT_NOTIFY_LOOKUP:
			esc_fill_event_lookup(ep, dvp, cnp, cred);
			break;
		case ESC_EVENT_AUTH_CREATE:
		case ESC_EVENT_NOTIFY_CREATE:
			esc_fill_event_create(ep, dvp, vap, cnp, cred);
			break;
		case ESC_EVENT_AUTH_UNLINK:
		case ESC_EVENT_NOTIFY_UNLINK:
			esc_fill_event_unlink(ep, dvp, vp, cnp, cred);
			break;
		case ESC_EVENT_AUTH_RENAME:
		case ESC_EVENT_NOTIFY_RENAME:
			esc_fill_event_rename(ep, rename_ctx, dvp, cnp, cred);
			break;
		case ESC_EVENT_AUTH_LINK:
			esc_fill_event_link(ep, vp, dvp, cnp, cred);
			break;
		case ESC_EVENT_AUTH_KLDLOAD:
		case ESC_EVENT_NOTIFY_KLDLOAD:
			esc_fill_event_kldload(ep, vp, cred);
			break;
		case ESC_EVENT_AUTH_MMAP:
			esc_fill_event_mmap(ep, vp, prot, mmap_flags, cred);
			break;
		case ESC_EVENT_AUTH_MPROTECT:
			esc_fill_event_mprotect(ep, vp, prot, cred);
			break;
		case ESC_EVENT_AUTH_SETMODE:
		case ESC_EVENT_NOTIFY_SETMODE:
			esc_fill_event_setmode(ep, vp, mode, cred);
			break;
		case ESC_EVENT_AUTH_SETOWNER:
		case ESC_EVENT_NOTIFY_SETOWNER:
			esc_fill_event_setowner(ep, vp, owner_uid, owner_gid, cred);
			break;
		case ESC_EVENT_AUTH_SETFLAGS:
		case ESC_EVENT_NOTIFY_SETFLAGS:
			esc_fill_event_setflags(ep, vp, fflags, cred);
			break;
		case ESC_EVENT_AUTH_SETUTIMES:
		case ESC_EVENT_NOTIFY_SETUTIMES:
			esc_fill_event_setutimes(ep, vp, atime, mtime, cred);
			break;
		case ESC_EVENT_AUTH_CHDIR:
			esc_fill_event_chdir(ep, dvp, cred);
			break;
		case ESC_EVENT_AUTH_CHROOT:
			esc_fill_event_chroot(ep, dvp, cred);
			break;
		case ESC_EVENT_AUTH_SETEXTATTR:
			esc_fill_event_setextattr(ep, vp, attrnamespace,
			    attrname, cred);
			break;
		case ESC_EVENT_AUTH_GETEXTATTR:
		case ESC_EVENT_NOTIFY_GETEXTATTR:
			esc_fill_event_getextattr(ep, vp, attrnamespace,
			    attrname, cred);
			break;
		case ESC_EVENT_AUTH_DELETEEXTATTR:
		case ESC_EVENT_NOTIFY_DELETEEXTATTR:
			esc_fill_event_deleteextattr(ep, vp, attrnamespace,
			    attrname, cred);
			break;
		case ESC_EVENT_AUTH_LISTEXTATTR:
		case ESC_EVENT_NOTIFY_LISTEXTATTR:
			esc_fill_event_listextattr(ep, vp, attrnamespace, cred);
			break;
		case ESC_EVENT_AUTH_GETACL:
		case ESC_EVENT_NOTIFY_GETACL:
			esc_fill_event_getacl(ep, vp, acl_type, cred);
			break;
		case ESC_EVENT_AUTH_SETACL:
		case ESC_EVENT_NOTIFY_SETACL:
			esc_fill_event_setacl(ep, vp, acl_type, cred);
			break;
		case ESC_EVENT_AUTH_DELETEACL:
		case ESC_EVENT_NOTIFY_DELETEACL:
			esc_fill_event_deleteacl(ep, vp, acl_type, cred);
			break;
		case ESC_EVENT_AUTH_RELABEL:
		case ESC_EVENT_NOTIFY_RELABEL:
			esc_fill_event_relabel(ep, vp, cred);
			break;
		case ESC_EVENT_NOTIFY_SIGNAL:
			esc_fill_event_signal(ep, target_proc, signum);
			break;
		case ESC_EVENT_AUTH_PTRACE:
		case ESC_EVENT_NOTIFY_PTRACE:
			if (target_proc != NULL) {
				PROC_LOCK(target_proc);
				esc_fill_process(
				    &ep->ep_msg.em_event_data.ptrace.target,
				    target_proc, NULL);
				PROC_UNLOCK(target_proc);
			}
			break;
		case ESC_EVENT_NOTIFY_SETUID:
			esc_fill_event_setuid(ep, uid);
			break;
		case ESC_EVENT_NOTIFY_SETGID:
			esc_fill_event_setgid(ep, gid);
			break;
		case ESC_EVENT_NOTIFY_SOCKET_CONNECT:
			esc_fill_socket_info(
			    &ep->ep_msg.em_event_data.socket_connect.socket, so);
			esc_fill_sockaddr(
			    &ep->ep_msg.em_event_data.socket_connect.address, sa);
			break;
		case ESC_EVENT_NOTIFY_SOCKET_BIND:
			esc_fill_socket_info(
			    &ep->ep_msg.em_event_data.socket_bind.socket, so);
			esc_fill_sockaddr(
			    &ep->ep_msg.em_event_data.socket_bind.address, sa);
			break;
		case ESC_EVENT_NOTIFY_SOCKET_LISTEN:
			esc_fill_socket_info(
			    &ep->ep_msg.em_event_data.socket_listen.socket, so);
			break;
		case ESC_EVENT_NOTIFY_SOCKET_CREATE:
			ep->ep_msg.em_event_data.socket_create.domain =
			    info->socket_domain;
			ep->ep_msg.em_event_data.socket_create.type =
			    info->socket_type;
			ep->ep_msg.em_event_data.socket_create.protocol =
			    info->socket_protocol;
			break;
		case ESC_EVENT_NOTIFY_SOCKET_ACCEPT:
			esc_fill_socket_info(
			    &ep->ep_msg.em_event_data.socket_accept.socket, so);
			break;
		case ESC_EVENT_NOTIFY_SOCKET_SEND:
			esc_fill_socket_info(
			    &ep->ep_msg.em_event_data.socket_send.socket, so);
			break;
		case ESC_EVENT_NOTIFY_SOCKET_RECEIVE:
			esc_fill_socket_info(
			    &ep->ep_msg.em_event_data.socket_receive.socket, so);
			break;
		case ESC_EVENT_NOTIFY_SOCKET_STAT:
			esc_fill_socket_info(
			    &ep->ep_msg.em_event_data.socket_stat.socket, so);
			break;
		case ESC_EVENT_NOTIFY_SOCKET_POLL:
			esc_fill_socket_info(
			    &ep->ep_msg.em_event_data.socket_poll.socket, so);
			break;
		case ESC_EVENT_NOTIFY_PIPE_READ:
		case ESC_EVENT_NOTIFY_PIPE_WRITE:
		case ESC_EVENT_NOTIFY_PIPE_STAT:
		case ESC_EVENT_NOTIFY_PIPE_POLL:
			ep->ep_msg.em_event_data.pipe.pipe_id =
			    (uint64_t)(uintptr_t)info->pipepair;
			break;
		case ESC_EVENT_NOTIFY_PIPE_IOCTL:
			ep->ep_msg.em_event_data.pipe.pipe_id =
			    (uint64_t)(uintptr_t)info->pipepair;
			ep->ep_msg.em_event_data.pipe.ioctl_cmd =
			    info->ioctl_cmd;
			break;
		case ESC_EVENT_NOTIFY_MOUNT_STAT:
			if (info->mp != NULL) {
				if (info->mp->mnt_vfc != NULL)
					strlcpy(ep->ep_msg.em_event_data.mount_stat.fstype,
					    info->mp->mnt_vfc->vfc_name,
					    sizeof(ep->ep_msg.em_event_data.mount_stat.fstype));
				strlcpy(ep->ep_msg.em_event_data.mount_stat.fspath,
				    info->mp->mnt_stat.f_mntonname,
				    sizeof(ep->ep_msg.em_event_data.mount_stat.fspath));
			}
			break;
		case ESC_EVENT_NOTIFY_PRIV_CHECK:
			ep->ep_msg.em_event_data.priv.priv = info->priv;
			break;
		case ESC_EVENT_NOTIFY_PROC_SCHED:
			if (info->target_proc != NULL) {
				if (info->nosleep) {
					/*
					 * NOSLEEP context: fill minimal info
					 * without PROC_LOCK. The scheduler holds
					 * a reference so pid/comm are stable.
					 * Cannot safely access p_stats for genid.
					 */
					esc_process_t *tp =
					    &ep->ep_msg.em_event_data.proc_sched.target;
					tp->ep_pid = info->target_proc->p_pid;
					tp->ep_token.ept_id = info->target_proc->p_pid;
					tp->ep_token.ept_genid = 0;
					strlcpy(tp->ep_comm,
					    info->target_proc->p_comm,
					    sizeof(tp->ep_comm));
				} else {
					PROC_LOCK(info->target_proc);
					esc_fill_process(
					    &ep->ep_msg.em_event_data.proc_sched.target,
					    info->target_proc, NULL);
					PROC_UNLOCK(info->target_proc);
				}
			}
			break;
		case ESC_EVENT_NOTIFY_REBOOT:
			ep->ep_msg.em_event_data.reboot.howto = reboot_howto;
			break;
		case ESC_EVENT_NOTIFY_SYSCTL:
			if (sysctl_name != NULL)
				strlcpy(ep->ep_msg.em_event_data.sysctl.name,
				    sysctl_name,
				    sizeof(ep->ep_msg.em_event_data.sysctl.name));
			ep->ep_msg.em_event_data.sysctl.op = sysctl_op;
			break;
		case ESC_EVENT_NOTIFY_KENV:
			if (kenv_name != NULL)
				strlcpy(ep->ep_msg.em_event_data.kenv.name,
				    kenv_name,
				    sizeof(ep->ep_msg.em_event_data.kenv.name));
			ep->ep_msg.em_event_data.kenv.op = kenv_op;
			break;
		case ESC_EVENT_AUTH_SWAPON:
		case ESC_EVENT_NOTIFY_SWAPON:
			if (vp != NULL)
				esc_fill_file(&ep->ep_msg.em_event_data.swapon.file,
				    vp, cred);
			break;
		case ESC_EVENT_AUTH_SWAPOFF:
		case ESC_EVENT_NOTIFY_SWAPOFF:
			if (vp != NULL)
				esc_fill_file(&ep->ep_msg.em_event_data.swapoff.file,
				    vp, cred);
			break;
		default:
			break;
		}
	}

	/* Use non-blocking delivery for NOSLEEP hooks */
	if (info->nosleep) {
		esc_deliver_notify_nosleep(ep, p);
		esc_pending_rele(ep);
		return (0);
	}

	error = esc_dispatch_event(ep, p, cred, notify_event);
	esc_pending_rele(ep);
	return (error);
}

/*
 * Generate exec event with arguments
 *
 * Captures argv from imgp->args for exec events.
 */
static int
esc_generate_exec_event(struct ucred *cred, struct vnode *vp,
    struct image_params *imgp)
{
	struct proc *p = curthread->td_proc;
	struct esc_pending *ep;
	esc_event_type_t event = ESC_EVENT_AUTH_EXEC;
	esc_event_type_t notify_event;
	int error = 0;

	if (!esc_softc.sc_active || p == NULL)
		return (0);

	/*
	 * Skip duplicate exec events when execpath is NULL.
	 * The MAC hook is called twice: once with the path during initial
	 * exec processing, and again during rtld/interpreter handling with
	 * NULL path. We only want to generate one event with the actual path.
	 */
	if (imgp == NULL || imgp->execpath == NULL)
		return (0);

	notify_event = esc_auth_to_notify(event);

	ep = esc_pending_alloc(event, p);
	if (ep == NULL) {
		atomic_add_64(&esc_softc.sc_alloc_failures, 1);
		if (ESC_EVENT_IS_AUTH(event))
			return (esc_default_action == ESC_AUTH_DENY ? EACCES : 0);
		return (0);
	}

	if (vp != NULL)
		esc_fill_file(&ep->ep_msg.em_event_data.exec.executable, vp,
		    cred);

	/* Pre-exec snapshot */
	PROC_LOCK(p);
	esc_fill_process(&ep->ep_msg.em_event_data.exec.target, p, NULL);
	PROC_UNLOCK(p);

	if (imgp != NULL && imgp->execpath != NULL) {
		strlcpy(ep->ep_msg.em_event_data.exec.executable.ef_path,
		    imgp->execpath,
		    sizeof(ep->ep_msg.em_event_data.exec.executable.ef_path));
		strlcpy(ep->ep_msg.em_process.ep_path, imgp->execpath,
		    sizeof(ep->ep_msg.em_process.ep_path));
		strlcpy(ep->ep_msg.em_event_data.exec.target.ep_path,
		    imgp->execpath,
		    sizeof(ep->ep_msg.em_event_data.exec.target.ep_path));
	}

	if (imgp != NULL && imgp->args != NULL) {
		struct image_args *args = imgp->args;
		esc_event_exec_t *exec = &ep->ep_msg.em_event_data.exec;
		size_t argv_len, envp_len, total_len;
		size_t copy_argv, copy_envp;
		char *envv_start;
		size_t offset = 0;

		exec->argc = args->argc;
		exec->envc = args->envc;
		exec->argv_len = 0;
		exec->envp_len = 0;
		exec->flags = 0;

		/* Calculate argv length (from begin_argv to begin_envv) */
		argv_len = 0;
		envp_len = 0;
		if (args->begin_argv != NULL) {
			envv_start = exec_args_get_begin_envv(args);
			if (envv_start != NULL && envv_start > args->begin_argv) {
				argv_len = envv_start - args->begin_argv;
			} else if (args->endp != NULL &&
			    args->endp > args->begin_argv) {
				argv_len = args->endp - args->begin_argv;
				envv_start = NULL;
			}

			/* Calculate envp length */
			if (envv_start != NULL && args->endp != NULL &&
			    args->endp > envv_start) {
				envp_len = args->endp - envv_start;
			}
		}

		/* Copy argv (truncate if necessary) */
		copy_argv = argv_len;
		if (copy_argv > ESC_EXEC_ARGS_MAX) {
			copy_argv = ESC_EXEC_ARGS_MAX;
			exec->flags |= EE_FLAG_ARGV_TRUNCATED;
		}
		if (copy_argv > 0 && args->begin_argv != NULL) {
			bcopy(args->begin_argv, exec->args, copy_argv);
			exec->argv_len = copy_argv;
			offset = copy_argv;
		}

		/* Copy envp if there's room */
		total_len = offset + envp_len;
		if (total_len > ESC_EXEC_ARGS_MAX) {
			copy_envp = ESC_EXEC_ARGS_MAX - offset;
			if (envp_len > 0)
				exec->flags |= EE_FLAG_ENVP_TRUNCATED;
		} else {
			copy_envp = envp_len;
		}
		if (copy_envp > 0 && envv_start != NULL) {
			bcopy(envv_start, exec->args + offset, copy_envp);
			exec->envp_len = copy_envp;
		}
	}

	error = esc_dispatch_event(ep, p, cred, notify_event);
	esc_pending_rele(ep);
	return (error);
}

/*
 * MAC hook: vnode_check_exec
 *
 * Called when a process attempts to execute a file.
 * This is sleepable - can block for AUTH response.
 */
static int
esc_mac_vnode_check_exec(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct image_params *imgp,
    struct label *execlabel)
{

	return (esc_generate_exec_event(cred, vp, imgp));
}

/*
 * MAC hook: vnode_check_open
 */
static int
esc_mac_vnode_check_open(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, accmode_t accmode)
{

	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.accmode = accmode;

	return (esc_generate_vnode_event(ESC_EVENT_AUTH_OPEN, &info));
}

/*
 * MAC hook: vnode_check_create
 */
static int
esc_mac_vnode_check_create(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct componentname *cnp, struct vattr *vap)
{

	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.dvp = dvp;
	info.cnp = cnp;
	info.vap = vap;

	return (esc_generate_vnode_event(ESC_EVENT_AUTH_CREATE, &info));
}

/*
 * MAC hook: vnode_check_unlink
 */
static int
esc_mac_vnode_check_unlink(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp)
{

	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.dvp = dvp;
	info.cnp = cnp;

	return (esc_generate_vnode_event(ESC_EVENT_AUTH_UNLINK, &info));
}

/*
 * MAC hook: vnode_check_rename_from
 */
static int
esc_mac_vnode_check_rename_from(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp)
{

	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.dvp = dvp;
	info.cnp = cnp;


	esc_rename_cache_store(curthread, &info);
	return (0);
}

/*
 * MAC hook: vnode_check_rename_to
 */
static int
esc_mac_vnode_check_rename_to(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    int samedir, struct componentname *cnp)
{
	int error;
	struct esc_rename_ctx *ctx;
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.dvp = dvp;
	info.cnp = cnp;


	(void)samedir;
	ctx = esc_rename_cache_take(curthread);
	info.rename_ctx = ctx;
	if (ctx == NULL)
		return (0);

	error = esc_generate_vnode_event(ESC_EVENT_AUTH_RENAME, &info);
	free(ctx, M_ESC);
	return (error);
}

/*
 * MAC hook: vnode_check_link
 */
static int
esc_mac_vnode_check_link(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp)
{

	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.dvp = dvp;
	info.cnp = cnp;

	return (esc_generate_vnode_event(ESC_EVENT_AUTH_LINK, &info));
}

/*
 * MAC hook: vnode_check_access
 */
static int
esc_mac_vnode_check_access(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, accmode_t accmode)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.accmode = accmode;

	return (esc_generate_vnode_event(ESC_EVENT_AUTH_ACCESS, &info));
}

/*
 * MAC hook: vnode_check_read
 */
static int
esc_mac_vnode_check_read(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(active_cred);

	info.vp = vp;

	return (esc_generate_vnode_event(ESC_EVENT_AUTH_READ, &info));
}

/*
 * MAC hook: vnode_check_write
 */
static int
esc_mac_vnode_check_write(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(active_cred);

	info.vp = vp;

	return (esc_generate_vnode_event(ESC_EVENT_AUTH_WRITE, &info));
}

/*
 * MAC hook: vnode_check_stat
 */
static int
esc_mac_vnode_check_stat(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(active_cred);

	info.vp = vp;

	return (esc_generate_vnode_event(ESC_EVENT_AUTH_STAT, &info));
}

/*
 * MAC hook: vnode_check_poll
 */
static int
esc_mac_vnode_check_poll(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(active_cred);

	info.vp = vp;

	return (esc_generate_vnode_event(ESC_EVENT_AUTH_POLL, &info));
}

/*
 * MAC hook: vnode_check_readdir
 */
static int
esc_mac_vnode_check_readdir(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.dvp = dvp;

	return (esc_generate_vnode_event(ESC_EVENT_AUTH_READDIR, &info));
}

/*
 * MAC hook: vnode_check_readlink
 */
static int
esc_mac_vnode_check_readlink(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.vp = vp;

	return (esc_generate_vnode_event(ESC_EVENT_AUTH_READLINK, &info));
}

/*
 * MAC hook: vnode_check_revoke
 */
static int
esc_mac_vnode_check_revoke(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.vp = vp;

	return (esc_generate_vnode_event(ESC_EVENT_AUTH_REVOKE, &info));
}

/*
 * MAC hook: vnode_check_lookup
 */
static int
esc_mac_vnode_check_lookup(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct componentname *cnp)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.dvp = dvp;
	info.cnp = cnp;

	return (esc_generate_vnode_event(ESC_EVENT_AUTH_LOOKUP, &info));
}

/*
 * MAC hook: vnode_check_setmode
 */
static int
esc_mac_vnode_check_setmode(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, mode_t mode)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.mode = mode;

	return (esc_generate_vnode_event(ESC_EVENT_AUTH_SETMODE, &info));
}

/*
 * MAC hook: vnode_check_setowner
 */
static int
esc_mac_vnode_check_setowner(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, uid_t uid, gid_t gid)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.owner_uid = uid;
	info.owner_gid = gid;

	return (esc_generate_vnode_event(ESC_EVENT_AUTH_SETOWNER, &info));
}

/*
 * MAC hook: vnode_check_setflags
 */
static int
esc_mac_vnode_check_setflags(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, u_long flags)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.fflags = flags;

	return (esc_generate_vnode_event(ESC_EVENT_AUTH_SETFLAGS, &info));
}

/*
 * MAC hook: vnode_check_setutimes
 */
static int
esc_mac_vnode_check_setutimes(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct timespec atime, struct timespec mtime)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.atime = atime;
	info.mtime = mtime;

	return (esc_generate_vnode_event(ESC_EVENT_AUTH_SETUTIMES, &info));
}

/*
 * MAC hook: vnode_check_chdir
 */
static int
esc_mac_vnode_check_chdir(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.dvp = dvp;

	return (esc_generate_vnode_event(ESC_EVENT_AUTH_CHDIR, &info));
}

/*
 * MAC hook: vnode_check_chroot
 */
static int
esc_mac_vnode_check_chroot(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.dvp = dvp;

	return (esc_generate_vnode_event(ESC_EVENT_AUTH_CHROOT, &info));
}

/*
 * MAC hook: vnode_check_mmap
 */
static int
esc_mac_vnode_check_mmap(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int prot, int flags)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.prot = prot;
	info.mmap_flags = flags;

	return (esc_generate_vnode_event(ESC_EVENT_AUTH_MMAP, &info));
}

/*
 * MAC hook: vnode_check_mprotect
 */
static int
esc_mac_vnode_check_mprotect(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int prot)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.prot = prot;

	return (esc_generate_vnode_event(ESC_EVENT_AUTH_MPROTECT, &info));
}

/*
 * MAC hook: vnode_check_setextattr
 */
static int
esc_mac_vnode_check_setextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.attrnamespace = attrnamespace;
	info.attrname = name;

	return (esc_generate_vnode_event(ESC_EVENT_AUTH_SETEXTATTR, &info));
}

/*
 * MAC hook: vnode_check_getextattr
 */
static int
esc_mac_vnode_check_getextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.attrnamespace = attrnamespace;
	info.attrname = name;

	return (esc_generate_vnode_event(ESC_EVENT_AUTH_GETEXTATTR, &info));
}

/*
 * MAC hook: vnode_check_deleteextattr
 */
static int
esc_mac_vnode_check_deleteextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.attrnamespace = attrnamespace;
	info.attrname = name;

	return (esc_generate_vnode_event(ESC_EVENT_AUTH_DELETEEXTATTR, &info));
}

/*
 * MAC hook: vnode_check_listextattr
 */
static int
esc_mac_vnode_check_listextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.attrnamespace = attrnamespace;

	return (esc_generate_vnode_event(ESC_EVENT_AUTH_LISTEXTATTR, &info));
}

/*
 * MAC hook: vnode_check_getacl
 */
static int
esc_mac_vnode_check_getacl(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.acl_type = type;

	return (esc_generate_vnode_event(ESC_EVENT_AUTH_GETACL, &info));
}

/*
 * MAC hook: vnode_check_setacl
 */
static int
esc_mac_vnode_check_setacl(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type, struct acl *acl)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.acl_type = type;


	(void)acl;
	return (esc_generate_vnode_event(ESC_EVENT_AUTH_SETACL, &info));
}

/*
 * MAC hook: vnode_check_deleteacl
 */
static int
esc_mac_vnode_check_deleteacl(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.vp = vp;
	info.acl_type = type;

	return (esc_generate_vnode_event(ESC_EVENT_AUTH_DELETEACL, &info));
}

/*
 * MAC hook: vnode_check_relabel
 */
static int
esc_mac_vnode_check_relabel(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *newlabel)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.vp = vp;


	(void)newlabel;
	return (esc_generate_vnode_event(ESC_EVENT_AUTH_RELABEL, &info));
}

/*
 * MAC hook: kld_check_load
 */
static int
esc_mac_kld_check_load(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{

	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.vp = vp;

	return (esc_generate_vnode_event(ESC_EVENT_AUTH_KLDLOAD, &info));
}

/*
 * MAC hook: proc_check_signal
 */
static int
esc_mac_proc_check_signal(struct ucred *cred, struct proc *p, int signum)
{
	struct esc_pending *ep;
	struct proc *curp = curthread->td_proc;

	if (!esc_softc.sc_active)
		return (0);

	ep = esc_pending_alloc(ESC_EVENT_NOTIFY_SIGNAL, curp);
	if (ep == NULL)
		return (0);

	PROC_LOCK(p);
	esc_fill_process(&ep->ep_msg.em_event_data.signal.target, p, NULL);
	PROC_UNLOCK(p);
	ep->ep_msg.em_event_data.signal.signum = signum;

	esc_deliver_notify_nosleep(ep, curp);
	esc_pending_rele(ep);
	return (0);
}

/*
 * MAC hook: cred_check_setuid
 */
static int
esc_mac_cred_check_setuid(struct ucred *cred, uid_t uid)
{
	struct esc_pending *ep;
	struct proc *curp = curthread->td_proc;

	if (!esc_softc.sc_active)
		return (0);

	ep = esc_pending_alloc(ESC_EVENT_NOTIFY_SETUID, curp);
	if (ep == NULL)
		return (0);

	ep->ep_msg.em_event_data.setuid.uid = uid;
	esc_deliver_notify_nosleep(ep, curp);
	esc_pending_rele(ep);
	return (0);
}

/*
 * MAC hook: cred_check_setgid
 */
static int
esc_mac_cred_check_setgid(struct ucred *cred, gid_t gid)
{
	struct esc_pending *ep;
	struct proc *curp = curthread->td_proc;

	if (!esc_softc.sc_active)
		return (0);

	ep = esc_pending_alloc(ESC_EVENT_NOTIFY_SETGID, curp);
	if (ep == NULL)
		return (0);

	ep->ep_msg.em_event_data.setgid.gid = gid;
	esc_deliver_notify_nosleep(ep, curp);
	esc_pending_rele(ep);
	return (0);
}

/*
 * MAC hook: proc_check_debug (for ptrace)
 *
 * This hook is sleepable - can block for AUTH response.
 */
static int
esc_mac_proc_check_debug(struct ucred *cred, struct proc *p)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.target_proc = p;

	return (esc_generate_vnode_event(ESC_EVENT_AUTH_PTRACE, &info));
}

static void
esc_fill_sockaddr(esc_sockaddr_t *esa, const struct sockaddr *sa)
{
	memset(esa, 0, sizeof(*esa));

	if (sa == NULL)
		return;

	esa->esa_family = sa->sa_family;

	switch (sa->sa_family) {
	case AF_INET:
		{
			const struct sockaddr_in *sin =
			    (const struct sockaddr_in *)sa;
			if (sa->sa_len < sizeof(struct sockaddr_in))
				break;  /* malformed, leave zeroed */
			esa->esa_port = sin->sin_port;
			esa->esa_addr.v4 = sin->sin_addr.s_addr;
		}
		break;

	case AF_INET6:
		{
			const struct sockaddr_in6 *sin6 =
			    (const struct sockaddr_in6 *)sa;
			if (sa->sa_len < sizeof(struct sockaddr_in6))
				break;  /* malformed, leave zeroed */
			esa->esa_port = sin6->sin6_port;
			memcpy(esa->esa_addr.v6, &sin6->sin6_addr, 16);
		}
		break;

	case AF_UNIX:
		{
			const struct sockaddr_un *sun =
			    (const struct sockaddr_un *)sa;
			size_t maxlen;

			/*
			 * AF_UNIX paths may not be NUL-terminated if the
			 * path fills the entire sun_path buffer.  Use sun_len
			 * to bound the copy and avoid reading past the struct.
			 */
			if (sun->sun_len > offsetof(struct sockaddr_un, sun_path))
				maxlen = sun->sun_len -
				    offsetof(struct sockaddr_un, sun_path);
			else
				maxlen = 0;
			if (maxlen > sizeof(sun->sun_path))
				maxlen = sizeof(sun->sun_path);
			if (maxlen > sizeof(esa->esa_addr.path) - 1)
				maxlen = sizeof(esa->esa_addr.path) - 1;
			memcpy(esa->esa_addr.path, sun->sun_path, maxlen);
			esa->esa_addr.path[maxlen] = '\0';
		}
		break;
	}
}

static void
esc_fill_socket_info(esc_socket_t *es, struct socket *so)
{
	memset(es, 0, sizeof(*es));

	if (so == NULL)
		return;

	/*
	 * Sockets should always have so_proto set, but check defensively
	 * in case we see a partially initialized socket.
	 */
	if (so->so_proto == NULL)
		return;

	if (so->so_proto->pr_domain != NULL)
		es->es_domain = so->so_proto->pr_domain->dom_family;
	es->es_type = so->so_type;
	es->es_protocol = so->so_proto->pr_protocol;
}

/*
 * MAC hook: socket_check_connect
 */
static int
esc_mac_socket_check_connect(struct ucred *cred, struct socket *so,
    struct label *solabel, struct sockaddr *sa)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);
	(void)solabel;

	info.socket = so;
	info.sockaddr = sa;
	info.nosleep = true;

	(void)esc_generate_vnode_event(ESC_EVENT_NOTIFY_SOCKET_CONNECT, &info);
	return (0);
}

/*
 * MAC hook: socket_check_bind
 */
static int
esc_mac_socket_check_bind(struct ucred *cred, struct socket *so,
    struct label *solabel, struct sockaddr *sa)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);
	(void)solabel;

	info.socket = so;
	info.sockaddr = sa;
	info.nosleep = true;

	(void)esc_generate_vnode_event(ESC_EVENT_NOTIFY_SOCKET_BIND, &info);
	return (0);
}

/*
 * MAC hook: socket_check_listen
 */
static int
esc_mac_socket_check_listen(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);
	(void)solabel;

	info.socket = so;
	info.nosleep = true;

	(void)esc_generate_vnode_event(ESC_EVENT_NOTIFY_SOCKET_LISTEN, &info);
	return (0);
}

/*
 * MAC hook: socket_check_create
 */
static int
esc_mac_socket_check_create(struct ucred *cred, int domain, int type,
    int protocol)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.socket_domain = domain;
	info.socket_type = type;
	info.socket_protocol = protocol;
	info.nosleep = true;

	(void)esc_generate_vnode_event(ESC_EVENT_NOTIFY_SOCKET_CREATE, &info);
	return (0);
}

/*
 * MAC hook: socket_check_accept
 */
static int
esc_mac_socket_check_accept(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);
	(void)solabel;

	info.socket = so;
	info.nosleep = true;

	(void)esc_generate_vnode_event(ESC_EVENT_NOTIFY_SOCKET_ACCEPT, &info);
	return (0);
}

/*
 * MAC hook: socket_check_send
 */
static int
esc_mac_socket_check_send(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);
	(void)solabel;

	info.socket = so;
	info.nosleep = true;

	(void)esc_generate_vnode_event(ESC_EVENT_NOTIFY_SOCKET_SEND, &info);
	return (0);
}

/*
 * MAC hook: socket_check_receive
 */
static int
esc_mac_socket_check_receive(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);
	(void)solabel;

	info.socket = so;
	info.nosleep = true;

	(void)esc_generate_vnode_event(ESC_EVENT_NOTIFY_SOCKET_RECEIVE, &info);
	return (0);
}

/*
 * MAC hook: socket_check_stat
 */
static int
esc_mac_socket_check_stat(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);
	(void)solabel;

	info.socket = so;
	info.nosleep = true;

	(void)esc_generate_vnode_event(ESC_EVENT_NOTIFY_SOCKET_STAT, &info);
	return (0);
}

/*
 * MAC hook: socket_check_poll
 */
static int
esc_mac_socket_check_poll(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);
	(void)solabel;

	info.socket = so;
	info.nosleep = true;

	(void)esc_generate_vnode_event(ESC_EVENT_NOTIFY_SOCKET_POLL, &info);
	return (0);
}

/*
 * MAC hook: system_check_reboot
 */
static int
esc_mac_system_check_reboot(struct ucred *cred, int howto)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.reboot_howto = howto;
	info.nosleep = true;

	(void)esc_generate_vnode_event(ESC_EVENT_NOTIFY_REBOOT, &info);
	return (0);
}

/*
 * MAC hook: system_check_sysctl
 */
static int
esc_mac_system_check_sysctl(struct ucred *cred, struct sysctl_oid *oidp,
    void *arg1, int arg2, struct sysctl_req *req)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);
	char name[256];

	/* Build the sysctl name from OID path */
	if (oidp != NULL && oidp->oid_name != NULL) {
		struct sysctl_oid *p;
		char *buf = name;
		size_t buflen = sizeof(name);
		size_t len;

		/* Walk up the tree to build full name */
		name[0] = '\0';
		for (p = oidp; p != NULL && p->oid_name != NULL;
		    p = SYSCTL_PARENT(p)) {
			if (name[0] != '\0') {
				len = strlen(p->oid_name);
				if (len + 1 + strlen(name) < buflen) {
					memmove(buf + len + 1, name,
					    strlen(name) + 1);
					memcpy(buf, p->oid_name, len);
					buf[len] = '.';
				}
			} else {
				strlcpy(name, p->oid_name, buflen);
			}
		}
		info.sysctl_name = name;
	}
	info.sysctl_op = (req != NULL && req->newptr != NULL) ? 1 : 0;
	info.nosleep = true;

	(void)esc_generate_vnode_event(ESC_EVENT_NOTIFY_SYSCTL, &info);
	return (0);
}

/*
 * MAC hook: kenv_check_set
 */
static int
esc_mac_kenv_check_set(struct ucred *cred, char *name, char *value)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	(void)value;
	info.kenv_name = name;
	info.kenv_op = 1;  /* set */
	info.nosleep = true;

	(void)esc_generate_vnode_event(ESC_EVENT_NOTIFY_KENV, &info);
	return (0);
}

/*
 * MAC hook: kenv_check_unset
 */
static int
esc_mac_kenv_check_unset(struct ucred *cred, char *name)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.kenv_name = name;
	info.kenv_op = 2;  /* unset */
	info.nosleep = true;

	(void)esc_generate_vnode_event(ESC_EVENT_NOTIFY_KENV, &info);
	return (0);
}

/*
 * MAC hook: pipe_check_read
 */
static int
esc_mac_pipe_check_read(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);
	(void)pplabel;

	info.pipepair = pp;
	info.nosleep = true;

	(void)esc_generate_vnode_event(ESC_EVENT_NOTIFY_PIPE_READ, &info);
	return (0);
}

/*
 * MAC hook: pipe_check_write
 */
static int
esc_mac_pipe_check_write(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);
	(void)pplabel;

	info.pipepair = pp;
	info.nosleep = true;

	(void)esc_generate_vnode_event(ESC_EVENT_NOTIFY_PIPE_WRITE, &info);
	return (0);
}

/*
 * MAC hook: pipe_check_stat
 */
static int
esc_mac_pipe_check_stat(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);
	(void)pplabel;

	info.pipepair = pp;
	info.nosleep = true;

	(void)esc_generate_vnode_event(ESC_EVENT_NOTIFY_PIPE_STAT, &info);
	return (0);
}

/*
 * MAC hook: pipe_check_poll
 */
static int
esc_mac_pipe_check_poll(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);
	(void)pplabel;

	info.pipepair = pp;
	info.nosleep = true;

	(void)esc_generate_vnode_event(ESC_EVENT_NOTIFY_PIPE_POLL, &info);
	return (0);
}

/*
 * MAC hook: pipe_check_ioctl
 */
static int
esc_mac_pipe_check_ioctl(struct ucred *cred, struct pipepair *pp,
    struct label *pplabel, unsigned long cmd, void *data)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);
	(void)pplabel;
	(void)data;

	info.pipepair = pp;
	info.ioctl_cmd = cmd;
	info.nosleep = true;

	(void)esc_generate_vnode_event(ESC_EVENT_NOTIFY_PIPE_IOCTL, &info);
	return (0);
}

/*
 * MAC hook: mount_check_stat
 */
static int
esc_mac_mount_check_stat(struct ucred *cred, struct mount *mp,
    struct label *mplabel)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);
	(void)mplabel;

	info.mp = mp;
	info.nosleep = true;

	(void)esc_generate_vnode_event(ESC_EVENT_NOTIFY_MOUNT_STAT, &info);
	return (0);
}

/*
 * MAC hook: priv_check
 */
static int
esc_mac_priv_check(struct ucred *cred, int priv)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.priv = priv;
	info.nosleep = true;

	(void)esc_generate_vnode_event(ESC_EVENT_NOTIFY_PRIV_CHECK, &info);
	return (0);
}

/*
 * MAC hook: proc_check_sched
 */
static int
esc_mac_proc_check_sched(struct ucred *cred, struct proc *p)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.target_proc = p;
	info.nosleep = true;

	(void)esc_generate_vnode_event(ESC_EVENT_NOTIFY_PROC_SCHED, &info);
	return (0);
}

/*
 * MAC hook: system_check_swapon
 *
 * Called when enabling swap on a device/file.
 */
static int
esc_mac_system_check_swapon(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.vp = vp;

	return (esc_generate_vnode_event(ESC_EVENT_AUTH_SWAPON, &info));
}

/*
 * MAC hook: system_check_swapoff
 *
 * Called when disabling swap on a device/file.
 */
static int
esc_mac_system_check_swapoff(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	struct esc_vnode_event_info info = ESC_VNODE_INFO_INIT(cred);

	info.vp = vp;

	return (esc_generate_vnode_event(ESC_EVENT_AUTH_SWAPOFF, &info));
}

/*
 * MAC policy operations structure
 */
static struct mac_policy_ops esc_mac_ops = {
	/* Credential label management */
	.mpo_cred_init_label = esc_mac_cred_init_label,
	.mpo_cred_destroy_label = esc_mac_cred_destroy_label,
	.mpo_cred_copy_label = esc_mac_cred_copy_label,
	.mpo_cred_check_setuid = esc_mac_cred_check_setuid,
	.mpo_cred_check_setgid = esc_mac_cred_check_setgid,

	/* Exec transition - regenerate exec_id */
	.mpo_vnode_execve_transition = esc_mac_vnode_execve_transition,

	/* Sleepable VFS checks - can block for AUTH */
	.mpo_vnode_check_exec = esc_mac_vnode_check_exec,
	.mpo_vnode_check_access = esc_mac_vnode_check_access,
	.mpo_vnode_check_lookup = esc_mac_vnode_check_lookup,
	.mpo_vnode_check_read = esc_mac_vnode_check_read,
	.mpo_vnode_check_write = esc_mac_vnode_check_write,
	.mpo_vnode_check_stat = esc_mac_vnode_check_stat,
	.mpo_vnode_check_poll = esc_mac_vnode_check_poll,
	.mpo_vnode_check_readdir = esc_mac_vnode_check_readdir,
	.mpo_vnode_check_readlink = esc_mac_vnode_check_readlink,
	.mpo_vnode_check_revoke = esc_mac_vnode_check_revoke,
	.mpo_vnode_check_open = esc_mac_vnode_check_open,
	.mpo_vnode_check_create = esc_mac_vnode_check_create,
	.mpo_vnode_check_unlink = esc_mac_vnode_check_unlink,
	.mpo_vnode_check_rename_from = esc_mac_vnode_check_rename_from,
	.mpo_vnode_check_rename_to = esc_mac_vnode_check_rename_to,
	.mpo_vnode_check_link = esc_mac_vnode_check_link,
	.mpo_vnode_check_chdir = esc_mac_vnode_check_chdir,
	.mpo_vnode_check_chroot = esc_mac_vnode_check_chroot,
	.mpo_vnode_check_mmap = esc_mac_vnode_check_mmap,
	.mpo_vnode_check_mprotect = esc_mac_vnode_check_mprotect,
	.mpo_vnode_check_setextattr = esc_mac_vnode_check_setextattr,
	.mpo_vnode_check_getextattr = esc_mac_vnode_check_getextattr,
	.mpo_vnode_check_deleteextattr = esc_mac_vnode_check_deleteextattr,
	.mpo_vnode_check_listextattr = esc_mac_vnode_check_listextattr,
	.mpo_vnode_check_getacl = esc_mac_vnode_check_getacl,
	.mpo_vnode_check_setacl = esc_mac_vnode_check_setacl,
	.mpo_vnode_check_deleteacl = esc_mac_vnode_check_deleteacl,
	.mpo_vnode_check_relabel = esc_mac_vnode_check_relabel,
	.mpo_vnode_check_setmode = esc_mac_vnode_check_setmode,
	.mpo_vnode_check_setowner = esc_mac_vnode_check_setowner,
	.mpo_vnode_check_setflags = esc_mac_vnode_check_setflags,
	.mpo_vnode_check_setutimes = esc_mac_vnode_check_setutimes,

	/* KLD check - sleepable (can block for AUTH response) */
	.mpo_kld_check_load = esc_mac_kld_check_load,

	/* Process checks - NOSLEEP (cannot block for AUTH response) */
	.mpo_proc_check_debug = esc_mac_proc_check_debug,
	.mpo_proc_check_signal = esc_mac_proc_check_signal,

	/* Socket checks - NOSLEEP (cannot block for AUTH response) */
	.mpo_socket_check_connect = esc_mac_socket_check_connect,
	.mpo_socket_check_bind = esc_mac_socket_check_bind,
	.mpo_socket_check_listen = esc_mac_socket_check_listen,
	.mpo_socket_check_create = esc_mac_socket_check_create,
	.mpo_socket_check_accept = esc_mac_socket_check_accept,
	.mpo_socket_check_send = esc_mac_socket_check_send,
	.mpo_socket_check_receive = esc_mac_socket_check_receive,
	.mpo_socket_check_stat = esc_mac_socket_check_stat,
	.mpo_socket_check_poll = esc_mac_socket_check_poll,

	/* Pipe checks - NOSLEEP (cannot block for AUTH response) */
	.mpo_pipe_check_read = esc_mac_pipe_check_read,
	.mpo_pipe_check_write = esc_mac_pipe_check_write,
	.mpo_pipe_check_stat = esc_mac_pipe_check_stat,
	.mpo_pipe_check_poll = esc_mac_pipe_check_poll,
	.mpo_pipe_check_ioctl = esc_mac_pipe_check_ioctl,

	/* Mount check - NOSLEEP */
	.mpo_mount_check_stat = esc_mac_mount_check_stat,

	/* Privilege check - NOSLEEP */
	.mpo_priv_check = esc_mac_priv_check,

	/* Process scheduling check - NOSLEEP */
	.mpo_proc_check_sched = esc_mac_proc_check_sched,

	/*
	 * System checks - mixed sleep semantics:
	 *   reboot, sysctl: NOSLEEP (cannot block for AUTH response)
	 *   swapon, swapoff: sleepable (can block for AUTH response)
	 */
	.mpo_system_check_reboot = esc_mac_system_check_reboot,
	.mpo_system_check_sysctl = esc_mac_system_check_sysctl,
	.mpo_system_check_swapon = esc_mac_system_check_swapon,
	.mpo_system_check_swapoff = esc_mac_system_check_swapoff,

	/* Kenv checks - NOSLEEP (cannot block for AUTH response) */
	.mpo_kenv_check_set = esc_mac_kenv_check_set,
	.mpo_kenv_check_unset = esc_mac_kenv_check_unset,
};

/*
 * MAC policy configuration - registered manually, not via MAC_POLICY_SET
 * because we're part of the esc module, not a standalone MAC policy module.
 */
static struct mac_policy_conf esc_mac_policy_conf = {
	.mpc_name = "esc",
	.mpc_fullname = "Endpoint Security Capabilities",
	.mpc_ops = &esc_mac_ops,
	.mpc_loadtime_flags = MPC_LOADTIME_FLAG_UNLOADOK,
	.mpc_field_off = &esc_slot,
	.mpc_runtime_flags = 0,
};

/*
 * Initialize MAC policy
 *
 * Called from esc module load. Registers with MAC framework.
 */
int
esc_mac_init(void)
{
	int error;

	error = mac_policy_modevent(NULL, MOD_LOAD, &esc_mac_policy_conf);
	if (error != 0) {
		ESC_ERR("failed to register MAC policy: %d", error);
		return (error);
	}

	esc_mac_registered = true;
	ESC_DEBUG("MAC policy registered");

	esc_rename_cache_init();

	esc_proc_fork_tag = EVENTHANDLER_REGISTER(process_fork,
	    esc_proc_event_fork, NULL, EVENTHANDLER_PRI_LAST);
	esc_proc_exit_tag = EVENTHANDLER_REGISTER(process_exit,
	    esc_proc_event_exit, NULL, EVENTHANDLER_PRI_LAST);
	esc_vfs_mounted_tag = EVENTHANDLER_REGISTER(vfs_mounted,
	    esc_vfs_event_mounted, NULL, EVENTHANDLER_PRI_LAST);
	esc_vfs_unmounted_tag = EVENTHANDLER_REGISTER(vfs_unmounted,
	    esc_vfs_event_unmounted, NULL, EVENTHANDLER_PRI_LAST);
	esc_kld_unload_tag = EVENTHANDLER_REGISTER(kld_unload,
	    esc_kld_event_unload, NULL, EVENTHANDLER_PRI_LAST);

	return (0);
}

/*
 * Uninitialize MAC policy
 *
 * Called from esc module unload. Unregisters from MAC framework.
 */
void
esc_mac_uninit(void)
{
	int error;

	if (!esc_mac_registered)
		return;

	if (esc_proc_fork_tag != NULL) {
		EVENTHANDLER_DEREGISTER(process_fork, esc_proc_fork_tag);
		esc_proc_fork_tag = NULL;
	}
	if (esc_proc_exit_tag != NULL) {
		EVENTHANDLER_DEREGISTER(process_exit, esc_proc_exit_tag);
		esc_proc_exit_tag = NULL;
	}
	if (esc_vfs_mounted_tag != NULL) {
		EVENTHANDLER_DEREGISTER(vfs_mounted, esc_vfs_mounted_tag);
		esc_vfs_mounted_tag = NULL;
	}
	if (esc_vfs_unmounted_tag != NULL) {
		EVENTHANDLER_DEREGISTER(vfs_unmounted, esc_vfs_unmounted_tag);
		esc_vfs_unmounted_tag = NULL;
	}
	if (esc_kld_unload_tag != NULL) {
		EVENTHANDLER_DEREGISTER(kld_unload, esc_kld_unload_tag);
		esc_kld_unload_tag = NULL;
	}

	esc_rename_cache_destroy();

	error = mac_policy_modevent(NULL, MOD_UNLOAD, &esc_mac_policy_conf);
	if (error != 0)
		ESC_WARN("failed to unregister MAC policy: %d", error);
	else {
		esc_mac_registered = false;
		ESC_DEBUG("MAC policy unregistered");
	}
}
