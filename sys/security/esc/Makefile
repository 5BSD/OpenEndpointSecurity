# $FreeBSD$
#
# ESC (Endpoint Security Capabilities) kernel module
#
# Build out of tree:
#   cd /home/koryheard/Projects/esc/sys/security/esc && make
#
# Build in tree (after copying to /usr/src/sys/security/esc):
#   cd /usr/src/sys/modules/esc && make
#

KMOD=	esc
SRCS=	esc_dev.c esc_client.c esc_cache.c esc_event.c esc_mac.c
SRCS+=	bus_if.h device_if.h vnode_if.h opt_mac.h

SYSDIR?=	/usr/src/sys

.if !exists(${SYSDIR}/sys/param.h)
.error "SYSDIR (${SYSDIR}) does not look like a FreeBSD src tree; set SYSDIR=/path/to/src/sys"
.endif

# For out-of-tree build, add our include path
# This allows #include <security/esc/esc.h> to work
# ${.CURDIR}/../.. resolves to .../esc/sys
.if exists(${.CURDIR}/../..)
CFLAGS+= -I${.CURDIR}/../..
.endif

.include <bsd.kmod.mk>
