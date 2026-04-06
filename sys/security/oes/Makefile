# $FreeBSD$
#
# OES (Endpoint Security Capabilities) kernel module
#
# Build out of tree:
#   cd /home/koryheard/Projects/OpenEndpointSecurity/sys/security/oes && make
#
# Build in tree (after copying to /usr/src/sys/security/oes):
#   cd /usr/src/sys/modules/oes && make
#

KMOD=	oes
SRCS=	oes_dev.c oes_client.c oes_cache.c oes_event.c oes_mac.c
SRCS+=	bus_if.h device_if.h vnode_if.h opt_mac.h

SYSDIR?=	/usr/src/sys

.if !exists(${SYSDIR}/sys/param.h)
.error "SYSDIR (${SYSDIR}) does not look like a FreeBSD src tree; set SYSDIR=/path/to/src/sys"
.endif

# For out-of-tree build, add our include path
# This allows #include <security/oes/oes.h> to work
# ${.CURDIR}/../.. resolves to .../OpenEndpointSecurity/sys
.if exists(${.CURDIR}/../..)
CFLAGS+= -I${.CURDIR}/../..
.endif

.include <bsd.kmod.mk>
