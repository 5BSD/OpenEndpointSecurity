# $FreeBSD$

PROGS=		escd vendor_client
SRCS_escd=	escd.c
SRCS_vendor_client= vendor_client.c

CFLAGS+=	-I${.CURDIR}/../lib/libesc
CFLAGS+=	-I${.CURDIR}/../sys

LDADD+=		-L${.CURDIR}/../lib/libesc -lesc
LDFLAGS+=	-Wl,-rpath,${.CURDIR}/../lib/libesc

WARNS?=		6

MAN=

.include <bsd.progs.mk>
