# $FreeBSD$

PROGS=		oesd vendor_client
SRCS_oesd=	oesd.c
SRCS_vendor_client= vendor_client.c

CFLAGS+=	-I${.CURDIR}/../lib/liboes
CFLAGS+=	-I${.CURDIR}/../sys

LDADD+=		-L${.CURDIR}/../lib/liboes -lesc
LDFLAGS+=	-Wl,-rpath,${.CURDIR}/../lib/liboes

WARNS?=		6

MAN=

.include <bsd.progs.mk>
