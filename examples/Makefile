# $FreeBSD$

PROGS=		oesd vendor_client oeslogger
SRCS_oesd=	oesd.c
SRCS_vendor_client= vendor_client.c
SRCS_oeslogger=	oeslogger.c

CFLAGS+=	-I${.CURDIR}/../lib/liboes
CFLAGS+=	-I${.CURDIR}/../sys

LDADD+=		-L${.CURDIR}/../lib/liboes -loes
LDFLAGS+=	-Wl,-rpath,${.CURDIR}/../lib/liboes

WARNS?=		6

MAN=

.include <bsd.progs.mk>
