
SHLIBDIR?= /lib

.include <src.opts.mk>

PACKAGE=	runtime
LIB=		nvtree
CFLAGS+=	-I${SRCTOP}/sys

SRCS+=	${LIB}.c
INCS+=	${LIB}.h

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.lib.mk>
