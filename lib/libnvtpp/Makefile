
SHLIBDIR?= /lib

.include <src.opts.mk>

PACKAGE=runtime
LIB_CXX=nvtpp
CXXSTD=c++20
CXXFLAGS+=-I.

SRCS+=	${LIB}.cc
INCS=	${LIB}.h
MAN=	lib${LIB}.9
MLINKS+=lib${LIB}.9 nvtpp.9

HAS_TESTS=
SUBDIR.${MK_TESTS}+=tests

.include <bsd.lib.mk>
