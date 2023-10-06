
SHLIBDIR?= /lib

.include <src.opts.mk>

PACKAGE=runtime
LIB=	nvtree
CFLAGS+=-I${SRCTOP}/sys

.PATH:	${SRCTOP}/sys/contrib/libnvtree
SRCS+=	${LIB}.c
MAN=	lib${LIB}.9
MLINKS+=lib${LIB}.9 nvtree.9
MLINKS+=lib${LIB}.9 nvtree_add.9
MLINKS+=lib${LIB}.9 nvtree_add_arr.9
MLINKS+=lib${LIB}.9 nvtree_add_tree.9
MLINKS+=lib${LIB}.9 nvtree_bool.9
MLINKS+=lib${LIB}.9 nvtree_create.9
MLINKS+=lib${LIB}.9 nvtree_destroy.9
MLINKS+=lib${LIB}.9 nvtree_nested.9
MLINKS+=lib${LIB}.9 nvtree_null.9
MLINKS+=lib${LIB}.9 nvtree_number.9
MLINKS+=lib${LIB}.9 nvtree_pack.9
MLINKS+=lib${LIB}.9 nvtree_pair.9
MLINKS+=lib${LIB}.9 nvtree_rem_arr.9
MLINKS+=lib${LIB}.9 nvtree_rem_tree.9
MLINKS+=lib${LIB}.9 nvtree_remove.9
MLINKS+=lib${LIB}.9 nvtree_size.9
MLINKS+=lib${LIB}.9 nvtree_string.9
MLINKS+=lib${LIB}.9 nvtree_unpack.9

HAS_TESTS=
SUBDIR.${MK_TESTS}+=tests

.include <bsd.lib.mk>
