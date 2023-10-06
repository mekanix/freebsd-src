#include <sys/cdefs.h>
#include <sys/nv.h>
#include <sys/dnv.h>
#include <sys/nvtree.h>
#include <sys/endian.h>

#include <atf-c++.hpp>
#include <err.h>

#define	fd_is_valid(fd)	(fcntl((fd), F_GETFL) != -1 || errno != EBADF)
#define	NVTREE_FLAG_BIG_ENDIAN	0x80
#define	NVTREE_TREE_HEADER_SIZE	19
#define	NVTREE_PAIR_HEADER_SIZE	19

static uint16_t
read_u16_order(const uint8_t *p, bool isbe)
{
	uint16_t v;
	memcpy(&v, p, sizeof(v));
#if BYTE_ORDER == BIG_ENDIAN
	return (isbe ? v : bswap16(v));
#else
	return (isbe ? bswap16(v) : v);
#endif
}

static uint64_t
read_u64_order(const uint8_t *p, bool isbe)
{
	uint64_t v;
	memcpy(&v, p, sizeof(v));
#if BYTE_ORDER == BIG_ENDIAN
	return (isbe ? v : bswap64(v));
#else
	return (isbe ? bswap64(v) : v);
#endif
}

static void
write_u16_order(uint8_t *p, uint16_t v, bool isbe)
{
#if BYTE_ORDER == BIG_ENDIAN
	if (!isbe)
		v = bswap16(v);
#else
	if (isbe)
		v = bswap16(v);
#endif
	memcpy(p, &v, sizeof(v));
}

static void
write_u64_order(uint8_t *p, uint64_t v, bool isbe)
{
#if BYTE_ORDER == BIG_ENDIAN
	if (!isbe)
		v = bswap64(v);
#else
	if (isbe)
		v = bswap64(v);
#endif
	memcpy(p, &v, sizeof(v));
}

static bool
rewrite_tree_endian(uint8_t *buf, size_t buflen, size_t start, bool src_isbe,
    bool dst_isbe, bool root, size_t *consumed)
{
	const size_t tsize = NVTREE_TREE_HEADER_SIZE;
	const size_t psize = NVTREE_PAIR_HEADER_SIZE;
	size_t ptr, body_end, body_len;
	uint64_t sz;

	if (start + tsize > buflen)
		return (false);
	buf[start + 2] &= ~NVTREE_FLAG_BIG_ENDIAN;
	buf[start + 2] |= dst_isbe ? NVTREE_FLAG_BIG_ENDIAN : 0;

	write_u64_order(buf + start + 3, read_u64_order(buf + start + 3, src_isbe),
	    dst_isbe);
	sz = read_u64_order(buf + start + 11, src_isbe);
	write_u64_order(buf + start + 11, sz, dst_isbe);
	body_len = root ? (size_t)sz : (size_t)(sz - (tsize + 1));
	ptr = start + tsize;
	body_end = ptr + body_len;
	if (body_end > buflen)
		return (false);

	while (ptr < body_end) {
		uint8_t ty = buf[ptr];
		uint16_t namesize;
		uint64_t datasize, nitems;

		namesize = read_u16_order(buf + ptr + 1, src_isbe);
		datasize = read_u64_order(buf + ptr + 3, src_isbe);
		nitems = read_u64_order(buf + ptr + 11, src_isbe);
		write_u16_order(buf + ptr + 1, namesize, dst_isbe);
		write_u64_order(buf + ptr + 3, datasize, dst_isbe);
		write_u64_order(buf + ptr + 11, nitems, dst_isbe);
		ptr += psize;
		if (namesize == 0 || ptr + namesize > body_end)
			return (false);
		ptr += namesize;

		switch (ty) {
		case NV_TYPE_NULL:
			break;
		case NV_TYPE_BOOL:
			ptr += sizeof(bool);
			break;
		case NV_TYPE_NUMBER:
			write_u64_order(buf + ptr, read_u64_order(buf + ptr, src_isbe),
			    dst_isbe);
			ptr += sizeof(uint64_t);
			break;
		case NV_TYPE_STRING:
			ptr += (size_t)datasize;
			break;
		case NV_TYPE_NVLIST: {
			size_t nested = 0;
			if (!rewrite_tree_endian(buf, buflen, ptr, src_isbe, dst_isbe,
			    false, &nested))
				return (false);
			if (nested != (size_t)datasize)
				return (false);
			ptr += nested;
			if (ptr + psize + 1 <= body_end &&
			    (buf[ptr] == 0xfe || buf[ptr] == 0xff)) {
				write_u16_order(buf + ptr + 1,
				    read_u16_order(buf + ptr + 1, src_isbe), dst_isbe);
				write_u64_order(buf + ptr + 3,
				    read_u64_order(buf + ptr + 3, src_isbe), dst_isbe);
				write_u64_order(buf + ptr + 11,
				    read_u64_order(buf + ptr + 11, src_isbe), dst_isbe);
				ptr += psize + 1;
			}
			break;
		}
		case NV_TYPE_NUMBER_ARRAY:
			for (uint64_t i = 0; i < nitems; i++) {
				write_u64_order(buf + ptr, read_u64_order(buf + ptr, src_isbe),
				    dst_isbe);
				ptr += sizeof(uint64_t);
			}
			break;
		case NV_TYPE_BOOL_ARRAY:
			ptr += (size_t)nitems * sizeof(bool);
			break;
		case NV_TYPE_STRING_ARRAY:
			ptr += (size_t)datasize;
			break;
		case 0xfe:
		case 0xff:
			if (consumed != NULL)
				*consumed = tsize + body_len;
			return (true);
		default:
			return (false);
		}
		if (ptr > body_end)
			return (false);
	}
	if (consumed != NULL)
		*consumed = tsize + body_len;
	return (true);
}

static nvtree_t *
generate_simple_tree()
{
	nvtree_t *root = NULL;

	root = nvtree_create();
	nvtree_add(root, nvtree_null("null"));
	nvtree_add(root, nvtree_bool("bool", true));
	nvtree_add(root, nvtree_number("number", 5));
	nvtree_add(root, nvtree_string("string", "something"));
	return root;
}

static nvtpair_t *
generate_array(const char *name, size_t type)
{
	nvtpair_t *arr = NULL;
	nvtpair_t *nested = NULL;

	arr = nvtree_array(name, type);
	for (uint64_t i = 1; i < 5; ++i) {
		switch(type) {
			case NVTREE_BOOL: {
				nvtree_add_pair(arr, nvtree_bool(NULL, true));
				break;
			}
			case NVTREE_NUMBER: {
				nvtree_add_pair(arr, nvtree_number(NULL, i));
				break;
			}
			case NVTREE_STRING: {
				nvtree_add_pair(arr, nvtree_string(NULL, "something"));
				break;
			}
			case NVTREE_NESTED: {
				nested = nvtree_nested(NULL, generate_simple_tree());
				nvtree_add_pair(arr, nested);
				break;
			}
		}
	}
	return arr;
}

static nvtree_t *
generate_tree()
{
	nvtree_t *root = NULL;
	nvtpair_t *pair = NULL;

	root = generate_simple_tree();
	pair = nvtree_nested("nested", generate_simple_tree());
	nvtree_add(root, generate_array("boolarr", NVTREE_BOOL));
	nvtree_add(root, pair);
	nvtree_add(root, generate_array("nestedarr", NVTREE_NESTED));
	nvtree_add(root, generate_array("numberarr", NVTREE_NUMBER));
	nvtree_add(root, generate_array("stringarr", NVTREE_STRING));
	return root;
}

static void
print_bytes(uint8_t *buf, size_t size, size_t offset) {
	uint8_t *byte = NULL;
	for (; offset < size; ++offset) {
		byte = buf + offset;
		printf("%x ", *byte);
	}
	printf("\n");
}

static void
check_tree(nvtree_t *root) {
	nvtpair_t *pair = NULL;

	pair = nvtree_find(root, "null");
	ATF_REQUIRE(pair != NULL);

	pair = nvtree_find(root, "bool");
	ATF_REQUIRE(pair != NULL);
	ATF_REQUIRE(pair->value.b);

	pair = nvtree_find(root, "number");
	ATF_REQUIRE(pair != NULL);
	ATF_REQUIRE_EQ(pair->value.num, 5);

	pair = nvtree_find(root, "string");
	ATF_REQUIRE(pair != NULL);
	ATF_REQUIRE(strcmp(pair->value.string, "something") == 0);
}

ATF_TEST_CASE_WITHOUT_HEAD(nvtree_create);
ATF_TEST_CASE_BODY(nvtree_create)
{
	nvtree_t *root = nvtree_create();
	ATF_REQUIRE(root != NULL);
	nvtree_destroy(root);
}

ATF_TEST_CASE_WITHOUT_HEAD(nvtree_fd);
ATF_TEST_CASE_BODY(nvtree_fd)
{
	nvlist_t *nvl = NULL;
	void *buf = NULL;
	size_t size = 0;

	nvl = nvlist_create(0);
	nvlist_add_descriptor(nvl, "descriptor", STDERR_FILENO);
	buf = nvlist_pack(nvl, &size);
	print_bytes((uint8_t *)buf, size, 0);
	printf("\n");

	nvlist_destroy(nvl);
}

ATF_TEST_CASE_WITHOUT_HEAD(nvtree_filter);
ATF_TEST_CASE_BODY(nvtree_filter)
{
	nvtree_t *root = NULL;
	nvtree_t *data = NULL;
	nvtree_t *dst = NULL;
	nvtpair_t *node = NULL;

	root = generate_tree();
	ATF_REQUIRE(root != NULL);
	data = nvtree_create();
	ATF_REQUIRE(data != NULL);
	nvtree_add(data, nvtree_bool("number", true));
	dst = nvtree_filter(root, data);
	ATF_REQUIRE(dst != NULL);
	node = nvtree_find(dst, "number");
	ATF_REQUIRE(node != NULL);
	ATF_REQUIRE(node->value.num == 5);

	nvtree_destroy(root);
	nvtree_destroy(data);
	nvtree_destroy(dst);
}

ATF_TEST_CASE_WITHOUT_HEAD(nvtree_find);
ATF_TEST_CASE_BODY(nvtree_find)
{
	nvtree_t *root = NULL;

	root = generate_tree();
	check_tree(root);
	nvtree_destroy(root);
}

ATF_TEST_CASE_WITHOUT_HEAD(nvtree_merge);
ATF_TEST_CASE_BODY(nvtree_merge)
{
	nvtree_t *first = NULL;
	nvtree_t *second = NULL;
	nvtpair_t *node = NULL;

	first = nvtree_create();
	nvtree_add(first, nvtree_number("number", 5));
	node = nvtree_find(first, "number");
	ATF_REQUIRE(node != NULL);
	ATF_REQUIRE(node->value.num == 5);

	second = nvtree_create();
	nvtree_add(second, nvtree_bool("bool", true));
	node = nvtree_find(second, "bool");
	ATF_REQUIRE(node != NULL);
	ATF_REQUIRE(node->value.b);

	nvtree_merge(first, second, false);
	node = nvtree_find(first, "number");
	ATF_REQUIRE(node != NULL);
	ATF_REQUIRE(node->value.num == 5);
	node = nvtree_find(first, "bool");
	ATF_REQUIRE(node != NULL);
	ATF_REQUIRE(node->value.b);

	nvtree_destroy(first);
	nvtree_destroy(second);
}

ATF_TEST_CASE_WITHOUT_HEAD(nvtree_pack);
ATF_TEST_CASE_BODY(nvtree_pack)
{
	size_t size = 0;
	void *buf = NULL;
	nvtree_t *root = NULL;
	nvlist_t *nvl = NULL;
	const nvlist_t *tmpnvl;
	const char *value;
	const bool *b;
	const uint64_t *n;
	const char * const *s = NULL;

	root = generate_tree();
	buf = nvtree_pack(root, &size);
	nvtree_destroy(root);
	ATF_REQUIRE(buf != NULL);
	ATF_REQUIRE(size != 0);

	nvl = nvlist_unpack(buf, size, 0);
	free(buf);
	ATF_REQUIRE(nvl != NULL);

	ATF_REQUIRE(nvlist_exists_null(nvl, "null"));
	ATF_REQUIRE_EQ(dnvlist_get_bool(nvl, "bool", false), true);
	ATF_REQUIRE_EQ(dnvlist_get_number(nvl, "number", 0), 5);
	value = dnvlist_get_string(nvl, "string", "v");
	ATF_REQUIRE_EQ(strcmp(value, "something"), 0);

	tmpnvl = nvlist_get_nvlist(nvl, "nested");
	ATF_REQUIRE(nvlist_exists_null(tmpnvl, "null"));
	ATF_REQUIRE_EQ(dnvlist_get_bool(tmpnvl, "bool", false), true);
	ATF_REQUIRE_EQ(dnvlist_get_number(tmpnvl, "number", 0), 5);
	value = dnvlist_get_string(tmpnvl, "string", "v");
	ATF_REQUIRE_EQ(strcmp(value, "something"), 0);

	b = nvlist_get_bool_array(nvl, "boolarr", &size);
	ATF_REQUIRE_EQ(size, 4);
	for (size_t i = 0; i < size; ++i) {
		ATF_REQUIRE_EQ(*(b + i), true);
	}
	n = nvlist_get_number_array(nvl, "numberarr", &size);
	ATF_REQUIRE_EQ(size, 4);
	for (size_t i = 0; i < size; ++i) {
		ATF_REQUIRE_EQ(*(n + i), i + 1);
	}
	s = nvlist_get_string_array(nvl, "stringarr", &size);
	ATF_REQUIRE_EQ(size, 4);
	for (size_t i = 0; i < size; ++i) {
		ATF_REQUIRE(strcmp(s[i], "something") == 0);
	}

	nvlist_destroy(nvl);
}

ATF_TEST_CASE_WITHOUT_HEAD(nvtree_unpack);
ATF_TEST_CASE_BODY(nvtree_unpack)
{
	size_t size = 0;
	uint8_t *buf = NULL;
	nvtree_t *root = NULL;
	nvtpair_t *pair = NULL;
	nvtpair_t *node = NULL;
	uint64_t n = 0;

	root = generate_tree();
	buf = (uint8_t *)nvtree_pack(root, &size);
	nvtree_destroy(root);
	ATF_REQUIRE(buf != NULL);
	ATF_REQUIRE(size != 0);

	root = nvtree_unpack(buf, size);
	free(buf);
	ATF_REQUIRE(root != NULL);

	check_tree(root);

	node = NULL;
	pair = nvtree_find(root, "nested");
	ATF_REQUIRE(pair != NULL);
	check_tree(pair->value.tree);

	node = NULL;
	pair = nvtree_find(root, "boolarr");
	ATF_REQUIRE(pair != NULL);
	TAILQ_FOREACH(node, pair->value.array, next) {
		ATF_REQUIRE(node->value.b);
	}

	node = NULL;
	pair = nvtree_find(root, "nestedarr");
	ATF_REQUIRE(pair != NULL);
	TAILQ_FOREACH(node, pair->value.array, next) {
		check_tree(node->value.tree);
	}

	node = NULL;
	pair = nvtree_find(root, "numberarr");
	ATF_REQUIRE(pair != NULL);
	n = 0;
	TAILQ_FOREACH(node, pair->value.array, next) {
		++n;
		ATF_REQUIRE_EQ(node->value.num, n);
	}

	node = NULL;
	pair = nvtree_find(root, "stringarr");
	ATF_REQUIRE(pair != NULL);
	TAILQ_FOREACH(node, pair->value.array, next) {
		ATF_REQUIRE(strcmp(node->value.string, "something") == 0);
	}

	nvtree_destroy(root);
}

ATF_TEST_CASE_WITHOUT_HEAD(nvtree_unpack_cross_endian);
ATF_TEST_CASE_BODY(nvtree_unpack_cross_endian)
{
	size_t size = 0;
	size_t consumed = 0;
	uint8_t *buf = NULL;
	nvtree_t *root = NULL;
	bool src_isbe = false;
	bool dst_isbe = false;

#if BYTE_ORDER == BIG_ENDIAN
	src_isbe = true;
#else
	src_isbe = false;
#endif
	dst_isbe = !src_isbe;

	root = generate_simple_tree();
	buf = (uint8_t *)nvtree_pack(root, &size);
	nvtree_destroy(root);
	ATF_REQUIRE(buf != NULL);
	ATF_REQUIRE(size != 0);
	ATF_REQUIRE(rewrite_tree_endian(buf, size, 0, src_isbe, dst_isbe, true,
	    &consumed));
	ATF_REQUIRE_EQ(consumed, size);

	root = nvtree_unpack(buf, size);
	free(buf);
	ATF_REQUIRE(root != NULL);
	check_tree(root);
	nvtree_destroy(root);
}

ATF_INIT_TEST_CASES(tp)
{
	ATF_ADD_TEST_CASE(tp, nvtree_create);
	ATF_ADD_TEST_CASE(tp, nvtree_fd);
	ATF_ADD_TEST_CASE(tp, nvtree_filter);
	ATF_ADD_TEST_CASE(tp, nvtree_find);
	ATF_ADD_TEST_CASE(tp, nvtree_merge);
	ATF_ADD_TEST_CASE(tp, nvtree_pack);
	ATF_ADD_TEST_CASE(tp, nvtree_unpack);
	ATF_ADD_TEST_CASE(tp, nvtree_unpack_cross_endian);
}
