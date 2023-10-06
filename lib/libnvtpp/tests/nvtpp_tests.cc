#include <iostream>

#include <atf-c++.hpp>

#include <sys/nv.h>
#include <sys/endian.h>
#include <nvtpp.h>

using namespace nvtpp;

#define	NV_FLAG_BIG_ENDIAN	0x80
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
rewrite_simple_tree_endian(uint8_t *buf, size_t len, bool src_isbe, bool dst_isbe)
{
	size_t ptr, end;

	if (len < NVTREE_TREE_HEADER_SIZE)
		return false;
	buf[2] &= ~NV_FLAG_BIG_ENDIAN;
	buf[2] |= dst_isbe ? NV_FLAG_BIG_ENDIAN : 0;
	write_u64_order(buf + 3, read_u64_order(buf + 3, src_isbe), dst_isbe);
	write_u64_order(buf + 11, read_u64_order(buf + 11, src_isbe), dst_isbe);

	ptr = NVTREE_TREE_HEADER_SIZE;
	end = len;
	while (ptr + NVTREE_PAIR_HEADER_SIZE <= end) {
		uint8_t ty = buf[ptr];
		uint16_t namesize = read_u16_order(buf + ptr + 1, src_isbe);
		uint64_t datasize = read_u64_order(buf + ptr + 3, src_isbe);
		uint64_t nitems = read_u64_order(buf + ptr + 11, src_isbe);
		write_u16_order(buf + ptr + 1, namesize, dst_isbe);
		write_u64_order(buf + ptr + 3, datasize, dst_isbe);
		write_u64_order(buf + ptr + 11, nitems, dst_isbe);
		ptr += NVTREE_PAIR_HEADER_SIZE;
		if (ptr + namesize > end)
			return false;
		ptr += namesize;
		switch (ty) {
		case NV_TYPE_NULL:
			break;
		case NV_TYPE_BOOL:
			ptr += sizeof(bool);
			break;
		case NV_TYPE_NUMBER:
			if (ptr + sizeof(uint64_t) > end)
				return false;
			write_u64_order(buf + ptr, read_u64_order(buf + ptr, src_isbe), dst_isbe);
			ptr += sizeof(uint64_t);
			break;
		case NV_TYPE_STRING:
			ptr += (size_t)datasize;
			break;
		default:
			return false;
		}
		if (ptr > end)
			return false;
	}
	return (ptr == end);
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
print_packed(const packed_t &data) {
	for (const auto &byte : data) {
		std::cout << std::hex << (unsigned)byte << ' ';
	}
	std::cout << std::endl;
}

ATF_TEST_CASE_WITHOUT_HEAD(get_set_array);
ATF_TEST_CASE_BODY(get_set_array)
{
	Array<String> arr;
	arr.add(new String("my", "value"));
	auto pair = arr[0];
	ATF_REQUIRE(pair != nullptr);
	std::string value;
	pair->get(value);
	ATF_REQUIRE(value == "value");
}


ATF_TEST_CASE_WITHOUT_HEAD(get_set_bool);
ATF_TEST_CASE_BODY(get_set_bool)
{
	Tree tree;
	tree.add(new Bool("my", true));
	auto pair = tree.find("my");
	ATF_REQUIRE(pair != nullptr);
	bool value;
	pair->get(value);
	ATF_REQUIRE(value);
	pair->set(false);
	pair->get(value);
	ATF_REQUIRE(!value);
}


ATF_TEST_CASE_WITHOUT_HEAD(get_set_descriptor);
ATF_TEST_CASE_BODY(get_set_descriptor)
{
	Tree tree;
	tree.add(new Descriptor("my", 5));
	auto pair = tree.find("my");
	ATF_REQUIRE(pair != nullptr);
	int64_t value;
	pair->get(value);
	ATF_REQUIRE(value == 5);
	pair->set(3);
	pair->get(value);
	ATF_REQUIRE(value == 3);
}


ATF_TEST_CASE_WITHOUT_HEAD(get_set_number);
ATF_TEST_CASE_BODY(get_set_number)
{
	Tree tree;
	tree.add(new Number("my", 5));
	auto pair = tree.find("my");
	ATF_REQUIRE(pair != nullptr);
	uint64_t value;
	pair->get(value);
	ATF_REQUIRE(value == 5);
	pair->set(3);
	pair->get(value);
	ATF_REQUIRE(value == 3);
}


ATF_TEST_CASE_WITHOUT_HEAD(get_set_string);
ATF_TEST_CASE_BODY(get_set_string)
{
	Tree tree;
	tree.add(new String("my", "value"));
	auto pair = tree.find("my");
	ATF_REQUIRE(pair != nullptr);
	std::string value;
	pair->get(value);
	ATF_REQUIRE(value == "value");
	pair->set("something");
	pair->get(value);
	ATF_REQUIRE(value == "something");
}


ATF_TEST_CASE_WITHOUT_HEAD(packing);
ATF_TEST_CASE_BODY(packing)
{
	Tree tree;
	packed_t data;
	nvlist_t *nvl = 0;
	nvlist_t *snvl = 0;
	uint8_t *buf = 0;
	size_t size = 0;

	auto *a = new Tree("sub");
	tree.add(a);
	a = new Tree("tree");
	tree.add(a);
	nvl = nvlist_create(0);
	snvl = nvlist_create(0);
	nvlist_add_nvlist(nvl, "sub", snvl);
	snvl = nvlist_create(0);
	nvlist_add_nvlist(nvl, "tree", snvl);
	buf = (uint8_t *)nvlist_pack(nvl, &size);
	
	std::cout << std::endl;
	if (tree.pack(data)) {
		std::cout << "(" << std::dec << data.size() << "): ";
		print_packed(data);
		std::cout << "(" << std::dec << size << "): ";
		print_bytes(buf, size, 0);
	} else {
		std::cout << "Something is wrong" << std::endl;
	}
	std::cout << std::endl;
}


ATF_TEST_CASE_WITHOUT_HEAD(unpacking);
ATF_TEST_CASE_BODY(unpacking)
{
	Tree tree;
	void *data = nullptr;
	size_t size = 0;
	nvlist_t *nvl = nullptr;
	// uint64_t number = 5;
	nvlist_t *snvl = nullptr;
	// const char *s = "something";

	nvl = nvlist_create(0);
	snvl = nvlist_create(0);
	// nvlist_add_bool(nvl, "bool", true);
	// nvlist_add_string(nvl, "string", "here");
	// nvlist_add_number(snvl, "number", 5);
	// nvlist_add_null(nvl, "null");
	// nvlist_add_string_array(nvl, "array", &s, 1);
	// nvlist_append_string_array(nvl, "array", "other");
	// nvlist_add_nvlist(nvl, "nvlist", snvl);
	// nvlist_add_number_array(nvl, "array", &number, 1);
	// nvlist_add_nvlist(nvl, "sub", snvl);
	nvlist_add_nvlist_array(nvl, "subarr", &snvl, 1);
	snvl = nvlist_create(0);
	nvlist_append_nvlist_array(nvl, "another", snvl);
	data = nvlist_pack(nvl, &size);
	print_bytes((uint8_t *)data, size, 0);
	try {
		tree.unpack(data, size);
	} catch (std::invalid_argument &e) {
		std::cout << "Some error: " << e.what() << std::endl;
	}
}

ATF_TEST_CASE_WITHOUT_HEAD(unpacking_cross_endian);
ATF_TEST_CASE_BODY(unpacking_cross_endian)
{
	Tree src;
	Tree out;
	packed_t data;
	bool src_isbe = false;
	bool dst_isbe = false;
	Pair *pair = nullptr;
	uint64_t number = 0;
	std::string string;

	src.add(new Null("null"));
	src.add(new Bool("bool", true));
	src.add(new Number("number", 123));
	src.add(new String("string", "cross-endian"));
	ATF_REQUIRE(src.pack(data));
	ATF_REQUIRE(data.size() > NVTREE_TREE_HEADER_SIZE);

#if BYTE_ORDER == BIG_ENDIAN
	src_isbe = true;
#else
	src_isbe = false;
#endif
	dst_isbe = !src_isbe;
	ATF_REQUIRE(rewrite_simple_tree_endian(data.data(), data.size(), src_isbe,
	    dst_isbe));

	ATF_REQUIRE(out.unpack(data.data(), data.size()));
	pair = out.find("number");
	ATF_REQUIRE(pair != nullptr);
	pair->get(number);
	ATF_REQUIRE_EQ(number, 123);
	pair = out.find("string");
	ATF_REQUIRE(pair != nullptr);
	pair->get(string);
	ATF_REQUIRE(string == "cross-endian");
}


ATF_INIT_TEST_CASES(tp)
{
       ATF_ADD_TEST_CASE(tp, get_set_array);
       ATF_ADD_TEST_CASE(tp, get_set_bool);
       ATF_ADD_TEST_CASE(tp, get_set_descriptor);
       ATF_ADD_TEST_CASE(tp, get_set_number);
       ATF_ADD_TEST_CASE(tp, get_set_string);
       ATF_ADD_TEST_CASE(tp, packing);
       ATF_ADD_TEST_CASE(tp, unpacking);
       ATF_ADD_TEST_CASE(tp, unpacking_cross_endian);
}
