#include <iostream>

#include <atf-c++.hpp>

#include <sys/nv.h>
#include <nvtpp.h>

using namespace nvtpp;

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


ATF_INIT_TEST_CASES(tp)
{
       ATF_ADD_TEST_CASE(tp, get_set_array);
       ATF_ADD_TEST_CASE(tp, get_set_bool);
       ATF_ADD_TEST_CASE(tp, get_set_descriptor);
       ATF_ADD_TEST_CASE(tp, get_set_number);
       ATF_ADD_TEST_CASE(tp, get_set_string);
       ATF_ADD_TEST_CASE(tp, packing);
       ATF_ADD_TEST_CASE(tp, unpacking);
}
