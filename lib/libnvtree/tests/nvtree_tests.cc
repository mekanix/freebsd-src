#include <sys/cdefs.h>
#include <sys/nv.h>

#include <atf-c++.hpp>
#include <err.h>
#include <string.h>
#include "../nvtree.h"

ATF_TEST_CASE_WITHOUT_HEAD(nvtree_create);
ATF_TEST_CASE_BODY(nvtree_create)
{
	nvtree_t *root = nvtree_create(0);
	ATF_REQUIRE(root != NULL);
	// ATF_REQUIRE_EQ(nvlist_error(nvl), 0);
	nvtree_destroy(root);
}

ATF_TEST_CASE_WITHOUT_HEAD(nvtree_find_number);
ATF_TEST_CASE_BODY(nvtree_find_number)
{
	const char *name = "number";
	nvtree_t *root = nvtree_create(0);
	nvtpair_t *pair = nvtree_number(name, 5);

	ATF_REQUIRE(nvtree_add(root, pair) == NULL);
	ATF_REQUIRE(nvtree_find(root, name) != NULL);
	ATF_REQUIRE(nvtree_find(root, "number") != NULL);
	nvtree_destroy(root);
}

ATF_TEST_CASE_WITHOUT_HEAD(nvtree_pack_scalar_types);
ATF_TEST_CASE_BODY(nvtree_pack_scalar_types)
{
	size_t size = 0;
	void *buf = NULL;
	nvtree_t *root = nvtree_create(0);
	nvlist_t *nvl = NULL;

	ATF_REQUIRE_EQ(nvtree_add(root, nvtree_bool("bool", true)), nullptr);
	ATF_REQUIRE_EQ(nvtree_add(root, nvtree_number("number", 5)), nullptr);
	ATF_REQUIRE_EQ(nvtree_add(root, nvtree_string("string", "value")), nullptr);
	ATF_REQUIRE_EQ(nvtree_add(root, nvtree_null("null")), nullptr);

	buf = nvtree_pack(root, &size);
	nvtree_destroy(root);
	ATF_REQUIRE(buf != NULL);
	ATF_REQUIRE(size != 0);

	nvl = nvlist_unpack(buf, size, 0);
	free(buf);
	ATF_REQUIRE(nvl != NULL);
	ATF_REQUIRE(nvlist_exists_bool(nvl, "bool"));
	ATF_REQUIRE(nvlist_get_bool(nvl, "bool"));
	ATF_REQUIRE(nvlist_exists_number(nvl, "number"));
	ATF_REQUIRE(nvlist_get_number(nvl, "number") == 5);
	ATF_REQUIRE(nvlist_exists_string(nvl, "string"));
	ATF_REQUIRE(strcmp(nvlist_get_string(nvl, "string"), "value") == 0);
	ATF_REQUIRE(nvlist_exists_null(nvl, "null"));

	nvlist_destroy(nvl);
}

ATF_TEST_CASE_WITHOUT_HEAD(nvtree_pack_nested_tree);
ATF_TEST_CASE_BODY(nvtree_pack_nested_tree)
{
	size_t size = 0;
	void *buf = NULL;
	nvlist_t *nvl = NULL;
	const nvlist_t *child = NULL;

	nvtree_t *root = nvtree_create(0);
	nvtpair_t *nested = nvtree_nested("nested", 0);

	ATF_REQUIRE_EQ(nvtree_add_tree(nested, nvtree_bool("child_bool", true)), nullptr);
	ATF_REQUIRE_EQ(nvtree_add_tree(nested, nvtree_number("child_number", 7)), nullptr);
	ATF_REQUIRE_EQ(nvtree_add_tree(nested, nvtree_string("child_string", "child")), nullptr);
	ATF_REQUIRE_EQ(nvtree_add_tree(nested, nvtree_null("child_null")), nullptr);
	ATF_REQUIRE_EQ(nvtree_add(root, nested), nullptr);

	buf = nvtree_pack(root, &size);
	nvtree_destroy(root);

	ATF_REQUIRE(buf != NULL);
	ATF_REQUIRE(size != 0);
	nvl = nvlist_unpack(buf, size, 0);
	free(buf);
	ATF_REQUIRE(nvl != NULL);

	ATF_REQUIRE(nvlist_exists_nvlist(nvl, "nested"));
	child = nvlist_get_nvlist(nvl, "nested");
	ATF_REQUIRE(child != NULL);
	ATF_REQUIRE(nvlist_exists_bool(child, "child_bool"));
	ATF_REQUIRE(nvlist_get_bool(child, "child_bool"));
	ATF_REQUIRE(nvlist_exists_number(child, "child_number"));
	ATF_REQUIRE(nvlist_get_number(child, "child_number") == 7);
	ATF_REQUIRE(nvlist_exists_string(child, "child_string"));
	ATF_REQUIRE(strcmp(nvlist_get_string(child, "child_string"), "child") == 0);
	ATF_REQUIRE(nvlist_exists_null(child, "child_null"));

	nvlist_destroy(nvl);
}

ATF_INIT_TEST_CASES(tp)
{
	ATF_ADD_TEST_CASE(tp, nvtree_create);
	ATF_ADD_TEST_CASE(tp, nvtree_find_number);
	ATF_ADD_TEST_CASE(tp, nvtree_pack_scalar_types);
	ATF_ADD_TEST_CASE(tp, nvtree_pack_nested_tree);
}
