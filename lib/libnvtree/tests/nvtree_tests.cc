#include <sys/cdefs.h>
#include <sys/nv.h>

#include <atf-c++.hpp>
#include <err.h>
#include "../nvtree.h"

ATF_TEST_CASE_WITHOUT_HEAD(nvtree_create);
ATF_TEST_CASE_BODY(nvtree_create)
{
	nvtree_t *root = nvtree_create(0);
	ATF_REQUIRE(root != NULL);
	// ATF_REQUIRE_EQ(nvlist_error(nvl), 0);
	nvtree_destroy(root);
}

ATF_TEST_CASE_WITHOUT_HEAD(nvtree_find);
ATF_TEST_CASE_BODY(nvtree_find)
{
	const char *name = "number";
	nvtree_t *root = nvtree_create(0);
	nvtpair_t *pair = nvtree_number(name, 5);

	ATF_REQUIRE(nvtree_add(root, pair) == NULL);
	ATF_REQUIRE(nvtree_find(root, name) != NULL);
	ATF_REQUIRE(nvtree_find(root, "number") != NULL);
	nvtree_destroy(root);
}

ATF_TEST_CASE_WITHOUT_HEAD(nvtree_pack);
ATF_TEST_CASE_BODY(nvtree_pack)
{
	size_t size = 0;
	void *buf = NULL;
	nvtree_t *root = nvtree_create(0);
	nvtpair_t *pair = nvtree_number("number", 5);
	nvlist_t *nvl = NULL;

	nvtree_add(root, pair);
	buf = nvtree_pack(root, &size);
	nvtree_destroy(root);
	ATF_REQUIRE(buf != NULL);
	ATF_REQUIRE(size != 0);

	nvl = nvlist_unpack(buf, size, 0);
	free(buf);
	ATF_REQUIRE(nvl != NULL);
	ATF_REQUIRE(nvlist_exists_number(nvl, "number"));
	ATF_REQUIRE(nvlist_get_number(nvl, "number") == 5);

	nvlist_destroy(nvl);
}

ATF_INIT_TEST_CASES(tp)
{
	ATF_ADD_TEST_CASE(tp, nvtree_create);
	ATF_ADD_TEST_CASE(tp, nvtree_find);
	ATF_ADD_TEST_CASE(tp, nvtree_pack);
}
