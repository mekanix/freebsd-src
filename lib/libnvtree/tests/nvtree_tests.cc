#include <sys/cdefs.h>

#include <atf-c++.hpp>
#include <errno.h>
#include "../nvtree.h"

ATF_TEST_CASE_WITHOUT_HEAD(nvtree_test);
ATF_TEST_CASE_BODY(nvtree_test)
{
	nvtree_t *root = nvtree_create();
	ATF_REQUIRE(root != NULL);
	// ATF_REQUIRE_EQ(nvlist_error(nvl), 0);
	// ATF_REQUIRE(nvlist_empty(nvl));
}

ATF_INIT_TEST_CASES(tp)
{
	ATF_ADD_TEST_CASE(tp, nvtree_test);
}
