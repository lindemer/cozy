#include <ztest.h>

extern void cose_test_mbedtls_sanity_check(void);
extern void cose_test_tinycbor_sanity_check(void);
extern void cose_test_sign1(void);

/* test case main entry */
void test_main(void)
{
    ztest_test_suite(cose_tests,
        ztest_unit_test(cose_test_mbedtls_sanity_check),
        ztest_unit_test(cose_test_tinycbor_sanity_check),
        ztest_unit_test(cose_test_sign1));
    ztest_run_test_suite(cose_tests);
}
