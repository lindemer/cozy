#include <ztest.h>

extern void test_cose_sign_write(void);
extern void test_cose_sign_read(void);
extern void test_cose_encrypt0_write(void);
extern void test_cose_encrypt0_read(void);
extern void test_cose_mac0_write(void);
extern void test_cose_mac0_read(void);

/* test case main entry */
void test_main(void)
{
    ztest_test_suite(cose_tests,
        ztest_unit_test(test_cose_sign_write),
        ztest_unit_test(test_cose_sign_read),
        ztest_unit_test(test_cose_encrypt0_write),
        ztest_unit_test(test_cose_encrypt0_read),
        ztest_unit_test(test_cose_mac0_write),
        ztest_unit_test(test_cose_mac0_read));
    ztest_run_test_suite(cose_tests);
}
