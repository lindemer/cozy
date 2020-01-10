#include <ztest.h>

extern void cose_test_sign1_write(void);
extern void cose_test_sign1_read(void);
extern void cose_test_encrypt0_write(void);
extern void cose_test_encrypt0_read(void);

/* test case main entry */
void test_main(void)
{
    ztest_test_suite(cose_tests,
        ztest_unit_test(cose_test_sign1_write),
        ztest_unit_test(cose_test_sign1_read),
        ztest_unit_test(cose_test_encrypt0_write),
        ztest_unit_test(cose_test_encrypt0_read));
    ztest_run_test_suite(cose_tests);
}
