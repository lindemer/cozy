/*
 * Copyright 2020 RISE Research Institutes of Sweden
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

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
