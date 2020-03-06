/*
 * Copyright (c) 2020, RISE Research Institutes of Sweden
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Samuel Tanner Lindemer
 * <samuel.lindemer@ri.se>
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
