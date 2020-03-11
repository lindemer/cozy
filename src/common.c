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

#include <cozy/cose.h>
#include <cozy/common.h>

int cose_encode_prot(cose_key_t * key, nanocbor_encoder_t * nc)
{
    nanocbor_fmt_map(nc, 1);
    nanocbor_fmt_int(nc, cose_header_algorithm);
    nanocbor_fmt_int(nc, key->alg);
    return nanocbor_encoded_len(nc);
}

void xxd(const uint8_t * data, size_t len, int w) 
{
    size_t i, j;
    for (i = 0; i < len; i += w) {
        for (j = 0; j < w; j++) {
            if (i + j == len) break;
            else printk("%2x ", *(data+i+j));
        }
        printk("\n");
    }
    printk("\n");
}
