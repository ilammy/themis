/*
 * Copyright (c) 2015 Cossack Labs Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SOTER_RSA_KEY_COMMON_H
#define SOTER_RSA_KEY_COMMON_H

#include <soter/soter_rsa_key.h>

static inline size_t rsa_pub_key_size(int mod_size)
{
    switch (mod_size) {
    case 128: /* 1024 */
        return sizeof(soter_rsa_pub_key_1024_t);
    case 256: /* 2048 */
        return sizeof(soter_rsa_pub_key_2048_t);
    case 512: /* 4096 */
        return sizeof(soter_rsa_pub_key_4096_t);
    case 1024: /* 8192 */
        return sizeof(soter_rsa_pub_key_8192_t);
    default:
        return 0;
    }
}

static inline size_t rsa_priv_key_size(int mod_size)
{
    switch (mod_size) {
    case 128: /* 1024 */
        return sizeof(soter_rsa_priv_key_1024_t);
    case 256: /* 2048 */
        return sizeof(soter_rsa_priv_key_2048_t);
    case 512: /* 4096 */
        return sizeof(soter_rsa_priv_key_4096_t);
    case 1024: /* 8192 */
        return sizeof(soter_rsa_priv_key_8192_t);
    default:
        return 0;
    }
}

static inline char* rsa_pub_key_tag(int mod_size)
{
    switch (mod_size) {
    case 128: /* 1024 */
        return RSA_PUB_KEY_TAG(1024);
    case 256: /* 2048 */
        return RSA_PUB_KEY_TAG(2048);
    case 512: /* 4096 */
        return RSA_PUB_KEY_TAG(4096);
    case 1024: /* 8192 */
        return RSA_PUB_KEY_TAG(8192);
    default:
        return NULL;
    }
}

static inline char* rsa_priv_key_tag(int mod_size)
{
    switch (mod_size) {
    case 128: /* 1024 */
        return RSA_PRIV_KEY_TAG(1024);
    case 256: /* 2048 */
        return RSA_PRIV_KEY_TAG(2048);
    case 512: /* 4096 */
        return RSA_PRIV_KEY_TAG(4096);
    case 1024: /* 8192 */
        return RSA_PRIV_KEY_TAG(8192);
    default:
        return NULL;
    }
}

static inline bool is_mod_size_supported(int mod_size)
{
    switch (mod_size) {
    case 128:
    case 256:
    case 512:
    case 1024:
        return true;
    default:
        return false;
    }
}

static inline const uint8_t* soter_rsa_pub_key_const_mod(const soter_container_hdr_t* key,
                                                         int mod_size)
{
    UNUSED(mod_size);
    return soter_container_const_data(key);
}

static inline uint8_t* soter_rsa_pub_key_mod(soter_container_hdr_t* key, int mod_size)
{
    UNUSED(mod_size);
    return soter_container_data(key);
}

static inline uint32_t soter_rsa_pub_key_get_pub_exp(const soter_container_hdr_t* key, int mod_size)
{
    return be32toh(*(const uint32_t*)(soter_container_const_data(key) + mod_size));
}

static inline void soter_rsa_pub_key_set_pub_exp(soter_container_hdr_t* key,
                                                 int mod_size,
                                                 uint32_t pub_exp)
{
    *(uint32_t*)(soter_container_data(key) + mod_size) = htobe32(pub_exp);
}

static inline const uint8_t* soter_rsa_priv_key_const_priv_exp(const soter_container_hdr_t* key,
                                                               int mod_size)
{
    UNUSED(mod_size);
    return soter_container_const_data(key);
}

static inline uint8_t* soter_rsa_priv_key_priv_exp(soter_container_hdr_t* key, int mod_size)
{
    UNUSED(mod_size);
    return soter_container_data(key);
}

static inline const uint8_t* soter_rsa_priv_key_const_p(const soter_container_hdr_t* key,
                                                        int mod_size)
{
    return soter_container_const_data(key) + mod_size;
}

static inline uint8_t* soter_rsa_priv_key_p(soter_container_hdr_t* key, int mod_size)
{
    return soter_container_data(key) + mod_size;
}

static inline const uint8_t* soter_rsa_priv_key_const_q(const soter_container_hdr_t* key,
                                                        int mod_size)
{
    return soter_container_const_data(key) + mod_size + mod_size / 2;
}

static inline uint8_t* soter_rsa_priv_key_q(soter_container_hdr_t* key, int mod_size)
{
    return soter_container_data(key) + mod_size + mod_size / 2;
}

static inline const uint8_t* soter_rsa_priv_key_const_dp(const soter_container_hdr_t* key,
                                                         int mod_size)
{
    return soter_container_const_data(key) + 2 * mod_size;
}

static inline uint8_t* soter_rsa_priv_key_dp(soter_container_hdr_t* key, int mod_size)
{
    return soter_container_data(key) + 2 * mod_size;
}

static inline const uint8_t* soter_rsa_priv_key_const_dq(const soter_container_hdr_t* key,
                                                         int mod_size)
{
    return soter_container_const_data(key) + 2 * mod_size + mod_size / 2;
}

static inline uint8_t* soter_rsa_priv_key_dq(soter_container_hdr_t* key, int mod_size)
{
    return soter_container_data(key) + 2 * mod_size + mod_size / 2;
}

static inline const uint8_t* soter_rsa_priv_key_const_qp(const soter_container_hdr_t* key,
                                                         int mod_size)
{
    return soter_container_const_data(key) + 3 * mod_size;
}

static inline uint8_t* soter_rsa_priv_key_qp(soter_container_hdr_t* key, int mod_size)
{
    return soter_container_data(key) + 3 * mod_size;
}

static inline const uint8_t* soter_rsa_priv_key_const_mod(const soter_container_hdr_t* key,
                                                          int mod_size)
{
    return soter_container_const_data(key) + 3 * mod_size + mod_size / 2;
}

static inline uint8_t* soter_rsa_priv_key_mod(soter_container_hdr_t* key, int mod_size)
{
    return soter_container_data(key) + 3 * mod_size + mod_size / 2;
}

static inline uint32_t soter_rsa_priv_key_get_pub_exp(const soter_container_hdr_t* key,
                                                      int mod_size)
{
    const uint8_t* ptr = (soter_container_const_data(key) + 4 * mod_size + mod_size / 2);
    return be32toh(*(const uint32_t*)ptr);
}

static inline void soter_rsa_priv_key_set_pub_exp(soter_container_hdr_t* key,
                                                  int mod_size,
                                                  uint32_t pub_exp)
{
    *(uint32_t*)(soter_container_data(key) + 4 * mod_size + mod_size / 2) = htobe32(pub_exp);
}

#endif /* SOTER_RSA_KEY_COMMON_H */
