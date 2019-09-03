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

#include "soter/soter_rsa_key.h"

#include <string.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "soter/portable_endian.h"
#include "soter/soter_rsa_key_common.h"

static soter_status_t bignum_to_bytes(BIGNUM* bn, uint8_t* to, size_t to_length)
{
    size_t bn_size = (size_t)BN_num_bytes(bn);
    size_t bytes_copied;

    if (bn_size > to_length) {
        return SOTER_FAIL;
    }

    bytes_copied = BN_bn2bin(bn, to + (to_length - bn_size));

    if (bytes_copied != bn_size) {
        return SOTER_FAIL;
    }

    memset(to, 0, to_length - bn_size);

    return SOTER_SUCCESS;
}

soter_status_t soter_engine_specific_to_rsa_pub_key(const soter_engine_specific_rsa_key_t* engine_key,
                                                    soter_container_hdr_t* key,
                                                    size_t* key_length)
{
    EVP_PKEY* pkey = (EVP_PKEY*)engine_key;
    RSA* rsa;
    soter_status_t res;
    int rsa_mod_size;
    size_t output_length;

    if (!key_length) {
        return SOTER_INVALID_PARAMETER;
    }

    if (EVP_PKEY_RSA != EVP_PKEY_id(pkey)) {
        return SOTER_INVALID_PARAMETER;
    }

    rsa = EVP_PKEY_get1_RSA((EVP_PKEY*)pkey);
    if (NULL == rsa) {
        return SOTER_FAIL;
    }

    rsa_mod_size = RSA_size(rsa);
    if (!is_mod_size_supported(rsa_mod_size)) {
        res = SOTER_INVALID_PARAMETER;
        goto err;
    }

    output_length = rsa_pub_key_size(rsa_mod_size);
    if ((!key) || (output_length > *key_length)) {
        *key_length = output_length;
        res = SOTER_BUFFER_TOO_SMALL;
        goto err;
    }

    if (BN_is_word(rsa->e, RSA_F4)) {
        soter_rsa_pub_key_set_pub_exp(key, rsa_mod_size, RSA_F4);
    } else if (BN_is_word(rsa->e, RSA_3)) {
        soter_rsa_pub_key_set_pub_exp(key, rsa_mod_size, RSA_3);
    } else {
        res = SOTER_INVALID_PARAMETER;
        goto err;
    }

    res = bignum_to_bytes(rsa->n, soter_rsa_pub_key_mod(key, rsa_mod_size), rsa_mod_size);
    if (SOTER_SUCCESS != res) {
        goto err;
    }

    memcpy(key->tag, rsa_pub_key_tag(rsa_mod_size), SOTER_CONTAINER_TAG_LENGTH);
    key->size = htobe32(output_length);
    soter_update_container_checksum(key);
    *key_length = output_length;
    res = SOTER_SUCCESS;

err:
    /* Free extra reference on RSA object provided by EVP_PKEY_get1_RSA */
    RSA_free(rsa);

    return res;
}

soter_status_t soter_engine_specific_to_rsa_priv_key(const soter_engine_specific_rsa_key_t* engine_key,
                                                     soter_container_hdr_t* key,
                                                     size_t* key_length)
{
    EVP_PKEY* pkey = (EVP_PKEY*)engine_key;
    RSA* rsa;
    soter_status_t res;
    int rsa_mod_size;
    size_t output_length;

    if (!key_length) {
        return SOTER_INVALID_PARAMETER;
    }

    if (EVP_PKEY_RSA != EVP_PKEY_id(pkey)) {
        return SOTER_INVALID_PARAMETER;
    }

    rsa = EVP_PKEY_get1_RSA((EVP_PKEY*)pkey);
    if (NULL == rsa) {
        return SOTER_FAIL;
    }

    rsa_mod_size = RSA_size(rsa);
    if (!is_mod_size_supported(rsa_mod_size)) {
        res = SOTER_INVALID_PARAMETER;
        goto err;
    }

    output_length = rsa_priv_key_size(rsa_mod_size);
    if ((!key) || (output_length > *key_length)) {
        *key_length = output_length;
        res = SOTER_BUFFER_TOO_SMALL;
        goto err;
    }

    if (BN_is_word(rsa->e, RSA_F4)) {
        soter_rsa_priv_key_set_pub_exp(key, rsa_mod_size, RSA_F4);
    } else if (BN_is_word(rsa->e, RSA_3)) {
        soter_rsa_priv_key_set_pub_exp(key, rsa_mod_size, RSA_3);
    } else {
        res = SOTER_INVALID_PARAMETER;
        goto err;
    }

    /* Private exponent */
    res = bignum_to_bytes(rsa->d, soter_rsa_priv_key_priv_exp(key, rsa_mod_size), rsa_mod_size);
    if (SOTER_SUCCESS != res) {
        goto err;
    }

    /* p */
    res = bignum_to_bytes(rsa->p, soter_rsa_priv_key_p(key, rsa_mod_size), rsa_mod_size / 2);
    if (SOTER_SUCCESS != res) {
        goto err;
    }

    /* q */
    res = bignum_to_bytes(rsa->q, soter_rsa_priv_key_q(key, rsa_mod_size), rsa_mod_size / 2);
    if (SOTER_SUCCESS != res) {
        goto err;
    }

    /* dp */
    res = bignum_to_bytes(rsa->dmp1, soter_rsa_priv_key_dp(key, rsa_mod_size), rsa_mod_size / 2);
    if (SOTER_SUCCESS != res) {
        goto err;
    }

    /* dq */
    res = bignum_to_bytes(rsa->dmq1, soter_rsa_priv_key_dq(key, rsa_mod_size), rsa_mod_size / 2);
    if (SOTER_SUCCESS != res) {
        goto err;
    }

    /* qp */
    res = bignum_to_bytes(rsa->iqmp, soter_rsa_priv_key_qp(key, rsa_mod_size), rsa_mod_size / 2);
    if (SOTER_SUCCESS != res) {
        goto err;
    }

    /* modulus */
    res = bignum_to_bytes(rsa->n, soter_rsa_priv_key_mod(key, rsa_mod_size), rsa_mod_size);
    if (SOTER_SUCCESS != res) {
        goto err;
    }

    memcpy(key->tag, rsa_priv_key_tag(rsa_mod_size), SOTER_CONTAINER_TAG_LENGTH);
    key->size = htobe32(output_length);
    soter_update_container_checksum(key);
    *key_length = output_length;
    res = SOTER_SUCCESS;

err:
    /* Free extra reference on RSA object provided by EVP_PKEY_get1_RSA */
    RSA_free(rsa);

    //	if (SOTER_SUCCESS != res)
    //	{
    //		/* Zero output memory to avoid leaking private key information */
    //		memset(key, 0, *key_length);
    //	}

    return res;
}

/* TODO: Maybe, basic container validation should be put in separate functions outside of
 * engine-specific code */
soter_status_t soter_rsa_pub_key_to_engine_specific(const soter_container_hdr_t* key,
                                                    size_t key_length,
                                                    soter_engine_specific_rsa_key_t** engine_key)
{
    int rsa_mod_size;
    uint32_t pub_exp;
    RSA* rsa;
    EVP_PKEY* pkey = (EVP_PKEY*)(*engine_key);

    if (key_length != be32toh(key->size)) {
        return SOTER_INVALID_PARAMETER;
    }

    /* Validate tag */
    if (memcmp(key->tag, RSA_PUB_KEY_PREF, strlen(RSA_PUB_KEY_PREF))) {
        return SOTER_INVALID_PARAMETER;
    }

    if (SOTER_SUCCESS != soter_verify_container_checksum(key)) {
        return SOTER_DATA_CORRUPT;
    }

    switch (key->tag[3]) {
    case RSA_SIZE_TAG_1024:
        rsa_mod_size = 128;
        break;
    case RSA_SIZE_TAG_2048:
        rsa_mod_size = 256;
        break;
    case RSA_SIZE_TAG_4096:
        rsa_mod_size = 512;
        break;
    case RSA_SIZE_TAG_8192:
        rsa_mod_size = 1024;
        break;
    default:
        return SOTER_INVALID_PARAMETER;
    }

    if (key_length < rsa_pub_key_size(rsa_mod_size)) {
        return SOTER_INVALID_PARAMETER;
    }

    pub_exp = soter_rsa_pub_key_get_pub_exp(key, rsa_mod_size);
    switch (pub_exp) {
    case RSA_3:
    case RSA_F4:
        break;
    default:
        return SOTER_INVALID_PARAMETER;
    }

    rsa = RSA_new();
    if (!rsa) {
        return SOTER_NO_MEMORY;
    }

    rsa->e = BN_new();
    if (!(rsa->e)) {
        RSA_free(rsa);
        return SOTER_NO_MEMORY;
    }

    if (!BN_set_word(rsa->e, pub_exp)) {
        RSA_free(rsa);
        return SOTER_FAIL;
    }

    rsa->n = BN_new();
    if (!(rsa->n)) {
        RSA_free(rsa);
        return SOTER_NO_MEMORY;
    }

    if (!BN_bin2bn(soter_rsa_pub_key_const_mod(key, rsa_mod_size), rsa_mod_size, rsa->n)) {
        RSA_free(rsa);
        return SOTER_FAIL;
    }

    if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
        RSA_free(rsa);
        return SOTER_FAIL;
    }

    /* EVP_PKEY_assign_RSA does not increment the reference count, so no need to free RSA object */
    return SOTER_SUCCESS;
}

soter_status_t soter_rsa_priv_key_to_engine_specific(const soter_container_hdr_t* key,
                                                     size_t key_length,
                                                     soter_engine_specific_rsa_key_t** engine_key)
{
    int rsa_mod_size;
    uint32_t pub_exp;
    RSA* rsa;
    EVP_PKEY* pkey = (EVP_PKEY*)(*engine_key);

    if (key_length != be32toh(key->size)) {
        return SOTER_INVALID_PARAMETER;
    }

    /* Validate tag */
    if (memcmp(key->tag, RSA_PRIV_KEY_PREF, strlen(RSA_PRIV_KEY_PREF))) {
        return SOTER_INVALID_PARAMETER;
    }

    if (SOTER_SUCCESS != soter_verify_container_checksum(key)) {
        return SOTER_DATA_CORRUPT;
    }

    switch (key->tag[3]) {
    case RSA_SIZE_TAG_1024:
        rsa_mod_size = 128;
        break;
    case RSA_SIZE_TAG_2048:
        rsa_mod_size = 256;
        break;
    case RSA_SIZE_TAG_4096:
        rsa_mod_size = 512;
        break;
    case RSA_SIZE_TAG_8192:
        rsa_mod_size = 1024;
        break;
    default:
        return SOTER_INVALID_PARAMETER;
    }

    if (key_length < rsa_priv_key_size(rsa_mod_size)) {
        return SOTER_INVALID_PARAMETER;
    }

    pub_exp = soter_rsa_priv_key_get_pub_exp(key, rsa_mod_size);
    switch (pub_exp) {
    case RSA_3:
    case RSA_F4:
        break;
    default:
        return SOTER_INVALID_PARAMETER;
    }

    rsa = RSA_new();
    if (!rsa) {
        return SOTER_NO_MEMORY;
    }

    rsa->e = BN_new();
    if (!(rsa->e)) {
        RSA_free(rsa);
        return SOTER_NO_MEMORY;
    }

    if (!BN_set_word(rsa->e, pub_exp)) {
        RSA_free(rsa);
        return SOTER_FAIL;
    }

    /* Private exponent */
    rsa->d = BN_new();
    if (!(rsa->d)) {
        RSA_free(rsa);
        return SOTER_NO_MEMORY;
    }

    if (!BN_bin2bn(soter_rsa_priv_key_const_priv_exp(key, rsa_mod_size), rsa_mod_size, rsa->d)) {
        RSA_free(rsa);
        return SOTER_FAIL;
    }

    /* p */
    rsa->p = BN_new();
    if (!(rsa->p)) {
        RSA_free(rsa);
        return SOTER_NO_MEMORY;
    }

    if (!BN_bin2bn(soter_rsa_priv_key_const_p(key, rsa_mod_size), rsa_mod_size / 2, rsa->p)) {
        RSA_free(rsa);
        return SOTER_FAIL;
    }

    /* q */
    rsa->q = BN_new();
    if (!(rsa->q)) {
        RSA_free(rsa);
        return SOTER_NO_MEMORY;
    }

    if (!BN_bin2bn(soter_rsa_priv_key_const_q(key, rsa_mod_size), rsa_mod_size / 2, rsa->q)) {
        RSA_free(rsa);
        return SOTER_FAIL;
    }

    /* dp */
    rsa->dmp1 = BN_new();
    if (!(rsa->dmp1)) {
        RSA_free(rsa);
        return SOTER_NO_MEMORY;
    }

    if (!BN_bin2bn(soter_rsa_priv_key_const_dp(key, rsa_mod_size), rsa_mod_size / 2, rsa->dmp1)) {
        RSA_free(rsa);
        return SOTER_FAIL;
    }

    /* dq */
    rsa->dmq1 = BN_new();
    if (!(rsa->dmq1)) {
        RSA_free(rsa);
        return SOTER_NO_MEMORY;
    }

    if (!BN_bin2bn(soter_rsa_priv_key_const_dq(key, rsa_mod_size), rsa_mod_size / 2, rsa->dmq1)) {
        RSA_free(rsa);
        return SOTER_FAIL;
    }

    /* qp */
    rsa->iqmp = BN_new();
    if (!(rsa->iqmp)) {
        RSA_free(rsa);
        return SOTER_NO_MEMORY;
    }

    if (!BN_bin2bn(soter_rsa_priv_key_const_qp(key, rsa_mod_size), rsa_mod_size / 2, rsa->iqmp)) {
        RSA_free(rsa);
        return SOTER_FAIL;
    }

    /* modulus */
    rsa->n = BN_new();
    if (!(rsa->n)) {
        RSA_free(rsa);
        return SOTER_NO_MEMORY;
    }

    if (!BN_bin2bn(soter_rsa_priv_key_const_mod(key, rsa_mod_size), rsa_mod_size, rsa->n)) {
        RSA_free(rsa);
        return SOTER_FAIL;
    }

    /* If at least one CRT parameter is zero, free them */
    if (BN_is_zero(rsa->p) || BN_is_zero(rsa->q) || BN_is_zero(rsa->dmp1) || BN_is_zero(rsa->dmq1)
        || BN_is_zero(rsa->iqmp)) {
        BN_free(rsa->p);
        rsa->p = NULL;

        BN_free(rsa->q);
        rsa->q = NULL;

        BN_free(rsa->dmp1);
        rsa->dmp1 = NULL;

        BN_free(rsa->dmq1);
        rsa->dmq1 = NULL;

        BN_free(rsa->iqmp);
        rsa->iqmp = NULL;
    }

    if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
        RSA_free(rsa);
        return SOTER_FAIL;
    }

    /* EVP_PKEY_assign_RSA does not increment the reference count, so no need to free RSA object */
    return SOTER_SUCCESS;
}
