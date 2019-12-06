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

#include "themis/secure_message.h"

#include "soter/soter_wipe.h"

#include "themis/secure_keygen.h"
#include "themis/secure_message_wrapper.h"

themis_status_t themis_secure_message_encrypt(const uint8_t* private_key,
                                              const size_t private_key_length,
                                              const uint8_t* public_key,
                                              const size_t public_key_length,
                                              const uint8_t* message,
                                              const size_t message_length,
                                              uint8_t* encrypted_message,
                                              size_t* encrypted_message_length)
{
    themis_status_t res = THEMIS_FAIL;
    themis_secure_message_encrypter_t* ctx = NULL;

    THEMIS_CHECK_PARAM(private_key != NULL);
    THEMIS_CHECK_PARAM(private_key_length != 0);
    THEMIS_CHECK_PARAM(public_key != NULL);
    THEMIS_CHECK_PARAM(public_key_length != 0);
    THEMIS_CHECK_PARAM(message != NULL);
    THEMIS_CHECK_PARAM(message_length != 0);
    THEMIS_CHECK_PARAM(encrypted_message_length != NULL);

    ctx = themis_secure_message_encrypter_init(private_key, private_key_length, public_key, public_key_length);
    if (!ctx) {
        return THEMIS_FAIL;
    }

    res = themis_secure_message_encrypter_proceed(ctx,
                                                  message,
                                                  message_length,
                                                  encrypted_message,
                                                  encrypted_message_length);

    themis_secure_message_encrypter_destroy(ctx);

    if (res != THEMIS_SUCCESS && res != THEMIS_BUFFER_TOO_SMALL) {
        soter_wipe(encrypted_message, *encrypted_message_length);
    }

    return res;
}

themis_status_t themis_secure_message_decrypt(const uint8_t* private_key,
                                              const size_t private_key_length,
                                              const uint8_t* public_key,
                                              const size_t public_key_length,
                                              const uint8_t* encrypted_message,
                                              const size_t encrypted_message_length,
                                              uint8_t* message,
                                              size_t* message_length)
{
    themis_status_t res = THEMIS_FAIL;
    themis_secure_message_decrypter_t* ctx = NULL;
    const themis_secure_message_hdr_t* message_hdr = (const themis_secure_message_hdr_t*)encrypted_message;

    THEMIS_CHECK_PARAM(private_key != NULL);
    THEMIS_CHECK_PARAM(private_key_length != 0);
    THEMIS_CHECK_PARAM(public_key != NULL);
    THEMIS_CHECK_PARAM(public_key_length != 0);
    THEMIS_CHECK_PARAM(encrypted_message != NULL);
    THEMIS_CHECK_PARAM(encrypted_message_length != 0);
    THEMIS_CHECK_PARAM(message_length != NULL);

    if (!IS_THEMIS_SECURE_MESSAGE_ENCRYPTED(message_hdr->message_type)) {
        return THEMIS_FAIL;
    }
    if (encrypted_message_length < THEMIS_SECURE_MESSAGE_LENGTH(message_hdr)) {
        return THEMIS_FAIL;
    }

    ctx = themis_secure_message_decrypter_init(private_key, private_key_length, public_key, public_key_length);
    if (!ctx) {
        return THEMIS_FAIL;
    }

    res = themis_secure_message_decrypter_proceed(ctx,
                                                  encrypted_message,
                                                  encrypted_message_length,
                                                  message,
                                                  message_length);

    themis_secure_message_decrypter_destroy(ctx);

    if (res != THEMIS_SUCCESS && res != THEMIS_BUFFER_TOO_SMALL) {
        soter_wipe(message, *message_length);
    }

    return res;
}

themis_status_t themis_secure_message_sign(const uint8_t* private_key,
                                           const size_t private_key_length,
                                           const uint8_t* message,
                                           const size_t message_length,
                                           uint8_t* signed_message,
                                           size_t* signed_message_length)
{
    themis_status_t res = THEMIS_FAIL;
    themis_secure_message_signer_t* ctx = NULL;

    THEMIS_CHECK_PARAM(private_key != NULL);
    THEMIS_CHECK_PARAM(private_key_length != 0);
    THEMIS_CHECK_PARAM(message != NULL);
    THEMIS_CHECK_PARAM(message_length != 0);
    THEMIS_CHECK_PARAM(signed_message_length != NULL);

    ctx = themis_secure_message_signer_init(private_key, private_key_length);
    if (!ctx) {
        return THEMIS_FAIL;
    }

    res = themis_secure_message_signer_proceed(ctx,
                                               message,
                                               message_length,
                                               signed_message,
                                               signed_message_length);

    themis_secure_message_signer_destroy(ctx);

    if (res != THEMIS_SUCCESS && res != THEMIS_BUFFER_TOO_SMALL) {
        soter_wipe(signed_message, *signed_message_length);
    }

    return res;
}

themis_status_t themis_secure_message_verify(const uint8_t* public_key,
                                             const size_t public_key_length,
                                             const uint8_t* signed_message,
                                             const size_t signed_message_length,
                                             uint8_t* message,
                                             size_t* message_length)
{
    themis_status_t res = THEMIS_FAIL;
    themis_secure_message_verifier_t* ctx = NULL;
    const themis_secure_message_hdr_t* message_hdr = (const themis_secure_message_hdr_t*)signed_message;

    THEMIS_CHECK_PARAM(public_key != NULL);
    THEMIS_CHECK_PARAM(public_key_length != 0);
    THEMIS_CHECK_PARAM(signed_message != NULL);
    THEMIS_CHECK_PARAM(signed_message_length != 0);
    THEMIS_CHECK_PARAM(message_length != NULL);

    if (!IS_THEMIS_SECURE_MESSAGE_SIGNED(message_hdr->message_type)) {
        return THEMIS_FAIL;
    }
    if (signed_message_length < THEMIS_SECURE_MESSAGE_LENGTH(message_hdr)) {
        return THEMIS_FAIL;
    }

    ctx = themis_secure_message_verifier_init(public_key, public_key_length);
    if (!ctx) {
        return THEMIS_FAIL;
    }

    res = themis_secure_message_verifier_proceed(ctx,
                                                 signed_message,
                                                 signed_message_length,
                                                 message,
                                                 message_length);

    themis_secure_message_verifier_destroy(ctx);

    if (res != THEMIS_SUCCESS && res != THEMIS_BUFFER_TOO_SMALL) {
        soter_wipe(message, *message_length);
    }

    return res;
}

/*
 * themis_secure_message_wrap() and themis_secure_message_unwrap() functions
 * are deprecated in favor of more specific themis_secure_message_encrypt()
 * themis_secure_message_decrypt(), themis_secure_message_sign(),
 * themis_secure_message_verify().
 *
 * The old functions combined the interface of the new ones (wrap = encrypt
 * or sign, unwrap = decrypt or verify). The new functions provide a more
 * cleanly separated interface for distinct concerns.
 *
 * Note that while their implementation looks similar, they are not quite
 * the same and differ slightly in error handling. Don't try to reimplement
 * them in terms of each other. We will remove wrap and unwrap eventually.
 */

themis_status_t themis_secure_message_wrap(const uint8_t* private_key,
                                           const size_t private_key_length,
                                           const uint8_t* public_key,
                                           const size_t public_key_length,
                                           const uint8_t* message,
                                           const size_t message_length,
                                           uint8_t* wrapped_message,
                                           size_t* wrapped_message_length)
{
    themis_status_t res = THEMIS_FAIL;

    THEMIS_CHECK_PARAM(private_key != NULL);
    THEMIS_CHECK_PARAM(private_key_length != 0);
    THEMIS_CHECK_PARAM(message != NULL);
    THEMIS_CHECK_PARAM(message_length != 0);
    THEMIS_CHECK_PARAM(wrapped_message_length != NULL);

    if (public_key == NULL && public_key_length == 0) {
        themis_secure_message_signer_t* ctx = NULL;

        ctx = themis_secure_message_signer_init(private_key, private_key_length);
        if (!ctx) {
            res = THEMIS_FAIL;
            goto error;
        }

        res = themis_secure_message_signer_proceed(ctx,
                                                   message,
                                                   message_length,
                                                   wrapped_message,
                                                   wrapped_message_length);

        themis_secure_message_signer_destroy(ctx);
    } else {
        themis_secure_message_encrypter_t* ctx = NULL;

        THEMIS_CHECK_PARAM(public_key != NULL);
        THEMIS_CHECK_PARAM(public_key_length != 0);

        ctx = themis_secure_message_encrypter_init(private_key, private_key_length, public_key, public_key_length);
        if (!ctx) {
            res = THEMIS_FAIL;
            goto error;
        }

        res = themis_secure_message_encrypter_proceed(ctx,
                                                      message,
                                                      message_length,
                                                      wrapped_message,
                                                      wrapped_message_length);

        themis_secure_message_encrypter_destroy(ctx);
    }

error:
    if (res != THEMIS_SUCCESS && res != THEMIS_BUFFER_TOO_SMALL) {
        soter_wipe(wrapped_message, *wrapped_message_length);
    }

    return res;
}

themis_status_t themis_secure_message_unwrap(const uint8_t* private_key,
                                             const size_t private_key_length,
                                             const uint8_t* public_key,
                                             const size_t public_key_length,
                                             const uint8_t* wrapped_message,
                                             const size_t wrapped_message_length,
                                             uint8_t* message,
                                             size_t* message_length)
{
    themis_status_t res = THEMIS_FAIL;
    const themis_secure_message_hdr_t* message_hdr = (const themis_secure_message_hdr_t*)wrapped_message;

    THEMIS_CHECK_PARAM(public_key != NULL);
    THEMIS_CHECK_PARAM(public_key_length != 0);
    THEMIS_CHECK_PARAM(wrapped_message != NULL);
    THEMIS_CHECK_PARAM(wrapped_message_length != 0);
    THEMIS_CHECK_PARAM(message_length != NULL);

    if (wrapped_message_length < THEMIS_SECURE_MESSAGE_LENGTH(message_hdr)) {
        goto error;
    }

    if (IS_THEMIS_SECURE_MESSAGE_SIGNED(message_hdr->message_type)) {
        themis_secure_message_verifier_t* ctx = NULL;

        ctx = themis_secure_message_verifier_init(public_key, public_key_length);
        if (!ctx) {
            res = THEMIS_FAIL;
            goto error;
        }

        res = themis_secure_message_verifier_proceed(ctx,
                                                     wrapped_message,
                                                     wrapped_message_length,
                                                     message,
                                                     message_length);

        themis_secure_message_verifier_destroy(ctx);
    }
    if (IS_THEMIS_SECURE_MESSAGE_ENCRYPTED(message_hdr->message_type)) {
        themis_secure_message_decrypter_t* ctx = NULL;

        THEMIS_CHECK_PARAM(private_key != NULL);
        THEMIS_CHECK_PARAM(private_key_length != 0);

        ctx = themis_secure_message_decrypter_init(private_key, private_key_length, public_key, public_key_length);
        if (!ctx) {
            res = THEMIS_FAIL;
            goto error;
        }

        res = themis_secure_message_decrypter_proceed(ctx,
                                                      wrapped_message,
                                                      wrapped_message_length,
                                                      message,
                                                      message_length);

        themis_secure_message_decrypter_destroy(ctx);
    }

error:
    if (res != THEMIS_SUCCESS && res != THEMIS_BUFFER_TOO_SMALL) {
        soter_wipe(message, *message_length);
    }

    return res;
}
