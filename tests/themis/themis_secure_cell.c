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

#include "themis/themis_test.h"

#include <stdbool.h>
#include <string.h>

#include <soter/soter_rand.h>

/* Fuzz parameters */
#define MAX_KEY_SIZE 256
#define MAX_CONTEXT_SIZE 2048
#define MAX_MESSAGE_SIZE 4096

/* Keep it under 2^31 to support 32-bit systems. */
#define CORRUPTED_LENGTH 0x5AFE

#define DEFAULT_SYM_KEY_LENGTH 32

static char passwd[] = "password";
static char message[] = "secure cell test message by Mnatsakanov Andrey from Cossack Labs";
static char user_context[] = "secure cell user context";

static bool non_zero_buffer(const uint8_t* buffer, size_t length)
{
    for (size_t i = 0; i < length; i++) {
        if (buffer[i] != 0) {
            return true;
        }
    }
    return false;
}

static bool different_buffers(const uint8_t* buffer1, size_t length1, const uint8_t* buffer2, size_t length2)
{
    size_t min = (length1 < length2) ? length1 : length2;
    if (memcmp(buffer1, buffer2, min) != 0) {
        return true;
    }
    return length1 != length2;
}

static void secure_cell_key_generation(void)
{
    themis_status_t res;
    uint8_t master_key_1[MAX_KEY_SIZE];
    uint8_t master_key_2[MAX_KEY_SIZE];
    size_t master_key_1_length = 0;
    size_t master_key_2_length = 0;

    /*
     * Normal usage of key generation API.
     */

    res = themis_gen_sym_key(NULL, &master_key_1_length);
    testsuite_fail_unless(res == THEMIS_BUFFER_TOO_SMALL, "keygen: query key size");
    testsuite_fail_unless(master_key_1_length == DEFAULT_SYM_KEY_LENGTH,
                          "keygen: recommends default key size");

    master_key_1_length = 0;
    res = themis_gen_sym_key(master_key_1, &master_key_1_length);
    testsuite_fail_unless(res == THEMIS_BUFFER_TOO_SMALL, "keygen: query key size (with buffer)");
    testsuite_fail_unless(master_key_1_length == DEFAULT_SYM_KEY_LENGTH,
                          "keygen: recommends default key size");

    size_t old_value = master_key_1_length;
    res = themis_gen_sym_key(master_key_1, &master_key_1_length);
    testsuite_fail_unless(res == THEMIS_SUCCESS, "keygen: generate recommended key");
    testsuite_fail_unless(master_key_1_length == old_value, "keygen: key length unchanged");

    master_key_1_length = MAX_KEY_SIZE;
    res = themis_gen_sym_key(master_key_1, &master_key_1_length);
    testsuite_fail_unless(res == THEMIS_SUCCESS, "keygen: generate extra-big key");
    testsuite_fail_unless(master_key_1_length == MAX_KEY_SIZE, "keygen: key length unchanged");

    master_key_1_length = 8;
    res = themis_gen_sym_key(master_key_1, &master_key_1_length);
    testsuite_fail_unless(res == THEMIS_SUCCESS, "keygen: generate small key");
    testsuite_fail_unless(master_key_1_length == 8, "keygen: key length unchanged");

    /*
     * Verify that key generation is not bogus and returns new keys.
     */

    memset(master_key_1, 0, sizeof(master_key_1));
    memset(master_key_2, 0, sizeof(master_key_2));

    master_key_1_length = MAX_KEY_SIZE;
    master_key_2_length = MAX_KEY_SIZE;

    res = themis_gen_sym_key(master_key_1, &master_key_1_length);
    testsuite_fail_unless(res == THEMIS_SUCCESS, "keygen: generates key 1");
    res = themis_gen_sym_key(master_key_2, &master_key_2_length);
    testsuite_fail_unless(res == THEMIS_SUCCESS, "keygen: generates key 2");

    testsuite_fail_unless(non_zero_buffer(master_key_1, master_key_1_length),
                          "keygen: returns nonzero key 1");
    testsuite_fail_unless(non_zero_buffer(master_key_2, master_key_2_length),
                          "keygen: returns nonzero key 2");

    testsuite_fail_unless(different_buffers(master_key_1, master_key_1_length, master_key_2, master_key_2_length),
                          "keygen: generates different keys");

    /*
     * Verify invalid input handling and error conditions.
     */

    res = themis_gen_sym_key(NULL, NULL);
    testsuite_fail_unless(res == THEMIS_INVALID_PARAMETER, "keygen: missing key length");

    res = themis_gen_sym_key(master_key_1, NULL);
    testsuite_fail_unless(res == THEMIS_INVALID_PARAMETER, "keygen: missing key length");
}

static int secure_cell_seal(void)
{
    uint8_t* encrypted_message;
    size_t encrypted_message_length = 0;
    if (themis_secure_cell_encrypt_seal((uint8_t*)passwd,
                                        sizeof(passwd),
                                        NULL,
                                        0,
                                        (uint8_t*)message,
                                        sizeof(message),
                                        NULL,
                                        &encrypted_message_length)
            != THEMIS_BUFFER_TOO_SMALL
        || encrypted_message_length == 0) {
        testsuite_fail_if(true,
                          "themis_secure_cell_encrypt_seal (encrypted_message_length determination) fail");
        return -1;
    }
    encrypted_message = malloc(encrypted_message_length);
    if (encrypted_message == NULL) {
        testsuite_fail_if(true, "encrypted_message malloc fail");
        return -2;
    }
    if (themis_secure_cell_encrypt_seal((uint8_t*)passwd,
                                        sizeof(passwd),
                                        NULL,
                                        0,
                                        (uint8_t*)message,
                                        sizeof(message),
                                        encrypted_message,
                                        &encrypted_message_length)
        != THEMIS_SUCCESS) {
        testsuite_fail_if(true, "themis_secure_cell_encrypt_seal fail");
        free(encrypted_message);
        return -3;
    }

    uint8_t* decrypted_message;
    size_t decrypted_message_length = 0;

    if (themis_secure_cell_decrypt_seal((uint8_t*)passwd,
                                        sizeof(passwd),
                                        NULL,
                                        0,
                                        encrypted_message,
                                        encrypted_message_length,
                                        NULL,
                                        &decrypted_message_length)
            != THEMIS_BUFFER_TOO_SMALL
        || decrypted_message_length == 0) {
        testsuite_fail_if(true,
                          "themis_secure_cell_decrypt_seal (decrypted_message_length determination) fail");
        free(encrypted_message);
        return -4;
    }
    decrypted_message = malloc(decrypted_message_length);
    if (decrypted_message == NULL) {
        testsuite_fail_if(true, "decrypted_message malloc fail");
        free(encrypted_message);
        return -5;
    }
    if (themis_secure_cell_decrypt_seal((uint8_t*)passwd,
                                        sizeof(passwd),
                                        NULL,
                                        0,
                                        encrypted_message,
                                        encrypted_message_length,
                                        decrypted_message,
                                        &decrypted_message_length)
        != THEMIS_SUCCESS) {
        testsuite_fail_if(true, "themis_secure_cell_decrypt_seal fail");
        free(encrypted_message);
        free(decrypted_message);
        return -6;
    }

    if (sizeof(message) != decrypted_message_length
        || memcmp((uint8_t*)message, decrypted_message, decrypted_message_length) != 0) {
        testsuite_fail_if(true, "message and decrypted_message not equal");
        free(encrypted_message);
        free(decrypted_message);
        return -6;
    }
    free(encrypted_message);
    free(decrypted_message);
    return 0;
}

static int secure_cell_token_protect(void)
{
    uint8_t* encrypted_message;
    size_t encrypted_message_length = 0;
    uint8_t* context;
    size_t context_length = 0;

    if (themis_secure_cell_encrypt_token_protect((uint8_t*)passwd,
                                                 sizeof(passwd),
                                                 NULL,
                                                 0,
                                                 (uint8_t*)message,
                                                 sizeof(message),
                                                 NULL,
                                                 &context_length,
                                                 NULL,
                                                 &encrypted_message_length)
            != THEMIS_BUFFER_TOO_SMALL
        || encrypted_message_length == 0) {
        testsuite_fail_if(true,
                          "themis_secure_cell_encrypt_token_protect "
                          "(encrypted_message_length determination) fail");
        return -1;
    }
    if (encrypted_message_length != sizeof(message)) {
        testsuite_fail_if(true,
                          "themis_secure_cell_encrypt_token_protect "
                          "(encrypted_message_length != message length) fail");
        return -1;
    }
    encrypted_message = malloc(encrypted_message_length);
    if (encrypted_message == NULL) {
        testsuite_fail_if(true, "encrypted_message malloc fail");
        return -2;
    }
    context = malloc(context_length);
    if (context == NULL) {
        testsuite_fail_if(true, "context malloc fail");
        free(encrypted_message);
        return -2;
    }

    if (themis_secure_cell_encrypt_token_protect((uint8_t*)passwd,
                                                 sizeof(passwd),
                                                 NULL,
                                                 0,
                                                 (uint8_t*)message,
                                                 sizeof(message),
                                                 context,
                                                 &context_length,
                                                 encrypted_message,
                                                 &encrypted_message_length)
        != THEMIS_SUCCESS) {
        testsuite_fail_if(true, "themis_secure_cell_encrypt_token_protect fail");
        free(encrypted_message);
        free(context);
        return -3;
    }
    if (encrypted_message_length != sizeof(message)) {
        testsuite_fail_if(true,
                          "themis_secure_cell_encrypt_token_protect "
                          "(encrypted_message_length != message length) fail");
        free(encrypted_message);
        free(context);
        return -3;
    }
    uint8_t* decrypted_message;
    size_t decrypted_message_length = 0;

    if (themis_secure_cell_decrypt_token_protect((uint8_t*)passwd,
                                                 sizeof(passwd),
                                                 NULL,
                                                 0,
                                                 encrypted_message,
                                                 encrypted_message_length,
                                                 context,
                                                 context_length,
                                                 NULL,
                                                 &decrypted_message_length)
            != THEMIS_BUFFER_TOO_SMALL
        || decrypted_message_length == 0) {
        testsuite_fail_if(true,
                          "themis_secure_cell_decrypt_token_protect "
                          "(decrypted_message_length determination) fail");
        free(encrypted_message);
        free(context);
        return -4;
    }
    decrypted_message = malloc(decrypted_message_length);
    if (decrypted_message == NULL) {
        testsuite_fail_if(true, "decrypted_message malloc fail");
        free(encrypted_message);
        free(context);
        return -5;
    }
    if (themis_secure_cell_decrypt_token_protect((uint8_t*)passwd,
                                                 sizeof(passwd),
                                                 NULL,
                                                 0,
                                                 encrypted_message,
                                                 encrypted_message_length,
                                                 context,
                                                 context_length,
                                                 decrypted_message,
                                                 &decrypted_message_length)
        != THEMIS_SUCCESS) {
        testsuite_fail_if(true, "themis_secure_cell_decrypt_token_protect fail");
        free(encrypted_message);
        free(decrypted_message);
        free(context);
        return -6;
    }

    if (sizeof(message) != decrypted_message_length
        || memcmp((uint8_t*)message, decrypted_message, decrypted_message_length) != 0) {
        testsuite_fail_if(true, "message and decrypted_message not equal");
        free(encrypted_message);
        free(decrypted_message);
        free(context);
        return -7;
    }
    free(encrypted_message);
    free(decrypted_message);
    free(context);
    return 0;
}

static int secure_cell_context_imprint(void)
{
    uint8_t* encrypted_message;
    size_t encrypted_message_length = 0;

    if (themis_secure_cell_encrypt_context_imprint((uint8_t*)passwd,
                                                   sizeof(passwd),
                                                   (uint8_t*)message,
                                                   sizeof(message),
                                                   (uint8_t*)user_context,
                                                   strlen(user_context),
                                                   NULL,
                                                   &encrypted_message_length)
            != THEMIS_BUFFER_TOO_SMALL
        || encrypted_message_length == 0) {
        testsuite_fail_if(true,
                          "themis_secure_cell_encrypt_context_imprint "
                          "(encrypted_message_length determination) fail");
        return -1;
    }
    encrypted_message = malloc(encrypted_message_length);
    if (encrypted_message == NULL) {
        testsuite_fail_if(true, "encrypted_message malloc fail");
        return -2;
    }

    if (themis_secure_cell_encrypt_context_imprint((uint8_t*)passwd,
                                                   sizeof(passwd),
                                                   (uint8_t*)message,
                                                   sizeof(message),
                                                   (uint8_t*)user_context,
                                                   strlen(user_context),
                                                   encrypted_message,
                                                   &encrypted_message_length)
        != THEMIS_SUCCESS) {
        testsuite_fail_if(true, "themis_secure_cell_encrypt_context_imprint fail");
        free(encrypted_message);
        return -3;
    }

    uint8_t* decrypted_message;
    size_t decrypted_message_length = 0;

    if (themis_secure_cell_decrypt_context_imprint((uint8_t*)passwd,
                                                   sizeof(passwd),
                                                   encrypted_message,
                                                   encrypted_message_length,
                                                   (uint8_t*)user_context,
                                                   strlen(user_context),
                                                   NULL,
                                                   &decrypted_message_length)
            != THEMIS_BUFFER_TOO_SMALL
        || decrypted_message_length == 0) {
        testsuite_fail_if(true,
                          "themis_secure_cell_decrypt_context_imprint "
                          "(decrypted_message_length determination) fail");
        free(encrypted_message);
        return -4;
    }
    decrypted_message = malloc(decrypted_message_length);
    if (decrypted_message == NULL) {
        testsuite_fail_if(true, "decrypted_message malloc fail");
        free(encrypted_message);
        return -5;
    }
    if (themis_secure_cell_encrypt_context_imprint((uint8_t*)passwd,
                                                   sizeof(passwd),
                                                   encrypted_message,
                                                   encrypted_message_length,
                                                   (uint8_t*)user_context,
                                                   strlen(user_context),
                                                   decrypted_message,
                                                   &decrypted_message_length)
        != THEMIS_SUCCESS) {
        testsuite_fail_if(true, "themis_secure_cell_decrypt_context_imprint fail");
        free(encrypted_message);
        free(decrypted_message);
        return -6;
    }

    if (sizeof(message) != decrypted_message_length
        || memcmp((uint8_t*)message, decrypted_message, decrypted_message_length) != 0) {
        testsuite_fail_if(true, "message and decrypted_message not equal");
        free(encrypted_message);
        free(decrypted_message);
        return -7;
    }
    free(encrypted_message);
    free(decrypted_message);
    return 0;
}

static void secure_cell_test(void)
{
    testsuite_fail_if(secure_cell_seal(), "secure cell seal mode");
    testsuite_fail_if(secure_cell_token_protect(), "secure cell token protect mode");
    testsuite_fail_if(secure_cell_context_imprint(), "secure cell context imprint mode");
}

/*
 * Make sure that we always return correct and consistent lengths, regardless of input.
 */
static void secure_cell_test_lengths(void)
{
    themis_status_t res;
    uint8_t encrypted_buffer[MAX_MESSAGE_SIZE];
    uint8_t authtoken_buffer[MAX_MESSAGE_SIZE];
    size_t encrypted_length;
    size_t encrypted_length_measured;
    size_t authtoken_length;
    size_t authtoken_length_measured;

    /* Seal mode */

    encrypted_length_measured = sizeof(encrypted_buffer);
    res = themis_secure_cell_encrypt_seal((const uint8_t*)"master key",
                                          strlen("master key"),
                                          (const uint8_t*)"my context",
                                          strlen("my context"),
                                          (const uint8_t*)"a message!",
                                          strlen("a message!"),
                                          NULL,
                                          &encrypted_length_measured);
    testsuite_fail_unless(res == THEMIS_BUFFER_TOO_SMALL, "seal: measuring length");

    encrypted_length = sizeof(encrypted_buffer);
    res = themis_secure_cell_encrypt_seal((const uint8_t*)"master key",
                                          strlen("master key"),
                                          (const uint8_t*)"my context",
                                          strlen("my context"),
                                          (const uint8_t*)"a message!",
                                          strlen("a message!"),
                                          encrypted_buffer,
                                          &encrypted_length);
    testsuite_fail_unless(res == THEMIS_SUCCESS, "seal: encrypting buffer");

    testsuite_fail_unless(encrypted_length == encrypted_length_measured,
                          "seal: returned message length");

    /* Token protect mode */

    authtoken_length_measured = sizeof(authtoken_buffer);
    encrypted_length_measured = sizeof(encrypted_buffer);
    res = themis_secure_cell_encrypt_token_protect((const uint8_t*)"master key",
                                                   strlen("master key"),
                                                   (const uint8_t*)"my context",
                                                   strlen("my context"),
                                                   (const uint8_t*)"a message!",
                                                   strlen("a message!"),
                                                   NULL,
                                                   &authtoken_length_measured,
                                                   NULL,
                                                   &encrypted_length_measured);
    testsuite_fail_unless(res == THEMIS_BUFFER_TOO_SMALL, "token protect: measuring length");

    authtoken_length = sizeof(authtoken_buffer);
    encrypted_length = sizeof(encrypted_buffer);
    res = themis_secure_cell_encrypt_token_protect((const uint8_t*)"master key",
                                                   strlen("master key"),
                                                   (const uint8_t*)"my context",
                                                   strlen("my context"),
                                                   (const uint8_t*)"a message!",
                                                   strlen("a message!"),
                                                   authtoken_buffer,
                                                   &authtoken_length,
                                                   encrypted_buffer,
                                                   &encrypted_length);
    testsuite_fail_unless(res == THEMIS_SUCCESS, "token protect: encrypting buffer");

    testsuite_fail_unless(authtoken_length == authtoken_length_measured,
                          "token protect: returned auth token length");
    testsuite_fail_unless(encrypted_length == encrypted_length_measured,
                          "token protect: returned message length");

    /* Context imprint mode */

    encrypted_length_measured = sizeof(encrypted_buffer);
    res = themis_secure_cell_encrypt_context_imprint((const uint8_t*)"master key",
                                                     strlen("master key"),
                                                     (const uint8_t*)"a message!",
                                                     strlen("a message!"),
                                                     (const uint8_t*)"my context",
                                                     strlen("my context"),
                                                     NULL,
                                                     &encrypted_length_measured);
    testsuite_fail_unless(res == THEMIS_BUFFER_TOO_SMALL, "context imprint: measuring length");

    encrypted_length = sizeof(encrypted_buffer);
    res = themis_secure_cell_encrypt_context_imprint((const uint8_t*)"master key",
                                                     strlen("master key"),
                                                     (const uint8_t*)"a message!",
                                                     strlen("a message!"),
                                                     (const uint8_t*)"my context",
                                                     strlen("my context"),
                                                     encrypted_buffer,
                                                     &encrypted_length);
    testsuite_fail_unless(res == THEMIS_SUCCESS, "context imprint: encrypting buffer");

    testsuite_fail_unless(encrypted_length == encrypted_length_measured,
                          "context imprint: returned message length");
}

static void secure_cell_api_test_seal(void)
{
    uint8_t key[MAX_KEY_SIZE];
    uint8_t message[MAX_MESSAGE_SIZE];

    size_t key_length = rand_int(MAX_KEY_SIZE);
    size_t message_length = rand_int(MAX_MESSAGE_SIZE);

    uint8_t* encrypted = NULL;
    size_t encrypted_length;

    uint8_t* decrypted = NULL;
    size_t decrypted_length;

    if (THEMIS_SUCCESS != soter_rand(key, key_length)) {
        testsuite_fail_if(true, "soter_rand fail");
        return;
    }

    if (THEMIS_SUCCESS != soter_rand(message, message_length)) {
        testsuite_fail_if(true, "soter_rand fail");
        return;
    }

    testsuite_fail_unless(THEMIS_BUFFER_TOO_SMALL
                              == themis_secure_cell_encrypt_seal(key,
                                                                 key_length,
                                                                 NULL,
                                                                 0,
                                                                 message,
                                                                 message_length,
                                                                 NULL,
                                                                 &encrypted_length),
                          "themis_secure_cell_encrypt_seal: get output size (NULL out buffer)");
    encrypted = malloc(encrypted_length);
    if (!encrypted) {
        testsuite_fail_if(true, "malloc fail");
        return;
    }

    testsuite_fail_unless(THEMIS_INVALID_PARAMETER
                              == themis_secure_cell_encrypt_seal(NULL,
                                                                 key_length,
                                                                 NULL,
                                                                 0,
                                                                 message,
                                                                 message_length,
                                                                 encrypted,
                                                                 &encrypted_length),
                          "themis_secure_cell_encrypt_seal: invalid key");
    testsuite_fail_unless(THEMIS_INVALID_PARAMETER
                              == themis_secure_cell_encrypt_seal(key,
                                                                 0,
                                                                 NULL,
                                                                 0,
                                                                 message,
                                                                 message_length,
                                                                 encrypted,
                                                                 &encrypted_length),
                          "themis_secure_cell_encrypt_seal: invalid key length");

    testsuite_fail_unless(THEMIS_INVALID_PARAMETER
                              == themis_secure_cell_encrypt_seal(key,
                                                                 key_length,
                                                                 NULL,
                                                                 0,
                                                                 NULL,
                                                                 message_length,
                                                                 encrypted,
                                                                 &encrypted_length),
                          "themis_secure_cell_encrypt_seal: invalid message");
    testsuite_fail_unless(THEMIS_INVALID_PARAMETER
                              == themis_secure_cell_encrypt_seal(key,
                                                                 key_length,
                                                                 NULL,
                                                                 0,
                                                                 message,
                                                                 0,
                                                                 encrypted,
                                                                 &encrypted_length),
                          "themis_secure_cell_encrypt_seal: invalid message length");

    encrypted_length--;
    testsuite_fail_unless(THEMIS_BUFFER_TOO_SMALL
                              == themis_secure_cell_encrypt_seal(key,
                                                                 key_length,
                                                                 NULL,
                                                                 0,
                                                                 message,
                                                                 message_length,
                                                                 encrypted,
                                                                 &encrypted_length),
                          "themis_secure_cell_encrypt_seal: get output size (small out buffer)");

    testsuite_fail_unless(THEMIS_SUCCESS
                              == themis_secure_cell_encrypt_seal(key,
                                                                 key_length,
                                                                 NULL,
                                                                 0,
                                                                 message,
                                                                 message_length,
                                                                 encrypted,
                                                                 &encrypted_length),
                          "themis_secure_cell_encrypt_seal: normal flow");

    testsuite_fail_unless(THEMIS_BUFFER_TOO_SMALL
                              == themis_secure_cell_decrypt_seal(key,
                                                                 key_length,
                                                                 NULL,
                                                                 0,
                                                                 encrypted,
                                                                 encrypted_length,
                                                                 NULL,
                                                                 &decrypted_length),
                          "themis_secure_cell_decrypt_seal: get output size (NULL out buffer)");

    decrypted = malloc(decrypted_length);
    if (!decrypted) {
        testsuite_fail_if(true, "malloc fail");
        free(encrypted);
        return;
    }

    testsuite_fail_unless(THEMIS_INVALID_PARAMETER
                              == themis_secure_cell_decrypt_seal(NULL,
                                                                 key_length,
                                                                 NULL,
                                                                 0,
                                                                 encrypted,
                                                                 encrypted_length,
                                                                 decrypted,
                                                                 &decrypted_length),
                          "themis_secure_cell_decrypt_seal: invalid key");
    testsuite_fail_unless(THEMIS_INVALID_PARAMETER
                              == themis_secure_cell_decrypt_seal(key,
                                                                 0,
                                                                 NULL,
                                                                 0,
                                                                 encrypted,
                                                                 encrypted_length,
                                                                 decrypted,
                                                                 &decrypted_length),
                          "themis_secure_cell_decrypt_seal: invalid key length");

    testsuite_fail_unless(THEMIS_INVALID_PARAMETER
                              == themis_secure_cell_decrypt_seal(key,
                                                                 key_length,
                                                                 NULL,
                                                                 0,
                                                                 NULL,
                                                                 encrypted_length,
                                                                 decrypted,
                                                                 &decrypted_length),
                          "themis_secure_cell_decrypt_seal: invalid message");
    testsuite_fail_unless(THEMIS_INVALID_PARAMETER
                              == themis_secure_cell_decrypt_seal(key,
                                                                 key_length,
                                                                 NULL,
                                                                 0,
                                                                 encrypted,
                                                                 0,
                                                                 decrypted,
                                                                 &decrypted_length),
                          "themis_secure_cell_decrypt_seal: invalid message length");

    decrypted_length--;
    testsuite_fail_unless(THEMIS_BUFFER_TOO_SMALL
                              == themis_secure_cell_decrypt_seal(key,
                                                                 key_length,
                                                                 NULL,
                                                                 0,
                                                                 encrypted,
                                                                 encrypted_length,
                                                                 decrypted,
                                                                 &decrypted_length),
                          "themis_secure_cell_decrypt_seal: get output size (small out buffer)");

    encrypted[0]++;
    testsuite_fail_unless(THEMIS_FAIL
                              == themis_secure_cell_decrypt_seal(key,
                                                                 key_length,
                                                                 NULL,
                                                                 0,
                                                                 encrypted,
                                                                 encrypted_length,
                                                                 decrypted,
                                                                 &decrypted_length),
                          "themis_secure_cell_decrypt_seal: header corrupt");
    encrypted[0]--;

    encrypted[encrypted_length / 2]++;
    testsuite_fail_unless(THEMIS_FAIL
                              == themis_secure_cell_decrypt_seal(key,
                                                                 key_length,
                                                                 NULL,
                                                                 0,
                                                                 encrypted,
                                                                 encrypted_length,
                                                                 decrypted,
                                                                 &decrypted_length),
                          "themis_secure_cell_decrypt_seal: message corrupt");
    encrypted[encrypted_length / 2]--;

    encrypted[encrypted_length - 1]++;
    testsuite_fail_unless(THEMIS_FAIL
                              == themis_secure_cell_decrypt_seal(key,
                                                                 key_length,
                                                                 NULL,
                                                                 0,
                                                                 encrypted,
                                                                 encrypted_length,
                                                                 decrypted,
                                                                 &decrypted_length),
                          "themis_secure_cell_decrypt_seal: tag corrupt");
    encrypted[encrypted_length - 1]--;

    testsuite_fail_unless(THEMIS_SUCCESS
                                  == themis_secure_cell_decrypt_seal(key,
                                                                     key_length,
                                                                     NULL,
                                                                     0,
                                                                     encrypted,
                                                                     encrypted_length,
                                                                     decrypted,
                                                                     &decrypted_length)
                              && (message_length == decrypted_length)
                              && !memcmp(message, decrypted, message_length),
                          "themis_secure_cell_decrypt_seal: normal flow");

    free(decrypted);
    free(encrypted);
}

static void secure_cell_api_test_context_imprint(void)
{
    uint8_t key[MAX_KEY_SIZE];
    uint8_t context[MAX_CONTEXT_SIZE];
    uint8_t message[MAX_MESSAGE_SIZE];

    size_t key_length = rand_int(MAX_KEY_SIZE);
    size_t context_length = rand_int(MAX_CONTEXT_SIZE);
    size_t message_length = rand_int(MAX_MESSAGE_SIZE);

    uint8_t encrypted[MAX_MESSAGE_SIZE];
    size_t encrypted_length = message_length;

    uint8_t decrypted[MAX_MESSAGE_SIZE];
    size_t decrypted_length = message_length;

    if (THEMIS_SUCCESS != soter_rand(key, key_length)) {
        testsuite_fail_if(true, "soter_rand fail");
        return;
    }

    if (THEMIS_SUCCESS != soter_rand(context, context_length)) {
        testsuite_fail_if(true, "soter_rand fail");
        return;
    }

    if (THEMIS_SUCCESS != soter_rand(message, message_length)) {
        testsuite_fail_if(true, "soter_rand fail");
        return;
    }

    testsuite_fail_unless(THEMIS_INVALID_PARAMETER
                              == themis_secure_cell_encrypt_context_imprint(NULL,
                                                                            key_length,
                                                                            message,
                                                                            message_length,
                                                                            context,
                                                                            context_length,
                                                                            encrypted,
                                                                            &encrypted_length),
                          "themis_secure_cell_encrypt_context_imprint: invalid key");
    testsuite_fail_unless(THEMIS_INVALID_PARAMETER
                              == themis_secure_cell_encrypt_context_imprint(key,
                                                                            0,
                                                                            message,
                                                                            message_length,
                                                                            context,
                                                                            context_length,
                                                                            encrypted,
                                                                            &encrypted_length),
                          "themis_secure_cell_encrypt_context_imprint: invalid key length");

    testsuite_fail_unless(THEMIS_INVALID_PARAMETER
                              == themis_secure_cell_encrypt_context_imprint(key,
                                                                            key_length,
                                                                            NULL,
                                                                            message_length,
                                                                            context,
                                                                            context_length,
                                                                            encrypted,
                                                                            &encrypted_length),
                          "themis_secure_cell_encrypt_context_imprint: invalid message");
    testsuite_fail_unless(THEMIS_INVALID_PARAMETER
                              == themis_secure_cell_encrypt_context_imprint(key,
                                                                            key_length,
                                                                            message,
                                                                            0,
                                                                            context,
                                                                            context_length,
                                                                            encrypted,
                                                                            &encrypted_length),
                          "themis_secure_cell_encrypt_context_imprint: invalid message length");

    testsuite_fail_unless(THEMIS_INVALID_PARAMETER
                              == themis_secure_cell_encrypt_context_imprint(key,
                                                                            key_length,
                                                                            message,
                                                                            message_length,
                                                                            NULL,
                                                                            context_length,
                                                                            encrypted,
                                                                            &encrypted_length),
                          "themis_secure_cell_encrypt_context_imprint: invalid context");
    testsuite_fail_unless(THEMIS_INVALID_PARAMETER
                              == themis_secure_cell_encrypt_context_imprint(key,
                                                                            key_length,
                                                                            message,
                                                                            message_length,
                                                                            context,
                                                                            0,
                                                                            encrypted,
                                                                            &encrypted_length),
                          "themis_secure_cell_encrypt_context_imprint: invalid context length");

    testsuite_fail_unless((THEMIS_BUFFER_TOO_SMALL
                           == themis_secure_cell_encrypt_context_imprint(key,
                                                                         key_length,
                                                                         message,
                                                                         message_length,
                                                                         context,
                                                                         context_length,
                                                                         NULL,
                                                                         &encrypted_length))
                              && (encrypted_length == message_length),
                          "themis_secure_cell_encrypt_context_imprint: get output size (NULL out buffer)");

    encrypted_length--;
    testsuite_fail_unless((THEMIS_BUFFER_TOO_SMALL
                           == themis_secure_cell_encrypt_context_imprint(key,
                                                                         key_length,
                                                                         message,
                                                                         message_length,
                                                                         context,
                                                                         context_length,
                                                                         encrypted,
                                                                         &encrypted_length))
                              && (encrypted_length == message_length),
                          "themis_secure_cell_encrypt_context_imprint: get output size (small out buffer)");

    testsuite_fail_unless((THEMIS_SUCCESS
                           == themis_secure_cell_encrypt_context_imprint(key,
                                                                         key_length,
                                                                         message,
                                                                         message_length,
                                                                         context,
                                                                         context_length,
                                                                         encrypted,
                                                                         &encrypted_length))
                              && (encrypted_length == message_length),
                          "themis_secure_cell_encrypt_context_imprint: normal flow");

    testsuite_fail_unless(THEMIS_INVALID_PARAMETER
                              == themis_secure_cell_decrypt_context_imprint(NULL,
                                                                            key_length,
                                                                            encrypted,
                                                                            encrypted_length,
                                                                            context,
                                                                            context_length,
                                                                            decrypted,
                                                                            &decrypted_length),
                          "themis_secure_cell_decrypt_context_imprint: invalid key");
    testsuite_fail_unless(THEMIS_INVALID_PARAMETER
                              == themis_secure_cell_decrypt_context_imprint(key,
                                                                            0,
                                                                            encrypted,
                                                                            encrypted_length,
                                                                            context,
                                                                            context_length,
                                                                            decrypted,
                                                                            &decrypted_length),
                          "themis_secure_cell_decrypt_context_imprint: invalid key length");

    testsuite_fail_unless(THEMIS_INVALID_PARAMETER
                              == themis_secure_cell_decrypt_context_imprint(key,
                                                                            key_length,
                                                                            NULL,
                                                                            encrypted_length,
                                                                            context,
                                                                            context_length,
                                                                            decrypted,
                                                                            &decrypted_length),
                          "themis_secure_cell_decrypt_context_imprint: invalid message");
    testsuite_fail_unless(THEMIS_INVALID_PARAMETER
                              == themis_secure_cell_decrypt_context_imprint(key,
                                                                            key_length,
                                                                            encrypted,
                                                                            0,
                                                                            context,
                                                                            context_length,
                                                                            decrypted,
                                                                            &decrypted_length),
                          "themis_secure_cell_decrypt_context_imprint: invalid message length");

    testsuite_fail_unless(THEMIS_INVALID_PARAMETER
                              == themis_secure_cell_decrypt_context_imprint(key,
                                                                            key_length,
                                                                            encrypted,
                                                                            encrypted_length,
                                                                            NULL,
                                                                            context_length,
                                                                            decrypted,
                                                                            &decrypted_length),
                          "themis_secure_cell_decrypt_context_imprint: invalid context");
    testsuite_fail_unless(THEMIS_INVALID_PARAMETER
                              == themis_secure_cell_decrypt_context_imprint(key,
                                                                            key_length,
                                                                            encrypted,
                                                                            encrypted_length,
                                                                            context,
                                                                            0,
                                                                            decrypted,
                                                                            &decrypted_length),
                          "themis_secure_cell_decrypt_context_imprint: invalid context length");

    testsuite_fail_unless((THEMIS_BUFFER_TOO_SMALL
                           == themis_secure_cell_decrypt_context_imprint(key,
                                                                         key_length,
                                                                         encrypted,
                                                                         encrypted_length,
                                                                         context,
                                                                         context_length,
                                                                         NULL,
                                                                         &decrypted_length))
                              && (decrypted_length == encrypted_length),
                          "themis_secure_cell_decrypt_context_imprint: get output size (NULL out buffer)");

    decrypted_length--;
    testsuite_fail_unless((THEMIS_BUFFER_TOO_SMALL
                           == themis_secure_cell_decrypt_context_imprint(key,
                                                                         key_length,
                                                                         encrypted,
                                                                         encrypted_length,
                                                                         context,
                                                                         context_length,
                                                                         decrypted,
                                                                         &decrypted_length))
                              && (decrypted_length == encrypted_length),
                          "themis_secure_cell_decrypt_context_imprint: get output size (small out buffer)");

    testsuite_fail_unless(THEMIS_SUCCESS
                                  == themis_secure_cell_decrypt_context_imprint(key,
                                                                                key_length,
                                                                                encrypted,
                                                                                encrypted_length,
                                                                                context,
                                                                                context_length,
                                                                                decrypted,
                                                                                &decrypted_length)
                              && (message_length == decrypted_length)
                              && (!memcmp(message, decrypted, message_length)),
                          "themis_secure_cell_decrypt_context_imprint: normal flow");
}

static void secure_cell_api_test(void)
{
    secure_cell_api_test_seal();
    secure_cell_api_test_context_imprint();
}

/*
 * See themis_auth_sym_message_hdr_t definition.
 */

static inline uint32_t get_context_iv_length(const uint8_t* context)
{
    if (!context) {
        return 0;
    }
    return ((const uint32_t*)context)[1];
}

static inline void set_context_iv_length(uint8_t* context, uint32_t value)
{
    if (!context) {
        return;
    }
    ((uint32_t*)context)[1] = value;
}

static inline uint32_t get_context_auth_tag_length(const uint8_t* context)
{
    if (!context) {
        return 0;
    }
    return ((const uint32_t*)context)[2];
}

static inline void set_context_auth_tag_length(uint8_t* context, uint32_t value)
{
    if (!context) {
        return;
    }
    ((uint32_t*)context)[2] = value;
}

static inline uint32_t get_context_message_length(const uint8_t* context)
{
    if (!context) {
        return 0;
    }
    return ((const uint32_t*)context)[3];
}

static inline void set_context_message_length(uint8_t* context, uint32_t value)
{
    if (!context) {
        return;
    }
    ((uint32_t*)context)[3] = value;
}

static themis_status_t encrypt_seal(uint8_t** encrypted_message, size_t* encrypted_message_length)
{
    themis_status_t res = THEMIS_SUCCESS;

    res = themis_secure_cell_encrypt_seal((uint8_t*)passwd,
                                          sizeof(passwd),
                                          NULL,
                                          0,
                                          (uint8_t*)message,
                                          sizeof(message),
                                          NULL,
                                          encrypted_message_length);
    if (res != THEMIS_BUFFER_TOO_SMALL) {
        testsuite_fail_if(true,
                          "themis_secure_cell_encrypt_seal: failed to determine encrypted message length");
        return res;
    }

    *encrypted_message = malloc(*encrypted_message_length);
    if (*encrypted_message == NULL) {
        testsuite_fail_if(true,
                          "themis_secure_cell_encrypt_seal: failed to allocate memory for encrypted message");
        return THEMIS_NO_MEMORY;
    }

    res = themis_secure_cell_encrypt_seal((uint8_t*)passwd,
                                          sizeof(passwd),
                                          NULL,
                                          0,
                                          (uint8_t*)message,
                                          sizeof(message),
                                          *encrypted_message,
                                          encrypted_message_length);
    if (res != THEMIS_SUCCESS) {
        testsuite_fail_if(true, "themis_secure_cell_encrypt_seal: failed to encrypt message");
        free(*encrypted_message);
        *encrypted_message = NULL;
        return res;
    }

    return THEMIS_SUCCESS;
}

static themis_status_t prepare_decrypt_seal(uint8_t* encrypted_message,
                                            size_t encrypted_message_length,
                                            uint8_t** decrypted_message,
                                            size_t* decrypted_message_length)
{
    themis_status_t res = THEMIS_SUCCESS;

    res = themis_secure_cell_decrypt_seal((uint8_t*)passwd,
                                          sizeof(passwd),
                                          NULL,
                                          0,
                                          encrypted_message,
                                          encrypted_message_length,
                                          NULL,
                                          decrypted_message_length);
    if (res != THEMIS_BUFFER_TOO_SMALL) {
        testsuite_fail_if(true,
                          "themis_secure_cell_decrypt_seal: failed to determine decrypted message length");
        return res;
    }

    *decrypted_message = malloc(*decrypted_message_length);
    if (*decrypted_message == NULL) {
        testsuite_fail_if(true,
                          "themis_secure_cell_decrypt_seal: failed to allocate memory for decrypted message");
        return THEMIS_NO_MEMORY;
    }

    return THEMIS_SUCCESS;
}

static void secure_cell_context_corruption_seal(void)
{
    themis_status_t res = THEMIS_SUCCESS;

    uint8_t* encrypted_message = NULL;
    size_t encrypted_message_length = 0;

    res = encrypt_seal(&encrypted_message, &encrypted_message_length);
    if (res != THEMIS_SUCCESS) {
        goto out;
    }

    uint32_t old_value = 0;

    uint8_t* decrypted_message = NULL;
    size_t decrypted_message_length = 0;

    old_value = get_context_iv_length(encrypted_message);
    set_context_iv_length(encrypted_message, CORRUPTED_LENGTH);
    {
        res = prepare_decrypt_seal(encrypted_message,
                                   encrypted_message_length,
                                   &decrypted_message,
                                   &decrypted_message_length);
        if (res != THEMIS_SUCCESS) {
            goto out;
        }

        res = themis_secure_cell_decrypt_seal((uint8_t*)passwd,
                                              sizeof(passwd),
                                              NULL,
                                              0,
                                              encrypted_message,
                                              encrypted_message_length,
                                              decrypted_message,
                                              &decrypted_message_length);
        testsuite_fail_if(res == THEMIS_SUCCESS,
                          "themis_secure_cell_decrypt_seal detects corrupted IV length");

        free(decrypted_message);
        decrypted_message = NULL;
    }
    set_context_iv_length(encrypted_message, old_value);

    old_value = get_context_auth_tag_length(encrypted_message);
    set_context_auth_tag_length(encrypted_message, CORRUPTED_LENGTH);
    {
        res = prepare_decrypt_seal(encrypted_message,
                                   encrypted_message_length,
                                   &decrypted_message,
                                   &decrypted_message_length);
        if (res != THEMIS_SUCCESS) {
            goto out;
        }

        res = themis_secure_cell_decrypt_seal((uint8_t*)passwd,
                                              sizeof(passwd),
                                              NULL,
                                              0,
                                              encrypted_message,
                                              encrypted_message_length,
                                              decrypted_message,
                                              &decrypted_message_length);
        testsuite_fail_if(res == THEMIS_SUCCESS,
                          "themis_secure_cell_decrypt_seal detects corrupted auth tag length");

        free(decrypted_message);
        decrypted_message = NULL;
    }
    set_context_auth_tag_length(encrypted_message, old_value);

    old_value = get_context_message_length(encrypted_message);
    set_context_message_length(encrypted_message, CORRUPTED_LENGTH);
    {
        res = themis_secure_cell_decrypt_seal((uint8_t*)passwd,
                                              sizeof(passwd),
                                              NULL,
                                              0,
                                              encrypted_message,
                                              encrypted_message_length,
                                              NULL,
                                              &decrypted_message_length);
        testsuite_fail_if(res == THEMIS_BUFFER_TOO_SMALL,
                          "themis_secure_cell_decrypt_seal detects corrupted message length");
    }
    set_context_message_length(encrypted_message, old_value);

out:
    free(encrypted_message);
}

static themis_status_t encrypt_token_protect(uint8_t** encrypted_message,
                                             size_t* encrypted_message_length,
                                             uint8_t** context,
                                             size_t* context_length)
{
    themis_status_t res = THEMIS_SUCCESS;

    res = themis_secure_cell_encrypt_token_protect((uint8_t*)passwd,
                                                   sizeof(passwd),
                                                   NULL,
                                                   0,
                                                   (uint8_t*)message,
                                                   sizeof(message),
                                                   NULL,
                                                   context_length,
                                                   NULL,
                                                   encrypted_message_length);
    if (res != THEMIS_BUFFER_TOO_SMALL || context_length == 0 || encrypted_message_length == 0) {
        testsuite_fail_if(true,
                          "themis_secure_cell_encrypt_token_protect: failed to determine "
                          "encrypted message length");
        return res;
    }

    *encrypted_message = malloc(*encrypted_message_length);
    if (*encrypted_message == NULL) {
        testsuite_fail_if(true,
                          "themis_secure_cell_encrypt_token_protect: failed to allocate "
                          "memory for encrypted message");
        return res;
    }

    *context = malloc(*context_length);
    if (*context == NULL) {
        testsuite_fail_if(true,
                          "themis_secure_cell_encrypt_token_protect: failed to allocate memory for auth context");
        free(*encrypted_message);
        *encrypted_message = NULL;
        return res;
    }

    res = themis_secure_cell_encrypt_token_protect((uint8_t*)passwd,
                                                   sizeof(passwd),
                                                   NULL,
                                                   0,
                                                   (uint8_t*)message,
                                                   sizeof(message),
                                                   *context,
                                                   context_length,
                                                   *encrypted_message,
                                                   encrypted_message_length);
    if (res != THEMIS_SUCCESS) {
        testsuite_fail_if(true, "themis_secure_cell_encrypt_token_protect: failed to encrypt message");
        free(*encrypted_message);
        *encrypted_message = NULL;
        free(*context);
        *context = NULL;
        return res;
    }

    return THEMIS_SUCCESS;
}

static themis_status_t prepare_decrypt_token_protect(uint8_t* encrypted_message,
                                                     size_t encrypted_message_length,
                                                     uint8_t* context,
                                                     size_t context_length,
                                                     uint8_t** decrypted_message,
                                                     size_t* decrypted_message_length)
{
    themis_status_t res = THEMIS_SUCCESS;

    res = themis_secure_cell_decrypt_token_protect((uint8_t*)passwd,
                                                   sizeof(passwd),
                                                   NULL,
                                                   0,
                                                   encrypted_message,
                                                   encrypted_message_length,
                                                   context,
                                                   context_length,
                                                   NULL,
                                                   decrypted_message_length);
    if (res != THEMIS_BUFFER_TOO_SMALL || decrypted_message_length == 0) {
        testsuite_fail_if(true,
                          "themis_secure_cell_decrypt_token_protect: failed to determine "
                          "decrypted message length");
        return res;
    }

    *decrypted_message = malloc(*decrypted_message_length);
    if (*decrypted_message == NULL) {
        testsuite_fail_if(true,
                          "themis_secure_cell_decrypt_token_protect: failed to allocate "
                          "memory for decrypted message");
        return THEMIS_NO_MEMORY;
    }

    return THEMIS_SUCCESS;
}

static void secure_cell_context_corruption_token_protect(void)
{
    themis_status_t res = THEMIS_SUCCESS;

    uint8_t* encrypted_message = NULL;
    size_t encrypted_message_length = 0;
    uint8_t* context = NULL;
    size_t context_length = 0;

    res = encrypt_token_protect(&encrypted_message, &encrypted_message_length, &context, &context_length);
    if (res != THEMIS_SUCCESS) {
        goto out;
    }

    uint32_t old_value = 0;

    uint8_t* decrypted_message = NULL;
    size_t decrypted_message_length = 0;

    old_value = get_context_iv_length(context);
    set_context_iv_length(context, CORRUPTED_LENGTH);
    {
        res = prepare_decrypt_token_protect(encrypted_message,
                                            encrypted_message_length,
                                            context,
                                            context_length,
                                            &decrypted_message,
                                            &decrypted_message_length);
        if (res != THEMIS_SUCCESS) {
            goto out;
        }

        res = themis_secure_cell_decrypt_token_protect((uint8_t*)passwd,
                                                       sizeof(passwd),
                                                       NULL,
                                                       0,
                                                       encrypted_message,
                                                       encrypted_message_length,
                                                       context,
                                                       context_length,
                                                       decrypted_message,
                                                       &decrypted_message_length);
        testsuite_fail_if(res == THEMIS_SUCCESS,
                          "themis_secure_cell_decrypt_token_protect detects corrupted IV length");

        free(decrypted_message);
        decrypted_message = NULL;
    }
    set_context_iv_length(context, old_value);

    old_value = get_context_auth_tag_length(context);
    set_context_auth_tag_length(context, CORRUPTED_LENGTH);
    {
        res = prepare_decrypt_token_protect(encrypted_message,
                                            encrypted_message_length,
                                            context,
                                            context_length,
                                            &decrypted_message,
                                            &decrypted_message_length);
        if (res != THEMIS_SUCCESS) {
            goto out;
        }

        res = themis_secure_cell_decrypt_token_protect((uint8_t*)passwd,
                                                       sizeof(passwd),
                                                       NULL,
                                                       0,
                                                       encrypted_message,
                                                       encrypted_message_length,
                                                       context,
                                                       context_length,
                                                       decrypted_message,
                                                       &decrypted_message_length);
        testsuite_fail_if(res == THEMIS_SUCCESS,
                          "themis_secure_cell_decrypt_token_protect detects corrupted auth tag length");

        free(decrypted_message);
        decrypted_message = NULL;
    }
    set_context_auth_tag_length(context, old_value);

    old_value = get_context_message_length(context);
    set_context_message_length(context, CORRUPTED_LENGTH);
    {
        res = prepare_decrypt_token_protect(encrypted_message,
                                            encrypted_message_length,
                                            context,
                                            context_length,
                                            &decrypted_message,
                                            &decrypted_message_length);
        if (res != THEMIS_SUCCESS) {
            goto out;
        }

        res = themis_secure_cell_decrypt_token_protect((uint8_t*)passwd,
                                                       sizeof(passwd),
                                                       NULL,
                                                       0,
                                                       encrypted_message,
                                                       encrypted_message_length,
                                                       context,
                                                       context_length,
                                                       decrypted_message,
                                                       &decrypted_message_length);
        testsuite_fail_if(res == THEMIS_SUCCESS,
                          "themis_secure_cell_decrypt_token_protect detects corrupted message length");

        free(decrypted_message);
        decrypted_message = NULL;
    }
    set_context_message_length(context, old_value);

out:
    free(encrypted_message);
    free(context);
}

static void secure_cell_context_corruption(void)
{
    secure_cell_context_corruption_seal();
    secure_cell_context_corruption_token_protect();
}

static void secure_cell_0_9_6_compatibility(void)
{
    static const uint8_t master_key[] = {
        0x08, 0xBC, 0xFB, 0xF3, 0x8D, 0xB4, 0xD3, 0xD9,
        0x0B, 0x21, 0x73, 0x88, 0x5C, 0xC2, 0xD9, 0xA3,
        0x9D, 0xA9, 0x46, 0x4E, 0x03, 0xE0, 0x78, 0x49,
        0x56, 0x94, 0x15, 0xB8, 0xD5, 0xC0, 0xCA, 0x8C,
    };
    static const uint8_t context[] = {
        0xAA, 0x5F, 0x14, 0x62, 0x49, 0x5C, 0x59, 0xEB,
    };
    /* "message encrypted with Themis 0.9.6" */
    static const uint8_t message[] = {
        0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20,
        0x65, 0x6E, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65,
        0x64, 0x20, 0x77, 0x69, 0x74, 0x68, 0x20, 0x54,
        0x68, 0x65, 0x6D, 0x69, 0x73, 0x20, 0x30, 0x2E,
        0x39, 0x2E, 0x36,
    };
    static const uint8_t encrypted_seal[] = {
        0x00, 0x01, 0x01, 0x40, 0x0C, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00,
        0xF6, 0x3B, 0xAB, 0x8D, 0xB8, 0x97, 0xFA, 0x1E,
        0xB1, 0x2C, 0x5A, 0x89, 0x8C, 0x1A, 0x86, 0x62,
        0xAB, 0xDD, 0xEE, 0x56, 0xE8, 0xBF, 0xAE, 0xCD,
        0xCE, 0xBF, 0xC0, 0x12, 0x53, 0x7A, 0x0E, 0xB7,
        0x1A, 0x50, 0x9A, 0x8A, 0x81, 0xE9, 0xD6, 0x96,
        0xEA, 0x5C, 0xA7, 0xF9, 0x35, 0x00, 0x5F, 0x2D,
        0x78, 0x46, 0xF9, 0xD0, 0x86, 0xB7, 0x42, 0xF0,
        0x76, 0xCE, 0xC7, 0x56, 0x51, 0xC0, 0xE9,
    };
    static const uint8_t encrypted_token_message[] = {
        0x0D, 0x8C, 0x96, 0xFF, 0x8A, 0x67, 0xF5, 0x4B,
        0xBF, 0xDD, 0x20, 0x16, 0xD8, 0x8C, 0x07, 0x49,
        0xD9, 0x4A, 0x06, 0xA0, 0x7E, 0xDD, 0x90, 0xEB,
        0x1A, 0x39, 0x40, 0xF7, 0x92, 0x14, 0x1F, 0x45,
        0x91, 0x13, 0x6F,
    };
    static const uint8_t encrypted_token_authdata[] = {
        0x00, 0x01, 0x01, 0x40, 0x0C, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00,
        0xDB, 0x29, 0x1F, 0x5F, 0x25, 0xF0, 0xF2, 0x10,
        0x5C, 0x0C, 0x27, 0xB4, 0x98, 0x9C, 0x5F, 0x0B,
        0xCC, 0x3F, 0x9B, 0x29, 0x71, 0xD0, 0xBA, 0xB0,
        0x6F, 0xAF, 0x75, 0x47,
    };
    static const uint8_t encrypted_imprint[] = {
        0x51, 0xF9, 0xA3, 0x5E, 0x9A, 0xA2, 0xAF, 0x69,
        0x58, 0xB1, 0xCA, 0x3E, 0x77, 0x2B, 0x52, 0x12,
        0x50, 0x09, 0x40, 0x07, 0x0F, 0x99, 0x84, 0xE8,
        0x30, 0x71, 0x3E, 0xB1, 0xA4, 0xC8, 0x2A, 0x71,
        0x0B, 0xBE, 0x26,
    };

    themis_status_t res = THEMIS_FAIL;
    uint8_t output[MAX_MESSAGE_SIZE] = {0};
    size_t output_length = 0;

    res = themis_secure_cell_decrypt_seal(master_key,
                                          sizeof(master_key),
                                          context,
                                          sizeof(context),
                                          encrypted_seal,
                                          sizeof(encrypted_seal),
                                          NULL,
                                          &output_length);

    testsuite_fail_if(res != THEMIS_BUFFER_TOO_SMALL, "Seal: measured output size");
    testsuite_fail_if(output_length != sizeof(message), "Seal: expected output size");

    res = themis_secure_cell_decrypt_seal(master_key,
                                          sizeof(master_key),
                                          context,
                                          sizeof(context),
                                          encrypted_seal,
                                          sizeof(encrypted_seal),
                                          output,
                                          &output_length);

    testsuite_fail_if(res != THEMIS_SUCCESS, "Seal: decrypted message ok");
    testsuite_fail_if(memcmp(output, message, output_length) != 0, "Seal: message content same");

    res = themis_secure_cell_decrypt_token_protect(master_key,
                                                   sizeof(master_key),
                                                   context,
                                                   sizeof(context),
                                                   encrypted_token_message,
                                                   sizeof(encrypted_token_message),
                                                   encrypted_token_authdata,
                                                   sizeof(encrypted_token_authdata),
                                                   NULL,
                                                   &output_length);

    testsuite_fail_if(res != THEMIS_BUFFER_TOO_SMALL, "Token: measured output size");
    testsuite_fail_if(output_length != sizeof(message), "Token: expected output size");

    res = themis_secure_cell_decrypt_token_protect(master_key,
                                                   sizeof(master_key),
                                                   context,
                                                   sizeof(context),
                                                   encrypted_token_message,
                                                   sizeof(encrypted_token_message),
                                                   encrypted_token_authdata,
                                                   sizeof(encrypted_token_authdata),
                                                   output,
                                                   &output_length);

    testsuite_fail_if(res != THEMIS_SUCCESS, "Token: decrypted message ok");
    testsuite_fail_if(memcmp(output, message, output_length) != 0, "Token: message content same");

    res = themis_secure_cell_decrypt_context_imprint(master_key,
                                                     sizeof(master_key),
                                                     encrypted_imprint,
                                                     sizeof(encrypted_imprint),
                                                     context,
                                                     sizeof(context),
                                                     NULL,
                                                     &output_length);

    testsuite_fail_if(res != THEMIS_BUFFER_TOO_SMALL, "Imprint: measured output size");
    testsuite_fail_if(output_length != sizeof(message), "Imprint: expected output size");

    res = themis_secure_cell_decrypt_context_imprint(master_key,
                                                     sizeof(master_key),
                                                     encrypted_imprint,
                                                     sizeof(encrypted_imprint),
                                                     context,
                                                     sizeof(context),
                                                     output,
                                                     &output_length);

    testsuite_fail_if(res != THEMIS_SUCCESS, "Imprint: decrypted message ok");
    /*
     * Unfortunately, Context Imprint mode is not fully compatible as Themis
     * is unable to verify correctness of decryption and thus does not use
     * the compatibility path unless a serious failure occurs. There is no
     * API to get the old behavior as it was deemed acceptable loss. Thus
     * we do not check the output content, it's most likely incorrect.
     */
}

void run_secure_cell_test(void)
{
    testsuite_enter_suite("secure cell: key generation");
    testsuite_run_test(secure_cell_key_generation);

    testsuite_enter_suite("secure cell: basic flow");
    testsuite_run_test(secure_cell_test);
    testsuite_run_test(secure_cell_test_lengths);

    testsuite_enter_suite("secure cell: api test");
    testsuite_run_test(secure_cell_api_test);

    testsuite_enter_suite("secure cell: context corruption");
    testsuite_run_test(secure_cell_context_corruption);

    testsuite_enter_suite("secure cell: compatibility with Themis 0.9.6");
    testsuite_run_test(secure_cell_0_9_6_compatibility);
}
