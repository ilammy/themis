/*
 * Copyright (c) 2019 Cossack Labs Limited
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

#include <jni.h>

/* Keep the classes pinned to keep method IDs valid */
static jclass KeyGenerationException;
static jclass SecureCellException;
static jclass SecureCompareException;
static jclass SecureMessageWrapException;
static jclass SecureSessionException;

static const char* KeyGenerationExceptionName = "com/cossacklabs/themis/KeyGenerationException";
static const char* SecureCellExceptionName = "com/cossacklabs/themis/SecureCellException";
static const char* SecureCompareExceptionName = "com/cossacklabs/themis/SecureCompareException";
static const char* SecureMessageWrapExceptionName = "com/cossacklabs/themis/SecureMessageWrapException";
static const char* SecureSessionExceptionName = "com/cossacklabs/themis/SecureSessionException";

static jmethodID NewKeyGenerationException;
static jmethodID NewSecureCellException;
static jmethodID NewSecureCompareException;
static jmethodID NewSecureMessageWrapException;
static jmethodID NewSecureSessionException;

static jclass find_and_pin_class(JNIEnv* env, const char* name)
{
    jclass klass;
    jclass klassPinned;

    klass = (*env)->FindClass(env, name);
    if (!klass) {
        return NULL;
    }

    klassPinned = (*env)->NewGlobalRef(env, klass);
    (*env)->DeleteLocalRef(env, klass);
    return klassPinned;
}

static void unpin_class(JNIEnv* env, jclass klass)
{
    (*env)->DeleteGlobalRef(env, klass);
}

void init_themis_exception_classes(JNIEnv* env)
{
    KeyGenerationException = find_and_pin_class(env, KeyGenerationExceptionName);
    SecureCellException = find_and_pin_class(env, SecureCellExceptionName);
    SecureCompareException = find_and_pin_class(env, SecureCompareExceptionName);
    SecureMessageWrapException = find_and_pin_class(env, SecureMessageWrapExceptionName);
    SecureSessionException = find_and_pin_class(env, SecureSessionExceptionName);

    /* KeyGenerationException(int errorCode) */
    NewKeyGenerationException = (*env)->GetMethodID(env, KeyGenerationException, "<init>", "(I)V");
    /* SecureCellException(int errorCode) */
    NewSecureCellException = (*env)->GetMethodID(env, SecureCellException, "<init>", "(I)V");
    /* SecureCompareException(int errorCode) */
    NewSecureCompareException = (*env)->GetMethodID(env, SecureCompareException, "<init>", "(I)V");
    /* SecureMessageWrapException(int errorCode) */
    NewSecureMessageWrapException = (*env)->GetMethodID(env, SecureMessageWrapException, "<init>", "(I)V");
    /* SecureSessionException(int errorCode) */
    NewSecureSessionException = (*env)->GetMethodID(env, SecureSessionException, "<init>", "(I)V");
}

void free_themis_exception_classes(JNIEnv* env)
{
    unpin_class(env, KeyGenerationException);
    unpin_class(env, SecureCellException);
    unpin_class(env, SecureCompareException);
    unpin_class(env, SecureMessageWrapException);
    unpin_class(env, SecureSessionException);

    KeyGenerationException = NULL;
    SecureCellException = NULL;
    SecureCompareException = NULL;
    SecureMessageWrapException = NULL;
    SecureSessionException = NULL;

    NewKeyGenerationException = NULL;
    NewSecureCellException = NULL;
    NewSecureCompareException = NULL;
    NewSecureMessageWrapException = NULL;
    NewSecureSessionException = NULL;
}

static void throw_common_themis_exception(JNIEnv* env, jclass klass, jmethodID constructor, jint errorCode)
{
    jobject exception;

    if ((*env)->ExceptionCheck() == JNI_TRUE) {
        /*
         * If we're being called when another exception is being thrown
         * then this is cleanup path. Don't throw anything new.
         */
        return;
    }

    exception = (*env)->NewObject(env, klass, constructor, errorCode);
    if (!exception) {
        /*
         * Failed to construct exception object and that new exception
         * is already in progress. Well okay, throw it instead :)
         */
        return;
    }

    (*env)->Throw(env, exception);
}

void throw_themis_key_generation_exception(JNIEnv* env, jint errorCode)
{
    throw_common_themis_exception(env, KeyGenerationException, NewKeyGenerationException, errorCode);
}

void throw_themis_secure_cell_exception(JNIEnv* env, jint errorCode)
{
    throw_common_themis_exception(env, SecureCellException, NewSecureCellException, errorCode);
}

void throw_themis_secure_compare_exception(JNIEnv* env, jint errorCode)
{
    throw_common_themis_exception(env, SecureCompareException, NewSecureCompareException, errorCode);
}

void throw_themis_secure_message_wrap_exception(JNIEnv* env, jint errorCode)
{
    throw_common_themis_exception(env, SecureMessageWrapException, NewSecureMessageWrapException, errorCode);
}

void throw_themis_secure_session_exception(JNIEnv* env, jint errorCode)
{
    throw_common_themis_exception(env, SecureSessionException, NewSecureSessionException, errorCode);
}
