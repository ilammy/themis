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

#ifndef THEMIS_JNI_ERROR_H
#define THEMIS_JNI_ERROR_H

#include <jni.h>

void init_themis_exception_classes(JNIEnv* env);

void free_themis_exception_classes(JNIEnv* env);

void throw_themis_key_generation_exception(JNIEnv* env, jint errorCode);
void throw_themis_secure_cell_exception(JNIEnv* env, jint errorCode);
void throw_themis_secure_compare_exception(JNIEnv* env, jint errorCode);
void throw_themis_secure_message_wrap_exception(JNIEnv* env, jint errorCode);
void throw_themis_secure_session_exception(JNIEnv* env, jint errorCode);

#endif /* THEMIS_JNI_ERROR_H */
