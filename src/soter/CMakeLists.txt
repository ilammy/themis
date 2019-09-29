# Copyright (c) 2019 Cossack Labs Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

file(GLOB soter_src *.c ed25519/*.c)

if(DEFINED ENGINE)
    if(NOT ENGINE MATCHES "BoringSSL|OpenSSL|LibreSSL")
        message(FATAL_ERROR "invalid ENGINE: ${ENGINE}, supported values: BoringSSL, OpenSSL, LibreSSL")
    endif()
else()
    # TODO: set BoringSSL for Android builds by default
    set(ENGINE OpenSSL)
endif()

if(${ENGINE} STREQUAL BoringSSL)
    file(GLOB engine_src boringssl/*.c)
else()
    file(GLOB engine_src openssl/*.c)
endif()

add_library(soter_object OBJECT ${soter_src} ${engine_src})
add_library(soter_static STATIC $<TARGET_OBJECTS:soter_object>)
add_library(soter_shared SHARED $<TARGET_OBJECTS:soter_object>)

target_include_directories(soter_object PRIVATE . ..)

# Windows builds have to produce import libraries for DLLs
# so the actual static library must have a different name
if(WIN32)
set_target_properties(soter_static PROPERTIES OUTPUT_NAME soter_static)
else()
set_target_properties(soter_static PROPERTIES OUTPUT_NAME soter)
endif()
set_target_properties(soter_shared PROPERTIES OUTPUT_NAME soter)

# While technically static libraries do not need PIC, we would like to compile
# the object files only once and thus compile them with PIC to reuse them with
# shared libraries. Some people argue that this has considerable performance
# impact, but it should be negligible on the architectures we care about:
# i686, x86_64, ARMv7, ARMv8, ARM64.
set_property(TARGET soter_object PROPERTY POSITION_INDEPENDENT_CODE 1)

# TODO: support for BoringSSL and LibreSSL
# TODO: set CRYPTO_ENGINE_PATH and CRYPTO_ENGINE_DEF
if(${ENGINE} STREQUAL OpenSSL)
    # If we're on macOS then tell CMake about OpenSSL installed by Homebrew,
    # unless the user gives their own hints
    if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin" AND NOT DEFINED OPENSSL_ROOT_DIR)
        execute_process(COMMAND brew --prefix openssl
                        OUTPUT_VARIABLE OPENSSL_ROOT_DIR
                        OUTPUT_STRIP_TRAILING_WHITESPACE
                        ERROR_QUIET)
    endif()
    find_package(OpenSSL REQUIRED)
    target_link_libraries(soter_object OpenSSL::Crypto)
    target_link_libraries(soter_static OpenSSL::Crypto)
    target_link_libraries(soter_shared OpenSSL::Crypto)
    # Due to historical reasons Themis needs access to Soter cryptographic engine,
    # export the path here so that it can be reused.
    set(soter_engine_include "${OPENSSL_INCLUDE_DIR}"
        CACHE PATH "Soter cryptographic engine include directory")
    mark_as_advanced(soter_engine_include)
endif()
