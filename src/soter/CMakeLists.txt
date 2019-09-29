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

if(ENGINE EQUAL BoringSSL)
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
if(ENGINE EQUAL OpenSSL)
    find_package(OpenSSL REQUIRED)
    target_include_directories(soter_object PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(soter_object INTERFACE ${OPENSSL_CRYPTO_LIBRARY})
endif()
