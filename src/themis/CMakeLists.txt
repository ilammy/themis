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

file(GLOB themis_src *.c)

add_library(themis_object OBJECT ${themis_src})
add_library(themis_static STATIC $<TARGET_OBJECTS:themis_object>)
add_library(themis_shared SHARED $<TARGET_OBJECTS:themis_object>)

target_include_directories(themis_object PRIVATE . ..)

# Windows builds have to produce import libraries for DLLs
# so the actual static library must have a different name
if(WIN32)
set_target_properties(themis_static PROPERTIES OUTPUT_NAME themis_static)
else()
set_target_properties(themis_static PROPERTIES OUTPUT_NAME themis)
endif()
set_target_properties(themis_shared PROPERTIES OUTPUT_NAME themis)

# While technically static libraries do not need PIC, we would like to compile
# the object files only once and thus compile them with PIC to reuse them with
# shared libraries. Some people argue that this has considerable performance
# impact, but it should be negligible on the architectures we care about:
# i686, x86_64, ARMv7, ARMv8, ARM64.
set_property(TARGET themis_object PROPERTY POSITION_INDEPENDENT_CODE 1)

target_link_libraries(themis_static soter_static)
target_link_libraries(themis_shared soter_shared)
