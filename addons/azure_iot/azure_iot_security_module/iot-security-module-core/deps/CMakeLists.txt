# Copyright (c) Microsoft Corporation. All rights reserved.
# SPDX-License-Identifier: MIT

cmake_minimum_required (VERSION 3.10)

set(build_as_32 OFF CACHE BOOL "build as 32 bit")

# Build flatcc runtime library
add_library(flatccrt STATIC
    $<$<NOT:$<BOOL:${serializer_custom_allocator}>>:${CMAKE_CURRENT_SOURCE_DIR}/flatcc/src/runtime/emitter.c>

    flatcc/src/runtime/builder.c
    flatcc/src/runtime/refmap.c
)

target_compile_definitions(flatccrt PUBLIC
    FLATCC_NO_ASSERT
    $<$<NOT:$<BOOL:${serializer_custom_allocator}>>:FLATCC_EMITTER_PAGE_SIZE=14016>
)
target_include_directories(flatccrt PUBLIC flatcc/include)

target_compile_options(flatccrt
    PUBLIC
        $<$<BOOL:${build_as_32}>:-m32>
)

if(${run_unittests} OR ${build_json_printer})
    add_library(flatccrt_json STATIC
        flatcc/src/runtime/json_printer.c
    )
    target_include_directories(flatccrt_json PUBLIC flatcc/include)
    target_compile_options(flatccrt_json
        PUBLIC
            $<$<BOOL:${build_as_32}>:-m32>
    )
endif()
