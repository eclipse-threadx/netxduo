#!/bin/bash
##############################################################################
# Copyright (c) 2026 Eclipse ThreadX contributors
#
# This program and the accompanying materials are made available under the
# terms of the MIT License which is available at
# https://opensource.org/licenses/MIT.
#
# SPDX-License-Identifier: MIT
##############################################################################

set -euo pipefail

script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "${script_directory}/.." && pwd)"
suite_directory="${repository_root}/test/cmake/netxduo"

cd "${suite_directory}"

# Clone required sibling test dependencies if not already present
[ -d ../threadx ] || git clone https://github.com/eclipse-threadx/threadx.git ../threadx --depth 1
[ -d ../filex ] || git clone https://github.com/eclipse-threadx/filex.git ../filex --depth 1

# Ensure bootstrap wrapper is linked
[ -f .run.sh ] || ln -sf ../threadx/scripts/cmake_bootstrap.sh .run.sh

# Build shared threadx and filex libraries (libs) once
./.run.sh build_libs

# Read all BUILD_CONFIGURATIONS from test/cmake/netxduo/CMakeLists.txt
mapfile -t profiles < <(
    awk '
        /set[[:space:]]*\(BUILD_CONFIGURATIONS/ {
            capture = 1
            sub(/^.*set[[:space:]]*\(BUILD_CONFIGURATIONS[[:space:]]*/, "")
        }
        capture {
            closing_parenthesis = index($0, ")")
            if (closing_parenthesis != 0) {
                $0 = substr($0, 1, closing_parenthesis - 1)
            }
            for (field = 1; field <= NF; field++) {
                if ($field ~ /^[[:alnum:]_]*build[[:alnum:]_]*$/) {
                    print $field
                }
            }
            if (closing_parenthesis != 0) {
                exit
            }
        }
    ' CMakeLists.txt
)

if [ "${#profiles[@]}" -eq 0 ]; then
    echo "Error: No BUILD_CONFIGURATIONS found in CMakeLists.txt" >&2
    exit 2
fi

if [ "$#" -gt 0 ]; then
    selected_profiles=("$@")
else
    selected_profiles=("${profiles[@]}")
fi

echo "======================================================================"
echo "Compiling NetX Duo library across ${#selected_profiles[@]} profiles (compile-only)"
echo "======================================================================"

toolchain_file="$(realpath ../threadx/cmake/linux.cmake)"
failed_profiles=()
mkdir -p build

for profile in "${selected_profiles[@]}"; do
    printf 'Compiling %-30s ... ' "${profile}"

    # Configure profile with compile-only flag
    if ! cmake -B"build/${profile}" -GNinja -DBUILD_SHARED_LIBS=ON \
               -DCMAKE_TOOLCHAIN_FILE="${toolchain_file}" \
               -DCMAKE_BUILD_TYPE="${profile}" \
               -DNETXDUO_COMPILE_ONLY=ON \
               -DTX_COVERAGE=OFF . >"build/${profile}_configure.log" 2>&1; then
        echo "CONFIG FAILED"
        failed_profiles+=("${profile} (configure)")
        cat "build/${profile}_configure.log" >&2
        continue
    fi

    # Compile ONLY netxduo library target (no tests, no test executables)
    if ! cmake --build "build/${profile}" --target netxduo -- -k 0 >"build/${profile}_build.log" 2>&1; then
        echo "COMPILE FAILED"
        failed_profiles+=("${profile} (compile)")
        cat "build/${profile}_build.log" >&2
        continue
    fi

    echo "OK"
done

echo "======================================================================"
if [ "${#failed_profiles[@]}" -ne 0 ]; then
    echo "ERROR: ${#failed_profiles[@]} of ${#selected_profiles[@]} NetX Duo profiles failed to compile:" >&2
    for failed in "${failed_profiles[@]}"; do
        echo "  - ${failed}" >&2
    done
    exit 1
fi

echo "SUCCESS: All ${#selected_profiles[@]} NetX Duo profiles compiled the netxduo library cleanly."
exit 0
