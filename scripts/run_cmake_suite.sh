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

usage()
{
    echo "Usage: $0 <suite> <build|test> [all|<profile> ...]" >&2
    exit 2
}

if [ "$#" -lt 2 ]; then
    usage
fi

readonly suite="$1"
readonly operation="$2"
shift 2

case "${suite}" in
    crypto|mqtt|mqtt_interoperability|netxduo|netxduo64|netxduo_fast|nx_secure|nx_secure_interoperability|ptp|web)
        ;;
    *)
        echo "Unsupported test suite: ${suite}" >&2
        usage
        ;;
esac

case "${operation}" in
    build|test)
        ;;
    *)
        echo "Unsupported operation: ${operation}" >&2
        usage
        ;;
esac

readonly script_directory="$(dirname "$(realpath "$0")")"
readonly suite_directory="${script_directory}/../test/cmake/${suite}"
readonly cmake_file="${suite_directory}/CMakeLists.txt"
readonly runner="${suite_directory}/run.sh"

if [ "$#" -eq 0 ]; then
    set -- all
fi

if [ "$1" = "all" ]; then
    if [ "$#" -ne 1 ]; then
        echo "The all profile cannot be combined with named profiles." >&2
        exit 2
    fi
else
    mapfile -t available_profiles < <(
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
        ' "${cmake_file}"
    )
    declare -A selected_profiles=()

    for profile in "$@"; do
        if [[ ! "${profile}" =~ ^[[:alnum:]_]+$ ]]; then
            echo "Malformed profile name: ${profile}" >&2
            exit 2
        fi
        if [[ -n "${selected_profiles[${profile}]:-}" ]]; then
            echo "Duplicate profile: ${profile}" >&2
            exit 2
        fi
        selected_profiles["${profile}"]=1

        profile_found=false
        for available_profile in "${available_profiles[@]}"; do
            if [ "${profile}" = "${available_profile}" ]; then
                profile_found=true
                break
            fi
        done
        if [ "${profile_found}" != true ]; then
            echo "Unknown ${suite} profile: ${profile}" >&2
            exit 2
        fi
    done
fi

if [ "${RUN_CMAKE_SUITE_DRY_RUN:-0}" = "1" ]; then
    printf '%s %s' "${runner}" "${operation}"
    printf ' %s' "$@"
    printf '\n'
    exit 0
fi

if [ "${operation}" = "test" ]; then
    if [[ "${suite}" = "mqtt_interoperability" || "${suite}" = "nx_secure_interoperability" ]]; then
        sudo env CTEST_PARALLEL_LEVEL=1 CTEST_REPEAT_FAIL="${CTEST_REPEAT_FAIL:-2}" \
            "${runner}" "${operation}" "$@"
    else
        CTEST_PARALLEL_LEVEL=4 CTEST_REPEAT_FAIL="${CTEST_REPEAT_FAIL:-2}" \
            "${runner}" "${operation}" "$@"
    fi
else
    "${runner}" "${operation}" "$@"
fi
