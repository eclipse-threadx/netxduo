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
# Portions of this file were generated with AI assistance.

set -euo pipefail

terminate_process_group()
{
    local pid_file="$1"
    local process_group_id=""
    local attempt

    if [ -r "${pid_file}" ]; then
        read -r process_group_id < "${pid_file}" || true
    fi

    if [[ "${process_group_id}" =~ ^[1-9][0-9]*$ ]]; then
        kill -TERM -- "-${process_group_id}" 2>/dev/null || true
        for attempt in {1..50}; do
            if ! kill -0 "${process_group_id}" 2>/dev/null; then
                break
            fi
            sleep 0.1
        done
        kill -KILL -- "-${process_group_id}" 2>/dev/null || true
    fi

    rm -f -- "${pid_file}"
}

if [ "${1:-}" = "--cleanup" ]; then
    if [ "$#" -ne 2 ]; then
        echo "Usage: $0 --cleanup <pid-file>" >&2
        exit 2
    fi
    terminate_process_group "$2"
    exit 0
fi

if [ "${1:-}" = "--check" ]; then
    if [ "$#" -lt 3 ]; then
        echo "Usage: $0 --check <repository-root> <suite> [...]" >&2
        exit 2
    fi
    readonly repository_root="$2"
    shift 2
    command -v setsid >/dev/null
    test -x "${repository_root}/scripts/run_cmake_suite.sh"
    for suite in "$@"; do
        case "${suite}" in
            mqtt_interoperability)
                test -L "${repository_root}/test/cmake/mqtt_interoperability/CMakeLists.txt" || {
                    echo 'The MQTT interoperability suite requires a Linux-native Git checkout with symbolic links.' >&2
                    exit 2
                }
                ;;
            nx_secure_interoperability)
                ;;
            *)
                echo "Unsupported interoperability suite: ${suite}" >&2
                exit 2
                ;;
        esac
        test -L "${repository_root}/test/cmake/${suite}/libs" || {
            echo "The ${suite} suite requires a Linux-native Git checkout with symbolic links." >&2
            exit 2
        }
        test -L "${repository_root}/test/cmake/${suite}/coverage.sh" || {
            echo "The ${suite} suite requires a Linux-native Git checkout with symbolic links." >&2
            exit 2
        }
    done
    exit 0
fi

if [ "$#" -lt 5 ]; then
    echo "Usage: $0 <pid-file> <repository-root> <suite> <build|test> <configuration> [...]" >&2
    exit 2
fi

readonly pid_file="$1"
readonly repository_root="$2"
readonly suite="$3"
readonly operation="$4"
shift 4

case "${suite}" in
    mqtt_interoperability|nx_secure_interoperability)
        ;;
    *)
        echo "Unsupported interoperability suite: ${suite}" >&2
        exit 2
        ;;
esac

case "${operation}" in
    build|test)
        ;;
    *)
        echo "Unsupported operation: ${operation}" >&2
        exit 2
        ;;
esac

readonly runner="${repository_root}/scripts/run_cmake_suite.sh"
if [ ! -x "${runner}" ]; then
    echo "Unable to execute ${runner}" >&2
    exit 2
fi

child_pid=""
cleanup()
{
    local status="$?"

    trap - EXIT INT TERM
    terminate_process_group "${pid_file}"
    exit "${status}"
}
trap cleanup EXIT INT TERM

setsid "${runner}" "${suite}" "${operation}" "$@" &
child_pid="$!"
printf '%s\n' "${child_pid}" > "${pid_file}"
wait "${child_pid}"
