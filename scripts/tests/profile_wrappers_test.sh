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

readonly test_directory="$(dirname "$(realpath "$0")")"
readonly scripts_directory="${test_directory}/.."

expect_failure()
{
    if "$@" >/dev/null 2>&1; then
        echo "Expected command to fail: $*" >&2
        exit 1
    fi
}

check_wrapper()
{
    local wrapper="$1"
    local suite="$2"
    local operation="$3"
    local profile="$4"
    local output

    output="$(RUN_CMAKE_SUITE_DRY_RUN=1 "${scripts_directory}/${wrapper}")"
    [[ "${output}" = *"/${suite}/run.sh ${operation} all" ]]

    output="$(RUN_CMAKE_SUITE_DRY_RUN=1 "${scripts_directory}/${wrapper}" "${profile}")"
    [[ "${output}" = *"/${suite}/run.sh ${operation} ${profile}" ]]
}

while read -r wrapper suite operation profile; do
    check_wrapper "${wrapper}" "${suite}" "${operation}" "${profile}"
done <<'EOF'
build_crypto.sh crypto build standalone_build
test_crypto.sh crypto test standalone_build
build_mqtt.sh mqtt build queue_depth_build
test_mqtt.sh mqtt test queue_depth_build
build_mqtt_interoperability.sh mqtt_interoperability build queue_depth_build
test_mqtt_interoperability.sh mqtt_interoperability test queue_depth_build
build_nxd.sh netxduo build v4_build
test_nxd.sh netxduo test v4_build
build_nxd64.sh netxduo64 build default_build_coverage
test_nxd64.sh netxduo64 test default_build_coverage
build_nxd_fast.sh netxduo_fast build v6_full_build
test_nxd_fast.sh netxduo_fast test v6_full_build
build_ptp.sh ptp build gptp_slave_build
test_ptp.sh ptp test gptp_slave_build
build_secure.sh nx_secure build psk_build_coverage
test_secure.sh nx_secure test psk_build_coverage
build_secure_interoperability.sh nx_secure_interoperability build psk_build_coverage
test_secure_interoperability.sh nx_secure_interoperability test psk_build_coverage
build_web.sh web build digest_authenticate_build
test_web.sh web test digest_authenticate_build
EOF

expect_failure env RUN_CMAKE_SUITE_DRY_RUN=1 \
    "${scripts_directory}/run_cmake_suite.sh" unknown build all
expect_failure env RUN_CMAKE_SUITE_DRY_RUN=1 \
    "${scripts_directory}/run_cmake_suite.sh" netxduo unknown all
expect_failure env RUN_CMAKE_SUITE_DRY_RUN=1 \
    "${scripts_directory}/run_cmake_suite.sh" netxduo build all v4_build
expect_failure env RUN_CMAKE_SUITE_DRY_RUN=1 \
    "${scripts_directory}/run_cmake_suite.sh" netxduo build v4_build v4_build
expect_failure env RUN_CMAKE_SUITE_DRY_RUN=1 \
    "${scripts_directory}/run_cmake_suite.sh" netxduo build not_a_profile
expect_failure env RUN_CMAKE_SUITE_DRY_RUN=1 \
    "${scripts_directory}/run_cmake_suite.sh" netxduo build 'v4_build;false'

output="$(RUN_CMAKE_SUITE_DRY_RUN=1 \
    "${scripts_directory}/run_cmake_suite.sh" netxduo build v4_build v6_build)"
[[ "${output}" = *"/netxduo/run.sh build v4_build v6_build" ]]

echo "Profile wrapper validation passed."
