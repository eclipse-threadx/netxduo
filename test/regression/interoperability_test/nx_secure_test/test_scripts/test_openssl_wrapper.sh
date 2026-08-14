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

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
wrapper_test_dir="$(mktemp -d)"
trap 'rm -rf -- "${wrapper_test_dir}"' EXIT

readonly WRAPPER_LOG="${wrapper_test_dir}/wrapper.log"
export WRAPPER_LOG

printf '%s\n' '#!/bin/bash' \
    'printf "openssl_conf=%s\n" "${OPENSSL_CONF:-}" > "${WRAPPER_LOG}"' \
    'printf "openssl_arg=%s\n" "$@" >> "${WRAPPER_LOG}"' \
    > "${wrapper_test_dir}/openssl"
printf '%s\n' '#!/bin/bash' \
    'printf "wolfssl_pwd=%s\n" "${PWD}" > "${WRAPPER_LOG}"' \
    'printf "wolfssl_arg=%s\n" "$@" >> "${WRAPPER_LOG}"' \
    > "${wrapper_test_dir}/wolfssl-server"
chmod +x "${wrapper_test_dir}/openssl" "${wrapper_test_dir}/wolfssl-server"

mkdir -p "${wrapper_test_dir}/wolfssl-home/certs"
touch "${wrapper_test_dir}/wolfssl-home/certs/dh2048.pem"
touch "${wrapper_test_dir}/ECTestServer9_192.key"
touch "${wrapper_test_dir}/ECTestServer9_192.crt"
touch "${wrapper_test_dir}/ECCA2.crt"

export NETXDUO_OPENSSL_BIN="${wrapper_test_dir}/openssl"
export NETXDUO_WOLFSSL_SERVER_BIN="${wrapper_test_dir}/wolfssl-server"
export NETXDUO_WOLFSSL_HOME="${wrapper_test_dir}/wolfssl-home"

"${SCRIPT_DIR}/openssl" version
grep -q "openssl_conf=${SCRIPT_DIR}/openssl_interoperability.cnf" "${WRAPPER_LOG}"
grep -q 'openssl_arg=version' "${WRAPPER_LOG}"

"${SCRIPT_DIR}/openssl" s_server -rev \
    -key "${wrapper_test_dir}/ECTestServer9_192.key" \
    -cert "${wrapper_test_dir}/ECTestServer9_192.crt" \
    -CAfile "${wrapper_test_dir}/ECCA2.crt" \
    -curves prime192v1 -naccept 1 -tls1_2 \
    -cipher ECDH-ECDSA-AES128-SHA256 -port 4433
grep -q "wolfssl_pwd=${wrapper_test_dir}/wolfssl-home" "${WRAPPER_LOG}"
grep -q 'wolfssl_arg=ECDH-ECDSA-AES128-SHA256' "${WRAPPER_LOG}"
if grep -q 'wolfssl_arg=ECDHE-RSA-AES128-SHA256' "${WRAPPER_LOG}"; then
    echo "Positive static-ECDH case selected the failure cipher" >&2
    exit 1
fi

"${SCRIPT_DIR}/openssl" s_server -rev \
    -key "${wrapper_test_dir}/ECTestServer9_192.key" \
    -cert "${wrapper_test_dir}/ECTestServer9_192.crt" \
    -CAfile "${wrapper_test_dir}/ECCA2.crt" \
    -curves secp224r1 -naccept 1 -tls1_2 \
    -cipher ECDH-ECDSA-AES128-SHA256 -port 4433
grep -q 'wolfssl_arg=ECDHE-RSA-AES128-SHA256' "${WRAPPER_LOG}"
