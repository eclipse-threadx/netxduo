#!/bin/bash
##############################################################################
# Copyright (c) 2024 Microsoft Corporation
# Copyright (c) 2026 Eclipse ThreadX contributors
#
# This program and the accompanying materials are made available under the
# terms of the MIT License which is available at
# https://opensource.org/licenses/MIT.
#
# SPDX-License-Identifier: MIT
##############################################################################


date
echo $0
echo $1
echo $2
echo $3
legacy_server_connect=()
if [ "${NETXDUO_OPENSSL_LEGACY_SERVER_CONNECT:-0}" = "1" ]; then
    legacy_server_connect=(-legacy_server_connect)
fi

echo "GET / HTTP/1.1" | openssl s_client -connect "$1":"$2" "$3" -ign_eof \
    "${legacy_server_connect[@]}"
