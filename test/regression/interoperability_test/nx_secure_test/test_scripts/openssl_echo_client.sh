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
#Show script name.
echo $0 $@

arg1=$1
arg2=$2
shift 2

legacy_server_connect=()
if [ "${NETXDUO_OPENSSL_LEGACY_SERVER_CONNECT:-0}" = "1" ]; then
    legacy_server_connect=(-legacy_server_connect)
fi

cd "$( dirname "$0" )"
echo "hello" | openssl s_client -connect "$arg1":"$arg2" -ign_eof \
    "${legacy_server_connect[@]}" "$@"
