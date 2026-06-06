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

cd "$( dirname "$0" )"
(sleep 4;echo "hello") | openssl-1.1 s_server -key "$arg1" -cert "$arg2" -naccept 1 $@
