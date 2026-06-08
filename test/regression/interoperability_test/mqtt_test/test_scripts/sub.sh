#! /bin/sh
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

dir=`dirname $0`
dir=`realpath $dir`
cd $dir
mosquitto_sub --cert CA/certs/ew2017.client.crt --key CA/private/ew2017.client.key --cafile CA/ca/ca.crt -p 8883 --insecure $*
