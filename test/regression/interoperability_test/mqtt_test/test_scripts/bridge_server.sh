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

if [ -d "../mosquitto-1.6.9/src/" ]; then 
    export PATH=$PATH;../mosquitto-1.4.10/src/
fi
mosquitto -c ./mosquitto-bridge.conf -v -p 8883
