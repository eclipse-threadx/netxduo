#! /bin/bash
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


function kill_mqtt_server(){
    kill $mqtt_server_pid
    wait
}

dir=`dirname $0`
dir=`realpath $dir`
cd $dir
mosquitto -c ./mosquitto.conf -v $* &
mqtt_server_pid=$!
trap kill_mqtt_server TERM ALRM
wait
