#! /bin/bash

function kill_mqtt_server(){
    kill $mqtt_server_pid
    wait
}

dir=`dirname $0`
dir=`realpath $dir`
cd $dir
mosquitto -c ./mosquitto_no_tls.conf -v $* &
mqtt_server_pid=$!
trap kill_mqtt_server TERM ALRM
wait
