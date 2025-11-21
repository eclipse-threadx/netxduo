#! /bin/sh
if [ -d "../mosquitto-1.6.9/src/" ]; then 
    export PATH=$PATH;../mosquitto-1.4.10/src/
fi
mosquitto -c ./mosquitto-bridge.conf -v -p 8883
