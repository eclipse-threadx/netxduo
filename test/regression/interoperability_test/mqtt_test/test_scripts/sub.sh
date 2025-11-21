#! /bin/sh
dir=`dirname $0`
dir=`realpath $dir`
cd $dir
mosquitto_sub --cert CA/certs/ew2017.client.crt --key CA/private/ew2017.client.key --cafile CA/ca/ca.crt -p 8883 --insecure $*
