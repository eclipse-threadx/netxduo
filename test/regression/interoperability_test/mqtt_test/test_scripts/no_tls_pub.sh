#! /bin/sh
dir=`dirname $0`
dir=`realpath $dir`
cd $dir
mosquitto_pub $*
