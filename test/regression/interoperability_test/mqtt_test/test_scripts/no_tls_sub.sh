#! /bin/sh
dir=`dirname $0`
dir=`realpath $dir`
cd $dir
mosquitto_sub -p 8883 $*
