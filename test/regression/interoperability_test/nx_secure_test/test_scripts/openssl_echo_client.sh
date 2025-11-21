#!/bin/bash

date
#Show script name.
echo $0 $@

arg1=$1
arg2=$2
shift 2

cd "$( dirname "$0" )"
echo "hello" | openssl s_client -connect "$arg1":"$arg2" -ign_eof $@
