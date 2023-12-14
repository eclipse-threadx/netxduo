#!/bin/bash

date
#Show script name.
echo $0 $@

arg1=$1
arg2=$2
shift 2

cd "$( dirname "$0" )"
echo "hello" | openssl s_server -key "$arg1" -cert "$arg2" -naccept 1 $@
