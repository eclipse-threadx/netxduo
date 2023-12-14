#!/bin/bash

date
echo $0
echo $1
echo $2
echo $3
echo "GET / HTTP/1.1" | openssl s_client -connect "$1":"$2" "$3" -ign_eof
