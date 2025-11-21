#!/bin/bash

set -e

cd $(dirname $0)
root_path=$(cd ../../../nx_secure/src; pwd)
mkdir -p coverage_report/$1
extra_args=""
if [ "$1" == "default_build_coverage" ];
then
    exclude_list="nx*_secure_dtls_*.c \
                  nx_secure_tls_server_handshake.c \
                  nx_secure_tls_process_clienthello.c \
                  nx_secure_tls_1_3_server_handshake.c \
                  nx_secure_tls_send_server* \
                  nx_secure_tls_process_client*"
    for e in $exclude_list
    do
        for f in $(ls $root_path/$e);
        do
            extra_args+="-e $f "
        done
    done
fi
gcovr --object-directory=build/$1/netxduo/CMakeFiles/netxduo.dir/nx_secure -r ../../../nx_secure --xml-pretty $extra_args --output coverage_report/$1.xml
gcovr --object-directory=build/$1/netxduo/CMakeFiles/netxduo.dir/nx_secure -r ../../../nx_secure --html --html-details $extra_args --output coverage_report/$1/index.html
