#!/bin/bash

set -e

cd $(dirname $0)
. ../coverage_common.sh

# Two reports come out of this suite and they measure different source.
#
# The subject report is nx_secure, which is outside the certified
# denominator -- TLS and DTLS appear in none of the nine 6.1.x certification
# artefacts. It is this suite's own figure and it is what this job publishes.
#
# The certified report is common/src, which this suite compiles and executes in
# full and discarded until now. This suite was measured reaching 21 lines of
# certified TCP source that no instrumented netxduo configuration reached, so
# it is an input to the component's figure, computed by coverage_merge.sh.
#
# The default_build_coverage exclusion list below is the suite's own and
# predates this work. It drops the DTLS and server-side handshake sources from
# that one configuration's subject report, which is out-of-scope source either
# way; it is carried unchanged rather than tidied, and it does not touch the
# certified report, which applies the certified denominator and nothing else.
if [ "$1" = "--merge" ]; then
    cov_merge per_configuration "nx_secure" "$cov_repo_root/nx_secure"
    exit $?
fi

subject_args=()
if [ "$1" = "default_build_coverage" ]; then
    root_path=$cov_repo_root/nx_secure/src
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
            subject_args+=(-e "$f")
        done
    done
fi

cov_report_subject "$1" nx_secure "${subject_args[@]}"
cov_report_certified "$1"
