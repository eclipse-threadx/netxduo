#!/bin/bash

set -e

cd $(dirname $0)
. ../coverage_common.sh

# netxduo_fast is netxduo's v6_full_build with one different nx_user.h, whose
# sole active define is NX_IP_PERIODIC_RATE 1000UL. That is a constant rather
# than a feature gate, so it compiles exactly the lines v6_full_build compiles
# and can add nothing to the denominator. It can add to the numerator, because
# a different tick rate changes which timeout and retransmission branches are
# taken, so it is instrumented and merged.
if [ "$1" = "--merge" ]; then
    cov_merge per_configuration/certified "certified source" "$cov_repo_root"
    exit $?
fi

cov_report_certified "$1"
