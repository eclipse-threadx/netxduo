#!/bin/bash

set -e

cd $(dirname $0)
. ../coverage_common.sh

# crypto compiles no certified source, and it is the one suite excluded from
# the component's merge by construction rather than by measurement of what it
# covers. Its CMakeLists filters the netxduo target's SOURCES down to
# crypto_libraries, so the certified object directory does not exist.
#
# That exclusion had to survive instrumenting every configuration, so it is
# checked on every run instead of being asserted in a comment: the assertion
# below fails if this suite ever compiles a certified-source object, which is
# the only thing that could make the exclusion wrong.
#
# Its subject report is crypto_libraries, which is outside the certified
# denominator, and it is kept for the same reason the addon suites' are.
if [ "$1" = "--merge" ]; then
    cov_merge per_configuration "crypto_libraries" "$cov_repo_root/crypto_libraries"
    exit $?
fi

cov_report_subject "$1" crypto_libraries
cov_assert_no_certified_objects "$1"
