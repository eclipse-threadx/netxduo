#!/bin/bash

set -e

cd $(dirname $0)
. ../coverage_common.sh

# Two reports come out of this suite and they measure different source.
#
# The subject report is addons/ptp, which is outside the certified
# denominator. It is this suite's own figure, it is what this job publishes,
# and it is kept because it is the only coverage signal the component has for
# that addon.
#
# The certified report is common/src, which this suite compiles and executes in
# full -- every configuration builds the whole netxduo library -- and which it
# discarded until now. It is an input to the component's figure rather than a
# figure of its own: nothing here prints a certified percentage, because a
# percentage for the share of common/src one addon suite happens to reach is
# not a number anybody should read.

# The two gPTP configurations run their tests and cover nothing.
#
# All seven tests report N/A in both of them and exit 0, which ctest counts as a
# pass: measured, 511 .gcno and 497 .gcda on disk and every counter zero, so gcov
# reads 0.00% of nx_ip_create.c. A configuration in the merge set that covers no
# certified line is test evidence and not coverage, so it is declared here and
# written to per_configuration/informational/ instead -- the same path-rather-
# than-name enforcement the 64-bit and optimised builds use.
#
# It costs the denominator nothing, which was measured before it was declared.
# What these two compile beyond the default is nx_link.c and the VLAN sites, all
# behind NX_ENABLE_VLAN, which netxduo/tsn_build_coverage also defines and
# exercises with 843 tests; NX_ENABLE_GPTP and NX_PTP_CLIENT_TRANSPORT appear
# nowhere in common/src or common/inc. So the contributing set goes from 104 to
# 102 while the denominator stays 13,682 and the figure stays where it was.
#
# This is not a way of hiding the gap. gPTP has no test coverage, and an N/A that
# takes out a whole configuration has to be reported as exactly that.
INFORMATIONAL="gptp_master_build gptp_slave_build"

if [ "$1" = "--merge" ]; then
    cov_merge per_configuration "addons/ptp" "$cov_repo_root/addons/ptp"
    exit $?
fi

cov_report_subject "$1" "addons/ptp"

for configuration in $INFORMATIONAL; do
    if [ "$1" = "$configuration" ]; then
        cov_report_informational "$1"
        exit $?
    fi
done

cov_report_certified "$1"
