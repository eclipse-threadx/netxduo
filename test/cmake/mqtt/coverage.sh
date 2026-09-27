#!/bin/bash

set -e

cd $(dirname $0)
. ../coverage_common.sh

# Two reports come out of this suite and they measure different source.
#
# The subject report is addons/mqtt, which is outside the certified
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
if [ "$1" = "--merge" ]; then
    cov_merge per_configuration "addons/mqtt" "$cov_repo_root/addons/mqtt"
    exit $?
fi

cov_report_subject "$1" "addons/mqtt"
cov_report_certified "$1"
