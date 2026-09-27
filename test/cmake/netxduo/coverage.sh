#!/bin/bash

set -e

cd $(dirname $0)
. ../coverage_common.sh

# This suite's subject is the certified source itself, so it emits no separate
# subject report: its per-configuration tracefiles are the certified ones, and
# its merged report is the union of them over all 43 configurations.
#
# That merged figure is this suite's, not the component's. The component's is a
# union across the eight suites that compile certified source, and
# coverage_merge.sh computes it one directory up.
if [ "$1" = "--merge" ]; then
    cov_merge per_configuration/certified "certified source" "$cov_repo_root"
    exit $?
fi

cov_report_certified "$1"
