#!/bin/bash

set -e

cd $(dirname $0)
. ../coverage_common.sh

# Configurations whose coverage is not evidence for the certified binary.
#
# optimize_build is default_build_coverage plus -O3. Same source, same macros,
# one flag -- and -O3 renumbers basic blocks and reattributes lines, so its
# tracefile does not describe the same compiled form as the other 42. Measured
# against default_build_coverage: it reports 1,604 executable lines the other
# does not and omits 972 that it does, and of the 1,302 lines it alone covers,
# 1,300 are lines no other configuration compiles at all. The remaining two are
# a continuation line of a condition whose first line every configuration covers
# (nx_ip_interface_address_set.c:141) and a trace macro that expands to nothing
# here (nxd_nd_cache_entry_delete.c:87). It is the sole source of coverage for
# no construct, and it would add 1,312 optimisation artefacts to the
# denominator, which no unoptimised certified build contains.
#
# This is the same rule that keeps netxduo64 out -- a build whose code
# generation differs from the certified build's is test evidence, not coverage
# evidence -- applied to the optimisation level rather than the ABI. The
# configuration keeps running, because an optimisation-dependent defect is
# exactly what it is there to catch.
#
# The exclusion is a path, not a name check that something else has to honour:
# these configurations go to per_configuration/informational/ and
# coverage_merge.sh collects per_configuration/certified/ only.
INFORMATIONAL="optimize_build"

# This suite's subject is the certified source itself, so it emits no separate
# subject report: its per-configuration tracefiles are the certified ones, and
# its merged report is the union of them.
#
# That merged figure is this suite's, not the component's. The component's is a
# union across the suites that compile certified source, and coverage_merge.sh
# computes it one directory up.
if [ "$1" = "--merge" ]; then
    cov_merge per_configuration/certified "certified source" "$cov_repo_root"
    exit $?
fi

for configuration in $INFORMATIONAL; do
    if [ "$1" = "$configuration" ]; then
        cov_report_informational "$1"
        exit $?
    fi
done

cov_report_certified "$1"
