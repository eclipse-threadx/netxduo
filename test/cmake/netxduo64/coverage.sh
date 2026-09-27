#!/bin/bash

set -e

cd $(dirname $0)
. ../coverage_common.sh

# netxduo64 builds the certified source under a different ABI -- no -m32, ELF
# 64-bit objects -- so its coverage is not evidence for the certified binary
# and it is kept out of the merge. It stays a test suite: 614 tests and
# real 64-bit portability signal that no other suite gives.
#
# The exclusion is enforced by where this writes. cov_report_informational puts
# the tracefiles under per_configuration/informational/, and coverage_merge.sh
# collects per_configuration/certified/ only. There is no argument to this
# script that reaches the merge set.
#
# Three lines are why: nx_ip_thread_entry.c:139,
# nx_ip_periodic_timer_entry.c:82 and nx_ip_fast_periodic_timer_entry.c:82
# carry 0 branches at 32-bit and 2 at 64-bit, measured on this tree, so position
# does not identify the same source branch across that boundary and a union
# over it would report branches covered that the certified binary does not
# contain.
if [ "$1" = "--merge" ]; then
    cov_merge per_configuration/informational "certified source, informational" \
              "$cov_repo_root"
    status=$?
    mkdir -p coverage_report/merged
    cat > coverage_report/merged/EXCLUDED-FROM-THE-CERTIFIED-FIGURE.txt <<'NOTE'
This report measures common/src built 64-bit.

The NetX Duo certification coverage figure is taken from 32-bit builds of the
certified configuration. This suite builds the same source with a different
pointer width, structure layout and code generation, so its figures are
portability signal and not coverage evidence, and they are excluded from the
merged certification figure.

The certification figure is the union across the suites that build the
certified source 32-bit. It is published separately and this report is not one
of its inputs.
NOTE
    exit $status
fi

cov_report_informational "$1"
