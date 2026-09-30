#! /bin/bash

here=$(dirname `realpath $0`)
# Resolved, because the probe compares it against /proc/<pid>/exe, which is resolved.
cmake_path=$(realpath $here/../test/cmake/netxduo)

# Observe any test that outlives the threshold, so a ctest timeout leaves a record of
# where the process was. The probe reads /proc only; it changes no test and its output
# lands in build/hang_probe.txt, which the test_reports artifact already collects.
$here/hang_probe.sh $cmake_path/build 600 &
probe=$!
trap 'kill $probe 2>/dev/null' EXIT

CTEST_PARALLEL_LEVEL=4 $cmake_path/run.sh test all
