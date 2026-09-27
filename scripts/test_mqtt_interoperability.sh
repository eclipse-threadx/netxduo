#! /bin/bash

# sudo resets the environment, so a variable the workflow sets on the step
# does not reach the runner -- which is why CTEST_PARALLEL_LEVEL has always
# been written on this line rather than exported. TX_COVERAGE and
# CTEST_REPEAT_FAIL need the same treatment and did not have it.
#
# TX_COVERAGE decides whether coverage is collected and merged at all. Left
# behind, this suite collects only the configurations whose names end in
# _coverage, never writes the merged report the workflow publishes, and
# contributes a short set to the certified figure.
#
# CTEST_REPEAT_FAIL decides how many attempts ctest gives a failing test.
# Left behind, the runner's own default of 2 applies and an intermittent
# failure is reported as a pass -- which is the one thing certification
# evidence must not do, and the reason the workflow sets it to 1.
sudo TX_COVERAGE=${TX_COVERAGE:-OFF} CTEST_REPEAT_FAIL=${CTEST_REPEAT_FAIL:-1} CTEST_PARALLEL_LEVEL=1 $(dirname `realpath $0`)/../test/cmake/mqtt_interoperability/run.sh test all
