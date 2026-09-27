#! /bin/bash

# The tests create a veth pair, address it and capture from it, so the runner
# has to hold CAP_NET_ADMIN and CAP_NET_RAW. On a workstation that means sudo.
# In CI it does not: the steps already run as root inside the pinned container,
# which carries no sudo at all, so invoking it unconditionally would fail the
# job on a missing binary rather than on anything to do with the tests. The
# capabilities themselves come from the container, not from here.
#
# sudo resets the environment, so a variable the workflow sets on the step does
# not reach the runner -- which is why CTEST_PARALLEL_LEVEL has always been
# written on this line rather than exported. TX_COVERAGE and CTEST_REPEAT_FAIL
# need the same treatment and did not have it.
#
# TX_COVERAGE decides whether coverage is collected and merged at all. Left
# behind, this suite collects only the configurations whose names end in
# _coverage, never writes the merged report the workflow publishes, and
# contributes a short set to the certified figure.
#
# CTEST_REPEAT_FAIL decides how many attempts ctest gives a failing test. Left
# behind, the runner's own default of 2 applies and an intermittent failure is
# reported as a pass -- which is the one thing certification evidence must not
# do, and the reason the workflow sets it to 1.
#
# env is the neutral prefix rather than an empty array. Bash decides which
# words are assignments while it parses the line, before any expansion, so with
# an empty first word TX_COVERAGE=... is parsed as the command name and the run
# fails with "TX_COVERAGE=ON: command not found". env takes the assignments as
# arguments and applies them itself, which is what sudo does too.
if [ "$(id -u)" -eq 0 ]; then
    privileged=(env)
else
    privileged=(sudo)
fi

"${privileged[@]}" TX_COVERAGE=${TX_COVERAGE:-OFF} CTEST_REPEAT_FAIL=${CTEST_REPEAT_FAIL:-1} CTEST_PARALLEL_LEVEL=1 $(dirname `realpath $0`)/../test/cmake/nx_secure_interoperability/run.sh test all
