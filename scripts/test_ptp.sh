#! /bin/bash

CTEST_PARALLEL_LEVEL=4 $(dirname `realpath $0`)/../test/cmake/ptp/run.sh test all
