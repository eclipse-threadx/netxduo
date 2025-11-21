#! /bin/bash

CTEST_PARALLEL_LEVEL=4 $(dirname `realpath $0`)/../test/cmake/mqtt/run.sh test all
