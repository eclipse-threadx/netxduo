#! /bin/bash

CTEST_PARALLEL_LEVEL=4 $(dirname `realpath $0`)/../test/cmake/web/run.sh test all
