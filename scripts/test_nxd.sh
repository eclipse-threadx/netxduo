#! /bin/bash

CTEST_PARALLEL_LEVEL=4 $(dirname `realpath $0`)/../test/cmake/netxduo/run.sh test default_build_coverage v4_full_build
